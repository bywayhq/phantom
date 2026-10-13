use std::{error::Error, future::Future, time::Duration};

use tokio::{sync::oneshot, time::timeout};

use super::{TestResult, bounded_for};
use crate::support::tunnel_proxy::ConnectionPeer;

const DEADLINE: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);

#[derive(Debug, PartialEq, Eq)]
enum PeerExit {
    Cancelled,
    Completed,
}

enum Outcome<T> {
    Served(TestResult<T>),
    Released,
}

struct ExitWitness {
    sender: Option<oneshot::Sender<PeerExit>>,
    completed: bool,
}

impl Drop for ExitWitness {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let exit = if self.completed {
                PeerExit::Completed
            } else {
                PeerExit::Cancelled
            };
            // The observer may itself have failed. A failed send is not closure evidence.
            let _ = sender.send(exit);
        }
    }
}

struct Observation<T> {
    release: Option<oneshot::Sender<()>>,
    exit: oneshot::Receiver<PeerExit>,
    outcome: oneshot::Receiver<Outcome<T>>,
}

impl<T> Drop for Observation<T> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            // Exceptional control exit must also release the old detached fixture.
            let _ = release.send(());
        }
    }
}

fn observe<T: Send + 'static>(
    future: impl Future<Output = TestResult<T>> + Send + 'static,
) -> (ConnectionPeer<TestResult<()>>, Observation<T>) {
    let (release, released) = oneshot::channel();
    let (exit_sender, exit) = oneshot::channel();
    let (outcome_sender, outcome) = oneshot::channel();
    let witness = ExitWitness {
        sender: Some(exit_sender),
        completed: false,
    };
    let peer = ConnectionPeer::spawn(async move {
        let mut witness = witness;
        let outcome = tokio::select! {
            result = future => Outcome::Served(result),
            result = released => match result {
                Ok(()) => Outcome::Released,
                Err(error) => Outcome::Served(Err(error.into())),
            },
        };
        witness.completed = true;
        outcome_sender
            .send(outcome)
            .map_err(|_| "peer result observer disappeared")?;
        TestResult::Ok(())
    });
    (
        peer,
        Observation {
            release: Some(release),
            exit,
            outcome,
        },
    )
}

impl<T> Observation<T> {
    async fn require_cancelled(mut self) -> TestResult<()> {
        let observed = match timeout(QUIET, &mut self.exit).await {
            Ok(result) => Some(result?),
            Err(_) => None,
        };

        if observed.is_none() {
            self.release
                .take()
                .ok_or("missing fallback release")?
                .send(())
                .map_err(|_| "fallback peer already stopped")?;
            match timeout(DEADLINE, &mut self.outcome).await?? {
                Outcome::Released => {}
                Outcome::Served(result) => {
                    result?;
                    return Err("peer completed before fallback".into());
                }
            }
            assert_eq!(
                timeout(DEADLINE, &mut self.exit).await??,
                PeerExit::Completed
            );
        } else if observed == Some(PeerExit::Completed) {
            match timeout(DEADLINE, &mut self.outcome).await?? {
                Outcome::Served(result) => {
                    result?;
                }
                Outcome::Released => return Err("unsolicited fallback release".into()),
            }
        }

        assert_eq!(
            observed,
            Some(PeerExit::Cancelled),
            "fixture outlived its owner during finite observation"
        );
        Ok(())
    }

    async fn served(mut self) -> TestResult<T> {
        let result = match timeout(DEADLINE, &mut self.outcome).await?? {
            Outcome::Served(result) => result,
            Outcome::Released => return Err("peer needed fallback on its normal path".into()),
        };
        assert_eq!(
            timeout(DEADLINE, &mut self.exit).await??,
            PeerExit::Completed
        );

        result
    }
}

fn cause<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref() {
            return Some(cause);
        }

        error = error.source()?;
    }
}

#[tokio::test]
async fn stream_deadline_retains_its_elapsed_cause() -> TestResult<()> {
    let error = bounded_for(QUIET, std::future::pending())
        .await
        .err()
        .ok_or("pending stream operation completed")?;
    assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    Ok(())
}

#[cfg(feature = "websocket")]
mod websocket {
    use std::io;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::support::{tls::read_head, websocket::header_value};

    type Opening = (
        Option<Vec<u8>>,
        Vec<u8>,
        crate::support::websocket::ClientFrame,
    );

    async fn opening() -> TestResult<(
        ConnectionPeer<TestResult<()>>,
        Observation<Opening>,
        TcpStream,
    )> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (peer, observation) = observe(super::super::websocket::serve(listener, false));
        let mut client = TcpStream::connect(address).await?;
        client
            .write_all(b"CONNECT 127.0.0.1:321 HTTP/1.1\r\nHost: 127.0.0.1:321\r\n\r\n")
            .await?;
        assert_eq!(
            read_head(&mut client).await?,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );

        client.write_all(b"GET /events?source=environment HTTP/1.1\r\nHost: 127.0.0.1:321\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").await?;
        let head = timeout(DEADLINE, read_head(&mut client)).await??;
        assert!(head.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        assert_eq!(
            header_value(&head, "sec-websocket-accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );

        let mut ping = [0; 13];
        timeout(DEADLINE, client.read_exact(&mut ping)).await??;
        assert_eq!(&ping, b"\x89\x0benvironment");

        Ok((peer, observation, client))
    }

    #[tokio::test]
    async fn an_early_owner_error_cancels_the_peer_after_connect_and_ping() -> TestResult<()> {
        let (peer, observation, mut client) = opening().await?;
        let failed_owner = async move {
            let _peer = peer;
            TestResult::<()>::Err(
                io::Error::new(io::ErrorKind::InvalidInput, "injected owner failure").into(),
            )
        }
        .await
        .err()
        .ok_or("owner error disappeared")?;
        assert_eq!(
            cause::<io::Error>(failed_owner.as_ref())
                .ok_or("missing owner I/O cause")?
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let primary = observation.require_cancelled().await;
        let cleanup = client.shutdown().await.map_err(Into::into);
        crate::support::tunnel_proxy::finish_with_cleanup(primary, cleanup)
    }

    #[tokio::test]
    async fn a_joined_peer_keeps_literal_connect_opening_and_pong() -> TestResult<()> {
        let (peer, observation, mut client) = opening().await?;
        client.write_all(b"\x8a\x8b\0\0\0\0environment").await?;
        timeout(DEADLINE, peer).await???;
        let (connect, opening, pong) = observation.served().await?;

        assert_eq!(
            connect.ok_or("missing CONNECT")?,
            b"CONNECT 127.0.0.1:321 HTTP/1.1\r\nHost: 127.0.0.1:321\r\n\r\n"
        );
        assert!(opening.starts_with(b"GET /events?source=environment HTTP/1.1\r\n"));
        assert_eq!(header_value(&opening, "host"), Some("127.0.0.1:321"));
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"environment");
        Ok(())
    }
}

#[cfg(feature = "sse")]
mod sse {
    use phantom::{EnvironmentProxies, HttpProtocol};
    use tokio::net::TcpListener;

    use super::*;
    use crate::support::{
        tls::{TestIdentity, client_builder},
        tunnel_proxy::ConnectionPeer,
    };

    #[tokio::test]
    async fn cancelling_the_owner_after_an_event_cancels_its_reconnect_peer() -> TestResult<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (peer, observation) = observe(super::super::sse::serve(listener));
        let identity = TestIdentity::generate()?;
        let snapshot =
            EnvironmentProxies::from_values([("http_proxy", format!("http://{address}"))])?;
        let client = client_builder(&identity, false)
            .environment_proxies(snapshot)
            .build()?;

        let mut events = client
            .event_source(
                HttpProtocol::Http1,
                "http://unresolvable.invalid/events?source=environment",
            )?
            .initial_retry(Duration::from_millis(1))
            .min_retry(Duration::ZERO)
            .max_reconnects(1)
            .connect()
            .await?
            .into_body();

        let event = events.next_event().await?.ok_or("missing first event")?;
        assert_eq!(event.data(), "one");
        assert_eq!(event.id(), "first");

        let (ready, ready_rx) = oneshot::channel();
        let owner = ConnectionPeer::spawn(async move {
            let _peer = peer;
            ready
                .send(())
                .map_err(|_| "owner readiness observer disappeared")?;
            std::future::pending::<TestResult<()>>().await
        });
        timeout(DEADLINE, ready_rx).await??;
        owner.abort();
        assert!(matches!(timeout(DEADLINE, owner).await?, Err(ref error) if error.is_cancelled()));
        let result = observation.require_cancelled().await;
        drop(events);
        drop(client);

        result
    }

    #[tokio::test]
    async fn a_joined_reconnect_peer_keeps_both_heads_and_last_event_id() -> TestResult<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (peer, observation) = observe(super::super::sse::serve(listener));
        let identity = TestIdentity::generate()?;
        let snapshot =
            EnvironmentProxies::from_values([("http_proxy", format!("http://{address}"))])?;
        let client = client_builder(&identity, false)
            .environment_proxies(snapshot)
            .build()?;
        let url = "http://unresolvable.invalid/events?source=environment";

        let mut events = client
            .event_source(HttpProtocol::Http1, url)?
            .initial_retry(Duration::from_millis(1))
            .min_retry(Duration::ZERO)
            .max_reconnects(1)
            .connect()
            .await?
            .into_body();

        let event = events.next_event().await?.ok_or("missing first event")?;
        assert_eq!(event.data(), "one");
        assert_eq!(event.id(), "first");

        assert_eq!(events.next_event().await?, None);
        assert_eq!(events.reconnects(), 1);
        assert!(events.is_closed());

        timeout(DEADLINE, peer).await???;
        let heads = observation.served().await?;

        assert_eq!(heads.len(), 2);
        for head in &heads {
            assert!(head.starts_with(format!("GET {url} HTTP/1.1\r\n").as_bytes()));
        }
        assert_eq!(super::super::sse::header(&heads[0], "last-event-id")?, None);
        assert_eq!(
            super::super::sse::header(&heads[1], "last-event-id")?,
            Some("first")
        );
        Ok(())
    }
}
