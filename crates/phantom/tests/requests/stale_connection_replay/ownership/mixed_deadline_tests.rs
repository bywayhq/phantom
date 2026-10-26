use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use phantom::HttpProtocol;
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::yield_now,
    time::{Instant, error::Elapsed, timeout},
};

use super::super::{bounded_until, prime, replaying_client};
use super::{Mode, Observation, TEST_TIMEOUT, TestResult, complete, spawn_single_stale_server};
use crate::support::deadline::FixtureDeadline;
use crate::support::tls::{is_peer_gone, read_head};
use crate::support::tunnel_proxy::connection_peer::{ConnectionPeer, FixtureFailures};
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn original_deadline_retains_the_completed_stale_serving_failure() -> TestResult {
    let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
    let (address, server) = spawn_single_stale_server(Some(control)).await?;
    let mut server = Some(server);
    let mut held = None;
    let mut held_pending_before_deadline = false;

    let observed = async {
        let client = replaying_client()?;
        timeout(
            TEST_TIMEOUT,
            prime(&client, &format!("http://{address}/prime")),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "mixed stale deadline original priming response exceeded its deadline",
                elapsed,
            )
        })??;

        observation
            .wait(
                "mixed stale deadline completed flush prerequisite exceeded its deadline",
                |state| state.primed && state.fault_taken && state.destroyed,
            )
            .await?;

        timeout(TEST_TIMEOUT, async {
            while !server
                .as_ref()
                .ok_or("original mixed stale task missing")?
                .is_finished()
            {
                yield_now().await;
            }
            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "mixed stale deadline original finished prerequisite exceeded its deadline",
                elapsed,
            )
        })??;

        held = Some(HeldRequest::spawn().await?);
        let held_address = held.as_ref().ok_or("held HTTP peer missing")?.address;
        let deadline = Instant::now() + TEST_TIMEOUT;

        let caller = bounded_until(deadline, async {
            let request = client
                .get_with_protocol(
                    HttpProtocol::Http1,
                    &format!("http://{held_address}/held-deadline"),
                )?
                .send();
            tokio::pin!(request);

            tokio::select! {
                result = &mut request => {
                    let _response = result?;
                    return Err("held HTTP response arrived before its Pending prerequisite".into());
                }
                result = held
                    .as_mut()
                    .ok_or("held HTTP peer missing during caller")?
                    .wait_pending() => {
                        result?;
                        held_pending_before_deadline = true;
                    }
            }

            let _response = request.await?;
            Ok(())
        })
        .await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual held HTTP caller escaped its original deadline")?;

        let checked = async {
            if !held_pending_before_deadline {
                return Err(
                    "held HTTP prerequisite did not complete inside the original deadline".into(),
                );
            }

            held.as_mut()
                .ok_or("held HTTP peer missing after caller deadline")?
                .wait_pending()
                .await?;

            deadline_and_serving_causes(&observation, error.as_ref())?;
            observation.no_backup()
        }
        .await;

        match checked {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let original_cleanup = observation.backup(&mut server, None).await;
    let held_cleanup = match held {
        Some(held) => held.finish().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(original_cleanup, held_cleanup);
    finish_with_cleanup(observed, cleanup)
}

fn deadline_and_serving_causes(
    observation: &Observation,
    error: &(dyn Error + Send + Sync + 'static),
) -> TestResult {
    let primary = match error.downcast_ref::<FixtureFailures>() {
        Some(failures) => failures.primary.as_ref(),
        None => error,
    };
    let deadline = primary
        .downcast_ref::<FixtureDeadline>()
        .ok_or("original mixed stale deadline type changed")?;

    if deadline.to_string() != "stale-connection replay test exceeded its deadline" {
        return Err("original mixed stale deadline message changed".into());
    }

    if !deadline
        .source()
        .is_some_and(|source| source.is::<Elapsed>())
    {
        return Err("original mixed stale deadline Elapsed cause lost".into());
    }

    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("original deadline and completed stale serving error were not both retained")?;
    observation.serving_cause(failures.cleanup.as_ref())
}

#[derive(Default)]
struct HeldState {
    head: Option<Vec<u8>>,
    read_pending: bool,
}

pub(super) struct HeldRequest {
    pub(super) address: SocketAddr,
    state: watch::Receiver<HeldState>,
    server: ConnectionPeer<TestResult>,
}

impl HeldRequest {
    pub(super) async fn spawn() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (state, received) = watch::channel(HeldState::default());
        let server = ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = HeldStream { stream, state };
            let head = read_head(&mut stream).await?;
            stream.state.send_modify(|state| state.head = Some(head));

            // The actual HTTP caller waits for a response while this socket is held.
            match stream.read(&mut [0_u8; 1]).await {
                Ok(0) => Ok(()),
                Err(error) if is_peer_gone(&error) => Ok(()),
                Err(error) => Err(error.into()),
                Ok(_) => Err("held HTTP peer received bytes after its request head".into()),
            }
        });

        Ok(Self {
            address,
            state: received,
            server,
        })
    }

    pub(super) async fn wait_pending(&mut self) -> TestResult {
        timeout(TEST_TIMEOUT, async {
            loop {
                let ready = {
                    let state = self.state.borrow();
                    state.read_pending && state.head.is_some()
                };
                if ready {
                    break;
                }

                self.state.changed().await?;
            }

            let state = self.state.borrow();
            let head = state
                .head
                .as_ref()
                .ok_or("actual held request head missing")?;
            if !head.starts_with(b"GET /held-deadline HTTP/1.1\r\n") {
                return Err("actual held request head changed".into());
            }

            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "mixed stale deadline held HTTP head and read Pending exceeded its deadline",
                elapsed,
            )
        })?
    }

    pub(super) async fn finish(mut self) -> TestResult {
        let requested = !self.server.is_finished();
        if requested {
            self.server.abort();
        }

        match timeout(TEST_TIMEOUT, &mut self.server).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(elapsed) => Err(FixtureDeadline::new(
                "mixed stale deadline held HTTP original cleanup exceeded its deadline",
                elapsed,
            )
            .into()),
        }
    }
}

struct HeldStream {
    stream: TcpStream,
    state: watch::Sender<HeldState>,
}

impl AsyncRead for HeldStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        let has_head = this.state.borrow().head.is_some();
        if result.is_pending() && has_head {
            this.state.send_modify(|state| state.read_pending = true);
        }

        result
    }
}
