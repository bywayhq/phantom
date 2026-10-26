//! HTTP/2 session authority-isolation integration tests.

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, timeout, timeout_at},
};
use tokio_btls::SslStream;

use crate::support::{
    deadline::FixtureDeadline,
    tls as tls_support,
    tunnel_proxy::connection_peer::{ConnectionPeer, finish_with_cleanup},
};
use tls_support::{H2_ALPN, TestIdentity, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn secondary_authority_uses_a_dedicated_connection() -> TestResult<()> {
    let mut peers = Vec::new();
    let result = bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), "localhost")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = async {
            let primary = accept_tls(&listener, &acceptor).await?;
            peers.push(ConnectionPeer::spawn(serve_one_request(
                primary,
                StatusCode::NO_CONTENT,
            )));

            let secondary = accept_tls(&listener, &acceptor).await?;
            peers.push(ConnectionPeer::spawn(serve_one_request(
                secondary,
                StatusCode::OK,
            )));

            let primary = (&mut peers[0]).await;
            drop(peers.remove(0));
            let primary = primary??;
            let secondary = (&mut peers[0]).await;
            drop(peers.remove(0));
            Ok::<_, Box<dyn Error + Send + Sync>>([primary, secondary??])
        };

        let caller = async {
            let session = test_client(&identity, true)?;
            let primary = session
                .get_with_protocol(HttpProtocol::Http2, &format!("https://{address}/"))?
                .send()
                .await?;
            assert_eq!(primary.status(), StatusCode::NO_CONTENT);
            primary.into_body().collect().await?;

            let secondary_authority = format!("localhost:{}", address.port());
            let secondary = session
                .get_with_protocol(
                    HttpProtocol::Http2,
                    &format!("https://{secondary_authority}/.well-known/phantom/421?key=fixed"),
                )?
                .send()
                .await?;
            assert_eq!(secondary.status(), StatusCode::OK);
            secondary.into_body().collect().await?;
            drop(session);
            Ok::<_, Box<dyn Error + Send + Sync>>(secondary_authority)
        };

        let (secondary_authority, [primary, secondary]) = tokio::try_join!(caller, server)?;
        assert_eq!(primary.authority, address.to_string());
        assert_eq!(primary.path_and_query, "/");
        assert_eq!(secondary.authority, secondary_authority);
        assert_eq!(
            secondary.path_and_query,
            "/.well-known/phantom/421?key=fixed"
        );
        Ok(())
    })
    .await;
    finish_with_cleanup(result, finish_peers(&mut peers).await)
}

#[tokio::test]
async fn dedicated_421_is_returned_without_hidden_replay() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (response_seen, response_seen_by_server) = oneshot::channel();
        let server = async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            serve_421_without_replay(listener, stream, response_seen_by_server).await
        };

        let session = test_client(&identity, true)?;
        let caller = async {
            let response = session
                .get_with_protocol(
                    HttpProtocol::Http2,
                    &format!("https://{address}/.well-known/phantom/421?key=fixed"),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
            response.into_body().collect().await?;
            response_seen
                .send(())
                .map_err(|()| "421 server stopped before the response was observed")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };

        let ((), request) = tokio::try_join!(caller, server)?;
        drop(session);
        assert_eq!(request.authority, address.to_string());
        assert_eq!(request.path_and_query, "/.well-known/phantom/421?key=fixed");
        Ok(())
    })
    .await
}

struct ObservedRequest {
    authority: String,
    path_and_query: String,
}

async fn finish_peers(
    peers: &mut Vec<ConnectionPeer<TestResult<ObservedRequest>>>,
) -> TestResult<()> {
    for peer in peers.iter() {
        if !peer.is_finished() {
            peer.abort();
        }
    }
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut result = Ok(());
    let mut index = 0;
    while index < peers.len() {
        let outcome = match timeout_at(deadline, &mut peers[index]).await {
            Ok(outcome) => {
                drop(peers.remove(index));
                match outcome {
                    Ok(outcome) => outcome.map(|_| ()),
                    Err(error) => Err(error.into()),
                }
            }
            Err(elapsed) => {
                index += 1;
                Err(FixtureDeadline::new("HTTP/2 authority peer did not stop", elapsed).into())
            }
        };
        result = finish_with_cleanup(result, outcome);
    }
    result
}

async fn serve_one_request(
    stream: SslStream<TcpStream>,
    status: StatusCode,
) -> TestResult<ObservedRequest> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let authority = request
        .uri()
        .authority()
        .ok_or("HTTP/2 request omitted :authority")?
        .to_string();
    let path_and_query = request
        .uri()
        .path_and_query()
        .ok_or("HTTP/2 request omitted :path")?
        .to_string();
    respond.send_response(Response::builder().status(status).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(ObservedRequest {
        authority,
        path_and_query,
    })
}

async fn serve_421_without_replay(
    listener: TcpListener,
    stream: SslStream<TcpStream>,
    response_seen: oneshot::Receiver<()>,
) -> TestResult<ObservedRequest> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let observed = ObservedRequest {
        authority: request
            .uri()
            .authority()
            .ok_or("HTTP/2 request omitted :authority")?
            .to_string(),
        path_and_query: request
            .uri()
            .path_and_query()
            .ok_or("HTTP/2 request omitted :path")?
            .to_string(),
    };
    respond.send_response(
        Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(())?,
        true,
    )?;

    tokio::select! {
        biased;
        replay = connection.accept() => {
            match replay {
                Some(Ok(_)) => Err("421 triggered a replay on the same connection".into()),
                Some(Err(error)) => Err(error.into()),
                None => Err("421 connection closed before the response was returned".into()),
            }
        }
        accepted = listener.accept() => {
            accepted?;
            Err("421 triggered a replay on a new connection".into())
        }
        observed_response = response_seen => {
            observed_response?;
            Ok(observed)
        }
    }
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future).await.map_err(|elapsed| {
        FixtureDeadline::new("HTTP/2 authority test exceeded its deadline", elapsed)
    })?
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::poll_fn, io, net::Ipv4Addr, task::Poll};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        time::timeout,
    };

    use crate::support::tunnel_proxy::connection_peer::{
        ConnectionPeer, FixtureFailures, finish_with_cleanup,
    };

    use super::{TestResult, bounded};

    #[tokio::test]
    async fn accepted_peers_keep_completed_failure_and_external_cancellation() -> TestResult<()> {
        let failed_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let failed_address = failed_listener.local_addr()?;
        let pending_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let pending_address = pending_listener.local_addr()?;
        let (entered, accepted) = oneshot::channel();
        let failed = ConnectionPeer::spawn(async move {
            let (mut stream, _) = failed_listener.accept().await?;
            assert_eq!(stream.read_u8().await?, b'!');
            TestResult::<super::ObservedRequest>::Err(
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "accepted authority peer failed",
                )
                .into(),
            )
        });
        let pending = ConnectionPeer::spawn(async move {
            let (mut stream, _) = pending_listener.accept().await?;
            entered
                .send(())
                .map_err(|()| "accepted-peer observer stopped")?;
            stream.read_u8().await?;
            Err("the pending peer received an unexpected byte".into())
        });
        let mut failed_client = TcpStream::connect(failed_address).await?;
        failed_client.write_all(b"!").await?;
        let mut pending_client = TcpStream::connect(pending_address).await?;
        timeout(super::TEST_TIMEOUT, accepted).await??;
        pending.abort();
        timeout(super::TEST_TIMEOUT, async {
            while !failed.is_finished() || !pending.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let mut peers = vec![failed, pending];
        let primary: TestResult<()> =
            Err(io::Error::new(io::ErrorKind::InvalidInput, "later authority setup failed").into());
        let error = finish_with_cleanup(primary, super::finish_peers(&mut peers).await)
            .err()
            .ok_or("authority failures were discarded")?;
        assert!(peers.is_empty());
        let causes = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("missing caller and peer causes")?;
        assert_eq!(
            causes
                .primary
                .downcast_ref::<io::Error>()
                .ok_or("missing caller I/O cause")?
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let peers = causes
            .cleanup
            .downcast_ref::<FixtureFailures>()
            .ok_or("missing independent peer causes")?;
        let original = peers
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("missing original peer I/O cause")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(original.to_string(), "accepted authority peer failed");
        assert!(
            peers
                .cleanup
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_cancelled)
        );
        let closed = timeout(super::TEST_TIMEOUT, pending_client.read(&mut [0_u8; 1])).await?;
        assert!(
            matches!(closed, Ok(0))
                || matches!(closed, Err(ref error) if crate::support::tls::is_peer_gone(error))
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn entered_pending_deadline_retains_its_original_elapsed() -> TestResult<()> {
        let entered = Cell::new(false);
        let operation = bounded(poll_fn(|_| {
            entered.set(true);
            Poll::<TestResult<()>>::Pending
        }));
        tokio::pin!(operation);
        assert!(futures_util::poll!(&mut operation).is_pending());
        assert!(entered.get(), "the actual operation was not polled");
        tokio::time::advance(super::TEST_TIMEOUT).await;

        let error = operation.await.err().ok_or("pending operation succeeded")?;
        assert_eq!(
            error.to_string(),
            "HTTP/2 authority test exceeded its deadline"
        );
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()),
            "the fixture deadline discarded its original Elapsed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_the_original_operation_error() -> TestResult<()> {
        let failure = io::Error::new(io::ErrorKind::PermissionDenied, "fixture operation failed");
        let error = bounded(async { Err(failure.into()) })
            .await
            .err()
            .ok_or("failed operation succeeded")?;
        let original = error
            .downcast_ref::<io::Error>()
            .ok_or("operation error type changed")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(original.to_string(), "fixture operation failed");
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_success() -> TestResult<()> {
        bounded(async { Ok(()) }).await
    }
}
