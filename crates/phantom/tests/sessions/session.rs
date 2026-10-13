//! Public session connection-reuse integration tests.

use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, TcpListener as StdTcpListener},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, Route};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::Barrier,
    time::{Instant, timeout, timeout_at},
};
use tokio_btls::SslStream;

use crate::support::{deadline::FixtureDeadline, tls as tls_support};
use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, client_builder, read_head, test_client};

mod body_ownership;
mod proxy_auth;
mod proxy_ownership;
mod request_ownership;
mod reuse_ownership;
mod upload_contract;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const UNICODE_ORIGIN_NAME: &str = "bücher.example";
const ASCII_ORIGIN_NAME: &str = "xn--bcher-kva.example";
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn sequential_same_origin_requests_reuse_one_http2_connection() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let (identity, address, server) = timeout_at(deadline, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = reuse_ownership::spawn_server(listener, acceptor, 2, None);
        Ok::<_, Box<dyn Error + Send + Sync>>((identity, address, server))
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("session test exceeded its deadline", elapsed))??;

    let caller = match timeout_at(deadline, async {
        let session = test_client(&identity, true)?;
        for path in ["/first", "/second"] {
            let response = session
                .get(HttpProtocol::Http2, &format!("https://{address}{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        drop(session);
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => {
            Err(FixtureDeadline::new("session test exceeded its deadline", elapsed).into())
        }
    };

    let requests = reuse_ownership::collect(caller, server).await?;
    assert_eq!(
        requests,
        vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
    );
    Ok(())
}

#[tokio::test]
async fn session_upload_and_followup_reuse_one_http2_connection() -> TestResult<()> {
    body_ownership::upload().await
}

#[tokio::test]
async fn concurrent_cold_requests_through_cloned_session_share_one_connection() -> TestResult<()> {
    request_ownership::cold().await
}

#[tokio::test]
async fn independently_built_clients_do_not_share_http2_connections() -> TestResult<()> {
    request_ownership::independent().await
}

#[tokio::test]
async fn idna_equivalent_origins_reuse_one_plaintext_connect_tunnel() -> TestResult<()> {
    proxy_ownership::plaintext().await
}

#[tokio::test]
async fn idna_equivalent_origins_reuse_one_https_connect_tunnel() -> TestResult<()> {
    proxy_ownership::https().await
}

#[tokio::test]
async fn invalid_http2_header_in_session_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let session = test_client(&identity, true)?;
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let result = session
        .get(HttpProtocol::Http2, &format!("https://{address}/"))?
        .header(RequestHeader::new("X-Uppercase", "rejected"))
        .send()
        .await;
    let error = match result {
        Ok(_) => return Err("invalid HTTP/2 header unexpectedly sent".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Http2);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn dropping_response_body_cancels_only_its_stream_and_preserves_reuse() -> TestResult<()> {
    body_ownership::cancelled_body().await
}

async fn send_after_barrier(
    client: Client,
    uri: String,
    start: std::sync::Arc<Barrier>,
) -> TestResult<()> {
    start.wait().await;
    send(client, uri).await
}

async fn send(client: Client, uri: String) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http2, &uri)?.send().await?;
    assert_eq!(response.status(), 204);
    response.into_body().collect().await?;
    Ok(())
}

async fn serve_requests(
    stream: reuse_ownership::Stream,
    count: usize,
) -> TestResult<Vec<(u32, String)>> {
    serve_requests_held(stream, count, None).await
}

async fn serve_requests_held(
    stream: reuse_ownership::Stream,
    count: usize,
    mut hold: Option<request_ownership::ResponseHold>,
) -> TestResult<Vec<(u32, String)>> {
    let observed = stream.observation();
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut requests = Vec::with_capacity(count);
    let mut responses = Vec::new();
    for _ in 0..count {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before expected request")??;
        requests.push((
            respond.stream_id().as_u32(),
            request.uri().path().to_owned(),
        ));
        if hold.is_some() {
            responses.push(respond);
        } else {
            respond.send_response(Response::builder().status(204).body(())?, true)?;
        }
    }

    if let Some(hold) = &mut hold {
        hold.accepted(&requests);
        let released = poll_fn(|context| {
            match reuse_ownership::poll_closed(&mut connection, observed.as_ref(), context) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(false)),
                Poll::Pending => hold.driver_pending(),
            }

            hold.poll_release(context)
                .map(|result| result.map(|()| true))
        })
        .await?;
        if !released {
            return Ok(requests);
        }

        for mut respond in responses {
            respond.send_response(Response::builder().status(204).body(())?, true)?;
        }
    }

    poll_fn(|context| reuse_ownership::poll_closed(&mut connection, observed.as_ref(), context))
        .await?;
    Ok(requests)
}

async fn collect_h2_request_body<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Bytes>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut received = Vec::new();
    loop {
        let chunk = poll_fn(|context| {
            if let Poll::Ready(item) = body.poll_data(context) {
                return Poll::Ready(item.transpose());
            }
            match connection.poll_closed(context) {
                // Driving EOF updates the stream's queued data or error.
                Poll::Ready(Ok(())) => body.poll_data(context).map(|item| item.transpose()),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        let Some(chunk) = chunk else {
            return Ok(Bytes::from(received));
        };
        received.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len())?;
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
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|elapsed| FixtureDeadline::new("session test exceeded its deadline", elapsed))?
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::poll_fn, io, task::Poll};

    use super::{TestResult, bounded};

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
        assert_eq!(error.to_string(), "session test exceeded its deadline");
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
