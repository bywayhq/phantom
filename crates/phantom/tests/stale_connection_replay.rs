//! Opt-in replay after a reused HTTP/1.1 connection closes before a response.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{error::Error, future::Future, net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ResponseInfo, RetryPolicy, profile::ClientProfile,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use tls_support::{
    H1_ALPN, TestIdentity, accept_tls_stream, client_builder, is_peer_gone, read_head, tls_settings,
};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Only confirms that no connection is already queued; a replay would have
/// blocked the client on an unanswered connection before its error returned.
const EXTRA_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
const PRIMING_RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
const REPLAY_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// One request as it arrived: the complete head, then the decoded body bytes.
#[derive(Debug, Eq, PartialEq)]
struct ReceivedRequest {
    head: Vec<u8>,
    framed_body: Vec<u8>,
}

#[tokio::test]
async fn stale_reused_http1_close_replays_idempotent_request_once() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let stale = serve_stale_connection(&listener).await?;
            let (mut replacement, _) = listener.accept().await?;
            let replayed = read_request(&mut replacement).await?;
            replacement.write_all(REPLAY_RESPONSE).await?;
            replacement.flush().await?;
            let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((stale, replayed, extra.is_err()))
        });
        let client = replaying_client()?;

        prime(&client, &format!("http://{address}/prime")).await?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/item"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 0);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        let (stale, replayed, had_no_extra_connection) = server.await??;
        assert!(stale.head.starts_with(b"PUT /item HTTP/1.1\r\n"));
        assert_eq!(stale.framed_body, b"payload");
        assert_eq!(replayed, stale);
        assert!(had_no_extra_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn fresh_http1_close_is_not_replayed() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut fresh, _) = listener.accept().await?;
            read_request(&mut fresh).await?;
            drop(fresh);
            let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>(extra.is_err())
        });
        let client = replaying_client()?;

        let result = client
            .get(HttpProtocol::Http1, &format!("http://{address}/fresh"))?
            .send()
            .await;

        let error = result.err().ok_or("fresh connection close was answered")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        assert!(server.await??, "a fresh-connection failure was replayed");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_reuse_replay_skips_post() -> TestResult {
    bounded(async {
        let (address, server) = spawn_single_stale_server().await?;
        let client = replaying_client()?;

        prime(&client, &format!("http://{address}/prime")).await?;
        let result = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/submit"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await;

        let error = result.err().ok_or("stale POST was answered")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        let (stale, had_no_extra_connection) = server.await??;
        assert!(stale.head.starts_with(b"POST /submit HTTP/1.1\r\n"));
        assert!(
            had_no_extra_connection,
            "a non-idempotent request was replayed"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_reuse_replay_refuses_one_shot_streaming_body() -> TestResult {
    bounded(async {
        let (address, server) = spawn_single_stale_server().await?;
        let client = replaying_client()?;

        prime(&client, &format!("http://{address}/prime")).await?;
        let result = client
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/upload"),
            )?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .send()
            .await;

        // The original transport error is returned, not a body-replay error.
        let error = result.err().ok_or("stale streaming upload was answered")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        let (stale, had_no_extra_connection) = server.await??;
        assert!(stale.head.starts_with(b"PUT /upload HTTP/1.1\r\n"));
        assert_eq!(stale.framed_body, b"payload");
        assert!(had_no_extra_connection, "a one-shot body was replayed");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_reuse_replay_is_bounded() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_stale_connection(&listener).await?;
            let (mut replacement, _) = listener.accept().await?;
            let replayed = read_request(&mut replacement).await?;
            drop(replacement);
            let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((replayed, extra.is_err()))
        });
        let client = replaying_client()?;

        prime(&client, &format!("http://{address}/prime")).await?;
        let result = client
            .get(HttpProtocol::Http1, &format!("http://{address}/twice"))?
            .send()
            .await;

        let error = result
            .err()
            .ok_or("closed replacement connection was answered")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        let (replayed, had_no_extra_connection) = server.await??;
        assert!(replayed.head.starts_with(b"GET /twice HTTP/1.1\r\n"));
        assert!(had_no_extra_connection, "the replay itself was replayed");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_reuse_replay_is_observable() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            serve_stale_connection(&listener).await?;
            let (mut replacement, _) = listener.accept().await?;
            read_request(&mut replacement).await?;
            replacement.write_all(REPLAY_RESPONSE).await?;
            replacement.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = replaying_client()?;
        let subscriber = OutcomeSubscriber::default();

        prime(&client, &format!("http://{address}/prime")).await?;
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/observed"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await?;

        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted metadata")?;
        assert_eq!(info.retries_performed(), 0);
        response.into_body().collect().await?;
        server.await??;
        assert_eq!(
            subscriber.reused_connection_replays_for("client.request"),
            [1]
        );
        assert!(
            subscriber
                .retries_performed_for("client.request")
                .is_empty()
        );
        assert!(subscriber.retry_reasons_for("client.request").is_empty());
        assert_eq!(subscriber.outcomes_for("client.request"), ["ok"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_reuse_is_not_replayed_by_default() -> TestResult {
    bounded(async {
        let (address, server) = spawn_single_stale_server().await?;
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        let subscriber = OutcomeSubscriber::default();

        prime(&client, &format!("http://{address}/prime")).await?;
        let result = client
            .get(HttpProtocol::Http1, &format!("http://{address}/default"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await;

        let error = result.err().ok_or("stale request was answered")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        let (_, had_no_extra_connection) = server.await??;
        assert!(had_no_extra_connection, "default policy replayed a request");
        assert!(
            subscriber
                .reused_connection_replays_for("client.request")
                .is_empty()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http1_stale_reuse_replays_once() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let stale_acceptor = identity.acceptor(H1_ALPN)?;
        let replacement_acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stale = accept_tls_stream(tcp, stale_acceptor).await?;
            read_request(&mut stale).await?;
            stale.write_all(PRIMING_RESPONSE).await?;
            stale.flush().await?;
            let stale_request = read_request(&mut stale).await?;
            drop(stale);
            let (tcp, _) = listener.accept().await?;
            let mut replacement = accept_tls_stream(tcp, replacement_acceptor).await?;
            let replayed = read_request(&mut replacement).await?;
            replacement.write_all(REPLAY_RESPONSE).await?;
            replacement.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((stale_request, replayed))
        });
        let client = client_builder(&identity, true)
            .retry_policy(RetryPolicy::none().with_reused_connection_replay(true))
            .build()?;

        client
            .get_negotiated(&format!("https://{address}/prime"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        let response = client
            .get_negotiated(&format!("https://{address}/negotiated"))?
            .send()
            .await?;

        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 0);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        let (stale, replayed) = server.await??;
        assert!(stale.head.starts_with(b"GET /negotiated HTTP/1.1\r\n"));
        assert_eq!(replayed, stale);
        Ok(())
    })
    .await
}

fn replaying_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings()))
        .retry_policy(RetryPolicy::none().with_reused_connection_replay(true))
        .build()?)
}

/// Completes one keep-alive exchange so the next request reuses the connection.
async fn prime(client: &Client, url: &str) -> TestResult {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

/// Answers the priming request, then reads the next request on the same
/// connection and closes it without any response byte.
async fn serve_stale_connection(listener: &TcpListener) -> TestResult<ReceivedRequest> {
    let (mut stream, _) = listener.accept().await?;
    let priming = read_request(&mut stream).await?;
    assert!(priming.head.starts_with(b"GET /prime HTTP/1.1\r\n"));
    stream.write_all(PRIMING_RESPONSE).await?;
    stream.flush().await?;
    let stale = read_request(&mut stream).await?;
    // Every request byte was read, so dropping the socket sends FIN, not RST.
    drop(stream);
    Ok(stale)
}

async fn spawn_single_stale_server() -> TestResult<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<TestResult<(ReceivedRequest, bool)>>,
)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stale = serve_stale_connection(&listener).await?;
        let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
        Ok((stale, extra.is_err()))
    });
    Ok((address, server))
}

/// Reads one request head and its `Content-Length` or chunked body.
async fn read_request<S>(stream: &mut S) -> TestResult<ReceivedRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_head(stream).await?;
    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let framed_body = if text.contains("\r\ntransfer-encoding: chunked\r\n") {
        read_chunked(stream).await?
    } else if let Some(length) = text
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length: "))
    {
        let mut body = vec![0_u8; length.trim().parse()?];
        stream.read_exact(&mut body).await?;
        body
    } else {
        Vec::new()
    };
    Ok(ReceivedRequest { head, framed_body })
}

async fn read_chunked<S>(stream: &mut S) -> TestResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let size_line = read_line(stream).await?;
        let size = usize::from_str_radix(size_line.trim(), 16)?;
        if size == 0 {
            // No trailers are sent by these tests; consume the final CRLF.
            read_line(stream).await?;
            return Ok(body);
        }
        let start = body.len();
        body.resize(start + size, 0);
        stream.read_exact(&mut body[start..]).await?;
        read_line(stream).await?;
    }
}

async fn read_line<S>(stream: &mut S) -> TestResult<String>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while !line.ends_with(b"\r\n") {
        if let Err(error) = stream.read_exact(&mut byte).await {
            if is_peer_gone(&error) {
                return Err("client closed inside a chunked body".into());
            }
            return Err(error.into());
        }
        line.push(byte[0]);
    }
    line.truncate(line.len() - 2);
    Ok(String::from_utf8(line)?)
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "stale-connection replay test exceeded its deadline")?
}
