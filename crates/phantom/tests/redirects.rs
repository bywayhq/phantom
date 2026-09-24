//! Redirect behavior exercised through the public session paths.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestErrorKind, ResponseInfo, profile::ClientProfile,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H2_ALPN, TestIdentity, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn session_matches_redirect_and_url_contract() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (first_drained, wait_for_first_drain) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept_tls(&listener, &acceptor).await?;
            serve_redirect_probe(first, StatusCode::FOUND, b"probe-302").await?;
            first_drained
                .send(())
                .map_err(|_| "client stopped before the first connection drained")?;

            let replacement = accept_tls(&listener, &acceptor).await?;
            serve_redirect_probe(replacement, StatusCode::TEMPORARY_REDIRECT, b"probe-307").await
        });

        let one = NonZeroUsize::MIN;
        let session = test_client(&identity, true)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(one))
            .build()?;

        let found = send_redirect_probe(&session, address, 302, b"probe-302").await?;
        assert_eq!(found.status(), StatusCode::OK);
        assert_response_info(
            &found,
            &format!("https://{address}/.well-known/phantom/redirect/302/final"),
        )?;
        found.into_body().collect().await?;

        if wait_for_first_drain.await.is_err() {
            // The server dropped the signal because its task failed; report
            // that failure rather than the lost signal.
            server.await??;
            return Err("server stopped before the first connection drained".into());
        }

        let temporary = send_redirect_probe(&session, address, 307, b"probe-307").await?;
        assert_eq!(temporary.status(), StatusCode::OK);
        assert_response_info(
            &temporary,
            &format!("https://{address}/.well-known/phantom/redirect/307/final"),
        )?;
        temporary.into_body().collect().await?;

        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http1_redirect_does_not_drain_an_adversarial_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(tls_support::H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            let first_head = tls_support::read_head(&mut first).await?;
            assert!(first_head.starts_with(b"POST /start HTTP/1.1\r\n"));
            let mut first_body = [0_u8; 7];
            first.read_exact(&mut first_body).await?;
            assert_eq!(&first_body, b"payload");
            first
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /a/%2e%2e/final\r\nContent-Length: 1024\r\n\r\nx",
                )
                .await?;
            first.flush().await?;

            let mut replacement = accept_tls(&listener, &acceptor).await?;
            let final_head = tls_support::read_head(&mut replacement).await?;
            assert!(final_head.starts_with(b"GET /final HTTP/1.1\r\n"));
            assert!(!contains_header(&final_head, b"content-length"));
            replacement
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            replacement.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = test_client(&identity, false)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = session
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{address}/start"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_response_info(&response, &format!("https://{address}/final"))?;
        response.into_body().collect().await?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn body_preserving_redirect_rejects_one_shot_stream_before_second_request() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(tls_support::H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            let head = tls_support::read_head(&mut first).await?;
            let mut body = [0_u8; 7];
            first.read_exact(&mut body).await?;
            first
                .write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            first.flush().await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body, second.is_err()))
        });

        let client = test_client(&identity, false)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let error = match client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{address}/start"),
            )?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .send()
            .await
        {
            Ok(_) => return Err("one-shot body was replayed across a 307 redirect".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);

        let (head, body, no_second_request) = server.await??;
        assert!(head.starts_with(b"POST /start HTTP/1.1\r\n"));
        assert_eq!(&body, b"payload");
        assert!(no_second_request);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_temporary_redirect_replays_the_owned_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let quic = incoming.await?;
            let mut connection =
                h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;

            let (initial, mut initial_stream) = accept_h3_request(&mut connection).await?;
            assert_eq!(initial.method(), Method::POST);
            assert_eq!(initial.uri().path(), "/start");
            assert_eq!(collect_h3_body(&mut initial_stream).await?, "payload");
            initial_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("location", "/a/%2e%2e/final")
                        .header("content-length", "0")
                        .body(())?,
                )
                .await?;
            initial_stream.finish().await?;

            let (followed, mut followed_stream) = accept_h3_request(&mut connection).await?;
            assert_eq!(followed.method(), Method::POST);
            assert_eq!(followed.uri().path(), "/final");
            assert_eq!(collect_h3_body(&mut followed_stream).await?, "payload");
            followed_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .header("content-length", "0")
                        .body(())?,
                )
                .await?;
            followed_stream.finish().await?;
            wait_for_client
                .await
                .map_err(|_| "client stopped before HTTP/3 response completion")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = http3_client(&identity)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = session
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/start"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_response_info(&response, &format!("https://{address}/final"))?;
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h3_redirect_follows_before_response_fin_on_same_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let callback = "/.well-known/phantom/h3-redirect/0123456789abcdef0123456789abcdef";
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let quic = incoming.await?;
            let mut connection =
                h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;

            let (initial, mut initial_stream) = accept_h3_request(&mut connection).await?;
            assert_eq!(initial.method(), Method::GET);
            assert_eq!(initial.uri().path(), "/.well-known/phantom/h3-redirect");
            assert!(collect_h3_body(&mut initial_stream).await?.is_empty());
            initial_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", callback)
                        .body(())?,
                )
                .await?;

            let (followed, mut followed_stream) = accept_h3_request(&mut connection).await?;
            assert_eq!(followed.method(), Method::GET);
            assert_eq!(followed.uri().path(), callback);
            assert!(collect_h3_body(&mut followed_stream).await?.is_empty());
            followed_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            followed_stream.finish().await?;
            let _ = initial_stream.finish().await;
            wait_for_client
                .await
                .map_err(|_| "client stopped before HTTP/3 response completion")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = http3_client(&identity)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = session
            .get(
                HttpProtocol::Http3,
                &format!("https://{address}/.well-known/phantom/h3-redirect"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_response_info(&response, &format!("https://{address}{callback}"))?;
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_request_that_is_not_redirected_is_sent_with_a_policy() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = tls_support::read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });

        let session = test_client(&identity, false)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = session
            .get(HttpProtocol::Http1, &format!("http://{address}/plain"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted redirect metadata")?;
        assert_eq!(info.redirects_followed(), 0);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "plain");

        let head = server.await??;
        assert!(head.starts_with(b"GET /plain HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_moved_permanently_to_https_is_followed() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let secure_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let secure_address = secure_listener.local_addr()?;
        let acceptor = identity.acceptor(tls_support::H1_ALPN)?;
        let plain_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let plain_address = plain_listener.local_addr()?;
        let location = format!("https://{secure_address}/secure");
        let plain = tokio::spawn(async move {
            let (mut stream, _) = plain_listener.accept().await?;
            let head = tls_support::read_head(&mut stream).await?;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });
        let secure = tokio::spawn(async move {
            let mut stream = accept_tls(&secure_listener, &acceptor).await?;
            let head = tls_support::read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });

        let session = test_client(&identity, false)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = session
            .get(HttpProtocol::Http1, &format!("http://{plain_address}/start"))?
            .header(phantom::RequestHeader::new("Authorization", "Bearer origin"))
            .header(phantom::RequestHeader::new("X-Kept", "yes"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_info(&response, &format!("https://{secure_address}/secure"))?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "secure");

        let plain_head = plain.await??;
        assert!(plain_head.starts_with(b"GET /start HTTP/1.1\r\n"));
        assert!(contains_header(&plain_head, b"authorization"));
        let secure_head = secure.await??;
        assert!(secure_head.starts_with(b"GET /secure HTTP/1.1\r\n"));
        // A scheme change is a new origin, so credentials are dropped.
        assert!(!contains_header(&secure_head, b"authorization"));
        assert!(contains_header(&secure_head, b"x-kept"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn redirect_to_plaintext_under_exact_http2_fails_at_that_hop() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let secure_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let secure_address = secure_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let plain_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let plain_address = plain_listener.local_addr()?;
        let location = format!("http://{plain_address}/plain");
        let (client_done, wait_for_client) = oneshot::channel::<()>();
        let secure = tokio::spawn(async move {
            let stream = accept_tls(&secure_listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = accept_request(&mut connection).await?;
            assert_eq!(request.uri().path(), "/start");
            respond.send_response(
                Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header("location", location)
                    .header("content-length", "0")
                    .body(())?,
                true,
            )?;
            // Keep the connection served until the client has its result.
            let _ = tokio::select! {
                _ = wait_for_client => Ok(()),
                closed = poll_fn(|context| connection.poll_closed(context)) => closed,
            };
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = test_client(&identity, true)?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let error = match session
            .get(
                HttpProtocol::Http2,
                &format!("https://{secure_address}/start"),
            )?
            .send()
            .await
        {
            Ok(_) => return Err("exact HTTP/2 followed a redirect to http://".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedScheme);
        let _ = client_done.send(());
        drop(session);
        secure.await??;
        assert!(
            timeout(Duration::from_millis(100), plain_listener.accept())
                .await
                .is_err(),
            "the refused hop reached the plaintext origin"
        );
        Ok(())
    })
    .await
}

async fn send_redirect_probe(
    session: &phantom::Session,
    address: std::net::SocketAddr,
    status: u16,
    body: &'static [u8],
) -> Result<Response<phantom::ResponseBody>, phantom::RequestError> {
    session
        .request(
            HttpProtocol::Http2,
            Method::POST,
            &format!("https://{address}/.well-known/phantom/redirect/{status}/start"),
        )?
        .body(Bytes::from_static(body))
        .send()
        .await
}

async fn serve_redirect_probe(
    stream: SslStream<TcpStream>,
    status: StatusCode,
    expected_body: &'static [u8],
) -> TestResult<()> {
    let status_number = status.as_u16();
    let start_path = format!("/.well-known/phantom/redirect/{status_number}/start");
    let final_path = format!("/.well-known/phantom/redirect/{status_number}/final");
    let location = format!("/.well-known/phantom/redirect/{status_number}/a/%2e%2e/final");
    let mut connection = ::http2::server::handshake(stream).await?;

    let (initial, mut initial_response) = accept_request(&mut connection).await?;
    assert_eq!(initial.method(), Method::POST);
    assert_eq!(initial.uri().path(), start_path);
    let initial_body = collect_body(&mut connection, initial.into_body()).await?;
    assert_eq!(initial_body, expected_body);
    initial_response.send_response(
        Response::builder()
            .status(status)
            .header("location", location)
            .header("cache-control", "no-store")
            .header("content-length", "0")
            .body(())?,
        true,
    )?;

    let (followed, mut final_response) = accept_request(&mut connection).await?;
    assert_eq!(followed.uri().path(), final_path);
    let expected_method = if status == StatusCode::FOUND {
        Method::GET
    } else {
        Method::POST
    };
    assert_eq!(followed.method(), expected_method);
    let followed_body = collect_body(&mut connection, followed.into_body()).await?;
    let expected_followed_body: &[u8] = if status == StatusCode::FOUND {
        &[]
    } else {
        expected_body
    };
    assert_eq!(followed_body, expected_followed_body);
    final_response.send_response(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-length", "0")
            .body(())?,
        true,
    )?;

    connection.graceful_shutdown();
    // The final response and graceful GOAWAY are the fixture's completion
    // boundary. The client may close its side while retiring this generation;
    // the next accepted connection below proves that it replaced the drain.
    let _ = poll_fn(|context| connection.poll_closed(context)).await;
    Ok(())
}

async fn accept_request<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
) -> TestResult<(
    Request<::http2::RecvStream>,
    ::http2::server::SendResponse<Bytes>,
)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    Ok(connection
        .accept()
        .await
        .ok_or("connection closed before expected request")??)
}

async fn collect_body<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    mut body: ::http2::RecvStream,
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
                Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
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

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn accept_h3_request(connection: &mut H3Connection) -> TestResult<(Request<()>, H3Stream)> {
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before expected HTTP/3 request")?;
    Ok(resolver.resolve_request().await?)
}

async fn collect_h3_body(stream: &mut H3Stream) -> TestResult<Bytes> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    Ok(Bytes::from(body))
}

fn http3_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tcp_tls = tls_support::tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(h3_support::client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn assert_response_info(response: &Response<phantom::ResponseBody>, uri: &str) -> TestResult<()> {
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted redirect metadata")?;
    assert_eq!(info.effective_uri().to_string(), uri);
    assert_eq!(info.redirects_followed(), 1);
    Ok(())
}

fn contains_header(head: &[u8], name: &[u8]) -> bool {
    head.split(|byte| *byte == b'\n').any(|line| {
        line.get(..name.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
            && line.get(name.len()) == Some(&b':')
    })
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "redirect test exceeded its deadline")?
}
