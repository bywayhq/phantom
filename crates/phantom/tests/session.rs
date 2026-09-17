//! Public session connection-reuse integration tests.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

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
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, Route, Session};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::Barrier,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, client_builder, read_head, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const UNICODE_ORIGIN_NAME: &str = "bücher.example";
const ASCII_ORIGIN_NAME: &str = "xn--bcher-kva.example";
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn sequential_same_origin_requests_reuse_one_http2_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            serve_requests(stream, 2).await
        });

        let client = test_client(&identity, true)?;
        let session = client.session();
        for path in ["/first", "/second"] {
            let response = session
                .get(HttpProtocol::Http2, &format!("https://{address}{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        drop(session);

        let requests = server.await??;
        assert_eq!(
            requests,
            vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_upload_and_followup_reuse_one_http2_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before upload")??;
            let first_id = respond.stream_id().as_u32();
            assert_eq!(request.method(), Method::POST);
            let mut incoming = request.into_body();
            let body = collect_h2_request_body(&mut connection, &mut incoming).await?;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;

            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before follow-up")??;
            let second_id = respond.stream_id().as_u32();
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri().path(), "/after-upload");
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((body, [first_id, second_id]))
        });

        let session = test_client(&identity, true)?.session();
        let response = session
            .request(
                HttpProtocol::Http2,
                Method::POST,
                &format!("https://{address}/upload"),
            )?
            .body(Bytes::from_static(b"pooled-payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let response = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/after-upload"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(session);

        let (body, stream_ids) = server.await??;
        assert_eq!(body, "pooled-payload");
        assert_eq!(stream_ids, [1, 3]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn concurrent_cold_requests_through_cloned_session_share_one_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            serve_requests(stream, 2).await
        });

        let client = test_client(&identity, true)?;
        let session = client.session();
        let start = std::sync::Arc::new(Barrier::new(3));
        let first = tokio::spawn(send_after_barrier(
            session.clone(),
            format!("https://{address}/first"),
            start.clone(),
        ));
        let second = tokio::spawn(send_after_barrier(
            session.clone(),
            format!("https://{address}/second"),
            start.clone(),
        ));
        start.wait().await;

        first.await??;
        second.await??;
        drop(session);

        let requests = server.await??;
        let mut stream_ids = requests
            .iter()
            .map(|(stream_id, _)| *stream_id)
            .collect::<Vec<_>>();
        stream_ids.sort_unstable();
        let mut paths = requests
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        assert_eq!(stream_ids, [1, 3]);
        assert_eq!(paths, vec!["/first".to_owned(), "/second".to_owned()]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn separately_created_sessions_do_not_share_http2_connections() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let first = accept_tls(&listener, &acceptor).await?;
            let first = tokio::spawn(serve_requests(first, 1));
            let second = accept_tls(&listener, &acceptor).await?;
            let second = tokio::spawn(serve_requests(second, 1));
            Ok::<_, Box<dyn Error + Send + Sync>>([first.await??, second.await??])
        });

        let client = test_client(&identity, true)?;
        let first_session = client.session();
        let second_session = client.session();
        let first = tokio::spawn(send(first_session, format!("https://{address}/first")));
        let second = tokio::spawn(send(second_session, format!("https://{address}/second")));

        first.await??;
        second.await??;

        let mut connections = server.await??;
        connections.sort_unstable();
        assert_eq!(
            connections,
            [
                vec![(1, "/first".to_owned())],
                vec![(1, "/second".to_owned())]
            ]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn idna_equivalent_origins_reuse_one_plaintext_connect_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(&origin_listener, &acceptor).await?;
            serve_requests(stream, 2).await
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_connect(proxy_listener, origin_address));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let session = test_client(&identity, true)?.session();
        for (host, path) in [
            (UNICODE_ORIGIN_NAME, "/first"),
            (ASCII_ORIGIN_NAME, "/second"),
        ] {
            let response = session
                .get(
                    HttpProtocol::Http2,
                    &format!("https://{host}:{}{path}", origin_address.port()),
                )?
                .route(route.clone())
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        drop(session);

        let requests = origin.await??;
        assert_eq!(
            requests,
            vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        assert_eq!(
            proxy.await??,
            format!(
                "CONNECT {ASCII_ORIGIN_NAME}:{} HTTP/1.1\r\nHost: {ASCII_ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port(),
                origin_address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn idna_equivalent_origins_reuse_one_https_connect_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(&origin_listener, &acceptor).await?;
            serve_requests(stream, 2).await
        });

        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(forward_one_https_connect(
            proxy_listener,
            proxy_acceptor,
            origin_address,
        ));
        let route = Route::http_connect(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let session = client_builder(&identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .build()?
            .session();
        for (host, path) in [
            (UNICODE_ORIGIN_NAME, "/first"),
            (ASCII_ORIGIN_NAME, "/second"),
        ] {
            let response = session
                .get(
                    HttpProtocol::Http2,
                    &format!("https://{host}:{}{path}", origin_address.port()),
                )?
                .route(route.clone())
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        drop(session);

        let requests = origin.await??;
        assert_eq!(
            requests,
            vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        assert_eq!(
            proxy.await??,
            format!(
                "CONNECT {ASCII_ORIGIN_NAME}:{} HTTP/1.1\r\nHost: {ASCII_ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port(),
                origin_address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_http2_header_in_session_fails_before_network_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = test_client(&identity, true)?;
    let session = client.session();
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
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before first request")??;
            let first_id = first.stream_id().as_u32();
            let mut first_body =
                first.send_response(Response::builder().status(200).body(())?, false)?;
            first_body.send_data(Bytes::from_static(b"partial"), false)?;

            let mut reset = None;
            let mut later = None;
            while reset.is_none() || later.is_none() {
                tokio::select! {
                    observed = poll_fn(|context| first_body.poll_reset(context)), if reset.is_none() => {
                        reset = Some(observed?);
                    }
                    incoming = connection.accept(), if later.is_none() => {
                        later = Some(incoming.ok_or("connection closed before later request")??);
                    }
                }
            }

            let (_, mut later) = later.ok_or("later request was not retained")?;
            let later_id = later.stream_id().as_u32();
            later.send_response(Response::builder().status(204).body(())?, true)?;
            drop(first_body);
            drop(first);
            drop(later);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((
                reset.ok_or("stream reset was not retained")?,
                [first_id, later_id],
            ))
        });

        let client = test_client(&identity, true)?;
        let session = client.session();
        let response = session
            .get(HttpProtocol::Http2, &format!("https://{address}/abandoned"))?
            .send()
            .await?;
        let mut abandoned = response.into_body();
        let frame = abandoned
            .frame()
            .await
            .ok_or("response ended before partial data")??;
        assert_eq!(frame.into_data().map_err(|_| "expected response data")?, "partial");
        drop(abandoned);

        let response = session
            .get(HttpProtocol::Http2, &format!("https://{address}/later"))?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);

        let (reset, stream_ids) = server.await??;
        assert_eq!(reset, ::http2::Reason::CANCEL);
        assert_eq!(stream_ids, [1, 3]);
        Ok(())
    })
    .await
}

async fn send_after_barrier(
    session: Session,
    uri: String,
    start: std::sync::Arc<Barrier>,
) -> TestResult<()> {
    start.wait().await;
    send(session, uri).await
}

async fn send(session: Session, uri: String) -> TestResult<()> {
    let response = session.get(HttpProtocol::Http2, &uri)?.send().await?;
    assert_eq!(response.status(), 204);
    response.into_body().collect().await?;
    Ok(())
}

async fn serve_requests(
    stream: SslStream<TcpStream>,
    count: usize,
) -> TestResult<Vec<(u32, String)>> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before expected request")??;
        requests.push((
            respond.stream_id().as_u32(),
            request.uri().path().to_owned(),
        ));
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    poll_fn(|context| connection.poll_closed(context)).await?;
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

async fn forward_one_connect(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<Vec<u8>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

async fn forward_one_https_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: std::net::SocketAddr,
) -> TestResult<Vec<u8>> {
    let mut downstream = accept_tls(&listener, &acceptor).await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "session test exceeded its deadline")?
}
