//! HTTP/2 transport to HTTPS proxies through the public route API.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{
    HttpProtocol, HttpProxy, ProxyConfigErrorKind, RequestErrorKind, RequestHeader, Route,
};
use phantom_net::proxy::HttpConnectError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
    is_peer_gone, read_head,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn plaintext_proxy_rejects_h2_transport_configuration() -> TestResult<()> {
    let error = match HttpProxy::new("http://127.0.0.1:8080")?.with_http2_transport() {
        Ok(_) => return Err("plaintext proxy accepted HTTP/2 transport".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ProxyConfigErrorKind::UnsupportedTransport);
    HttpProxy::new("https://127.0.0.1:8443")?.with_http2_transport()?;
    Ok(())
}

#[tokio::test]
async fn h1_origin_over_h2_proxy_tunnel_completes_request() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn StdError + Send + Sync>>((request, body))
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Tunnel(origin_address)).await
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .header(RequestHeader::new("User-Agent", "phantom-test"))
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{origin_address}/through-h2-proxy"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "secure");

        let record = proxy_task.await??;
        assert_eq!(record.authority.as_deref(), Some(origin_address.to_string().as_str()));
        assert_eq!(
            record.fields,
            [("user-agent".to_owned(), b"phantom-test".to_vec())]
        );
        let (request, body) = origin.await??;
        assert_eq!(
            request,
            format!(
                "POST /through-h2-proxy HTTP/1.1\r\nHost: {origin_address}\r\nContent-Length: 7\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_origin_over_h2_proxy_tunnel_completes_request() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, origin_acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("origin connection closed before request")??;
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"h2-in-h2"), true)?;
            let path = request.uri().path().to_owned();
            drop(request);
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
            Ok::<_, Box<dyn StdError + Send + Sync>>(path)
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Tunnel(origin_address)).await
        });
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_http2_transport()?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{origin_address}/nested"),
            )?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "h2-in-h2");
        drop(client);

        let record = proxy_task.await??;
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        assert!(record.fields.is_empty(), "{:?}", record.fields);
        assert_eq!(origin.await??, "/nested");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_basic_challenge_replays_once_on_fresh_connection() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn StdError + Send + Sync>>(())
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (first, _) = listener.accept().await?;
            let challenged = serve_connect(first, &acceptor, Reply::Challenge).await?;
            let (second, _) = listener.accept().await?;
            let authorized =
                serve_connect(second, &acceptor, Reply::Tunnel(origin_address)).await?;
            Ok::<_, Box<dyn StdError + Send + Sync>>((challenged, authorized))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let (challenged, authorized) = proxy_task.await??;
        assert!(challenged.fields.is_empty(), "{:?}", challenged.fields);
        assert_eq!(
            challenged.later_requests, 0,
            "challenged connection was reused"
        );
        assert_eq!(
            authorized.fields,
            [(
                "proxy-authorization".to_owned(),
                b"Basic YWxpY2U6c2VjcmV0".to_vec()
            )]
        );
        origin.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_rejection_is_typed() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let origin_identity = TestIdentity::generate()?;

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Status(403)).await
        });
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_http2_transport()?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http2, &format!("https://{origin_address}/"))?
            .send()
            .await
        {
            Ok(_) => return Err("rejected HTTP/2 CONNECT succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::Rejected { status: 403 })
        ));
        proxy_task.await??;
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn default_https_proxy_transport_remains_http1() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let mut byte = [0_u8; 1];
            let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>(match read {
                Ok(Ok(count)) => count == 0,
                Ok(Err(error)) => is_peer_gone(&error),
                Err(_) => false,
            })
        });
        // The profile offers `h2, http/1.1`; the proxy selects `h2`.
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http1, "https://127.0.0.1:9/")?
            .send()
            .await
        {
            Ok(_) => return Err("default HTTPS proxy transport accepted h2".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::UnsupportedAlpn { selected }) if selected.as_ref() == b"h2"
        ));
        assert!(
            proxy_task.await??,
            "HTTP/1.1 CONNECT bytes reached the h2 proxy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_transport_rejects_http1_selection_without_fallback() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = listener.local_addr()?;
        let acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let mut byte = [0_u8; 1];
            let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>(match read {
                Ok(Ok(count)) => count == 0,
                Ok(Err(error)) => is_peer_gone(&error),
                Err(_) => false,
            })
        });
        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http2, "https://127.0.0.1:9/")?
            .send()
            .await
        {
            Ok(_) => return Err("HTTP/2 proxy transport fell back to HTTP/1.1".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::UnsupportedAlpn { selected }) if selected.as_ref() == b"http/1.1"
        ));
        assert!(
            proxy_task.await??,
            "HTTP/1.1 CONNECT bytes reached the proxy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_transport_rejects_plaintext_forwarding_before_io() -> TestResult<()> {
    let origin_identity = TestIdentity::generate()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let route = Route::http_proxy(
        HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
    );
    let client = client_builder(&origin_identity, true)
        .route(route)
        .build()?;

    let error = match client
        .get(HttpProtocol::Http1, "http://origin.invalid/")?
        .send()
        .await
    {
        Ok(_) => return Err("plaintext request was forwarded over HTTP/2 transport".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    assert!(matches!(
        connect_error(&error),
        Some(HttpConnectError::ForwardingRequiresHttp1)
    ));
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

struct H2Proxy {
    identity: TestIdentity,
    listener: TcpListener,
    address: SocketAddr,
}

impl H2Proxy {
    async fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            identity: TestIdentity::generate()?,
            listener,
            address,
        })
    }

    fn into_parts(self) -> TestResult<(String, Vec<u8>, SslAcceptor, TcpListener)> {
        let acceptor = self.identity.acceptor(H2_ALPN)?;
        Ok((
            format!("https://{}", self.address),
            self.identity.root_der.clone(),
            acceptor,
            self.listener,
        ))
    }
}

enum Reply {
    Tunnel(SocketAddr),
    Challenge,
    Status(u16),
}

#[derive(Debug)]
struct ConnectRecord {
    authority: Option<String>,
    fields: Vec<(String, Vec<u8>)>,
    later_requests: usize,
}

/// Serves one HTTP/2 proxy connection with one CONNECT exchange.
///
/// The HTTP/2 server rejects `:scheme` or `:path` in a classic CONNECT, so
/// every recorded request used the two-field pseudo-header form.
async fn serve_connect(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    reply: Reply,
) -> TestResult<ConnectRecord> {
    let stream = accept_tls_stream(tcp, acceptor.clone()).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("proxy connection closed before CONNECT")??;
    if request.method() != Method::CONNECT {
        return Err("proxy received a non-CONNECT request".into());
    }
    let authority = request.uri().authority().map(ToString::to_string);
    let fields = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("missing ordered CONNECT fields")?
        .as_slice()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    let mut record = ConnectRecord {
        authority,
        fields,
        later_requests: 0,
    };

    match reply {
        Reply::Tunnel(origin) => {
            let send = respond.send_response(Response::new(()), false)?;
            let upstream = TcpStream::connect(origin).await?;
            spawn_relay(request.into_body(), send, upstream);
            tokio::spawn(async move {
                while let Some(result) = connection.accept().await {
                    if result.is_err() {
                        break;
                    }
                }
            });
        }
        Reply::Challenge | Reply::Status(_) => {
            let mut response = Response::builder().status(match reply {
                Reply::Status(status) => status,
                _ => 407,
            });
            if matches!(reply, Reply::Challenge) {
                response = response.header("proxy-authenticate", "Basic realm=\"proxy\"");
            }
            respond.send_response(response.body(())?, true)?;
            drop(request);
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
                record.later_requests += 1;
            }
        }
    }
    Ok(record)
}

fn spawn_relay(
    mut downstream: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
) {
    let (mut read, mut write) = upstream.into_split();
    tokio::spawn(async move {
        while let Some(Ok(chunk)) = downstream.data().await {
            let _ = downstream.flow_control().release_capacity(chunk.len());
            if write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let count = match read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = send.send_data(Bytes::new(), true);
                    return;
                }
                Ok(count) => count,
            };
            let mut chunk = Bytes::copy_from_slice(&buffer[..count]);
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
                    Some(Ok(capacity)) => capacity,
                    _ => return,
                };
                let part = chunk.split_to(capacity.min(chunk.len()));
                if send.send_data(part, false).is_err() {
                    return;
                }
            }
        }
    });
}

fn connect_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a HttpConnectError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(found) = error.downcast_ref::<HttpConnectError>() {
            return Some(found);
        }
        current = error.source();
    }
    None
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/2 proxy integration test exceeded its deadline")?
}
