//! Public caller-supplied streams retain HTTP identity and client ownership.

use std::{
    error::Error,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom::{
    BuildErrorKind, Client, ConnectedStream, Http1WriteStrategy, HttpProtocol, RequestErrorKind,
    RequestTimeouts, TcpConnector,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::mpsc,
    time::timeout,
};

use crate::support::{
    h2,
    tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, client_builder, read_head},
};

mod policies;
#[cfg(unix)]
mod unix;
#[cfg(feature = "websocket")]
mod websocket;

const LIMIT: Duration = Duration::from_secs(10);
const URL: &str = "http://unresolved.invalid:4321/path";

fn connector() -> (TcpConnector, mpsc::Receiver<DuplexStream>, Arc<AtomicUsize>) {
    let (sender, receiver) = mpsc::channel(4);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let connector = TcpConnector::from_fn(move |target| {
        assert!(!target.host.is_empty());
        observed.fetch_add(1, Ordering::SeqCst);
        let sender = sender.clone();
        async move {
            let (client, peer) = tokio::io::duplex(8192);
            sender
                .send(peer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(ConnectedStream::new(client))
        }
    });
    (connector, receiver, calls)
}

fn builder(connector: TcpConnector) -> phantom::ClientBuilder {
    Client::builder(ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2()))
        .tcp_connector(connector)
}

async fn get(client: &Client) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
    assert_eq!(
        response.into_body().collect_with_limit(8).await?.as_ref(),
        b"ok"
    );
    Ok(())
}

#[tokio::test]
async fn url_authority_survives_pool_reuse_and_independent_clients() -> TestResult<()> {
    timeout(LIMIT, async {
        let (connector, mut peers, calls) = connector();
        let client = builder(connector.clone())
            .http1_write_strategy(Http1WriteStrategy::Queued)
            .build()?;
        let independent = builder(connector).build()?;
        let caller = async {
            get(&client).await?;
            get(&client.clone()).await?;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            get(&independent).await?;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let peer = async {
            for requests in [2, 1] {
                let mut stream = peers
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                for _ in 0..requests {
                    let head = read_head(&mut stream).await?;
                    assert!(head.starts_with(b"GET /path HTTP/1.1\r\n"));
                    assert!(
                        head.windows(b"Host: unresolved.invalid:4321\r\n".len())
                            .any(|part| part == b"Host: unresolved.invalid:4321\r\n")
                    );
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await?;
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn custom_streams_support_tls_http1_http2_and_alpn() -> TestResult<()> {
    for strategy in [Http1WriteStrategy::Automatic, Http1WriteStrategy::Queued] {
        for (http2, negotiated) in [(false, false), (false, true), (true, false), (true, true)] {
            timeout(LIMIT, async {
                let identity = TestIdentity::generate()?;
                let acceptor = identity.acceptor(if http2 { H2_ALPN } else { H1_ALPN })?;
                let (connector, mut peers, calls) = connector();
                let client = client_builder(&identity, http2 || negotiated)
                    .http1_write_strategy(strategy)
                    .tcp_connector(connector)
                    .build()?;
                let caller = async {
                    for _ in 0..2 {
                        let request = if negotiated {
                            client.get_negotiated("https://127.0.0.1:4321/path")?
                        } else {
                            client.get(
                                if http2 {
                                    HttpProtocol::Http2
                                } else {
                                    HttpProtocol::Http1
                                },
                                "https://127.0.0.1:4321/path",
                            )?
                        };
                        let request = if http2 {
                            request
                        } else {
                            request.body("payload")
                        };
                        assert_eq!(request.send().await?.status(), http::StatusCode::OK);
                    }
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    Ok::<_, Box<dyn Error + Send + Sync>>(())
                };
                let peer = async {
                    let stream = peers
                        .recv()
                        .await
                        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                    let ssl = btls::ssl::Ssl::new(acceptor.context())?;
                    let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
                    std::pin::Pin::new(&mut stream).accept().await?;
                    if http2 {
                        h2::accept_client_preface(&mut stream).await?;
                    }
                    for id in [1, 3] {
                        if http2 {
                            h2::read_request_headers(&mut stream, id).await?;
                            h2::write_frame(&mut stream, 1, 5, id, &[0x88]).await?;
                        } else {
                            let head = read_head(&mut stream).await?;
                            assert!(
                                head.windows(b"Content-Length: 7\r\n".len())
                                    .any(|part| part == b"Content-Length: 7\r\n")
                            );
                            let mut body = [0; 7];
                            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut body).await?;
                            assert_eq!(&body, b"payload");
                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                .await?;
                        }
                    }
                    Ok::<_, Box<dyn Error + Send + Sync>>(())
                };
                tokio::try_join!(caller, peer)?;
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn queued_invalid_headers_fail_before_custom_connection_io() -> TestResult<()> {
    let (connector, _peers, calls) = connector();
    let client = builder(connector)
        .http1_write_strategy(Http1WriteStrategy::Queued)
        .build()?;
    let error = client
        .get(HttpProtocol::Http1, URL)?
        .header(phantom::RequestHeader::new("Host", "forbidden"))
        .send()
        .await
        .err()
        .ok_or("caller Host was accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn custom_stream_still_verifies_the_url_hostname() -> TestResult<()> {
    timeout(LIMIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (connector, mut peers, _) = connector();
        let client = client_builder(&identity, false)
            .tcp_connector(connector)
            .build()?;
        let caller = async {
            let error = client
                .get(HttpProtocol::Http1, "https://wrong.invalid/")?
                .send()
                .await
                .err()
                .ok_or("hostname mismatch was accepted")?;
            assert_eq!(error.kind(), RequestErrorKind::Tls);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let peer = async {
            let stream = peers
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let ssl = btls::ssl::Ssl::new(acceptor.context())?;
            let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
            assert!(std::pin::Pin::new(&mut stream).accept().await.is_err());
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn connect_timeout_drops_the_callback_future() -> TestResult<()> {
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = dropped.clone();
    let connector = TcpConnector::from_fn(move |_| {
        let guard = Dropped(observed.clone());
        async move {
            let _guard = guard;
            std::future::pending::<io::Result<ConnectedStream>>().await
        }
    });
    let client = builder(connector)
        .request_timeouts(RequestTimeouts::new().connect(Duration::from_secs(1)))
        .build()?;
    let error = client
        .get(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("pending connector succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn proxy_overrides_are_rejected_before_calling_the_connector() -> TestResult<()> {
    let (connector, _peers, calls) = connector();
    let client = builder(connector).build()?;
    let proxy = phantom::Route::http_proxy(phantom::HttpProxy::new("http://127.0.0.1:9")?);
    let error = client
        .get(HttpProtocol::Http1, URL)?
        .route(proxy)
        .send()
        .await
        .err()
        .ok_or("proxy route was accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn conflicting_socket_and_discovery_settings_fail_at_build() -> TestResult<()> {
    let (connector, _peers, calls) = connector();
    for builder in [
        builder(connector.clone()).local_address(std::net::Ipv4Addr::LOCALHOST.into()),
        builder(connector.clone()).alt_svc(std::num::NonZeroUsize::MIN),
        builder(connector).route(phantom::Route::http_proxy(phantom::HttpProxy::new(
            "http://127.0.0.1:9",
        )?)),
    ] {
        let error = builder
            .build()
            .err()
            .ok_or("incompatible policy was accepted")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
