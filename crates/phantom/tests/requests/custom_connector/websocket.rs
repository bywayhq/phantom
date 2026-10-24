use super::*;
use crate::support::websocket::{header_value, websocket_accept};

async fn upgrade(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
) -> TestResult<()> {
    let head = read_head(&mut stream).await?;
    let key = header_value(&head, "sec-websocket-key").ok_or("missing WebSocket key")?;
    let accept = websocket_accept(key);
    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
    Ok(())
}

#[tokio::test]
async fn websocket_openings_use_the_selected_custom_stream() -> TestResult<()> {
    for strategy in [Http1WriteStrategy::Automatic, Http1WriteStrategy::Queued] {
        for tls in [false, true] {
            timeout(LIMIT, async {
                let identity = TestIdentity::generate()?;
                let acceptor = identity.acceptor(H1_ALPN)?;
                let (connector, mut peers, calls) = connector();
                let client = client_builder(&identity, false)
                    .http1_write_strategy(strategy)
                    .tcp_connector(connector)
                    .build()?;
                let caller = async {
                    let url = if tls {
                        "wss://127.0.0.1:4321/path"
                    } else {
                        "ws://127.0.0.1:4321/path"
                    };
                    client
                        .websocket_with_protocol(HttpProtocol::Http1, url)?
                        .connect()
                        .await?;
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    Ok::<_, Box<dyn Error + Send + Sync>>(())
                };
                let peer = async {
                    let stream = peers
                        .recv()
                        .await
                        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                    if tls {
                        let ssl = btls::ssl::Ssl::new(acceptor.context())?;
                        let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
                        std::pin::Pin::new(&mut stream).accept().await?;
                        upgrade(stream).await?;
                    } else {
                        upgrade(stream).await?;
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
async fn http2_websocket_opening_uses_the_custom_stream() -> TestResult<()> {
    timeout(LIMIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (connector, mut peers, calls) = connector();
        let client = client_builder(&identity, true).tcp_connector(connector).build()?;
        let (done, finished) = tokio::sync::oneshot::channel();
        let caller = async {
            let websocket = client.websocket_with_protocol(
                HttpProtocol::Http2, "wss://127.0.0.1:4321/path",
            )?.connect().await?;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let _ = done.send(());
            drop(websocket);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let peer = async {
            let stream = peers.recv().await.ok_or("connector did not open a stream")?;
            let ssl = btls::ssl::Ssl::new(acceptor.context())?;
            let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
            std::pin::Pin::new(&mut stream).accept().await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, bytes::Bytes>(stream).await?;
            let (request, mut respond) = connection.accept().await.ok_or("missing CONNECT")??;
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.uri().authority().map(|a| a.as_str()), Some("127.0.0.1:4321"));
            assert_eq!(request.extensions().get::<::http2::ext::Protocol>().map(|p| p.as_str()), Some("websocket"));
            let _body = respond.send_response(http::Response::new(()), false)?;
            tokio::select! {
                biased;
                result = finished => result?,
                unexpected = connection.accept() => return Err(format!("unexpected connection end: {unexpected:?}").into()),
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}
