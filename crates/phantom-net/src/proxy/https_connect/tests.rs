//! Actual sockets at the physical-selection boundary, without OS race timing.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use btls::ssl::Ssl;
use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{Http2RejectedConnect, browser::firefox};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    HttpConnectError, HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol,
    PreparedHttp2Connect, http2_connect,
};
use crate::{
    tcp::{ProfileTcpStream, SlowerAttempt},
    tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn},
};

fn connector(identity: &TestIdentity) -> TestResult<HttpsProxyConnector> {
    Ok(HttpsProxyConnector::new_with_additional_roots(
        &firefox::v157_tcp_tls(),
        [identity.root_der()],
    )?
    .with_http2_settings(&firefox::v157_http2())
    .with_tcp_settings(&firefox::v157_tcp())
    .with_protocol(HttpsProxyProtocol::Http2))
}

async fn sockets() -> TestResult<(ProfileTcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (client, (server, _)) = tokio::try_join!(TcpStream::connect(address), listener.accept())?;
    Ok((ProfileTcpStream::new(client), server))
}

async fn tls(
    server: TcpStream,
    identity: &TestIdentity,
    alpn: TestServerAlpn,
) -> TestResult<SslStream<TcpStream>> {
    let acceptor = identity.acceptor(alpn)?;
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, server)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn closed_without_bytes(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        other => Err(format!("retired connection was not application-quiet: {other:?}").into()),
    }
}

async fn quiet_h2(server: SslStream<TcpStream>, ready: oneshot::Sender<()>) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(server).await?;
    // Keep the client alive until the peer has flushed its initial SETTINGS.
    ready
        .send(())
        .map_err(|_| "the H2 client stopped before peer readiness")?;
    match connection.accept().await {
        None => Ok(()),
        Some(Err(error))
            if error.get_io().is_some_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                )
            }) =>
        {
            Ok(())
        }
        Some(Err(error)) => Err(error.into()),
        Some(Ok(_)) => Err("a setup-only connection sent an application request".into()),
    }
}

#[tokio::test]
async fn verified_h2_retires_the_connected_raw_backup_before_connect() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let (first, server) = sockets().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let slower = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let client = async {
            let connection = connector.finish_pooled_http2_proxy(first, Some(slower), TEST_SERVER_NAME, connector.http2_builder()?).await?;
            let prepared = PreparedHttp2Connect::new("origin.invalid:443", &[HttpConnectHeader::authority("Host")])?;
            let mut tunnel = http2_connect::establish(&connection, &prepared, Http2RejectedConnect::EndStream).await?;
            let mut prefix = [0; 2];
            tunnel.read_exact(&mut prefix).await?;
            assert_eq!(&prefix, b"ok");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            // TLS cannot progress until the loser has actually connected.
            let (mut backup, _) = listener.accept().await?;
            assert!(matches!(backup.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            let server = tls(server, &identity, TestServerAlpn::H2).await?;
            // No authentication response or CONNECT success has been sent.
            closed_without_bytes(&mut backup).await?;
            let mut connection = ::http2::server::handshake(server).await?;
            let (request, mut respond) = connection.accept().await.ok_or("no CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.uri().authority().map(|value| value.as_str()), Some("origin.invalid:443"));
            assert!(!request.headers().contains_key("proxy-authorization"));
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"ok"), true)?;
            drop(send);
            drop(request);
            assert!(connection.accept().await.is_none(), "a second CONNECT was sent");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    }).await.map_err(|_| "H2 backup retirement exceeded its deadline")?
}

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn verified_h2_cancels_a_still_pending_backup() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let (first, server) = sockets().await?;
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        let slower = SlowerAttempt::scripted(
            async move {
                let _guard = guard;
                std::future::pending::<io::Result<TcpStream>>().await
            },
            Duration::ZERO,
            None,
        );
        let (ready, peer_ready) = oneshot::channel();
        let client = async {
            let connection = connector
                .finish_pooled_http2_proxy(
                    first,
                    Some(slower),
                    TEST_SERVER_NAME,
                    connector.http2_builder()?,
                )
                .await?;
            assert!(dropped.load(Ordering::Acquire));
            peer_ready.await?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer =
            async { quiet_h2(tls(server, &identity, TestServerAlpn::H2).await?, ready).await };
        tokio::try_join!(client, peer)?;
        Ok(())
    })
    .await
    .map_err(|_| "pending H2 backup cancellation exceeded its deadline")?
}

#[tokio::test]
async fn cancelling_proxy_tls_releases_both_actual_sockets() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let (first, mut server) = sockets().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let slower = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let mut opening = Box::pin(connector.finish_pooled_http2_proxy(first, Some(slower), TEST_SERVER_NAME, connector.http2_builder()?));
        let (mut backup, _) = tokio::select! {
            result = &mut opening => return Err(format!("TLS completed without peer handshake: {}", result.is_ok()).into()),
            accepted = listener.accept() => accepted?,
        };
        assert!(matches!(backup.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(opening);
        closed_without_bytes(&mut backup).await?;
        // The primary may contain its ClientHello but no application request.
        let mut bytes = Vec::new();
        match server.read_to_end(&mut bytes).await {
            Ok(_) => {},
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => {},
            Err(error) => return Err(error.into()),
        }
        assert_eq!(bytes.first(), Some(&22), "primary never sent its ClientHello");
        Ok(())
    }).await.map_err(|_| "proxy TLS cancellation exceeded its deadline")?
}

#[tokio::test]
async fn wrong_alpn_retires_the_backup_without_connect_or_fallback() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let (first, server) = sockets().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let slower = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let client = async {
            let error = connector.finish_pooled_http2_proxy(first, Some(slower), TEST_SERVER_NAME, connector.http2_builder()?).await.err().ok_or("wrong ALPN accepted")?;
            assert!(matches!(error, HttpConnectError::UnsupportedAlpn { selected } if selected.as_ref() == b"http/1.1"));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut backup, _) = listener.accept().await?;
            let mut server = tls(server, &identity, TestServerAlpn::Http1).await?;
            closed_without_bytes(&mut backup).await?;
            closed_without_bytes(&mut server).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    }).await.map_err(|_| "proxy ALPN failure exceeded its deadline")?
}

#[tokio::test]
async fn certificate_rejection_preserves_its_tls_cause_and_retires_the_backup() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let (first, server) = sockets().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let slower = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let client = async {
            let error = connector
                .finish_pooled_http2_proxy(
                    first,
                    Some(slower),
                    "wrong.phantom.test",
                    connector.http2_builder()?,
                )
                .await
                .err()
                .ok_or("wrong certificate name accepted")?;
            let HttpConnectError::ProxyTls(error) = error else {
                return Err("certificate rejection lost its proxy TLS category".into());
            };
            assert_eq!(error.kind(), crate::tls::TlsErrorKind::Handshake);
            assert!(std::error::Error::source(&error).is_some());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut backup, _) = listener.accept().await?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let mut stream = SslStream::new(Ssl::new(acceptor.context())?, server)?;
            assert!(Pin::new(&mut stream).accept().await.is_err());
            closed_without_bytes(&mut backup).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    })
    .await
    .map_err(|_| "proxy certificate rejection exceeded its deadline")?
}
