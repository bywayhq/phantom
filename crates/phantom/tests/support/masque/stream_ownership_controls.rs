use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use btls::{ssl::SslConnector, x509::X509};
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    H1_ALPN, MasqueStreamProxy, STREAM_SHUTDOWN, StreamLeg, StreamLog, StreamMode, TestIdentity,
    TestResult, encode_capsule, finish_with_cleanup, lock, read_head, serve_http1, serve_http2,
};
use crate::support::tunnel_proxy::{ConnectionPeer, FixtureFailures};

async fn completed(proxy: &MasqueStreamProxy) -> TestResult<()> {
    timeout(STREAM_SHUTDOWN, async {
        while lock(&proxy.log).completed_connections != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

async fn authenticated(
    identity: &TestIdentity,
    address: std::net::SocketAddr,
) -> TestResult<tokio_btls::SslStream<TcpStream>> {
    let mut connector = SslConnector::builder(btls::ssl::SslMethod::tls())?;
    connector
        .cert_store_mut()
        .add_cert(X509::from_der(&identity.root_der)?)?;
    connector.set_alpn_protos(H1_ALPN)?;
    let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
    let mut peer = tokio_btls::SslStream::new(ssl, TcpStream::connect(address).await?)?;
    timeout(STREAM_SHUTDOWN, Pin::new(&mut peer).connect()).await??;
    assert_eq!(
        peer.ssl().selected_alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    Ok(peer)
}

fn head(port: u16) -> String {
    format!(
        "GET /.well-known/masque/udp/127.0.0.1/{port}/ HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n"
    )
}

async fn preamble(peer: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let response = timeout(STREAM_SHUTDOWN, read_head(peer)).await??;
    assert!(response.starts_with(b"HTTP/1.1 101 "));
    let mut bytes = [0; 23];
    timeout(STREAM_SHUTDOWN, peer.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"\x2a\x03xyz\x00\x10\x02unknown-context");
    Ok(())
}

#[tokio::test]
async fn accepted_tls_failure_keeps_both_original_caller_and_handshake_causes() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut proxy =
        MasqueStreamProxy::spawn(&identity, StreamLeg::Http1, StreamMode::Relay).await?;
    let mut peer = TcpStream::connect(proxy.address).await?;
    peer.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    peer.shutdown().await?;
    completed(&proxy).await?;

    let caller: Box<dyn Error + Send + Sync> = Box::new(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "original MASQUE caller failure",
    ));
    let original = ptr::from_ref(caller.as_ref());
    let result: TestResult<()> = finish_with_cleanup(Err(caller), proxy.shutdown().await);
    let error = result.err().ok_or("accepted TLS failure disappeared")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("original causes were not grouped")?;
    assert!(ptr::eq(original, ptr::from_ref(failures.primary.as_ref())));
    assert!(
        failures
            .cleanup
            .downcast_ref::<btls::ssl::Error>()
            .is_some()
    );
    assert!(proxy.task.is_none());
    let rebound = TcpListener::bind(proxy.address).await?;
    assert_eq!(rebound.local_addr()?, proxy.address);
    Ok(())
}

#[tokio::test]
async fn authenticated_partial_capsule_reaches_the_original_proxy_shutdown_cause() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let mut proxy =
        MasqueStreamProxy::spawn(&identity, StreamLeg::Http1, StreamMode::Relay).await?;
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let mut peer = authenticated(&identity, proxy.address).await?;
    peer.write_all(head(target.local_addr()?.port()).as_bytes())
        .await?;
    preamble(&mut peer).await?;
    peer.write_all(b"\x00\x03\x00!!").await?;
    let mut bytes = [0; 16];
    let (count, relay) = timeout(STREAM_SHUTDOWN, target.recv_from(&mut bytes)).await??;
    assert_eq!(&bytes[..count], b"!!");

    peer.write_all(b"\x00\x02\x00").await?;
    peer.shutdown().await?;
    completed(&proxy).await?;
    let error = proxy
        .shutdown()
        .await
        .err()
        .ok_or("partial capsule became successful cleanup")?;
    let cause = error
        .downcast_ref::<io::Error>()
        .ok_or("original partial capsule EOF missing")?;
    assert_eq!(cause.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        cause.to_string(),
        "CONNECT-UDP stream ended inside a capsule"
    );
    assert_eq!(proxy.client_capsules(), [(0, Some(0), 3)]);
    let rebound = phantom_testkit::udp::bind_tokio(relay)?;
    assert_eq!(rebound.local_addr()?, relay);
    Ok(())
}

#[tokio::test]
async fn an_actual_udp_send_error_survives_the_inline_capsule_relay() -> TestResult<()> {
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let (mut peer, stream) = tokio::io::duplex(128 * 1024);
    let mut owner = ConnectionPeer::spawn(serve_http1(
        stream,
        StreamMode::Relay,
        Arc::new(Mutex::new(StreamLog::default())),
    ));
    peer.write_all(head(target.local_addr()?.port()).as_bytes())
        .await?;
    preamble(&mut peer).await?;

    // IPv4 UDP carries at most 65,507 payload bytes, independent of capsules.
    let mut payload = vec![0];
    payload.extend(std::iter::repeat_n(b'x', 65_508));
    peer.write_all(&encode_capsule(0, &payload)).await?;
    let error = timeout(STREAM_SHUTDOWN, owner.join())
        .await??
        .err()
        .ok_or("oversized UDP send was discarded")?;
    let cause = error
        .downcast_ref::<io::Error>()
        .ok_or("original UDP socket error missing")?;
    assert!(
        matches!(cause.raw_os_error(), Some(40 | 90 | 10040)),
        "{cause}"
    );
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_actual_non_cancel_h2_reset_keeps_its_remote_typed_error() -> TestResult<()> {
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let (peer, stream) = tokio::io::duplex(4096);
    let mut owner = ConnectionPeer::spawn(serve_http2(
        stream,
        StreamMode::Relay,
        Arc::new(Mutex::new(StreamLog::default())),
    ));
    let mut driver = None;
    let primary = async {
        let (client, connection) =
            timeout(STREAM_SHUTDOWN, ::http2::client::handshake(peer)).await??;
        driver = Some(ConnectionPeer::spawn(async move {
            connection.await.map_err(|error| error.into())
        }));
        let mut client = timeout(STREAM_SHUTDOWN, client.ready()).await??;
        timeout(STREAM_SHUTDOWN, async {
            while !client.is_extended_connect_protocol_enabled() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let request = http::Request::builder()
            .method("CONNECT")
            .version(http::Version::HTTP_2)
            .uri(format!(
                "https://localhost/.well-known/masque/udp/127.0.0.1/{}/",
                target.local_addr()?.port()
            ))
            .extension(::http2::ext::Protocol::from_static("connect-udp"))
            .body(())?;
        let (response, mut send) = client.send_request(request, false)?;
        let response = timeout(STREAM_SHUTDOWN, response).await??;
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut body = response.into_body();
        let bytes = timeout(STREAM_SHUTDOWN, body.data())
            .await?
            .ok_or("H2 preamble missing")??;
        body.flow_control().release_capacity(bytes.len())?;
        assert_eq!(bytes.as_ref(), b"\x2a\x03xyz\x00\x10\x02unknown-context");
        send.send_data(Bytes::from_static(b"\x00\x03\x00!!"), false)?;
        let mut observed = [0; 16];
        let (count, _) = timeout(STREAM_SHUTDOWN, target.recv_from(&mut observed)).await??;
        assert_eq!(&observed[..count], b"!!");

        send.send_reset(::http2::Reason::INTERNAL_ERROR);
        let error = timeout(STREAM_SHUTDOWN, owner.join())
            .await??
            .err()
            .ok_or("wrong reset code was accepted as cleanup")?;
        let cause = error
            .downcast_ref::<::http2::Error>()
            .ok_or("original H2 reset error missing")?;
        assert!(cause.is_reset() && cause.is_remote());
        assert_eq!(cause.reason(), Some(::http2::Reason::INTERNAL_ERROR));
        owner.shutdown().await?;
        let completed = timeout(
            STREAM_SHUTDOWN,
            driver
                .as_mut()
                .ok_or("H2 client driver owner missing")?
                .join(),
        )
        .await??;
        match completed {
            Ok(()) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<::http2::Error>()
                    .is_some_and(super::stream_outcomes::h2_peer_closed) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    .await;

    let result = finish_with_cleanup(primary, owner.shutdown().await);
    match driver.as_mut() {
        Some(driver) => finish_with_cleanup(result, driver.shutdown().await),
        None => result,
    }
}

#[tokio::test]
async fn interrupted_borrowed_shutdown_keeps_its_actual_tls_child_for_retry() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut proxy =
        MasqueStreamProxy::spawn(&identity, StreamLeg::Http1, StreamMode::Relay).await?;
    let mut peer = TcpStream::connect(proxy.address).await?;
    timeout(STREAM_SHUTDOWN, async {
        while proxy.connections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let mut shutdown = Box::pin(proxy.shutdown());
    poll_fn(|context| {
        assert!(shutdown.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(shutdown);
    assert!(proxy.task.is_some());
    timeout(STREAM_SHUTDOWN, proxy.shutdown()).await??;
    assert!(proxy.task.is_none());
    assert_eq!(lock(&proxy.log).completed_connections, 1);
    assert_eq!(timeout(STREAM_SHUTDOWN, peer.read(&mut [0; 1])).await??, 0);
    let rebound = TcpListener::bind(proxy.address).await?;
    assert_eq!(rebound.local_addr()?, proxy.address);
    Ok(())
}

#[derive(Debug)]
struct WriteCause(Arc<()>);

impl fmt::Display for WriteCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original capsule pump write failure")
    }
}

impl Error for WriteCause {}

struct FaultWrite {
    stream: DuplexStream,
    fail: Arc<AtomicBool>,
    error: Option<io::Error>,
}

impl AsyncRead for FaultWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for FaultWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fail.load(Ordering::SeqCst)
            && let Some(error) = this.error.take()
        {
            return Poll::Ready(Err(error));
        }

        Pin::new(&mut this.stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

#[tokio::test]
async fn a_reply_pump_keeps_its_original_write_cause_after_real_udp_traffic() -> TestResult<()> {
    let target = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    let (mut peer, stream) = tokio::io::duplex(4096);
    let fail = Arc::new(AtomicBool::new(false));
    let identity = Arc::new(());
    let stream = FaultWrite {
        stream,
        fail: fail.clone(),
        error: Some(io::Error::new(
            io::ErrorKind::PermissionDenied,
            WriteCause(identity.clone()),
        )),
    };
    let mut owner = ConnectionPeer::spawn(serve_http1(
        stream,
        StreamMode::Relay,
        Arc::new(Mutex::new(StreamLog::default())),
    ));
    peer.write_all(head(target.local_addr()?.port()).as_bytes())
        .await?;
    preamble(&mut peer).await?;
    peer.write_all(b"\x00\x03\x00!!").await?;
    let mut bytes = [0; 16];
    let (count, relay) = timeout(STREAM_SHUTDOWN, target.recv_from(&mut bytes)).await??;
    assert_eq!(&bytes[..count], b"!!");

    fail.store(true, Ordering::SeqCst);
    target.send_to(b"reply", relay).await?;
    let error = timeout(STREAM_SHUTDOWN, owner.join())
        .await??
        .err()
        .ok_or("reply write failure was discarded")?;
    let cause = error
        .downcast_ref::<io::Error>()
        .ok_or("original pump I/O cause missing")?;
    assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
    let marker = cause
        .get_ref()
        .and_then(|source| source.downcast_ref::<WriteCause>())
        .ok_or("write marker missing")?;
    assert!(Arc::ptr_eq(&identity, &marker.0));
    owner.shutdown().await?;
    let rebound = phantom_testkit::udp::bind_tokio(relay)?;
    assert_eq!(rebound.local_addr()?, relay);
    Ok(())
}
