use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, ReadBuf},
    net::TcpStream,
};

use super::*;

#[tokio::test]
async fn cancelling_the_script_keeps_its_already_failed_original_page_driver() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let hellos = Hellos::default();
    let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let failures = PageFailures::default();
    let errors = failures.clone();
    let (ready, page_ready) = oneshot::channel();
    let mut server = ConnectionPeer::spawn(async move {
        let page =
            OpenPage::serve(accept(&listener, &acceptor, Duration::ZERO).await?, errors).await?;
        ready
            .send(())
            .map_err(|_| "page readiness receiver disappeared")?;
        // Keep the real page owner while this later scripted phase waits.
        std::future::pending::<()>().await;
        page.close().await
    });
    let mut connector = btls::ssl::SslConnector::builder(btls::ssl::SslMethod::tls())?;
    connector
        .cert_store_mut()
        .add_cert(btls::x509::X509::from_der(&identity.root_der)?)?;
    connector.set_alpn_protos(b"\x02h2")?;
    let ssl = connector.build().configure()?.into_ssl("localhost")?;
    let mut client = tokio_btls::SslStream::new(ssl, TcpStream::connect(address).await?)?;
    Pin::new(&mut client).connect().await?;
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await?;
    client.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
    // GET /, :scheme https, :authority localhost. The stream ends in HEADERS.
    let headers = b"\x82\x87\x84\x01\x09localhost";
    client.write_all(&[0, 0, 14, 1, 5, 0, 0, 0, 1]).await?;
    client.write_all(headers).await?;
    timeout(Duration::from_secs(5), async {
        loop {
            let mut header = [0; 9];
            client.read_exact(&mut header).await?;
            let length =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            let mut payload = vec![0; length];
            client.read_exact(&mut payload).await?;
            if header[3] == 1 && header[8] == 1 {
                break;
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    timeout(Duration::from_secs(5), page_ready).await??;
    // SETTINGS payload lengths must be multiples of six.
    client.write_all(&[0, 0, 1, 4, 0, 0, 0, 0, 0, 0]).await?;
    timeout(Duration::from_secs(5), async {
        loop {
            if !failures
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let primary: TestResult<()> =
        Err(io::Error::new(io::ErrorKind::InvalidInput, "script stopped").into());
    let error = failures
        .finish(finish_with_cleanup(primary, server.shutdown().await))
        .err()
        .ok_or("page driver failure was discarded")?;
    let failures = error
        .downcast_ref::<crate::support::tunnel_proxy::connection_peer::FixtureFailures>()
        .ok_or("caller and page failures were not retained together")?;
    assert_eq!(
        failures
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("caller cause missing")?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let mut cause: &(dyn Error + 'static) = failures.cleanup.as_ref();
    loop {
        if let Some(error) = cause.downcast_ref::<::http2::Error>() {
            assert_eq!(error.reason(), Some(::http2::Reason::FRAME_SIZE_ERROR));
            break;
        }
        cause = cause
            .source()
            .ok_or("original HTTP/2 protocol cause missing")?;
    }
    Ok(())
}

#[tokio::test]
async fn dropping_an_open_page_ends_its_original_http2_driver() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let hellos = Hellos::default();
    let acceptor = acceptor(&identity, &hellos, H2_THEN_HTTP1)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (ready, page) = oneshot::channel();
    let mut server = ConnectionPeer::spawn(async move {
        let page = OpenPage::serve(
            accept(&listener, &acceptor, Duration::ZERO).await?,
            PageFailures::default(),
        )
        .await?;
        ready
            .send(page)
            .map_err(|_| "page owner receiver disappeared")?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let mut connector = btls::ssl::SslConnector::builder(btls::ssl::SslMethod::tls())?;
    connector
        .cert_store_mut()
        .add_cert(btls::x509::X509::from_der(&identity.root_der)?)?;
    connector.set_alpn_protos(b"\x02h2")?;
    let ssl = connector.build().configure()?.into_ssl("localhost")?;
    let mut tls = tokio_btls::SslStream::new(ssl, TcpStream::connect(address).await?)?;
    Pin::new(&mut tls).connect().await?;
    let (mut sender, connection) = ::http2::client::handshake(tls).await?;
    let mut driver =
        ConnectionPeer::spawn(async move { relay_result(connection.await.map_err(Into::into)) });
    let request = http::Request::builder()
        .uri(format!("https://localhost:{}/", address.port()))
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    assert_eq!(
        timeout(Duration::from_secs(5), response).await??.status(),
        StatusCode::OK
    );
    let page = timeout(Duration::from_secs(5), page).await??;
    server.join().await??;
    drop(page);
    timeout(Duration::from_secs(5), driver.join()).await???;
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[derive(Debug)]
struct CloseFailure;

impl fmt::Display for CloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("opening peer read failed")
    }
}

impl Error for CloseFailure {}

struct FailAfterByte(TcpStream);

impl AsyncRead for FailAfterByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.0).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() > before => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::PermissionDenied, CloseFailure),
            )),
            outcome => outcome,
        }
    }
}

#[tokio::test]
async fn opening_close_keeps_a_non_disconnect_error_after_real_input() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut client = TcpStream::connect(listener.local_addr()?).await?;
    let (server, _) = listener.accept().await?;
    client.write_all(b"!").await?;
    let error = timeout(
        Duration::from_secs(5),
        read_upgrade_close(&mut FailAfterByte(server)),
    )
    .await?
    .err()
    .ok_or("opening read failure was discarded")?;
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("original I/O error missing")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .get_ref()
            .is_some_and(|cause| cause.is::<CloseFailure>())
    );
    Ok(())
}

#[tokio::test]
async fn dropping_proxy_closes_its_original_accepted_relay_with_runtime_live() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let proxy = TunnelProxy::start(listener, origin.local_addr()?);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"CONNECT origin:443 HTTP/1.1\r\n\r\n")
        .await?;
    let (mut upstream, _) = timeout(Duration::from_secs(5), origin.accept()).await??;
    assert!(
        tls_support::read_head(&mut client)
            .await?
            .starts_with(b"HTTP/1.1 200")
    );
    client.write_all(b"witness").await?;
    let mut witness = [0; 7];
    timeout(Duration::from_secs(5), upstream.read_exact(&mut witness)).await??;
    assert_eq!(&witness, b"witness");
    drop(proxy);
    for stream in [&mut client, &mut upstream] {
        let outcome = timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?;
        assert!(
            matches!(outcome, Ok(0))
                || matches!(outcome, Err(ref error) if tls_support::is_peer_gone(error))
        );
    }
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn explicit_proxy_cleanup_joins_the_original_accepted_relay() -> TestResult<()> {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut proxy = TunnelProxy::start(listener, origin.local_addr()?);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"CONNECT origin:443 HTTP/1.1\r\n\r\n")
        .await?;
    let (mut upstream, _) = timeout(Duration::from_secs(5), origin.accept()).await??;
    tls_support::read_head(&mut client).await?;
    proxy.finish(Ok(())).await?;
    for stream in [&mut client, &mut upstream] {
        let outcome = timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?;
        assert!(
            matches!(outcome, Ok(0))
                || matches!(outcome, Err(ref error) if tls_support::is_peer_gone(error))
        );
    }
    drop(proxy);
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}
