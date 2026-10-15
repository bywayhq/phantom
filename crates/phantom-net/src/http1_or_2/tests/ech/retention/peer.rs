//! One bounded loopback ECH peer, including an optional authenticated retry.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

pub(super) async fn serve_requests(
    listener: Arc<TcpListener>,
    acceptor: SslAcceptor,
    retry: bool,
    ready: oneshot::Sender<()>,
) -> TestResult<()> {
    if retry {
        let (tcp, _) = listener.accept().await?;
        let rejected = observe(tcp, &acceptor).await?;
        assert!(!rejected.ech_accepted);
        assert_eq!(rejected.ech.as_ref().map(|ech| ech.config_id), Some(1));
    }
    let (mut tcp, _) = listener.accept().await?;
    let capture = capture_client_hello(
        &mut tcp,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(64 * 1024, 64 * 1024, 8),
    )
    .await?;
    let summary = capture.summary()?;
    assert_eq!(summary.server_name(), Some(PUBLIC_NAME.as_bytes()));
    assert_eq!(
        summary
            .encrypted_client_hello()
            .and_then(EchOuterExtension::parse)
            .map(|ech| ech.config_id),
        Some(if retry { 2 } else { 1 })
    );
    let prefix = capture
        .records()
        .iter()
        .flat_map(|record| record.wire_bytes().iter().copied())
        .collect();
    let mut tls = SslStream::new(
        Ssl::new(acceptor.context())?,
        Replayed {
            prefix,
            offset: 0,
            inner: tcp,
        },
    )?;
    Pin::new(&mut tls).accept().await?;
    assert!(
        tls.ssl().ech_accepted(),
        "peer did not decrypt the retained ECH handshake"
    );
    assert_eq!(tls.ssl().servername(NameType::HOST_NAME), Some(INNER_NAME));
    ready
        .send(())
        .map_err(|_| "client left before authenticated handshake")?;
    // Any automatic request would be the first head and fail these exact paths.
    for path in ["/first", "/second"] {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if tls.read(&mut byte).await? == 0 {
                return Err("connection closed before request".into());
            }
            head.push(byte[0]);
            if head.len() > 4096 {
                return Err("request head exceeded fixture bound".into());
            }
        }
        assert_eq!(
            head,
            format!("GET {path} HTTP/1.1\r\nHost: {INNER_NAME}\r\n\r\n").as_bytes()
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        tls.flush().await?;
    }
    Ok(())
}
