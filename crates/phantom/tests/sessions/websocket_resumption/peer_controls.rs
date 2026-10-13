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
