use std::{
    error::Error,
    io,
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::timeout,
};

use crate::proxy_h2::relay_contract::Fault;

use super::{
    OriginFaults, TestIdentity, TestResult, chromium_profile, client, get_https,
    peer_contract::{TaskProbe, TaskRole},
    seen, spawn_origin_fixture_with_faults, spawn_proxy_fixture,
};

pub(super) struct WriteFailure<S> {
    pub(super) inner: S,
    pub(super) fault: Option<Fault>,
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteFailure<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteFailure<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.fault.as_ref().and_then(|fault| fault.error(context)) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Read,
    Write,
    Tls,
}

async fn actual_origin_failure(failure: Failure) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy_probe = TaskProbe::default();
    let origin_probe = TaskProbe::default();
    let fault = Fault::default();
    let proxy = spawn_proxy_fixture(&identity, None, Some(proxy_probe.clone())).await?;
    let origin = spawn_origin_fixture_with_faults(
        &identity,
        Some(origin_probe.clone()),
        OriginFaults {
            read: matches!(failure, Failure::Read).then(|| fault.clone()),
            write: matches!(failure, Failure::Write).then(|| fault.clone()),
            ..OriginFaults::default()
        },
    )
    .await?;
    let client = client(chromium_profile(), &identity, &identity, proxy.address)?;
    timeout(Duration::from_secs(5), get_https(&client, origin.address)).await??;
    assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
    let records = seen(&proxy.log);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, http::Method::CONNECT);
    assert_eq!(records[0].authority, origin.address.to_string());
    assert!(origin_probe.live().contains(&TaskRole::OriginConnection));
    assert_eq!(origin.completed_handlers()?, 0);
    assert_eq!(fault.observations(), 0);
    let mut second = None;
    match failure {
        Failure::Read => fault.enable()?,
        Failure::Write => {
            fault.enable()?;
            second =
                Some(timeout(Duration::from_secs(5), get_https(&client, origin.address)).await);
        }
        Failure::Tls => {
            let mut invalid =
                timeout(Duration::from_secs(5), TcpStream::connect(origin.address)).await??;
            timeout(
                Duration::from_secs(5),
                invalid.write_all(b"GET /not-tls HTTP/1.0\r\n\r\n"),
            )
            .await??;
            timeout(Duration::from_secs(5), invalid.shutdown()).await??;
        }
    }
    let completed = timeout(Duration::from_secs(5), async {
        while origin.completed_handlers()? == 0 {
            tokio::task::yield_now().await;
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await;
    let received = origin.requests.load(Ordering::SeqCst);
    let returned = origin.finish().await;
    let proxy_stop = proxy_probe.backup().await;
    let origin_stop = origin_probe.backup().await;
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(proxy_stop, origin_stop);
    drop(proxy);
    drop(client);
    let checked = (|| {
        completed??;
        match failure {
            Failure::Read | Failure::Write => {
                assert!(
                    fault.observations() > 0,
                    "actual origin never returned its controlled I/O error"
                );
                if matches!(failure, Failure::Write) {
                    assert!(
                        received >= 2,
                        "actual origin never read the request preceding its write failure"
                    );
                    assert!(
                        second
                            .ok_or("actual second origin request absent")??
                            .is_err()
                    );
                }
                let error = returned
                    .err()
                    .ok_or("actual origin discarded its postexchange I/O error")?;
                assert_eq!(
                    error
                        .downcast_ref::<io::Error>()
                        .ok_or("origin lost its typed I/O error")?
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            }
            Failure::Tls => {
                assert_eq!(received, 1);
                let error = returned
                    .err()
                    .ok_or("actual origin discarded its unrelated TLS handshake failure")?;
                assert!(
                    error.downcast_ref::<btls::ssl::Error>().is_some(),
                    "actual origin lost its TLS error type"
                );
            }
        }
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn actual_origin_keeps_a_postexchange_read_error() -> TestResult<()> {
    actual_origin_failure(Failure::Read).await
}
#[tokio::test]
async fn actual_origin_keeps_a_postexchange_write_error() -> TestResult<()> {
    actual_origin_failure(Failure::Write).await
}
#[tokio::test]
async fn actual_origin_keeps_an_unrelated_tls_failure_after_a_healthy_exchange() -> TestResult<()> {
    actual_origin_failure(Failure::Tls).await
}
