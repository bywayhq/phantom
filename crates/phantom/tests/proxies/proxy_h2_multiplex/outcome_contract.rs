use std::{
    error::Error,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use http::Method;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::timeout,
};

use crate::{
    proxy_h2::relay_contract::Fault, support::tunnel_proxy::connection_peer::FixtureFailures,
};

use super::{
    TestIdentity, TestResult, chromium_profile, client, get_forwarded, observe_log,
    peer_contract::{TaskProbe, TaskRole},
    spawn_proxy_fixture_with_fault,
};

pub(crate) struct ReadFailure<S> {
    pub(crate) inner: S,
    pub(crate) fault: Option<Fault>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadFailure<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = self.fault.as_ref().and_then(|fault| fault.error(context)) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadFailure<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn peer_io<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a io::Error> {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Some(error);
        }
        if let Some(error) = error
            .downcast_ref::<::http2::Error>()
            .and_then(|error| error.get_io())
        {
            return Some(error);
        }
        cause = error.source();
    }
    None
}

async fn completed_failure(primary: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fault = Fault::default();
    let fixture =
        spawn_proxy_fixture_with_fault(&identity, None, Some(probe.clone()), Some(fault.clone()))
            .await?;
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "completed.test:8080"),
    )
    .await??;
    let records = observe_log(&fixture.log)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, Method::GET);
    assert_eq!(records[0].authority, "completed.test:8080");
    assert!(probe.live().contains(&TaskRole::ProxyConnection));
    assert_eq!(fault.observations(), 0);
    fault.enable()?;
    let completed = timeout(Duration::from_secs(5), async {
        while fixture.completed_handlers()? != 1 {
            tokio::task::yield_now().await;
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await;
    let operation = if primary {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "actual caller failed after its response",
        )
        .into())
    } else {
        Ok(())
    };
    let result = fixture.finish_operation(operation).await;
    // The completed child and live external client precede finite backup.
    let cleanup = probe.backup().await;
    drop(client);
    let checked = (|| {
        completed??;
        assert!(
            fault.observations() > 0,
            "the actual accepted handler never returned its controlled I/O error"
        );
        let error = result
            .err()
            .ok_or("multiplex finish discarded its completed accepted-handler error")?;
        if primary {
            let both = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("multiplex caller discarded its completed accepted-handler cause")?;
            assert_eq!(
                both.primary
                    .downcast_ref::<io::Error>()
                    .ok_or("caller type lost")?
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                peer_io(both.cleanup.as_ref())
                    .ok_or("completed child type lost")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        } else {
            assert_eq!(
                peer_io(error.as_ref())
                    .ok_or("completed child type lost")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn ordinary_finish_keeps_a_completed_actual_handler_failure() -> TestResult<()> {
    completed_failure(false).await
}

#[tokio::test]
async fn a_primary_failure_keeps_the_completed_actual_handler_failure() -> TestResult<()> {
    completed_failure(true).await
}

async fn log_writer(poisoned: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fixture =
        spawn_proxy_fixture_with_fault(&identity, None, Some(probe.clone()), None).await?;
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "writer.test:8080"),
    )
    .await??;
    assert_eq!(observe_log(&fixture.log)?.len(), 1);
    if poisoned {
        super::peer_contract::poison(&fixture.log)?;
    }
    let second = timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "second.test:8080"),
    )
    .await;
    let observed = if poisoned {
        None
    } else {
        Some(observe_log(&fixture.log)?)
    };
    let cleanup = probe.backup().await;
    drop(fixture);
    drop(client);
    let checked = (|| {
        let second = second?;
        if poisoned {
            assert!(
                second.is_err(),
                "actual poisoned log writer still answered a second forwarded request successfully"
            );
        } else {
            second?;
            let records = observed.ok_or("healthy records missing")?;
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].method, Method::GET);
            assert_eq!(records[1].method, Method::GET);
            assert_eq!(records[1].authority, "second.test:8080");
            assert_eq!(records[0].connection, records[1].connection);
        }
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn a_poisoned_actual_writer_does_not_answer_an_unrecorded_request() -> TestResult<()> {
    log_writer(true).await
}

#[tokio::test]
async fn a_healthy_actual_writer_records_both_forwarded_requests() -> TestResult<()> {
    log_writer(false).await
}
