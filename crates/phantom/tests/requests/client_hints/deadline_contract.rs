use std::{error::Error, io, task::Poll};

use tokio::time::Instant;

use super::{TEST_TIMEOUT, TestResult, bounded};

#[tokio::test]
async fn the_actual_bound_returns_a_ready_success() -> TestResult<()> {
    let observed = bounded(async { Ok(37_u8) }).await?;
    assert_eq!(observed, 37);
    Ok(())
}

#[tokio::test]
async fn the_actual_bound_keeps_a_ready_inner_error() -> TestResult<()> {
    let error = bounded(async {
        Err::<(), Box<dyn Error + Send + Sync>>(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controlled inner operation",
            )
            .into(),
        )
    })
    .await
    .err()
    .ok_or("actual bound accepted a failed inner operation")?;

    let inner = error
        .downcast_ref::<io::Error>()
        .ok_or("actual bound replaced its ready inner error type")?;
    assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(inner.to_string(), "controlled inner operation");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_actual_five_second_bound_keeps_elapsed_and_context() -> TestResult<()> {
    let started = Instant::now();
    let mut entered = false;
    let error = bounded(std::future::poll_fn(|_| {
        entered = true;
        Poll::<TestResult<()>>::Pending
    }))
    .await
    .err()
    .ok_or("pending actual operation did not expire")?;

    assert!(entered, "the actual bound never polled its inner operation");
    assert!(started.elapsed() >= TEST_TIMEOUT);
    assert!(error.to_string().contains("client-hint test timed out"));

    let mut cause: Option<&(dyn Error + 'static)> = Some(error.as_ref());
    while let Some(current) = cause {
        if current.is::<tokio::time::error::Elapsed>() {
            return Ok(());
        }
        cause = current.source();
    }
    Err("actual five-second bound discarded its concrete Elapsed".into())
}
