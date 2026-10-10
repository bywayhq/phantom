use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    task::Poll,
};

use super::{TEST_TIMEOUT, TestResult, bounded};

#[derive(Debug)]
struct InnerFailure;

impl fmt::Display for InnerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("forward deadline inner failure")
    }
}

impl Error for InnerFailure {}

#[tokio::test(start_paused = true)]
async fn expiry_retains_the_actual_elapsed_cause() -> TestResult<()> {
    let mut operation = Box::pin(bounded(std::future::pending()));
    poll_fn(|context| {
        assert!(operation.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(TEST_TIMEOUT).await;

    let error = operation.await.err().ok_or("deadline did not expire")?;
    assert!(
        error
            .to_string()
            .contains("forward-proxy test exceeded its deadline")
    );
    let mut cause: &(dyn Error + 'static) = error.as_ref();
    while !cause.is::<tokio::time::error::Elapsed>() {
        cause = cause
            .source()
            .ok_or("forward deadline lost its actual Elapsed cause")?;
    }
    Ok(())
}

#[tokio::test]
async fn an_inner_failure_keeps_its_concrete_type() -> TestResult<()> {
    let error = bounded(async { Err(InnerFailure.into()) })
        .await
        .err()
        .ok_or("inner failure was discarded")?;
    assert!(error.downcast_ref::<InnerFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_ready_operation_completes() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
