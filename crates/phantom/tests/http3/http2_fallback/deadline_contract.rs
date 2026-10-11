use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, pending, poll_fn},
    pin::pin,
    task::Poll,
};

use tokio::time::{advance, error::Elapsed};

use super::{TEST_TIMEOUT, bounded};
use crate::support::tls::TestResult;

#[derive(Debug)]
struct InnerFailure;

impl fmt::Display for InnerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("literal fallback operation failure")
    }
}

impl Error for InnerFailure {}

#[tokio::test(start_paused = true)]
async fn an_entered_pending_fallback_operation_retains_its_elapsed_cause() -> TestResult<()> {
    let entered = Cell::new(false);
    let mut operation = pin!(bounded(async {
        entered.set(true);
        pending::<TestResult<()>>().await
    }));

    poll_fn(|context| match operation.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => Poll::Ready(Err(
            "fallback operation completed before clock advancement".into(),
        )),
    })
    .await?;
    assert!(entered.get(), "the actual bounded operation was not entered");

    advance(TEST_TIMEOUT).await;
    let error = operation
        .await
        .err()
        .ok_or("pending fallback operation completed without its deadline")?;
    assert_eq!(error.to_string(), "HTTP/2 fallback test exceeded its deadline");

    let mut cause: &(dyn Error + 'static) = error.as_ref();
    loop {
        if cause.downcast_ref::<Elapsed>().is_some() {
            return Ok(());
        }

        cause = cause
            .source()
            .ok_or("fallback deadline discarded its original Elapsed cause")?;
    }
}

#[tokio::test(start_paused = true)]
async fn a_ready_fallback_operation_keeps_its_original_inner_error() -> TestResult<()> {
    let original = Box::new(InnerFailure);
    let identity = original.as_ref() as *const InnerFailure;
    let error = bounded(async move { Err(original as Box<dyn Error + Send + Sync>) })
        .await
        .err()
        .ok_or("failed fallback operation completed successfully")?;
    let cause = error
        .downcast_ref::<InnerFailure>()
        .ok_or("fallback wrapper replaced the concrete inner failure")?;

    assert!(std::ptr::eq(cause, identity));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_ready_fallback_operation_completes_before_the_deadline() -> TestResult<()> {
    let entered = Cell::new(false);
    bounded(async {
        entered.set(true);
        Ok(())
    })
    .await?;

    assert!(entered.get());
    Ok(())
}
