use std::{cell::Cell, error::Error, fmt, future::pending};

use tokio::time::error::Elapsed;

use super::bounded;
use crate::support::tls::TestResult;

#[derive(Debug)]
struct InnerFailure;

impl fmt::Display for InnerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HTTPS-record deadline inner failure")
    }
}

impl Error for InnerFailure {}

#[tokio::test(start_paused = true)]
async fn an_entered_pending_operation_retains_its_elapsed_cause() -> TestResult<()> {
    let entered = Cell::new(false);
    let error = bounded(async {
        entered.set(true);
        pending::<TestResult<()>>().await
    })
    .await
    .err()
    .ok_or("pending HTTPS-record operation completed successfully")?;

    assert!(entered.get(), "deadline did not poll the actual operation");
    assert_eq!(error.to_string(), "ECH test exceeded its deadline");

    let mut cause: &(dyn Error + 'static) = error.as_ref();
    loop {
        if cause.downcast_ref::<Elapsed>().is_some() {
            return Ok(());
        }

        cause = cause
            .source()
            .ok_or("HTTPS-record deadline discarded its typed Elapsed cause")?;
    }
}

#[tokio::test(start_paused = true)]
async fn a_completed_operation_retains_its_typed_inner_failure() -> TestResult<()> {
    let error = bounded(async { Err(Box::new(InnerFailure) as Box<dyn Error + Send + Sync>) })
        .await
        .err()
        .ok_or("failed HTTPS-record operation completed successfully")?;

    assert!(error.downcast_ref::<InnerFailure>().is_some());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_completed_operation_is_accepted_before_the_deadline() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
