use std::{error::Error, fmt, future::pending};

use tokio::time::error::Elapsed;

use super::bounded;
use crate::support::tls::TestResult;

#[derive(Debug)]
struct DeadlineControlFailure;

impl fmt::Display for DeadlineControlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deadline control failed")
    }
}

impl Error for DeadlineControlFailure {}

#[tokio::test(start_paused = true)]
async fn the_actual_deadline_retains_elapsed_as_a_typed_source() -> TestResult<()> {
    let error = bounded(pending::<TestResult<()>>())
        .await
        .err()
        .ok_or("pending deadline control completed")?;
    assert!(
        error
            .to_string()
            .contains("Alt-Svc persistence integration test exceeded its deadline")
    );

    let mut cause: &(dyn Error + 'static) = error.as_ref();
    loop {
        if cause.downcast_ref::<Elapsed>().is_some() {
            return Ok(());
        }

        cause = cause
            .source()
            .ok_or("deadline discarded its typed Elapsed cause")?;
    }
}

#[tokio::test(start_paused = true)]
async fn the_deadline_preserves_a_completed_typed_failure() -> TestResult<()> {
    let error =
        bounded(async { Err(Box::new(DeadlineControlFailure) as Box<dyn Error + Send + Sync>) })
            .await
            .err()
            .ok_or("failed deadline control completed successfully")?;

    assert!(error.downcast_ref::<DeadlineControlFailure>().is_some());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_deadline_accepts_a_completed_success() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
