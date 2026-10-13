use std::{error::Error, fmt};

use super::{TEST_TIMEOUT, TestResult, bounded};

#[derive(Debug)]
struct OperationFailure;

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("field-order operation failed")
    }
}

impl Error for OperationFailure {}

#[tokio::test(start_paused = true)]
async fn the_actual_field_order_bound_retains_elapsed_and_context() -> TestResult<()> {
    let mut operation = Box::pin(bounded(std::future::pending()));
    assert!(futures_util::poll!(&mut operation).is_pending());
    tokio::time::advance(TEST_TIMEOUT).await;

    let error = operation
        .await
        .err()
        .ok_or("field-order deadline did not expire")?;
    assert!(error.to_string().contains("test timed out"));
    let mut source: &(dyn Error + 'static) = error.as_ref();
    while !source.is::<tokio::time::error::Elapsed>() {
        source = source
            .source()
            .ok_or("field-order deadline lost its actual Elapsed")?;
    }
    Ok(())
}

#[tokio::test]
async fn the_field_order_bound_retains_an_inner_typed_failure() -> TestResult<()> {
    let error = bounded(async { Err(OperationFailure.into()) })
        .await
        .err()
        .ok_or("field-order inner failure was accepted")?;
    assert!(error.downcast_ref::<OperationFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn the_field_order_bound_accepts_a_ready_operation() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
