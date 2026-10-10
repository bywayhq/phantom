use std::{error::Error, fmt};

use super::{TEST_TIMEOUT, TestResult, bounded};

#[derive(Debug)]
struct OperationFailure;

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled local SOCKS operation failed")
    }
}

impl Error for OperationFailure {}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }

        error = error.source()?;
    }
}

#[tokio::test(start_paused = true)]
async fn the_actual_local_socks_bound_keeps_elapsed_and_context() -> TestResult<()> {
    let operation = bounded(std::future::pending::<TestResult<()>>());
    tokio::pin!(operation);
    assert!(futures_util::poll!(&mut operation).is_pending());
    tokio::time::advance(TEST_TIMEOUT).await;

    let error = operation
        .await
        .err()
        .ok_or("pending local operation completed")?;
    assert!(find_source::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    assert!(
        error
            .to_string()
            .starts_with("local-DNS SOCKS5 integration test exceeded its deadline")
    );
    Ok(())
}

#[tokio::test]
async fn the_local_socks_bound_keeps_an_inner_typed_failure() -> TestResult<()> {
    let error = bounded(async { Err(Box::new(OperationFailure) as Box<dyn Error + Send + Sync>) })
        .await
        .err()
        .ok_or("failed local operation was accepted")?;

    assert!(find_source::<OperationFailure>(error.as_ref()).is_some());
    Ok(())
}

#[tokio::test]
async fn the_local_socks_bound_keeps_a_successful_operation() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
