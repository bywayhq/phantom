use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    task::Poll,
};

use super::{TEST_TIMEOUT, TestResult, bounded};

#[tokio::test(start_paused = true)]
async fn expiry_keeps_the_actual_elapsed_cause() -> TestResult<()> {
    let mut operation = Box::pin(bounded(std::future::pending()));
    poll_fn(|context| {
        assert!(operation.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(TEST_TIMEOUT).await;

    let error = operation
        .await
        .err()
        .ok_or("HTTP/2 multiplex timer did not expire")?;
    assert!(
        error
            .to_string()
            .contains("HTTP/2 proxy multiplexing test exceeded its deadline")
    );
    let mut cause: &(dyn Error + 'static) = error.as_ref();
    while !cause.is::<tokio::time::error::Elapsed>() {
        cause = cause
            .source()
            .ok_or("HTTP/2 multiplex deadline lost its actual Elapsed cause")?;
    }
    Ok(())
}

#[tokio::test]
async fn an_inner_error_keeps_its_type() -> TestResult<()> {
    let error = bounded(async {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "inner multiplex failure").into())
    })
    .await
    .err()
    .ok_or("inner error disappeared")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("inner io error type disappeared")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    Ok(())
}

#[tokio::test]
async fn a_ready_operation_completes() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}
