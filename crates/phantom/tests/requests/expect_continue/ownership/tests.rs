use std::{error::Error, future::Future, pin::Pin};

use phantom::{RequestError, RequestErrorKind};
use tokio::{sync::oneshot, task::Id};

use super::super::{TestResult, http1_continue, http2_continue, http3};
use super::Control;
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};
use fixture::Fixture;

mod fixture;

#[derive(Clone, Copy)]
enum Case {
    Http1,
    Http2,
    Http3,
}

impl Case {
    fn caller(self, control: Control) -> Pin<Box<dyn Future<Output = TestResult>>> {
        match self {
            Self::Http1 => Box::pin(http1_continue(Some(control))),
            Self::Http2 => Box::pin(http2_continue(Some(control))),
            Self::Http3 => Box::pin(http3::http3_continue(Some(control))),
        }
    }
}

enum Exit {
    Drop,
    Deadline,
}

#[tokio::test]
async fn dropping_http1_caller_destroys_its_original_pending_peer() -> TestResult {
    pending(Case::Http1, Exit::Drop).await
}

#[tokio::test]
async fn http1_deadline_retains_elapsed_and_destroys_its_original_peer() -> TestResult {
    pending(Case::Http1, Exit::Deadline).await
}

#[tokio::test]
async fn http1_input_error_retains_its_original_completed_peer_cause() -> TestResult {
    completed(Case::Http1).await
}

#[tokio::test]
async fn queued_http1_setup_destroys_its_original_peer_on_resume_error() -> TestResult {
    queued(Case::Http1).await
}

#[tokio::test]
async fn dropping_http2_caller_destroys_its_original_pending_peer() -> TestResult {
    pending(Case::Http2, Exit::Drop).await
}

#[tokio::test]
async fn http2_deadline_retains_elapsed_and_destroys_its_original_peer() -> TestResult {
    pending(Case::Http2, Exit::Deadline).await
}

#[tokio::test]
async fn http2_input_error_retains_its_original_completed_peer_cause() -> TestResult {
    completed(Case::Http2).await
}

#[tokio::test]
async fn queued_http2_setup_destroys_its_original_peer_on_resume_error() -> TestResult {
    queued(Case::Http2).await
}

#[tokio::test]
async fn dropping_http3_caller_destroys_its_original_pending_peer() -> TestResult {
    pending(Case::Http3, Exit::Drop).await
}

#[tokio::test]
async fn http3_deadline_retains_elapsed_and_destroys_its_original_peer() -> TestResult {
    pending(Case::Http3, Exit::Deadline).await
}

#[tokio::test]
async fn http3_input_error_retains_its_original_completed_peer_cause() -> TestResult {
    completed(Case::Http3).await
}

#[tokio::test]
async fn queued_http3_setup_destroys_its_original_peer_on_resume_error() -> TestResult {
    queued(Case::Http3).await
}

async fn pending(case: Case, exit: Exit) -> TestResult {
    let (control, mut fixture) = Fixture::new(None);
    let mut caller = case.caller(control);
    let preparation = fixture.start(case, &mut caller).await;

    let target = match preparation {
        Err(error) => {
            drop(caller);
            Err(error)
        }
        Ok(()) => match exit {
            Exit::Drop => {
                drop(caller);
                fixture.exited(None).await
            }
            Exit::Deadline => {
                let result = caller.await;

                let destruction = fixture.exited(None).await;

                deadline_target(result, destruction)
            }
        },
    };

    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

async fn completed(case: Case) -> TestResult {
    let (control, mut fixture) = Fixture::new(Some("https://127.0.0.1/invalid uri"));
    let mut caller = case.caller(control);
    let target = async {
        fixture.start(case, &mut caller).await?;

        let id = fixture.foreign_abort().await?;

        fixture.resume()?;

        let result = caller.as_mut().await;
        completed_target(result, id)
    }
    .await;

    drop(caller);

    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

async fn queued(case: Case) -> TestResult {
    let (control, mut fixture) = Fixture::new(None);
    let mut caller = case.caller(control);
    let preparation = fixture.queued(case, &mut caller).await;

    let target = match preparation {
        Err(error) => {
            drop(caller);
            Err(error)
        }
        Ok(setup) => match fixture.close_resume() {
            Err(error) => {
                drop(caller);
                Err(error)
            }
            Ok(()) => {
                let result = caller.await;

                match resume_target(result) {
                    Ok(()) => fixture.exited(Some(&setup)).await,
                    Err(error) => Err(error),
                }
            }
        },
    };

    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

fn deadline_target(result: TestResult, destruction: TestResult) -> TestResult {
    match result {
        Err(error)
            if error.downcast_ref::<FixtureDeadline>().is_some()
                && error.to_string() == "expect-continue test exceeded its deadline"
                && error
                    .source()
                    .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()) =>
        {
            match destruction {
                Ok(()) => Ok(()),
                Err(target) => finish_with_cleanup(Err(error), Err(target)),
            }
        }
        result => finish_with_cleanup(
            finish_with_cleanup(
                Err("original expect-continue Elapsed cause missing".into()),
                result,
            ),
            destruction,
        ),
    }
}

fn completed_target(result: TestResult, id: Id) -> TestResult {
    let error = result
        .err()
        .ok_or("invalid request unexpectedly succeeded")?;

    if !original_uri(error.as_ref()) {
        return finish_with_cleanup(
            Err(error),
            Err("actual InvalidUri parser source missing".into()),
        );
    }

    if !original_cancel(error.as_ref(), id) {
        return finish_with_cleanup(
            Err(error),
            Err("original completed peer cancellation cause missing".into()),
        );
    }

    Ok(())
}

fn original_uri(error: &(dyn Error + 'static)) -> bool {
    if let Some(error) = error.downcast_ref::<RequestError>() {
        return error.kind() == RequestErrorKind::InvalidUri
            && error
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>());
    }

    error
        .downcast_ref::<FixtureFailures>()
        .is_some_and(|errors| {
            original_uri(errors.primary.as_ref()) || original_uri(errors.cleanup.as_ref())
        })
}

fn original_cancel(error: &(dyn Error + 'static), id: Id) -> bool {
    if let Some(error) = error.downcast_ref::<tokio::task::JoinError>() {
        return error.is_cancelled() && error.id() == id;
    }

    error
        .downcast_ref::<FixtureFailures>()
        .is_some_and(|errors| {
            original_cancel(errors.primary.as_ref(), id)
                || original_cancel(errors.cleanup.as_ref(), id)
        })
}

fn resume_target(result: TestResult) -> TestResult {
    match result {
        Err(error) if error.is::<oneshot::error::RecvError>() => Ok(()),
        result => finish_with_cleanup(Err("actual queued resume RecvError missing".into()), result),
    }
}
