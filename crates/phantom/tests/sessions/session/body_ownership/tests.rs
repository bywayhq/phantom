use std::{error::Error, future::Future, pin::Pin};

use tokio::sync::oneshot;

use super::{Control, TestResult, cancelled_controlled, upload_controlled};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;
use peer_fixture::{Fixture, completed_target, deadline_target};

pub(in super::super) mod peer_fixture;

enum Body {
    Upload,
    Cancelled,
}

impl Body {
    fn caller(self, control: Control) -> Pin<Box<dyn Future<Output = TestResult<()>>>> {
        match self {
            Self::Upload => Box::pin(upload_controlled(Some(control))),
            Self::Cancelled => Box::pin(cancelled_controlled(Some(control))),
        }
    }
}

pub(in super::super) enum Exit {
    Drop,
    Deadline,
}

#[tokio::test]
async fn dropping_upload_caller_destroys_its_actual_accepted_peer() -> TestResult<()> {
    pending(Body::Upload, Exit::Drop).await
}

#[tokio::test]
async fn upload_deadline_destroys_its_actual_accepted_peer() -> TestResult<()> {
    pending(Body::Upload, Exit::Deadline).await
}

#[tokio::test]
async fn upload_input_error_retains_its_completed_original_peer_cause() -> TestResult<()> {
    completed(Body::Upload).await
}

#[tokio::test]
async fn dropping_body_reset_caller_destroys_its_actual_accepted_peer() -> TestResult<()> {
    pending(Body::Cancelled, Exit::Drop).await
}

#[tokio::test]
async fn body_reset_deadline_destroys_its_actual_accepted_peer() -> TestResult<()> {
    pending(Body::Cancelled, Exit::Deadline).await
}

#[tokio::test]
async fn body_reset_input_error_retains_its_completed_original_peer_cause() -> TestResult<()> {
    completed(Body::Cancelled).await
}

#[tokio::test]
async fn queued_setup_cleanup_destroys_the_actual_accepted_upload_peer() -> TestResult<()> {
    let (control, mut fixture) = Fixture::new(None);
    let mut caller = Body::Upload.caller(control);
    let preparation = fixture.prepare_queued(&mut caller).await;

    let target = match preparation {
        Err(error) => {
            drop(caller);
            Err(error)
        }
        Ok(setup) => match fixture.close_queued_resume() {
            Err(error) => {
                drop(caller);
                Err(error)
            }
            Ok(()) => {
                let result = fixture.start(&mut caller).await;

                drop(caller);

                match queued_caller_failure(result) {
                    Err(error) => Err(error),
                    Ok(error) => {
                        let stopped = fixture.stop().await;

                        let exited = fixture.queued_exit(&setup).await;

                        match finish_with_cleanup(stopped, exited) {
                            Ok(()) => Ok(()),
                            Err(target) => finish_with_cleanup(Err(target), Err(error)),
                        }
                    }
                }
            }
        },
    };

    let backup = fixture.backup_queued().await;
    finish_with_cleanup(target, backup)
}

async fn pending(body: Body, exit: Exit) -> TestResult<()> {
    let (control, mut fixture) = Fixture::new(None);
    let mut caller = body.caller(control);
    let preparation = fixture.start(&mut caller).await;

    let target = match preparation {
        Err(error) => {
            drop(caller);
            Err(error)
        }
        Ok(()) => match exit {
            Exit::Drop => {
                drop(caller);
                fixture
                    .exited("body peer remained live after actual caller drop")
                    .await
            }
            Exit::Deadline => {
                let result = caller.await;

                let destruction = fixture
                    .exited("body peer remained live after original deadline")
                    .await;

                deadline_target(result, destruction)
            }
        },
    };

    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

async fn completed(body: Body) -> TestResult<()> {
    let (control, mut fixture) = Fixture::new(Some("https://["));
    let mut caller = body.caller(control);
    let target = async {
        fixture.start(&mut caller).await?;

        let ids = fixture.foreign_abort()?;
        fixture.finished().await?;

        fixture.resume()?;

        let result = caller.as_mut().await;
        completed_target(result, &ids)
    }
    .await;

    drop(caller);
    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

fn queued_caller_failure(result: TestResult<()>) -> TestResult<Box<dyn Error + Send + Sync>> {
    let error = match result {
        Err(error) => error,
        Ok(()) => return Err("queued canonical caller unexpectedly succeeded".into()),
    };

    if !original_resume(error.as_ref())
        || !error
            .to_string()
            .starts_with("canonical session caller ended before its prerequisite")
    {
        return finish_with_cleanup(
            Err("actual queued caller resume failure missing".into()),
            Err(error),
        );
    }

    Ok(error)
}

fn original_resume(error: &(dyn Error + 'static)) -> bool {
    if error.is::<oneshot::error::RecvError>() {
        return true;
    }

    error
        .downcast_ref::<FixtureFailures>()
        .is_some_and(|failures| {
            original_resume(failures.primary.as_ref()) || original_resume(failures.cleanup.as_ref())
        })
}
