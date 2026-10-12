use std::{
    error::Error,
    future::{Future, poll_fn},
    task::Poll,
};

use phantom::{RequestError, RequestErrorKind};
use tokio::time::{Instant, error::Elapsed};

use super::super::bounded_until;
use super::raw_fixture::{Protocol, RawFixture};
use super::{TEST_TIMEOUT, TestResult, complete};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn raw_plain_caller_drop_closes_the_actual_primed_socket() -> TestResult {
    caller_drop(Protocol::Plain).await
}

#[tokio::test]
async fn raw_tls_caller_drop_closes_the_actual_primed_socket() -> TestResult {
    caller_drop(Protocol::Tls).await
}

async fn caller_drop(protocol: Protocol) -> TestResult {
    let mut fixture = RawFixture::pending(protocol).await?;

    let observed = async {
        let server = fixture.take_server()?;

        {
            let mut caller = Box::pin(async {
                let deadline = Instant::now() + TEST_TIMEOUT;
                let mut server = Some(server);

                let caller = bounded_until(deadline, fixture.waiting_caller()).await;

                complete(&mut server, caller, deadline).await
            });

            poll_fn(|context| match caller.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(Ok(())),
                Poll::Ready(Ok(_)) => Poll::Ready(Err(
                    "actual raw caller completed before the Drop prerequisite".into(),
                )),
                Poll::Ready(Err(original)) => Poll::Ready(finish_with_cleanup(
                    Err("actual raw caller failed before the Drop prerequisite".into()),
                    Err(original),
                )),
            })
            .await?;
        }

        fixture
            .closed(
                "raw stale destruction after caller Drop exceeded its deadline",
                "raw stale socket closure after caller Drop exceeded its deadline",
            )
            .await?;
        fixture.no_backup()
    }
    .await;

    let backup = fixture.backup().await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn raw_caller_failure_closes_the_actual_primed_socket() -> TestResult {
    let mut fixture = RawFixture::pending(Protocol::Plain).await?;

    let observed = async {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let caller = bounded_until(deadline, fixture.invalid_uri()).await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw invalid URI succeeded")?;

        let checked = async {
            caller_cause(error.as_ref())?;

            fixture
                .closed(
                    "raw stale destruction after caller failure exceeded its deadline",
                    "raw stale socket closure after caller failure exceeded its deadline",
                )
                .await?;
            fixture.no_backup()
        }
        .await;

        match checked {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = fixture.backup().await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn raw_tls_original_deadline_closes_the_actual_primed_socket() -> TestResult {
    let mut fixture = RawFixture::pending(Protocol::Tls).await?;

    let observed = async {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);
        let mut caller_entered_pending = false;

        let caller = bounded_until(deadline, async {
            let mut caller = Box::pin(fixture.waiting_caller());

            poll_fn(|context| {
                let result = caller.as_mut().poll(context);
                if result.is_pending() {
                    caller_entered_pending = true;
                }

                result
            })
            .await?;

            TestResult::Ok(())
        })
        .await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw TLS caller escaped its original deadline")?;

        let checked =
            async {
                if !caller_entered_pending {
                    return Err(
                        "actual raw TLS caller did not enter Pending inside its original deadline"
                            .into(),
                    );
                }

                let deadline = error
                    .downcast_ref::<FixtureDeadline>()
                    .ok_or("actual raw TLS original deadline type changed")?;

                if deadline.to_string() != "stale-connection replay test exceeded its deadline" {
                    return Err("actual raw TLS original deadline message changed".into());
                }

                if !deadline
                    .source()
                    .is_some_and(|source| source.is::<Elapsed>())
                {
                    return Err("actual raw TLS original Elapsed was lost".into());
                }

                fixture.closed(
                "raw stale destruction after original TLS deadline exceeded its deadline",
                "raw stale socket closure after original TLS deadline exceeded its deadline",
            ).await?;
                fixture.no_backup()
            }
            .await;

        match checked {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = fixture.backup().await;
    finish_with_cleanup(observed, backup)
}

fn caller_cause(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("actual raw caller request error type changed")?;

    if request.kind() != RequestErrorKind::InvalidUri {
        return Err("actual raw caller InvalidUri kind changed".into());
    }

    if !request
        .source()
        .is_some_and(|source| source.is::<http::uri::InvalidUri>())
    {
        return Err("actual raw caller original URI source was lost".into());
    }

    Ok(())
}

mod causes;
