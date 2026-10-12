use std::{error::Error, sync::atomic::Ordering};

use phantom::{Client, HttpProtocol, RequestError, RequestErrorKind};
use tokio::{task::JoinError, time::error::Elapsed};

use super::{Mode, TestResult, collect_body, complete, completed, partial_response};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn raw_owner_drop_closes_the_actual_partial_total_body_peer() -> TestResult {
    let (mut server, _client, mut body, mut observation) = partial_response(Mode::Healthy).await?;

    drop(server.take());

    let observed = async {
        observation
            .closed(
                &mut body,
                "total-body destruction after raw owner Drop timed out",
                "total-body peer closure after raw owner Drop timed out",
            )
            .await?;

        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut body)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn caller_failure_closes_the_actual_partial_total_body_peer() -> TestResult {
    let (mut server, client, mut body, mut observation) = partial_response(Mode::Healthy).await?;

    let observed = async {
        let error = complete(&mut server, invalid_uri(&client))
            .await
            .err()
            .ok_or("invalid URI succeeded")?;

        let validation = async {
            caller_cause(error.as_ref())?;

            observation
                .closed(
                    &mut body,
                    "total-body destruction after caller failure timed out",
                    "total-body peer closure after caller failure timed out",
                )
                .await?;

            observation.no_backup()
        }
        .await;

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut body)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_partial_response_write_failure() -> TestResult {
    let (mut server, _client, _body, mut observation) =
        partial_response(Mode::FailPartialWrite).await?;

    let observed = async {
        observation
            .wait("total-body write fault consumption timed out", |state| {
                state.partial_written && state.fault_taken && state.destroyed
            })
            .await?;

        completed(&server, "total-body write-fault task completion timed out").await?;

        let error = complete(&mut server, async { Ok(()) })
            .await
            .err()
            .ok_or("actual total-body write failure was discarded")?;

        let validation = observation
            .serving_cause(error.as_ref())
            .and_then(|()| observation.no_backup());

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_caller_and_completed_total_body_errors() -> TestResult {
    let (mut server, client, _body, mut observation) =
        partial_response(Mode::FailPartialWrite).await?;

    let observed = async {
        observation
            .wait(
                "total-body combined write-fault prerequisite timed out",
                |state| state.partial_written && state.fault_taken && state.destroyed,
            )
            .await?;

        completed(
            &server,
            "total-body combined original task completion timed out",
        )
        .await?;

        let error = complete(&mut server, invalid_uri(&client))
            .await
            .err()
            .ok_or("invalid URI succeeded")?;

        let validation = (|| {
            let caller = match error.downcast_ref::<FixtureFailures>() {
                Some(failures) => failures.primary.as_ref(),
                None => error.as_ref(),
            };

            caller_cause(caller)?;

            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("actual total-body caller and serving errors were not both retained")?;
            observation.serving_cause(failures.cleanup.as_ref())?;

            observation.no_backup()
        })();

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_completed_foreign_cancellation() -> TestResult {
    let (mut server, _client, _body, mut observation) = partial_response(Mode::Healthy).await?;

    let observed = async {
        let original = server.as_ref().ok_or("original total-body task missing")?;
        let id = original.id();
        original.abort_handle().abort();

        completed(
            &server,
            "total-body foreign-cancellation completion timed out",
        )
        .await?;

        let error = complete(&mut server, async { Ok(()) })
            .await
            .err()
            .ok_or("actual completed foreign cancellation was discarded")?;

        let validation = (|| {
            let join = error
                .downcast_ref::<JoinError>()
                .ok_or("original total-body JoinError type lost")?;

            if !join.is_cancelled() || join.id() != id {
                return Err("original total-body cancellation or task identity changed".into());
            }

            observation.no_backup()
        })();

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn body_watchdog_retains_its_actual_elapsed_cause() -> TestResult {
    let (mut server, _client, body, mut observation) = partial_response(Mode::Healthy).await?;

    let observed = async {
        let error = collect_body(body, Some(&observation))
            .await
            .err()
            .ok_or("actual held total body escaped its original watchdog")?;

        let validation = (|| {
            if !observation.collect_pending.load(Ordering::Acquire) {
                return Err("actual total-body collection did not enter Pending".into());
            }

            if error.to_string() != "response body did not observe its total deadline" {
                return Err("original total-body watchdog message changed".into());
            }

            if !error.is::<Elapsed>()
                && !error.source().is_some_and(|source| source.is::<Elapsed>())
            {
                return Err("original total-body Elapsed cause was lost".into());
            }

            observation.no_backup()
        })();

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn body_watchdog_failure_destroys_the_actual_partial_response_worker() -> TestResult {
    let (mut server, _client, body, mut observation) = partial_response(Mode::Healthy).await?;

    let observed = async {
        let error = complete(&mut server, async {
            collect_body(body, Some(&observation)).await??;
            Ok(())
        })
        .await
        .err()
        .ok_or("actual held total body escaped its original watchdog")?;

        let validation = async {
            if !observation.collect_pending.load(Ordering::Acquire) {
                return Err("actual total-body collection did not enter Pending".into());
            }

            if error.to_string() != "response body did not observe its total deadline" {
                return Err("original total-body watchdog message changed".into());
            }

            observation
                .wait(
                    "total-body destruction after watchdog failure timed out",
                    |state| state.destroyed,
                )
                .await?;

            observation.no_backup()
        }
        .await;

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn explicit_backup_collects_the_actual_partial_response_worker() -> TestResult {
    let (mut server, _client, mut body, mut observation) = partial_response(Mode::Healthy).await?;

    let observed = observation.no_backup();
    let backup = observation.backup(&mut server, Some(&mut body)).await;

    let observed = observed.and_then(|()| {
        if server.is_some() {
            return Err("explicit backup retained the original total-body join owner".into());
        }

        Ok(())
    });

    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn body_watchdog_keeps_the_actual_incomplete_body_failure() -> TestResult {
    let (mut server, _client, body, mut observation) =
        partial_response(Mode::FailPartialWrite).await?;

    let observed = async {
        observation
            .wait(
                "total-body typed-body-failure write prerequisite timed out",
                |state| state.partial_written && state.fault_taken && state.destroyed,
            )
            .await?;

        completed(
            &server,
            "total-body typed-body-failure task completion timed out",
        )
        .await?;

        let error = collect_body(body, Some(&observation))
            .await?
            .err()
            .ok_or("actual incomplete total body completed successfully")?;

        let validation = (|| {
            if error.kind() != RequestErrorKind::Http1
                || error.protocol() != Some(HttpProtocol::Http1)
                || error.source().is_none()
            {
                return Err("original total-body operation failure type or source changed".into());
            }

            observation.no_backup()
        })();

        match validation {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error.into())),
        }
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    let backup = match backup {
        Err(error) => match observation.serving_cause(error.as_ref()) {
            Ok(()) => Ok(()),
            Err(validation) => finish_with_cleanup(Err(validation), Err(error)),
        },
        Ok(()) => Err("explicit backup lost the expected original write failure".into()),
    };

    finish_with_cleanup(observed, backup)
}

async fn invalid_uri(client: &Client) -> TestResult {
    let _response = client
        .get(HttpProtocol::Http1, "https://127.0.0.1/invalid uri")?
        .send()
        .await?;

    Ok(())
}

fn caller_cause(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("original total-body caller type changed")?;

    if request.kind() != RequestErrorKind::InvalidUri {
        return Err("original total-body caller kind changed".into());
    }

    if !request
        .source()
        .is_some_and(|source| source.is::<http::uri::InvalidUri>())
    {
        return Err("original total-body invalid URI source lost".into());
    }

    Ok(())
}
