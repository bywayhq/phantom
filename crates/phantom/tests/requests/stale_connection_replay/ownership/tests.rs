use std::error::Error;

use phantom::{HttpProtocol, RequestError, RequestErrorKind};
use tokio::{
    task::yield_now,
    time::{error::Elapsed, timeout},
};

use super::super::{bounded, prime, replaying_client};
use super::{
    Mode, Observation, TEST_TIMEOUT, TestResult, complete, pending, spawn_single_stale_server,
};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn raw_owner_drop_closes_the_actual_primed_stale_socket() -> TestResult {
    let (_, mut server, mut stream, mut observation) = pending().await?;

    drop(server.take());
    let observed = async {
        observation
            .closed(
                &mut stream,
                "stale-replay destruction after raw owner Drop exceeded its deadline",
                "stale-replay socket closure after raw owner Drop exceeded its deadline",
            )
            .await?;
        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut stream)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn caller_failure_closes_the_actual_primed_stale_socket() -> TestResult {
    let (_, mut server, mut stream, mut observation) = pending().await?;

    let observed = async {
        let error = complete(&mut server, invalid_uri())
            .await
            .err()
            .ok_or("invalid URI succeeded")?;
        caller_cause(error.as_ref())?;

        observation
            .closed(
                &mut stream,
                "stale-replay destruction after caller failure exceeded its deadline",
                "stale-replay socket closure after caller failure exceeded its deadline",
            )
            .await?;
        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut stream)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn original_deadline_closes_the_actual_primed_stale_socket() -> TestResult {
    let (address, mut server, mut stream, mut observation) = pending().await?;

    let observed = async {
        let client = replaying_client()?;
        let error = bounded(async {
            complete(
                &mut server,
                prime(&client, &format!("http://{address}/prime")),
            )
            .await?;
            Ok(())
        })
        .await
        .err()
        .ok_or("actual held stale exchange escaped its deadline")?;

        if error.to_string() != "stale-connection replay test exceeded its deadline" {
            return Err("original stale-replay deadline message changed".into());
        }

        observation
            .closed(
                &mut stream,
                "stale-replay destruction after original deadline exceeded its deadline",
                "stale-replay socket closure after original deadline exceeded its deadline",
            )
            .await?;
        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut stream)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn original_deadline_retains_its_actual_elapsed_cause() -> TestResult {
    let (address, mut server, mut stream, mut observation) = pending().await?;

    let observed = async {
        let client = replaying_client()?;
        let error = bounded(async {
            complete(
                &mut server,
                prime(&client, &format!("http://{address}/prime")),
            )
            .await?;
            Ok(())
        })
        .await
        .err()
        .ok_or("actual held stale exchange escaped its deadline")?;

        if !error.is::<Elapsed>() && !error.source().is_some_and(|source| source.is::<Elapsed>()) {
            return Err("original stale-replay Elapsed cause was lost".into());
        }

        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, Some(&mut stream)).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn explicit_backup_collects_the_actual_primed_stale_worker() -> TestResult {
    let (_, mut server, mut stream, mut observation) = pending().await?;

    let observed = observation.no_backup();
    let backup = observation.backup(&mut server, Some(&mut stream)).await;

    let observed = observed.and_then(|()| {
        if server.is_some() {
            return Err("explicit backup retained the original stale task join owner".into());
        }

        Ok(())
    });
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_stale_prime_flush_failure() -> TestResult {
    let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
    let (address, server) = spawn_single_stale_server(Some(control)).await?;
    let mut server = Some(server);

    let observed = async {
        let client = replaying_client()?;
        let error = complete(
            &mut server,
            prime(&client, &format!("http://{address}/prime")),
        )
        .await
        .err()
        .ok_or("actual stale prime flush failure was discarded")?;

        observation
            .wait(
                "stale prime flush consumption and destruction exceeded its deadline",
                |state| state.primed && state.fault_taken && state.destroyed,
            )
            .await?;

        observation.serving_cause(error.as_ref())?;
        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_caller_and_completed_stale_errors() -> TestResult {
    let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
    let (address, server) = spawn_single_stale_server(Some(control)).await?;
    let mut server = Some(server);

    let observed = async {
        let client = replaying_client()?;
        prime(&client, &format!("http://{address}/prime")).await?;
        observation
            .wait(
                "stale completed prime flush prerequisite exceeded its deadline",
                |state| state.primed && state.fault_taken && state.destroyed,
            )
            .await?;

        timeout(TEST_TIMEOUT, async {
            while !server
                .as_ref()
                .ok_or("original stale task missing")?
                .is_finished()
            {
                yield_now().await;
            }
            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "stale original task completion prerequisite exceeded its deadline",
                elapsed,
            )
        })??;

        let error = complete(&mut server, invalid_uri())
            .await
            .err()
            .ok_or("invalid URI succeeded")?;

        let caller = match error.downcast_ref::<FixtureFailures>() {
            Some(failures) => failures.primary.as_ref(),
            None => error.as_ref(),
        };
        caller_cause(caller)?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("actual caller and completed stale worker errors were not both retained")?;
        observation.serving_cause(failures.cleanup.as_ref())?;
        observation.no_backup()
    }
    .await;

    let backup = observation.backup(&mut server, None).await;
    finish_with_cleanup(observed, backup)
}

async fn invalid_uri() -> TestResult {
    let client = replaying_client()?;

    let _response = client
        .get(HttpProtocol::Http1, "http://127.0.0.1/invalid uri")?
        .send()
        .await?;
    Ok(())
}

fn caller_cause(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("original stale caller type changed")?;

    if request.kind() != RequestErrorKind::InvalidUri {
        return Err("original stale caller kind changed".into());
    }

    if !request
        .source()
        .is_some_and(|source| source.is::<http::uri::InvalidUri>())
    {
        return Err("original stale invalid URI source lost".into());
    }

    Ok(())
}
