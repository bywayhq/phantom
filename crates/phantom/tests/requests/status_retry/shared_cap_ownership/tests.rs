use std::{
    error::Error,
    future::{Future, poll_fn},
    sync::atomic::Ordering,
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestError, RequestErrorKind};
use tokio::{
    task::{JoinError, yield_now},
    time::{Instant, error::Elapsed, timeout},
};

use super::{
    Mode, OBSERVATION_LIMIT, Observation, TestResult, collect_server, complete, pending,
    plain_builder, start_server,
};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn handle_drop_closes_the_actual_pending_shared_cap_socket() -> TestResult {
    let (_, server, mut stream, mut observation) = pending().await?;

    drop(server);
    let observed = observation
        .closed(
            &mut stream,
            "shared-cap server destruction after handle Drop exceeded its deadline",
            "shared-cap socket closure after handle Drop exceeded its deadline",
        )
        .await;
    assert!(
        !observation
            .state
            .borrow()
            .backup_requested
            .load(Ordering::Acquire)
    );

    let backup = observation.backup_stop(&mut stream).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn caller_failure_closes_the_actual_pending_shared_cap_socket() -> TestResult {
    let (_, server, mut stream, mut observation) = pending().await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let error = complete(deadline, server, invalid_uri())
        .await
        .err()
        .ok_or("invalid URI succeeded")?;
    caller_cause(error.as_ref())?;

    let observed = observation
        .closed(
            &mut stream,
            "shared-cap server destruction after caller failure exceeded its deadline",
            "shared-cap socket closure after caller failure exceeded its deadline",
        )
        .await;
    assert!(
        !observation
            .state
            .borrow()
            .backup_requested
            .load(Ordering::Acquire)
    );

    let backup = observation.backup_stop(&mut stream).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn completion_retains_the_actual_shared_cap_prime_flush_error() -> TestResult {
    let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
    let (address, server) = start_server(Some(control)).await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let result = complete(deadline, server, prime_request(address)).await;
    observation
        .wait(
            "shared-cap prime flush fault consumption and destruction exceeded its deadline",
            |state| state.flushed && state.fault_taken && state.destroyed,
        )
        .await?;

    let error = result
        .err()
        .ok_or("shared-cap prime flush error was discarded")?;
    observation.serving_cause(error.as_ref())
}

#[tokio::test]
async fn explicit_backup_abort_closes_the_actual_pending_shared_cap_socket() -> TestResult {
    let (_, server, mut stream, mut observation) = pending().await?;

    observation.backup_stop(&mut stream).await?;
    assert!(
        observation
            .state
            .borrow()
            .backup_requested
            .load(Ordering::Acquire)
    );

    let result = timeout(OBSERVATION_LIMIT, server)
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("shared-cap backup join exceeded its deadline", elapsed)
        })?;
    assert!(matches!(result, Err(error) if error.is_cancelled()));
    Ok(())
}

#[tokio::test]
async fn completion_retains_the_actual_caller_and_completed_shared_cap_errors() -> TestResult {
    let (control, mut observation) = Observation::control(Mode::FailPrimeFlush);
    let (address, server) = start_server(Some(control)).await?;

    prime_request(address).await?;
    observation
        .wait(
            "shared-cap completed prime flush fault prerequisite exceeded its deadline",
            |state| state.flushed && state.fault_taken && state.destroyed,
        )
        .await?;

    timeout(OBSERVATION_LIMIT, async {
        while !server.is_finished() {
            yield_now().await;
        }
    })
    .await
    .map_err(|elapsed| {
        FixtureDeadline::new(
            "shared-cap original server completion prerequisite exceeded its deadline",
            elapsed,
        )
    })?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let error = complete(deadline, server, invalid_uri())
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
        .ok_or("shared-cap caller and completed serving failure were not both retained")?;
    observation.serving_cause(failures.cleanup.as_ref())
}

#[tokio::test]
async fn exchange_deadline_closes_the_actual_pending_shared_cap_socket() -> TestResult {
    let (address, server, mut stream, mut observation) = pending().await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let error = complete(deadline, server, prime_request(address))
        .await
        .err()
        .ok_or("blocked shared-cap exchange succeeded")?;
    error
        .downcast_ref::<Elapsed>()
        .ok_or("original shared-cap exchange deadline was lost")?;

    let observed = observation
        .closed(
            &mut stream,
            "shared-cap server destruction after exchange deadline exceeded its deadline",
            "shared-cap socket closure after exchange deadline exceeded its deadline",
        )
        .await;
    assert!(
        !observation
            .state
            .borrow()
            .backup_requested
            .load(Ordering::Acquire)
    );

    let backup = observation.backup_stop(&mut stream).await;
    finish_with_cleanup(observed, backup)
}

#[tokio::test]
async fn caller_deadline_retains_the_completed_shared_cap_flush_error() -> TestResult {
    let (control, mut failed_observation) = Observation::control(Mode::FailPrimeFlush);
    let (failed_address, server) = start_server(Some(control)).await?;
    let mut failed_server = Some(server);
    let held = pending().await;
    let (held_address, mut held_server, mut stream, mut observation) = match held {
        Ok(held) => held,
        Err(error) => {
            let cleanup = collect_server(
                failed_server
                    .as_mut()
                    .ok_or("original failed server missing")?,
                true,
            )
            .await
            .map(|_| ());
            return finish_with_cleanup(Err(error), cleanup);
        }
    };

    let observed = async {
        prime_request(failed_address).await?;

        failed_observation
            .wait(
                "shared-cap deadline completed flush fault prerequisite exceeded its deadline",
                |state| state.flushed && state.fault_taken && state.destroyed,
            )
            .await?;

        timeout(OBSERVATION_LIMIT, async {
            while !failed_server
                .as_ref()
                .ok_or("original failed server missing")?
                .is_finished()
            {
                yield_now().await;
            }
            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "shared-cap deadline original failed server completion exceeded its deadline",
                elapsed,
            )
        })??;

        let caller = prime_request(held_address);
        tokio::pin!(caller);
        let mut entered_pending = false;
        let caller = poll_fn(|context| {
            let result = caller.as_mut().poll(context);
            entered_pending |= result.is_pending();
            result
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = complete(
            deadline,
            failed_server
                .take()
                .ok_or("original failed server missing")?,
            caller,
        )
        .await;

        if !entered_pending {
            return Err("actual shared-cap deadline caller never entered Pending".into());
        }

        let error = result
            .err()
            .ok_or("actual shared-cap pending caller escaped its deadline")?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("shared-cap caller deadline and completed serving error were not retained")?;
        failures
            .primary
            .downcast_ref::<Elapsed>()
            .ok_or("original shared-cap caller deadline type was lost")?;
        failed_observation.serving_cause(failures.cleanup.as_ref())
    }
    .await;

    let mut cleanup = collect_server(&mut held_server, true).await.map(|_| ());
    if let Some(mut server) = failed_server.take() {
        let failed = collect_server(&mut server, true).await.map(|_| ());
        cleanup = finish_with_cleanup(cleanup, failed);
    }

    let closed = observation
        .closed(
            &mut stream,
            "shared-cap held peer destruction after deadline control exceeded its deadline",
            "shared-cap held socket closure after deadline control exceeded its deadline",
        )
        .await;
    let cleanup = finish_with_cleanup(cleanup, closed);
    let backup = observation.backup_stop(&mut stream).await;
    finish_with_cleanup(observed, finish_with_cleanup(cleanup, backup))
}

#[tokio::test]
async fn completion_retains_an_already_completed_foreign_shared_cap_cancellation() -> TestResult {
    let (_, server, mut stream, mut observation) = pending().await?;
    let abort = server.abort_handle();
    let id = abort.id();
    let mut server = Some(server);

    abort.abort();
    let observed = async {
        timeout(OBSERVATION_LIMIT, async {
            while !server
                .as_ref()
                .ok_or("original foreign-cancelled server missing")?
                .is_finished()
            {
                yield_now().await;
            }
            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "shared-cap foreign task completion prerequisite exceeded its deadline",
                elapsed,
            )
        })??;

        let deadline = Instant::now() + Duration::from_secs(10);
        let error = complete(
            deadline,
            server
                .take()
                .ok_or("original foreign-cancelled server missing")?,
            invalid_uri(),
        )
        .await
        .err()
        .ok_or("invalid URI and foreign cancellation succeeded")?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("shared-cap caller and foreign cancellation were not retained")?;
        caller_cause(failures.primary.as_ref())?;

        let cancellation = failures
            .cleanup
            .downcast_ref::<JoinError>()
            .ok_or("original foreign shared-cap JoinError type was lost")?;

        if !cancellation.is_cancelled() {
            return Err("shared-cap original foreign task failure was not cancellation".into());
        }

        if cancellation.id() != id {
            return Err("shared-cap original foreign cancellation task identity changed".into());
        }

        Ok(())
    }
    .await;

    let cleanup = if let Some(mut server) = server.take() {
        collect_server(&mut server, false).await.map(|_| ())
    } else {
        Ok(())
    };
    let closed = observation
        .closed(
            &mut stream,
            "shared-cap foreign task destruction exceeded its deadline",
            "shared-cap foreign socket closure exceeded its deadline",
        )
        .await;
    let cleanup = finish_with_cleanup(cleanup, closed);
    let backup = observation.backup_stop(&mut stream).await;
    finish_with_cleanup(observed, finish_with_cleanup(cleanup, backup))
}

async fn invalid_uri() -> TestResult {
    let client = plain_builder().build()?;

    let _response = client
        .get(HttpProtocol::Http1, "http://127.0.0.1/invalid uri")?
        .send()
        .await?;
    Ok(())
}

fn caller_cause(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("original caller type changed")?;

    if request.kind() != RequestErrorKind::InvalidUri {
        return Err("original caller kind changed".into());
    }

    if !request
        .source()
        .is_some_and(|source| source.is::<http::uri::InvalidUri>())
    {
        return Err("original invalid URI source was lost".into());
    }

    Ok(())
}

async fn prime_request(address: std::net::SocketAddr) -> TestResult {
    let client = plain_builder().build()?;

    let response = client
        .get(HttpProtocol::Http1, &format!("http://{address}/prime"))?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await?.to_bytes().as_ref(),
        b"ok"
    );
    Ok(())
}
