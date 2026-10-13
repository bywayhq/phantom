use std::error::Error;

use tokio::{
    task::{Id, JoinError},
    time::Instant,
};

use super::super::super::bounded_until;
use super::super::raw_fixture::{Protocol, RawFixture};
use super::super::{TEST_TIMEOUT, complete};
use super::{TestResult, caller_cause};
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn raw_completion_retains_the_actual_tls_prime_flush_failure() -> TestResult {
    let mut fixture = RawFixture::completed_fault(Protocol::Tls).await?;

    let observed = async {
        let caller = fixture.take_priming_caller()?;
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw TLS prime flush failure was discarded")?;

        let checked = async {
            fixture.serving_cause(error.as_ref())?;
            fixture
                .destroyed("raw TLS flush fault destruction exceeded its deadline")
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
async fn raw_caller_failure_retains_the_actual_completed_serving_cause() -> TestResult {
    let mut fixture = RawFixture::completed_fault(Protocol::Plain).await?;

    let observed = async {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let caller = bounded_until(deadline, fixture.invalid_uri()).await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw invalid URI succeeded")?;

        let checked = async {
            let primary = error
                .downcast_ref::<FixtureFailures>()
                .map_or(error.as_ref(), |failures| failures.primary.as_ref());

            caller_cause(primary)?;

            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("actual raw caller and completed serving causes were not both retained")?;

            fixture.serving_cause(failures.cleanup.as_ref())?;
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
async fn raw_caller_failure_retains_the_finished_foreign_cancellation_and_id() -> TestResult {
    let mut fixture = RawFixture::pending(Protocol::Plain).await?;

    let observed = async {
        let id = fixture.original_id()?;
        fixture.abort_original()?;
        fixture.wait_finished().await?;

        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let caller = bounded_until(deadline, fixture.invalid_uri()).await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw invalid URI succeeded")?;

        let checked = async {
            let primary = error
                .downcast_ref::<FixtureFailures>()
                .map_or(error.as_ref(), |failures| failures.primary.as_ref());

            caller_cause(primary)?;

            let failures = error.downcast_ref::<FixtureFailures>().ok_or(
                "actual raw caller and finished foreign cancellation were not both retained",
            )?;

            foreign_cause(failures.cleanup.as_ref(), id)?;
            fixture
                .closed(
                    "raw finished foreign cancellation destruction exceeded its deadline",
                    "raw finished foreign cancellation socket closure exceeded its deadline",
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
async fn raw_completion_retains_the_finished_foreign_cancellation_and_id() -> TestResult {
    let mut fixture = RawFixture::pending_client(Protocol::Plain).await?;

    let observed = async {
        let id = fixture.original_id()?;
        fixture.abort_original()?;
        fixture.wait_finished().await?;

        let caller = fixture.take_priming_caller()?;
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("actual raw finished foreign cancellation was discarded")?;

        let checked = async {
            foreign_cause(error.as_ref(), id)?;
            fixture
                .destroyed(
                    "raw healthy caller foreign cancellation destruction exceeded its deadline",
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
async fn explicit_raw_backup_collects_the_original_primed_plain_worker() -> TestResult {
    let mut fixture = RawFixture::pending(Protocol::Plain).await?;

    let observed = fixture.no_backup();
    let backup = fixture.backup().await;
    finish_with_cleanup(observed, backup)
}

fn foreign_cause(error: &(dyn Error + Send + Sync + 'static), id: Id) -> TestResult {
    let join = error
        .downcast_ref::<JoinError>()
        .ok_or("actual raw foreign JoinError type was lost")?;

    if !join.is_cancelled() || join.id() != id {
        return Err("actual raw foreign cancellation identity changed".into());
    }

    Ok(())
}

mod mixed_deadline;
