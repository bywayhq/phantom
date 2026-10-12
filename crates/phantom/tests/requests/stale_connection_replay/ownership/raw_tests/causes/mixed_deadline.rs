use std::error::Error;

use tokio::time::{Instant, error::Elapsed};

use super::super::super::super::bounded_until;
use super::super::super::mixed_deadline_tests::HeldRequest;
use super::super::super::raw_fixture::{Protocol, RawFixture};
use super::super::super::{TEST_TIMEOUT, complete};
use super::TestResult;
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn raw_original_deadline_retains_the_actual_completed_serving_cause() -> TestResult {
    let mut fixture = RawFixture::completed_fault(Protocol::Plain).await?;
    let mut held = None;
    let mut held_pending_before_deadline = false;

    let observed = async {
        fixture.take_priming_caller()??;

        held = Some(HeldRequest::spawn().await?);
        let address = held.as_ref().ok_or("raw mixed held peer missing")?.address;
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = Some(fixture.take_server()?);

        let caller = bounded_until(deadline, async {
            let request = fixture.held_request(address);
            tokio::pin!(request);

            tokio::select! {
                result = &mut request => {
                    result?;
                    return Err("raw mixed caller completed before its held Pending prerequisite".into());
                }
                result = held.as_mut().ok_or("raw mixed held peer missing during caller")?.wait_pending() => {
                    result?;
                    held_pending_before_deadline = true;
                }
            }

            request.await
        })
        .await;

        let error = complete(&mut server, caller, deadline)
            .await
            .err()
            .ok_or("raw mixed caller escaped its original deadline")?;

        let checked = async {
            if !held_pending_before_deadline {
                return Err("raw mixed held Pending was not observed inside the original deadline".into());
            }

            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("raw mixed original deadline and completed serving cause were not both retained")?;

            let deadline = failures.primary
                .downcast_ref::<FixtureDeadline>()
                .ok_or("raw mixed original deadline type changed")?;

            if deadline.to_string() != "stale-connection replay test exceeded its deadline" {
                return Err("raw mixed original deadline message changed".into());
            }

            if !deadline
                .source()
                .is_some_and(|source| source.is::<Elapsed>())
            {
                return Err("raw mixed original Elapsed cause was lost".into());
            }

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

    let original_cleanup = fixture.backup().await;
    let held_cleanup = match held {
        Some(held) => held.finish().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(original_cleanup, held_cleanup);
    finish_with_cleanup(observed, cleanup)
}
