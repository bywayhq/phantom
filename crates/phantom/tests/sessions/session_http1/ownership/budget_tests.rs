use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use phantom::HttpProtocol;
use tokio::{sync::watch, task::coop, time::timeout};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::tests::original_uri_failure;
use super::{ActiveBody, QueuedObservation, QueuedState, TestResult, active_body, collect_peer};

const LIMIT: Duration = Duration::from_secs(5);
const INVALID_URI: &str = "https://127.0.0.1/invalid uri";

#[tokio::test(flavor = "current_thread")]
async fn finished_foreign_peer_cancellation_survives_a_real_budget_pending_join() -> TestResult {
    let (state, mut observed) = watch::channel(QueuedState::default());
    let mut server = None;
    let mut active = None;
    let mut session = None;
    let mut original_id = None;

    let operation: TestResult = async {
        let prepared = timeout(
            LIMIT,
            active_body(Some(QueuedObservation(state)), &mut server),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("HTTP/1 active-body setup exceeded deadline", elapsed)
        })?;
        let ActiveBody {
            session: client,
            active: response,
            server: peer,
            ..
        } = prepared?;
        server = Some(peer);
        active = Some(response);
        session = Some(client);

        timeout(
            LIMIT,
            observed.wait_for(|state| state.peer_pending && !state.peer_destroyed),
        )
        .await??;
        let peer = server
            .as_ref()
            .ok_or("original active-body server missing")?;
        if peer.is_finished() {
            return Err("original active-body peer completed before foreign cancellation".into());
        }

        original_id = Some(peer.abort_handle().id());
        peer.abort();
        timeout(LIMIT, async {
            while !peer.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        timeout(LIMIT, observed.wait_for(|state| state.peer_destroyed)).await??;

        let client = session
            .as_ref()
            .ok_or("original active HTTP/1 client missing")?;
        let caller = client
            .get_with_protocol(HttpProtocol::Http1, INVALID_URI)
            .err()
            .ok_or("original invalid URI caller succeeded")?;
        original_uri_failure(&caller)?;

        // The current-thread test poll has a real finite Tokio budget.
        while coop::has_budget_remaining() {
            coop::consume_budget().await;
        }

        let peer = server
            .as_mut()
            .ok_or("original completed peer missing before budget poll")?;
        if !peer.is_finished() {
            return Err("original peer unfinished before cooperative budget poll".into());
        }

        let snapshot = poll_fn(|context| Poll::Ready(Pin::new(&mut *peer).poll(context))).await;

        match snapshot {
            Poll::Pending => collect_peer(Err(caller.into()), server.take()).await,
            Poll::Ready(joined) => {
                drop(server.take());
                let cleanup = match joined {
                    Ok(result) => result,
                    Err(error) => Err(error.into()),
                };
                let primary = finish_with_cleanup(
                    Err("original finished peer join did not reach cooperative Pending".into()),
                    Err(caller.into()),
                );

                finish_with_cleanup(primary, cleanup)
            }
        }
    }
    .await;

    let collected = collect_peer(operation, server).await;

    let primary: TestResult = (|| {
        let error = collected
            .err()
            .ok_or("original caller and foreign peer cancellation succeeded")?;
        let checked: TestResult = (|| {
            let failures = error.downcast_ref::<FixtureFailures>()
                .ok_or("completed original foreign peer cancellation was discarded after cooperative Pending")?;
            original_uri_failure(failures.primary.as_ref())?;

            let original = failures
                .cleanup
                .downcast_ref::<tokio::task::JoinError>()
                .ok_or("original foreign peer cancellation JoinError type changed")?;
            assert!(original.is_cancelled());
            assert_eq!(
                original.id(),
                original_id.ok_or("original peer task identity missing")?
            );
            Ok(())
        })();

        if let Err(check) = checked {
            return finish_with_cleanup(Err(check), Err(error));
        }

        Ok(())
    })();

    drop(active);
    drop(session);

    primary
}
