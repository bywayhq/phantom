//! A read marker is not a task's captured socket lifetime.

use super::*;
use crate::support::tunnel_proxy::ConnectionPeer;
use relay_observation::ReadLifetime;
use std::{future::Future, task::Poll};
use tokio::sync::oneshot;

async fn require_pending(
    future: &mut std::pin::Pin<&mut impl Future<Output = TestResult<()>>>,
) -> TestResult<()> {
    std::future::poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(result) => Poll::Ready(Err(format!(
            "abandonment was reported while a captured socket remained owned: {result:?}"
        )
        .into())),
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn read_markers_cannot_release_a_rebind_before_both_socket_owners_finish() -> TestResult<()> {
    let observation = Arc::new(RelayObservation::default());
    let front = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let reply = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let address = front.local_addr()?;
    let upstream = reply.local_addr()?;
    let (front_ready, front_seen) = tokio::sync::oneshot::channel();
    let (reply_ready, reply_seen) = tokio::sync::oneshot::channel();
    let (front_release, front_released) = oneshot::channel();
    let (reply_release, reply_released) = oneshot::channel();
    let front_observation = Arc::clone(&observation);
    let reply_observation = Arc::clone(&observation);
    let mut parent = ConnectionPeer::spawn(async move {
        // Deliberately expose the same read-guard signal before captured data
        // destruction. This controls ownership, not Windows socket timing.
        drop(ReadLifetime::front(front_observation));
        front_ready.send(()).map_err(|_| "front observer ended")?;
        front_released.await?;
        drop(front);
        TestResult::Ok(())
    });
    let mut receiver = ConnectionPeer::spawn(async move {
        drop(ReadLifetime::reply(reply_observation));
        reply_ready.send(()).map_err(|_| "reply observer ended")?;
        reply_released.await?;
        drop(reply);
        TestResult::Ok(())
    });
    let result: TestResult<()> = async {
        timeout(OBSERVATION_LIMIT, async {
            front_seen.await?;
            reply_seen.await?;
            if !observation.front.destroyed.load(Ordering::SeqCst)
                || !observation.reply.destroyed.load(Ordering::SeqCst)
                || parent.is_finished()
                || receiver.is_finished()
            {
                return Err("controlled read markers did not precede both socket owners".into());
            }
            let parent_handle = parent.abort_handle();
            let receiver_handle = receiver.abort_handle();
            let waiting = wait_for_abandonment(&parent_handle, &receiver_handle, &observation);
            tokio::pin!(waiting);
            require_pending(&mut waiting).await?;

            front_release.send(()).map_err(|_| "front owner ended")?;
            parent.join().await??;
            if !parent_handle.is_finished() || receiver_handle.is_finished() {
                return Err("only the parent socket owner should have finished".into());
            }
            require_pending(&mut waiting).await?;

            reply_release.send(()).map_err(|_| "reply owner ended")?;
            receiver.join().await??;
            waiting.await?;
            let _front = phantom_testkit::udp::bind_tokio(address)?;
            let _reply = phantom_testkit::udp::bind_tokio(upstream)?;
            TestResult::Ok(())
        })
        .await?
    }
    .await;
    let cleanup = finish_with_cleanup(parent.shutdown().await, receiver.shutdown().await);
    finish_with_cleanup(result, cleanup)
}
