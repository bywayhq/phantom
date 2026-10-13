use super::*;

use crate::{
    http3_early_data::relay_outcomes::{RelayBackup, exchange, pending_front},
    support::tunnel_proxy::finish_with_cleanup,
};

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_hello_sniffer_releases_its_actual_pending_receiver() -> TestResult<()> {
    let mut backup = RelayBackup::new();
    let result: TestResult<()> = async {
        let target = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let client = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let sniffer = HelloSniffer::spawn_observed(
            target.local_addr()?,
            Some(Arc::clone(&backup.observation)),
        )
        .await?;
        backup.register(sniffer.task.abort_handle());
        let address = sniffer.address;

        let upstream = exchange(&client, &target, address).await?;
        pending_front(&backup.observation).await?;
        if !sniffer.hellos().is_empty() || sniffer.task.is_finished() {
            return Err("literal UDP sniffer prerequisites were not retained".into());
        }

        drop(sniffer);
        timeout(Duration::from_secs(2), async {
            while !backup.observation.front.destroyed.load(Ordering::SeqCst)
                || !backup.observation.reply.destroyed.load(Ordering::SeqCst)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let _front = phantom_testkit::udp::bind_tokio(address)?;
        let _reply = phantom_testkit::udp::bind_tokio(upstream)?;

        Ok(())
    }
    .await;
    let cleanup = backup.finish().await;
    finish_with_cleanup(result, cleanup)
}
