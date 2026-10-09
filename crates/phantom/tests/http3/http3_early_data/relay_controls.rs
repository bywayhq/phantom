use super::*;

fn socket() -> std::io::Result<UdpSocket> {
    phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())
}

async fn round_trip(
    client: &UdpSocket,
    target: &UdpSocket,
    relay: SocketAddr,
) -> TestResult<SocketAddr> {
    client.send_to(b"request", relay).await?;
    let mut bytes = [0; 64];
    let (len, upstream) = target.recv_from(&mut bytes).await?;
    assert_eq!(&bytes[..len], b"request");
    target.send_to(b"response", upstream).await?;
    let (len, from) = client.recv_from(&mut bytes).await?;
    assert_eq!(from, relay);
    assert_eq!(&bytes[..len], b"response");
    Ok(upstream)
}

async fn abort_and_join(task: JoinHandle<()>) -> TestResult<()> {
    task.abort();
    let error = task
        .await
        .err()
        .ok_or("relay owner completed before cancellation")?;
    assert!(error.is_cancelled());
    Ok(())
}

async fn reacquire(address: SocketAddr) -> TestResult<UdpSocket> {
    // These are the fixture's observed addresses, not fixed test ports.
    // Descendant cancellation may need another scheduler turn after joining
    // the front task; success requires an actual bind, not a quiet timer.
    Ok(timeout(Duration::from_secs(5), async {
        loop {
            match phantom_testkit::udp::bind_tokio(address) {
                Ok(socket) => return Ok::<_, std::io::Error>(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| "a cancelled relay still holds its observed UDP socket")??)
}

#[tokio::test]
async fn cancelling_a_delaying_relay_releases_both_observed_sockets() -> TestResult<()> {
    bounded(async {
        let target = socket()?;
        let client = socket()?;
        let (relay, task) = delaying_relay(target.local_addr()?).await?;

        let upstream = round_trip(&client, &target, relay).await?;

        abort_and_join(task).await?;
        let _front = reacquire(relay).await?;
        let _upstream = reacquire(upstream).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_a_gated_relay_releases_sockets_with_the_gate_sender_alive() -> TestResult<()> {
    bounded(async {
        let target = socket()?;
        let client = socket()?;
        let (gate, open) = tokio::sync::watch::channel(true);
        let (relay, task) = gated_relay(target.local_addr()?, open).await?;

        let upstream = round_trip(&client, &target, relay).await?;
        gate.send_replace(false);

        abort_and_join(task).await?;
        let _front = reacquire(relay).await?;
        let _upstream = reacquire(upstream).await?;
        // Retain the sender through both binds: dropping it must not be what
        // stops the downstream task and releases the sockets.
        assert!(!*gate.borrow());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_a_delayed_receiver_cancels_its_already_queued_packet() -> TestResult<()> {
    bounded(async {
        let target = socket()?;
        let client = socket()?;
        let upstream = Arc::new(socket()?);
        upstream.connect(target.local_addr()?).await?;
        let upstream_address = upstream.local_addr()?;
        let front = Arc::new(socket()?);
        let front_address = front.local_addr()?;
        let task = tokio::spawn(forward_delayed(
            Arc::clone(&upstream),
            Arc::clone(&front),
            client.local_addr()?,
        ));

        target.send_to(b"positive", upstream_address).await?;
        let mut bytes = [0; 64];
        let (len, from) = client.recv_from(&mut bytes).await?;
        assert_eq!(from, front_address);
        assert_eq!(&bytes[..len], b"positive");
        // Wait until the completed positive send releases its front clone.
        while Arc::strong_count(&front) != 2 {
            tokio::task::yield_now().await;
        }

        target.send_to(b"cancelled", upstream_address).await?;
        // The extra socket owner witnesses receipt and creation of the
        // delayed send before cancellation, rather than assuming readiness
        // after a sleep. Actual UDP delivery is checked independently below.
        while Arc::strong_count(&front) == 2 {
            tokio::task::yield_now().await;
        }
        abort_and_join(task).await?;
        drop((front, upstream));

        match timeout(RELAY_DELAY * 3, client.recv_from(&mut bytes)).await {
            Err(_) => {}
            Ok(Ok((len, _))) => {
                return Err(
                    format!("a cancelled delayed send delivered {:?}", &bytes[..len]).into(),
                );
            }
            Ok(Err(error)) => return Err(error.into()),
        }
        let _front = reacquire(front_address).await?;
        let _upstream = reacquire(upstream_address).await?;
        Ok(())
    })
    .await
}
