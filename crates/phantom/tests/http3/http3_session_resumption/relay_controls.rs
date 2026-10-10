use super::*;

#[tokio::test]
async fn cancelling_a_hello_sniffer_releases_both_observed_udp_sockets() -> TestResult<()> {
    bounded(async {
        let target = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let client = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let mut sniffer = HelloSniffer::spawn(target.local_addr()?).await?;
        let address = sniffer.address;

        client.send_to(b"request", address).await?;
        let mut bytes = [0; 64];
        let (len, upstream) = target.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..len], b"request");
        target.send_to(b"response", upstream).await?;
        let (len, from) = client.recv_from(&mut bytes).await?;
        assert_eq!(from, address);
        assert_eq!(&bytes[..len], b"response");
        assert!(sniffer.hellos().is_empty());

        // Observe the same abort used by Drop and join that exact owner. The
        // real sockets must be freed while this runtime and peers stay live.
        sniffer.task.abort();
        let error = (&mut sniffer.task)
            .await
            .err()
            .ok_or("sniffer completed before cancellation")?;
        assert!(error.is_cancelled());
        drop(sniffer);

        let _front = reacquire(address).await?;
        let _upstream = reacquire(upstream).await?;
        Ok(())
    })
    .await
}

async fn reacquire(address: SocketAddr) -> TestResult<UdpSocket> {
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
    .map_err(|_| "a cancelled sniffer still holds its observed UDP socket")??)
}
