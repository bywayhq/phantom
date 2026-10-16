//! The existing SOCKS negotiation owner feeds both negotiated and exact H2.
use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use crate::{
    host_resolver::{AddressResolver, HostResolver},
    http1_or_2::Http1Or2Connection,
    tcp::{AddressFamily, AddressFamilyMemory},
    tls::test_support::{TestIdentity, TestResult, TestServerAlpn},
};

mod completed;
mod failures;
mod identity;
mod peer;
use peer::*;

#[tokio::test]
async fn negotiated_h1_retains_the_crossed_socks_backup_and_uses_only_the_claiming_body()
-> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connectors = Connectors::new(&identity, true)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::new();
        let (release, released) = oneshot::channel();
        let (claim, claimed) = oneshot::channel();
        let (quiet, was_quiet) = oneshot::channel();
        let peer = async {
            let mut first = negotiate(&listener, false).await?;
            let mut second = negotiate(&listener, false).await?;
            reply(&mut second).await?;
            let mut winner = tls(second, &acceptor).await?;
            released.await?;
            reply(&mut first).await?;
            let mut spare = tls(first, &acceptor).await?;
            let mut byte = [0];
            tokio::select! {
                biased;
                read = spare.read(&mut byte) => return Err(format!("unclaimed spare sent bytes: {read:?}").into()),
                ready = claimed => ready?,
            }
            quiet.send(()).map_err(|_| "claim owner ended")?;
            serve_h1(spare, "/current").await?;
            match winner.read(&mut byte).await {
                Ok(0) => {},
                Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof) => {},
                other => return Err(format!("unused winner received request bytes: {other:?}").into()),
            }
            TestResult::Ok(())
        };
        let caller = async {
            let (winner, slower) = connectors.connect(false, origin(&host, address.port(), false), &family).await?;
            assert!(matches!(winner, Http1Or2Connection::Http1(_)));
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            let slower = slower.ok_or("missing unfinished H1 backup")?;
            assert!(!slower.progress().has_connected());
            release.send(()).map_err(|_| "peer ended")?;
            let spare = slower.finish().await.ok_or("backup TLS failed")?;
            claim.send(()).map_err(|_| "peer ended")?;
            was_quiet.await?;
            send(&spare, "/current").await?;
            drop(spare);
            drop(winner);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}

#[tokio::test]
async fn negotiated_h2_cancels_an_unfinished_complete_socks_backup() -> TestResult<()> {
    h2_pending_canceled(false).await
}

#[tokio::test]
async fn exact_h2_cancels_an_unfinished_complete_socks_backup() -> TestResult<()> {
    h2_pending_canceled(true).await
}

async fn h2_pending_canceled(exact: bool) -> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connectors = Connectors::new(&identity, true)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::new();
        let peer = async {
            let mut first = negotiate(&listener, false).await?;
            let mut second = negotiate(&listener, false).await?;
            reply(&mut second).await?;
            let winner = tls(second, &acceptor).await?;
            // No SOCKS success reply was sent on first. H2 selection must drop it.
            closed(&mut first).await?;
            serve_h2(winner, "/winner").await
        };
        let caller = async {
            let (winner, slower) = connectors
                .connect(exact, origin(&host, address.port(), false), &family)
                .await?;
            assert!(matches!(winner, Http1Or2Connection::Http2(_)));
            assert!(slower.is_none());
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            send(&winner, "/winner").await?;
            drop(winner);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn both_h2_connectors_keep_remote_dns_out_of_family_memory_and_local_lookup() -> TestResult<()>
{
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate()?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let count = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&count);
            let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                async { Err(io::Error::other("remote target looked up locally")) }
            }));
            let connectors = Connectors::new(&identity, false)?.with_resolver(resolver)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let peer = async {
                let mut first = negotiate(&listener, true).await?;
                let mut second = negotiate(&listener, true).await?;
                reply(&mut second).await?;
                let winner = tls(second, &acceptor).await?;
                closed(&mut first).await?;
                serve_h2(winner, "/remote").await
            };
            let caller = async {
                let (winner, slower) = connectors
                    .connect(exact, origin(&host, address.port(), true), &family)
                    .await?;
                assert!(slower.is_none());
                assert_eq!(family.family(), None);
                send(&winner, "/remote").await?;
                drop(winner);
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            assert_eq!(count.load(Ordering::Relaxed), 0);
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn non_backup_policy_keeps_both_early_data_connectors_on_one_socks_tunnel() -> TestResult<()>
{
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate()?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let mut connectors = Connectors::new(&identity, true)?;
            let mut tcp = phantom_profile::browser::firefox::v157_tcp();
            tcp.address_selection = phantom_profile::TcpAddressSelection::default();
            connectors.exact = connectors.exact.with_tcp_settings(&tcp);
            connectors.negotiated = connectors.negotiated.with_tcp_settings(&tcp);
            assert!(connectors.negotiated.offers_early_data());
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let peer = async {
                let mut stream = negotiate(&listener, false).await?;
                reply(&mut stream).await?;
                let stream = tls(stream, &acceptor).await?;
                serve_h2(stream, "/legacy").await?;
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(listener.poll_accept(&mut context).is_pending());
                TestResult::Ok(())
            };
            let caller = async {
                let (winner, slower) = connectors
                    .connect(exact, origin(&host, address.port(), false), &family)
                    .await?;
                assert!(slower.is_none());
                assert_eq!(family.family(), None);
                send(&winner, "/legacy").await?;
                drop(winner);
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}

mod quiet_opening;
