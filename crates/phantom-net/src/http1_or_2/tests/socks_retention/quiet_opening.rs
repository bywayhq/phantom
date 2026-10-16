//! Public staged owners preserve the original tunnel through ordinary claims.
use super::*;
use crate::{
    http1::Http1SocksOpening, http1_or_2::Http1Or2SocksOpening, http2::Http2SocksOpening,
    tcp::SlowerConnection,
};
enum Quiet {
    H1(Http1SocksOpening),
    H2(Http2SocksOpening),
    Both(Http1Or2SocksOpening),
}
impl Quiet {
    async fn finish(self) -> TestResult<Http1Or2Connection> {
        Ok(match self {
            Self::H1(opening) => Http1Or2Connection::Http1(opening.finish().await?),
            Self::H2(opening) => Http1Or2Connection::Http2(opening.finish().await?),
            Self::Both(opening) => opening.finish().await?,
        })
    }
}
#[tokio::test]
async fn completed_socks_openings_are_quiet_until_their_original_connector_is_claimed()
-> TestResult<()> {
    for mode in 0..3 {
        timeout(WAIT, quiet_opening(mode)).await??;
    }
    Ok(())
}
async fn quiet_opening(mode: usize) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let alpn = if mode == 0 {
        TestServerAlpn::Http1
    } else {
        TestServerAlpn::H2
    };
    let acceptor = identity.acceptor(alpn)?;
    let connectors = Connectors::new(&identity, true)?;
    assert!(connectors.negotiated.offers_early_data());
    let h1 = connectors
        .negotiated
        .http1_connector(&[Box::from(&b"http/1.1"[..])])?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::new();
    let (released, release) = oneshot::channel();
    let (claim, claimed) = oneshot::channel();
    let (quiet, was_quiet) = oneshot::channel();
    let caller = async {
        let (winner, slower) = match mode {
            0 => {
                let (winner, slower) = h1
                    .open_socks_retaining(origin(&host, address.port(), false), &family)
                    .await?;
                (
                    Quiet::H1(winner),
                    slower.map(|s| {
                        SlowerConnection::new(s.progress(), async move {
                            s.finish().await.map(Quiet::H1)
                        })
                    }),
                )
            }
            1 => {
                let (winner, slower) = connectors
                    .exact
                    .open_socks_retaining(origin(&host, address.port(), false), &family)
                    .await?;
                (
                    Quiet::H2(winner),
                    slower.map(|s| {
                        SlowerConnection::new(s.progress(), async move {
                            s.finish().await.map(Quiet::H2)
                        })
                    }),
                )
            }
            _ => {
                let (winner, slower) = connectors
                    .negotiated
                    .open_socks_retaining(origin(&host, address.port(), false), &family)
                    .await?;
                (
                    Quiet::Both(winner),
                    slower.map(|s| {
                        SlowerConnection::new(s.progress(), async move {
                            s.finish().await.map(Quiet::Both)
                        })
                    }),
                )
            }
        };
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        drop(winner);
        released
            .send(())
            .map_err(|_| "peer ended before backup release")?;
        let spare = slower
            .ok_or("missing crossed SOCKS backup")?
            .finish()
            .await
            .ok_or("backup negotiation failed")?;
        claim
            .send(())
            .map_err(|_| "peer ended before quiet check")?;
        was_quiet.await?;
        let connection = spare.finish().await?;
        send(&connection, "/claimed").await?;
        drop(connection);
        TestResult::Ok(())
    };
    let peer = async {
        let mut spare = negotiate(&listener, false).await?;
        let mut winner = negotiate(&listener, false).await?;
        reply(&mut winner).await?;
        // The returned winner can be dropped before any origin byte.
        release.await?;
        closed(&mut winner).await?;
        reply(&mut spare).await?;
        let mut byte = [0];
        tokio::select! {
            biased;
            read = spare.read(&mut byte) => {
                return Err(format!("unclaimed tunnel sent origin bytes: {read:?}").into());
            }
            ready = claimed => ready?,
        }
        quiet.send(()).map_err(|_| "claimant ended")?;
        let connection = tls(spare, &acceptor).await?;
        if mode == 0 {
            serve_h1(connection, "/claimed").await?;
        } else {
            serve_h2(connection, "/claimed").await?;
        }
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(listener.poll_accept(&mut cx).is_pending());
        TestResult::Ok(())
    };
    tokio::try_join!(caller, peer)?;
    TestResult::Ok(())
}

#[tokio::test]
async fn quiet_socks_openings_reject_direct_routes_with_either_early_data_policy() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::new();
    for early in [false, true] {
        let connectors = Connectors::new(&identity, early)?;
        let h1 = connectors
            .negotiated
            .http1_connector(&[Box::from(&b"http/1.1"[..])])?;
        let route = || crate::route::OriginRoute::Tls {
            tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: &host,
                port: address.port(),
            }),
            server_name: crate::tls::test_support::TEST_SERVER_NAME,
            setup: crate::route::DirectTlsSetup::Default,
        };
        assert!(h1.open_socks_retaining(route(), &family).await.is_err());
        assert!(
            connectors
                .exact
                .open_socks_retaining(route(), &family)
                .await
                .is_err()
        );
        assert!(
            connectors
                .negotiated
                .open_socks_retaining(route(), &family)
                .await
                .is_err()
        );
        assert_eq!(family.family(), None);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(listener.poll_accept(&mut cx).is_pending());
    }
    Ok(())
}
