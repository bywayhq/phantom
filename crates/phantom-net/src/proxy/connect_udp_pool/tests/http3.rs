//! An observed HTTP/3 GOAWAY retires reuse, not accepted UDP flows.

mod peer;

use std::{io::IoSliceMut, sync::Arc, time::Duration};

use http::Request;
use phantom_profile::{Http3Setting, browser::chrome};
use quinn::AsyncUdpSocket;
use tracing::Span;

use super::super::*;
use super::admission::setup;
use crate::tls::test_support::TestIdentity;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn catch_poll<F: std::future::Future>(
    future: F,
) -> Result<F::Output, Box<dyn std::any::Any + Send>> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future.as_mut().poll(context)
        })) {
            Ok(poll) => poll.map(Ok),
            Err(payload) => std::task::Poll::Ready(Err(payload)),
        }
    })
    .await
}

fn connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    let mut settings = chrome::v154_http3();
    if !settings.receives_datagrams() {
        settings
            .initial_settings
            .push(Http3Setting::H3Datagram(true));
    }
    Ok(Http3Connector::new_with_additional_roots(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &settings,
        &chrome::v154_http3_request(),
        [identity.root_der()],
    )?)
}

fn request(address: std::net::SocketAddr, path: &str) -> TestResult<Request<()>> {
    let mut request = Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_3)
        .uri(format!("https://{address}{path}"))
        .header("capsule-protocol", "?1")
        .body(())?;
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_UDP);
    Ok(request)
}

async fn marker(
    socket: &Arc<dyn AsyncUdpSocket>,
    remote: std::net::SocketAddr,
    payload: &'static [u8],
) -> TestResult {
    socket.try_send(&quinn::udp::Transmit {
        destination: remote,
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    })?;
    let mut bytes = [0; 128];
    let mut metadata = [quinn::udp::RecvMeta::default()];
    let count = std::future::poll_fn(|context| {
        socket.poll_recv(context, &mut [IoSliceMut::new(&mut bytes)], &mut metadata)
    })
    .await?;
    assert_eq!(count, 1);
    assert_eq!(metadata[0].addr, remote);
    assert_eq!(&bytes[..metadata[0].len], payload);
    Ok(())
}

#[tokio::test]
async fn observed_goaway_preserves_accepted_datagrams_and_opens_a_fresh_outer() -> TestResult {
    let identity = TestIdentity::generate_for_names(&["127.0.0.1"])?;
    let base = connector(&identity)?;
    let mut peer = peer::Peer::spawn(&identity)?;
    let primary = catch_poll(tokio::time::timeout(Duration::from_secs(30), async {
        let authority = peer.address.to_string();
        let key = PoolKey::http3(
            &ProxySettingsId::default(),
            &ProxySettingsId::default(),
            "127.0.0.1",
            peer.address.port(),
            &authority,
            &[],
            None,
        )?;
        let pool = ConnectUdpProxyPool::new();
        let first_path = "/.well-known/masque/udp/127.0.0.1/41001/";
        let next_path = "/.well-known/masque/udp/127.0.0.1/41002/";
        let (first, first_remote) = pool
            .open_http3(
                key.clone(),
                &base,
                &base,
                "127.0.0.1",
                peer.address.port(),
                request(peer.address, first_path)?,
                None,
                Span::none(),
            )
            .await?;
        let first_seen = peer.next_request().await?;
        first_seen.assert_request(&authority, first_path);
        marker(&first, first_remote, b"first-before-goaway").await?;
        let Acquisition::Reuse {
            session: OuterSession::Http3(outer),
            authenticated,
            lease,
        } = pool.acquire(key.clone()).await?
        else {
            return Err("accepted outer was not retained".into());
        };
        assert!(!authenticated);
        let isolated = lease.http3_connector(&base);
        assert!(isolated.can_reuse_now(&outer));
        peer.send_goaway().await?;
        while isolated.can_reuse_now(&outer) {
            tokio::task::yield_now().await;
        }
        marker(&first, first_remote, b"first-after-observed-goaway").await?;
        let retired = setup(pool.acquire(key.clone()).await?)?;
        // Release this inspection lease; the next real open owns fresh setup.
        drop(retired);
        let (next, next_remote) = pool
            .open_http3(
                key,
                &base,
                &base,
                "127.0.0.1",
                peer.address.port(),
                request(peer.address, next_path)?,
                None,
                Span::none(),
            )
            .await?;
        let next_seen = peer.next_request().await?;
        next_seen.assert_request(&authority, next_path);
        assert_ne!(first_seen.outer, next_seen.outer);
        assert_eq!(first_seen.stream, 0);
        assert_eq!(next_seen.stream, 0);
        marker(&next, next_remote, b"fresh-outer-after-goaway").await?;
        marker(&first, first_remote, b"first-alongside-fresh-outer").await?;
        peer.assert_no_extra_request()?;
        drop(next);
        drop(first);
        drop(lease);
        drop(outer);
        drop(isolated);
        pool.clear();
        Ok(())
    }))
    .await;
    let primary: TestResult = match primary {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("GOAWAY control assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    };
    let cleanup = peer.finish().await;
    match (primary, cleanup) {
        (Ok(()), cleanup) | (cleanup, Ok(())) => cleanup,
        (Err(primary), Err(cleanup)) => {
            Err(format!("GOAWAY caller failed: {primary}; peer cleanup failed: {cleanup}").into())
        }
    }
}
