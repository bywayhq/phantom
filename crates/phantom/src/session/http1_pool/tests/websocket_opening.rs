//! Actual Upgrade cancellation and rejection retain only their HTTP owner.
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use phantom_net::tcp::AddressFamily;
use phantom_profile::{
    ClientProfile,
    browser::{chrome, firefox},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::TestResult;
use crate::{Client, Route, authority::Endpoint, session::prune_timer::PruneTimer};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum End {
    Cancelled,
    Rejected,
    Upgraded,
    InvalidUpgrade,
}

async fn lifecycle(end: End, policy: bool) -> TestResult {
    let profile = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_websocket(chrome::v154_websocket());
    lifecycle_with_profile(end, policy, profile).await
}

async fn lifecycle_with_profile(end: End, policy: bool, profile: ClientProfile) -> TestResult {
    let separate = profile.websocket().is_some_and(|settings| {
        settings.connection.cleartext_state == phantom_profile::WebSocketCleartextState::Separate
    });
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let mut client = Client::builder(profile).build()?;
        let state = Arc::get_mut(&mut client.state).ok_or("new client state already shared")?;
        state.http1 = super::super::Http1Pool::new(std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN).with_prune_timer(Some(Arc::clone(&timer)));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let endpoint = Endpoint::new(address.to_string().parse()?, 80)?;
        let mut key = super::super::PoolKey::new(&endpoint, &Route::Direct, super::super::Http1ConnectionMode::PlaintextOrigin);
        if separate {
            key.purpose = super::super::PoolPurpose::WebSocket;
        }
        let entry = client.state.http1.entry(key).await;
        let (seen, head_seen) = oneshot::channel();
        let uri = format!("ws://{address}/opening");
        let builder = if policy {
            client.websocket_with_profile_policy(&uri)?
        } else {
            client.websocket(&uri)?
        };
        let caller = async {
            let mut opening = Box::pin(builder.connect());
            if matches!(end, End::Cancelled) {
                tokio::select! {
                    result = &mut opening => {
                        drop(result);
                        return Err("opening settled before cancellation".into());
                    }
                    observed = head_seen => observed?,
                }
                assert_eq!(entry.connections.lock().openings, 1);
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                timer.fire();
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                drop(opening);
            } else if matches!(end, End::Rejected) {
                let result = opening.await;
                let error = match result {
                    Err(error) => error,
                    Ok(_) => return Err("403 upgraded a socket".into()),
                };
                let response = error.into_response().ok_or("403 lost its rejection response")?;
                assert_eq!(response.status(), 403);
                assert_eq!(entry.connections.lock().openings, 1);
                timer.fire();
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                drop(response);
            } else if matches!(end, End::InvalidUpgrade) {
                let error = match opening.await {
                    Err(error) => error,
                    Ok(_) => return Err("invalid handshake upgraded a socket".into()),
                };
                assert_eq!(error.kind(), crate::WebSocketErrorKind::InvalidHandshake);
            } else {
                let socket = opening.await?;
                // The accepted WebSocket has left the HTTP pool even while alive.
                assert_eq!(entry.connections.lock().openings, 0);
                timer.fire();
                assert_eq!(entry.connections.family.family(), None);
                drop(socket);
            }
            assert_eq!(entry.connections.lock().openings, 0);
            timer.fire();
            assert_eq!(entry.connections.family.family(), None);
            TestResult::Ok(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await?;
                head.push(byte[0]);
            }
            seen.send(()).map_err(|()| "opening observer ended")?;
            if matches!(end, End::Rejected) {
                // Keep the body incomplete so the rejection still owns HTTP.
                stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\n").await?;
            } else if matches!(end, End::Upgraded | End::InvalidUpgrade) {
                let text = std::str::from_utf8(&head)?;
                let key = text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim())
                }).ok_or("missing WebSocket key")?;
                let mut bytes = key.as_bytes().to_vec();
                bytes.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                let accept = if matches!(end, End::InvalidUpgrade) {
                    "invalid".into()
                } else {
                    btls::base64::encode_block(&btls::sha::sha1(&bytes))
                };
                stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
            }
            let mut remaining = Vec::new();
            match stream.read_to_end(&mut remaining).await {
                Ok(_) => {},
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe) => {},
                Err(error) => return Err(error.into()),
            }
            assert!(remaining.is_empty(), "cancelled/rejected/upgraded owner sent unexpected application bytes");
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}

#[tokio::test]
async fn cancelled_upgrade_releases_its_opening_and_family() -> TestResult {
    lifecycle(End::Cancelled, false).await
}

#[tokio::test]
async fn rejected_upgrade_body_keeps_family_until_dropped() -> TestResult {
    lifecycle(End::Rejected, false).await
}

#[tokio::test]
async fn accepted_upgrade_releases_http_family_before_socket_drop() -> TestResult {
    lifecycle(End::Upgraded, false).await
}

#[tokio::test]
async fn cancelled_opening_leaves_pending_spare_owned_until_last_pool_drop() -> TestResult {
    use phantom_net::tcp::{SlowerConnection, SlowerProgress};
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let one = std::num::NonZeroUsize::MIN;
        let pool =
            super::super::Http1Pool::new(one, one, one).with_prune_timer(Some(Arc::clone(&timer)));
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let opening = pool.origin_opening(&endpoint, false).await;
        let family = Arc::clone(opening.family());
        family.remember(AddressFamily::Ipv4);
        let (started, running) = oneshot::channel();
        let (dropped, cancelled) = oneshot::channel::<()>();
        opening.adopt(SlowerConnection::new(SlowerProgress::new(), async move {
            let _drop_signal = dropped;
            if started.send(()).is_err() {
                return None;
            }
            std::future::pending().await
        }));
        running.await?;
        drop(opening);
        timer.fire();
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        drop(pool);
        assert!(
            cancelled.await.is_err(),
            "pending spare did not drop its owned future"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn plaintext_policy_opening_uses_exact_http1_owner() -> TestResult {
    lifecycle(End::Cancelled, true).await
}

mod state;
