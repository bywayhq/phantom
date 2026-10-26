//! Windows' refused IPv6 attempt leaves a real slower IPv4 connection.
//! Pool ownership controls using a custom profile.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, Client, HttpProtocol, WebSocketMessage,
    dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver},
    profile::{
        ClientProfile, WebSocketField,
        browser::{chrome, firefox},
    },
};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::{oneshot, watch},
    time::timeout,
};

use crate::support::{
    ech::{
        ORIGIN_NAME, PUBLIC_NAME, TEST_TIMEOUT, ech_acceptor, ech_tls_settings,
        https_rdata_with_alpn, origin_identity,
    },
    tls::{H1_ALPN, TestIdentity, TestResult},
};

mod peer;

fn client(identity: &TestIdentity, port: u16) -> TestResult<Client> {
    let config = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"http/1.1"], &config))?;
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            format!("_{port}._https.{ORIGIN_NAME}"),
            300,
            record,
        )],
        None,
    );
    let (published, ready) = watch::channel(false);
    let https = HttpsRecordResolver::from_fn(move |_, _| {
        let published = published.clone();
        let records = records.clone();
        async move {
            published.send_replace(true);
            Ok(records)
        }
    });
    // The current-thread runtime publishes HTTPS state before releasing DNS.
    let addresses = AddressResolver::from_fn(move |_| {
        let mut ready = ready.clone();
        async move {
            while !*ready.borrow_and_update() {
                ready
                    .changed()
                    .await
                    .map_err(|_| io::Error::other("HTTPS publisher ended"))?;
            }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        }
    });
    let mut websocket = chrome::v154_websocket();
    // Both opening modes use this exact list, making order observable.
    websocket.http1_fields = vec![
        WebSocketField::authority("Host"),
        WebSocketField::literal("X-Order", "first"),
        WebSocketField::literal("Upgrade", "websocket"),
        WebSocketField::literal("Connection", "Upgrade"),
        WebSocketField::key("Sec-WebSocket-Key"),
        WebSocketField::literal("Sec-WebSocket-Version", "13"),
    ];
    let profile = ClientProfile::new(ech_tls_settings())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_tcp(firefox::v157_tcp())
        .with_http3(crate::support::h3::client_settings())
        .with_websocket(websocket);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .https_record_discovery(https)
        .dns_resolver(addresses)
        .build()?)
}

async fn control(negotiated: bool) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // Windows keeps this refused attempt pending beyond the IPv4 backup.
        let unlistened = TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: this host has no IPv6 loopback address");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let identity = origin_identity()?;
        let acceptor = ech_acceptor(&identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, port)?;
        let authority = format!("{ORIGIN_NAME}:{port}");
        let websocket_uri = format!("wss://{authority}/events");
        let page_uri = format!("https://{authority}/page");
        let (ready, spare_ready) = oneshot::channel();
        let (release, release_101) = oneshot::channel();
        let builder = if negotiated {
            client.websocket_with_profile_policy(&websocket_uri)?
        } else {
            client.websocket(&websocket_uri)?
        };
        let caller = async move {
            let mut opening = Box::pin(builder.connect());
            tokio::select! {
                result = &mut opening => {
                    drop(result);
                    return Err("WebSocket settled before the peer released 101".into());
                }
                observed = spare_ready => observed?,
            }
            let page = if negotiated {
                client.get(&page_uri)?
            } else {
                client.get_with_protocol(HttpProtocol::Http1, &page_uri)?
            };
            let response = page.send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "done");
            release
                .send(())
                .map_err(|()| "101 peer ended before release")?;
            let mut socket = opening.await?;
            socket
                .send(WebSocketMessage::Binary(Bytes::from_static(b"client")))
                .await?;
            assert_eq!(
                socket.receive().await?,
                WebSocketMessage::Binary(Bytes::from_static(b"peer"))
            );
            drop(socket);
            drop(client);
            TestResult::Ok(())
        };
        tokio::try_join!(
            caller,
            peer::serve(listener, acceptor, authority, ready, release_101)
        )?;
        drop(unlistened);
        // No task is spawned: timeout or assertion unwinding drops all owned
        // peer streams and each in-flight operation in this lexical scope.
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn exact_h1_websocket_keeps_a_quiet_ech_spare_claimable_before_101() -> TestResult<()> {
    control(false).await
}

#[tokio::test]
async fn policy_h1_websocket_keeps_a_quiet_ech_spare_claimable_before_101() -> TestResult<()> {
    control(true).await
}

#[tokio::test]
async fn plaintext_policy_websocket_spare_is_claimed_by_ordinary_http_before_101() -> TestResult<()>
{
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // The primary tries refused IPv6 first; after the IPv4 backup wins,
        // it finishes on IPv4 while the winning Upgrade waits for 101.
        let unlistened = TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: this host has no IPv6 loopback address");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let addresses = AddressResolver::from_fn(|_| async {
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        });
        let mut websocket = chrome::v154_websocket();
        websocket.http1_fields = vec![
            WebSocketField::authority("Host"),
            WebSocketField::literal("X-Order", "first"),
            WebSocketField::literal("Upgrade", "websocket"),
            WebSocketField::literal("Connection", "Upgrade"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::literal("Sec-WebSocket-Version", "13"),
        ];
        let profile = ClientProfile::new(firefox::v157_tcp_tls())
            .with_tcp(firefox::v157_tcp())
            .with_http1(firefox::v157_http1())
            .with_http2(firefox::v157_http2())
            .with_websocket(websocket);
        let client = Client::builder(profile).dns_resolver(addresses).build()?;
        let authority = format!("{ORIGIN_NAME}:{port}");
        let websocket_uri = format!("ws://{authority}/events");
        let page_uri = format!("http://{authority}/page");
        let (ready, spare_ready) = oneshot::channel();
        let (release, release_101) = oneshot::channel();
        let builder = client.websocket_with_profile_policy(&websocket_uri)?;
        let caller = async move {
            let mut opening = Box::pin(builder.connect());
            tokio::select! {
                result = &mut opening => {
                    drop(result);
                    return Err("plaintext opening settled before released 101".into());
                }
                observed = spare_ready => observed?,
            }
            // Ordinary profile-policy plaintext uses the exact HTTP/1 pool.
            let response = client.get(&page_uri)?.send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "done");
            release.send(()).map_err(|()| "plaintext 101 peer ended")?;
            let mut socket = opening.await?;
            socket
                .send(WebSocketMessage::Binary(Bytes::from_static(b"client")))
                .await?;
            assert_eq!(
                socket.receive().await?,
                WebSocketMessage::Binary(Bytes::from_static(b"peer"))
            );
            drop(socket);
            drop(client);
            TestResult::Ok(())
        };
        tokio::try_join!(
            caller,
            peer::serve_plaintext(listener, authority, ready, release_101)
        )?;
        drop(unlistened);
        Ok(())
    })
    .await?
}

mod proxy;

mod proxy_h2;
mod proxy_h2_peer;
mod proxy_peer;
