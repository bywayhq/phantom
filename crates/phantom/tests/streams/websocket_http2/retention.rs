//! Actual connected Windows backups for exact and profile-policy H2 WebSockets.

use crate::support::{
    ech::{
        ORIGIN_NAME, PUBLIC_NAME, ech_acceptor, ech_tls_settings, https_rdata_with_alpn,
        origin_identity,
    },
    tls::{H2_ALPN, TestIdentity, TestResult, tls_settings},
};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use phantom::{
    AddressResolver, Client, HttpProtocol, WebSocketMessage,
    dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, HttpsRecordResolver},
    profile::{ClientProfile, browser::firefox},
};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::{oneshot, watch},
    time::timeout,
};

mod peer;
const DEADLINE: Duration = Duration::from_secs(10);

fn client(identity: &TestIdentity, port: u16, ech: bool) -> TestResult<Client> {
    let (published, ready) = watch::channel(!ech);
    let config = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(&[b"h2"], &config))?;
    let records = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            format!("_{port}._https.{ORIGIN_NAME}"),
            300,
            record,
        )],
        None,
    );
    let https = HttpsRecordResolver::from_fn(move |_, _| {
        let published = published.clone();
        let records = records.clone();
        async move {
            published.send_replace(true);
            Ok(records)
        }
    });
    // The resolver finishes and its cache publishes on this current-thread
    // runtime before address resolution resumes, without a readiness sleep.
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
    let mut websocket = firefox::v157_websocket();
    websocket.http2_fields = vec![
        phantom::profile::WebSocketField::literal("x-order", "first"),
        phantom::profile::WebSocketField::literal("sec-websocket-version", "13"),
        phantom::profile::WebSocketField::literal("x-last", "last"),
    ];
    let profile = ClientProfile::new(if ech {
        ech_tls_settings()
    } else {
        tls_settings()
    })
    .with_http1(firefox::v157_http1())
    .with_http2(firefox::v157_http2())
    .with_tcp(firefox::v157_tcp())
    .with_http3(crate::support::h3::client_settings())
    .with_websocket(websocket);
    let mut builder = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .dns_resolver(addresses);
    if ech {
        builder = builder
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(https);
    }
    Ok(builder.build()?)
}

async fn control(negotiated: bool, ech: bool, retired: bool) -> TestResult<()> {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let unlistened = TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: this host has no IPv6 loopback address"); return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let identity = origin_identity()?;
        let acceptor = if ech { ech_acceptor(&identity, H2_ALPN, 1, &TEST_ECH_KEYS[0])? }
            else { identity.acceptor(H2_ALPN)? };
        let client = client(&identity, port, ech)?;
        let url = format!("wss://{ORIGIN_NAME}:{port}/events");
        let page = format!("https://{ORIGIN_NAME}:{port}/page");
        let builder = if negotiated { client.websocket_with_profile_policy(&url)? }
            else { client.websocket_with_protocol(HttpProtocol::Http2, &url)? };
        let (ready, spare_ready) = oneshot::channel();
        let (done, completed) = oneshot::channel();
        let caller = async {
            if retired {
                // The original CONNECT fails; it is never moved onto the backup.
                match builder.connect().await {
                    Ok(_) => return Err("retired dedicated CONNECT unexpectedly succeeded".into()),
                    Err(error) => assert_eq!(error.kind(), phantom::WebSocketErrorKind::Http2),
                }
                spare_ready.await?;
                for _ in 0..2 {
                    let request = if negotiated { client.get_negotiated(&page)? }
                        else { client.get(HttpProtocol::Http2, &page)? };
                    let response = request.send().await?;
                    assert_eq!(response.status(), 200);
                    assert!(response.into_body().collect().await?.to_bytes().is_empty());
                }
            } else {
                let mut opening = Box::pin(builder.connect());
                tokio::select! {
                    result = &mut opening => { drop(result); return Err("CONNECT settled before quiet backup barrier".into()); }
                    observed = spare_ready => observed?,
                }
                let mut socket = opening.await?;
                socket.send(WebSocketMessage::Binary(Bytes::from_static(b"client"))).await?;
                assert_eq!(socket.receive().await?, WebSocketMessage::Binary(Bytes::from_static(b"peer")));
                drop(socket);
            }
            done.send(()).map_err(|_| "peer ended before caller completion")?;
            drop(client);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer::serve(listener, acceptor, ech, retired, ready, completed))?;
        drop(unlistened);
        // All peer sockets/futures are lexical owners; deadline/unwind drops them.
        Ok(())
    }).await.map_err(|_| "H2 WebSocket retention exceeded its deadline")?
}

#[tokio::test]
async fn dedicated_h2_websocket_closes_quiet_authenticated_redundant_backups() -> TestResult<()> {
    for negotiated in [false, true] {
        for ech in [false, true] {
            control(negotiated, ech, false).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn retired_h2_websocket_leaves_backup_for_later_http_without_replaying_connect()
-> TestResult<()> {
    for negotiated in [false, true] {
        for ech in [false, true] {
            control(negotiated, ech, true).await?;
        }
    }
    Ok(())
}
