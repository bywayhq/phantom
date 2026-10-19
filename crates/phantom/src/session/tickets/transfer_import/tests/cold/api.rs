use std::{
    error::Error as _,
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use phantom_net::http2::Http2TlsConnector;
use phantom_testkit::http1::{CaptureLimits, capture_request_head};

use super::*;
use crate::{
    Client, ClientBuilder, EnvironmentProxies, HttpProtocol, SessionTicketErrorKind,
    SessionTicketSnapshot,
};

fn builder(fixture: &ImportFixture) -> ClientBuilder {
    Client::builder(fixture.profile.clone()).add_root_certificate_der(fixture.roots[0].clone())
}

async fn public_exchange(
    fixture: &ImportFixture,
    listener: &TcpListener,
    client: &Client,
    resumed: bool,
) -> TestResult {
    let url = format!("https://{}/", listener.local_addr()?);
    tokio::time::timeout(DEADLINE, async {
        tokio::try_join!(
            async {
                let response = client.get(HttpProtocol::Http1, &url)?.send().await?;
                let response = crate::response_bytes(response, 1).await?;
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(response.body().as_ref(), b"x");
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let (tcp, _) = listener.accept().await?;
                assert!(tcp.local_addr()?.ip().is_loopback());
                let mut peer = SslStream::new(Ssl::new(fixture.server.context())?, tcp)?;
                Pin::new(&mut peer).accept().await?;
                assert_eq!(peer.ssl().session_reused(), resumed);
                let head = capture_request_head(
                    &mut peer,
                    tokio::time::Instant::now() + DEADLINE,
                    CaptureLimits::new(8192, 8192, 32),
                )
                .await?;
                assert_eq!(head.method(), b"GET");
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                )
                .await?;
                peer.flush().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn public_request_export_and_cold_import_resume_the_first_request() -> TestResult {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = ImportFixture::for_version(version)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let source = builder(&fixture).route(Route::Direct).build()?;
        public_exchange(&fixture, &listener, &source, false).await?;
        let snapshot = source.export_session_tickets(&KEY)?;
        let restored = SessionTicketSnapshot::from_bytes(snapshot.as_bytes())?;
        assert_eq!(restored.as_bytes(), snapshot.as_bytes());

        let recipient = builder(&fixture).route(Route::Direct).build()?;
        recipient.import_session_tickets(&restored, &KEY, &[])?;
        assert!(recipient.state.tickets.registry().caches.is_empty());
        let cold = cold_snapshot(&recipient.state.tickets)?;
        assert_eq!(cold.owners.len(), 1);
        assert!(!cold.native.is_empty());
        public_exchange(&fixture, &listener, &recipient, true).await?;
        assert!(recipient.state.tickets.registry().cold.is_none());
        assert_eq!(recipient.state.tickets.registry().caches.len(), 1);
        assert!(source.state.tickets.registry().cold.is_none());
    }
    Ok(())
}

#[cfg(feature = "session-snapshot")]
#[tokio::test]
async fn unified_checkpoint_restores_real_tls_sessions_without_changing_recipient() -> TestResult {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = ImportFixture::for_version(version)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let source = builder(&fixture).build()?;
        public_exchange(&fixture, &listener, &source, false).await?;
        let snapshot = source.export_session(&KEY)?;
        let recipient = builder(&fixture).build()?;
        let restored = recipient.restore_session(&snapshot, &KEY, &[])?;
        assert!(recipient.state.tickets.registry().caches.is_empty());
        assert!(recipient.state.tickets.registry().cold.is_none());
        public_exchange(&fixture, &listener, &restored, true).await?;
        // Export and restore retain the source's independently consumable tickets.
        public_exchange(&fixture, &listener, &source, true).await?;
        public_exchange(&fixture, &listener, &recipient, false).await?;
    }
    Ok(())
}

#[tokio::test]
async fn configured_environment_route_rejects_last_owner_without_replacing_live_or_cold_state()
-> TestResult {
    let fixture = ImportFixture::new()?;
    let proxies = EnvironmentProxies::from_values([
        ("https_proxy", "http://proxy.invalid:8080"),
        ("no_proxy", "127.0.0.1:443,127.0.0.1:445"),
    ])?;
    let recipient = builder(&fixture)
        .environment_proxies(proxies.clone())
        .build()?;
    let live = fixture.store(&recipient.state.tickets, 443)?;
    fixture.exchange(&live, false).await?;
    fixture.exchange(&live, true).await?;
    let prior = fixture.owner()?;
    let prior_store = fixture.store(&prior, 445)?;
    fixture.exchange(&prior_store, false).await?;
    let prior_snapshot = SessionTicketSnapshot::from_bytes(&live_snapshot(&prior, None)?)?;
    recipient.import_session_tickets(&prior_snapshot, &KEY, &[])?;

    let source = fixture.owner()?;
    let first = fixture.store(&source, 443)?;
    fixture.exchange(&first, false).await?;
    let first_snapshot = SessionTicketSnapshot::from_bytes(&live_snapshot(&source, None)?)?;
    let first_control = builder(&fixture)
        .environment_proxies(proxies.clone())
        .build()?;
    first_control.import_session_tickets(&first_snapshot, &KEY, &[])?;
    assert_eq!(cold_snapshot(&first_control.state.tickets)?.owners.len(), 1);
    let last = fixture.store(&source, 444)?;
    fixture.exchange(&last, false).await?;
    let snapshot = SessionTicketSnapshot::from_bytes(&live_snapshot(&source, None)?)?;
    let before_live = store_header(&live)?;
    let before_cold = cold_snapshot(&recipient.state.tickets)?;
    assert!(before_live.record_count() > 0);
    assert_ne!(before_live, store_header(&first)?);
    assert_eq!(before_cold.owners.len(), 1);
    assert_eq!(before_cold.owners[0].authority, "127.0.0.1:445");

    let error = recipient
        .import_session_tickets(&snapshot, &KEY, &[])
        .err()
        .ok_or("accepted last owner selected for a proxy")?;
    assert_eq!(error.kind(), SessionTicketErrorKind::Policy);
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<ImportError>()),
        Some(ImportError::OwnerMapping)
    ));
    assert_eq!(store_header(&live)?, before_live);
    assert_eq!(cold_snapshot(&recipient.state.tickets)?, before_cold);
    fixture.exchange(&live, true).await?;

    let direct = builder(&fixture)
        .environment_proxies(proxies)
        .route(Route::Direct)
        .build()?;
    direct.import_session_tickets(&snapshot, &KEY, &[])?;
    assert_eq!(cold_snapshot(&direct.state.tickets)?.owners.len(), 2);
    Ok(())
}

#[tokio::test]
async fn public_import_rejects_unconfigured_http2_intent_and_preserves_prior_tickets() -> TestResult
{
    let fixture = ImportFixture::new()?;
    let recipient = builder(&fixture).route(Route::Direct).build()?;
    assert!(recipient.inner.http2.is_none());
    let live = fixture.store(&recipient.state.tickets, 443)?;
    fixture.exchange(&live, false).await?;
    let prior = fixture.owner()?;
    let prior_store = fixture.store(&prior, 445)?;
    fixture.exchange(&prior_store, false).await?;
    recipient.import_session_tickets(
        &SessionTicketSnapshot::from_bytes(&live_snapshot(&prior, None)?)?,
        &KEY,
        &[],
    )?;
    let before_live = store_header(&live)?;
    let before_cold = cold_snapshot(&recipient.state.tickets)?;

    // An actual empty H2 cache is valid clear intent, without synthetic records.
    let h2_fixture = ImportFixture {
        profile: fixture.profile.clone().with_http2(chrome::v154_http2()),
        roots: fixture.roots.clone(),
        server: fixture.server.clone(),
    };
    let source = h2_fixture.owner()?;
    let connector = Http2TlsConnector::new_with_additional_roots(
        h2_fixture.profile.tls(),
        h2_fixture.profile.http2().ok_or("H2 settings missing")?,
        h2_fixture.roots.iter().map(AsRef::as_ref),
    )?
    .with_isolated_session_cache();
    let origin = Endpoint::new("127.0.0.1:444".parse()?, 443)?;
    source.register(
        connector.session_ticket_cache(),
        TicketCacheBinding {
            origin: &origin,
            server_name: NAME,
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http2),
            route: &Route::Direct,
        },
    );
    let snapshot = SessionTicketSnapshot::from_bytes(&live_snapshot(&source, None)?)?;
    let matching = builder(&h2_fixture).route(Route::Direct).build()?;
    assert!(matching.inner.http2.is_some());
    matching.import_session_tickets(&snapshot, &KEY, &[])?;
    let accepted = cold_snapshot(&matching.state.tickets)?;
    assert_eq!(accepted.owners.len(), 1);
    assert!(accepted.owners[0].slots.is_empty());
    assert!(accepted.native.is_empty());

    let error = recipient
        .import_session_tickets(&snapshot, &KEY, &[])
        .err()
        .ok_or("accepted H2 intent without an H2 connector")?;
    assert_eq!(error.kind(), SessionTicketErrorKind::Policy);
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<ImportError>()),
        Some(ImportError::OwnerMapping)
    ));
    assert_eq!(store_header(&live)?, before_live);
    assert_eq!(cold_snapshot(&recipient.state.tickets)?, before_cold);
    fixture.exchange(&live, true).await?;
    Ok(())
}

#[test]
fn snapshot_bounds_redaction_and_public_failure_sources_are_preserved() -> TestResult {
    let fixture = ImportFixture::new()?;
    let client = builder(&fixture).route(Route::Direct).build()?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let canary = format!("snapshot-canary-{}-{nonce}", std::process::id());
    let malformed = SessionTicketSnapshot::from_bytes(canary.as_bytes())?;
    assert_eq!(malformed.as_bytes(), canary.as_bytes());
    for rendered in [format!("{malformed:?}"), format!("{malformed:#?}")] {
        assert!(rendered.contains("SessionTicketSnapshot"));
        assert!(!rendered.contains(&canary));
    }
    let error = client
        .import_session_tickets(&malformed, &KEY, &[])
        .err()
        .ok_or("accepted malformed snapshot")?;
    assert_eq!(error.kind(), SessionTicketErrorKind::InvalidSnapshot);
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<ImportError>()),
        Some(ImportError::Manifest(EnvelopeError::Malformed))
    ));
    assert!(!format!("{error:?} {error}").contains(&canary));

    let snapshot = client.export_session_tickets(&KEY)?;
    let mut wrong_key = KEY;
    wrong_key[0] ^= 1;
    let error = client
        .import_session_tickets(&snapshot, &wrong_key, &[])
        .err()
        .ok_or("accepted wrong snapshot key")?;
    assert_eq!(error.kind(), SessionTicketErrorKind::Authentication);
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<ImportError>()),
        Some(ImportError::Manifest(EnvelopeError::Authentication))
    ));
    let rendered = format!("{error:?} {error}");
    assert!(rendered.contains("SessionTicketError"));
    assert!(!rendered.contains(&format!("{wrong_key:?}")));
    assert!(client.state.tickets.registry().caches.is_empty());
    assert!(client.state.tickets.registry().cold.is_none());

    let bytes = vec![0; 16 * 1024 * 1024 + 1];
    let maximum = SessionTicketSnapshot::from_bytes(&bytes[..16 * 1024 * 1024])?;
    assert_eq!(maximum.as_bytes().len(), 16 * 1024 * 1024);
    let error = SessionTicketSnapshot::from_bytes(&bytes)
        .err()
        .ok_or("accepted snapshot above 16 MiB")?;
    assert_eq!(error.kind(), SessionTicketErrorKind::TooLarge);
    assert!(error.source().is_none());
    Ok(())
}
