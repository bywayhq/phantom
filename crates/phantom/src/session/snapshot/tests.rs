use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

use phantom_profile::browser::chrome;

use super::*;
use crate::{AltSvcSnapshot, AltSvcSnapshotEntry, ClientBuilder, HttpProxy, ServerSpkiPins};

type TestResult = Result<(), Box<dyn StdError>>;
const KEY: &[u8; 32] = &[42; 32];

fn builder(capacity: usize) -> ClientBuilder {
    Client::builder(chrome::v154_windows())
        .alt_svc(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN))
}

fn alternatives(origins: usize, expiry: SystemTime) -> AltSvcSnapshot {
    AltSvcSnapshot::new(
        (0..origins)
            .map(|index| {
                AltSvcSnapshotEntry::new(
                    format!("https://origin{index}.example"),
                    "alt.example",
                    443,
                    expiry,
                )
            })
            .collect(),
    )
}

#[test]
fn checkpoint_restores_discovery_into_independent_empty_pools() -> TestResult {
    let client = builder(2).build()?;
    let expected = alternatives(2, SystemTime::now() + Duration::from_secs(600));
    client.import_alt_svc(&expected)?;
    let snapshot = client.export_session(KEY)?;
    let exported = client.export_alt_svc().ok_or("disabled")?;
    assert_eq!(exported.len(), 2);
    let recipient = builder(2).build()?;
    recipient.import_alt_svc(&alternatives(
        1,
        SystemTime::now() + Duration::from_secs(20),
    ))?;
    let restored = recipient.restore_session(&snapshot, KEY, &[])?;
    let received = restored.export_alt_svc().ok_or("disabled")?;
    assert_eq!(received.len(), exported.len());
    for (actual, expected) in received.entries().iter().zip(exported.entries()) {
        assert_eq!(actual.origin(), expected.origin());
        assert_eq!(actual.alternative_host(), expected.alternative_host());
        assert_eq!(actual.alternative_port(), expected.alternative_port());
        assert!(actual.expires_at() <= expected.expires_at());
    }
    assert_eq!(recipient.export_alt_svc().ok_or("disabled")?.len(), 1);
    assert!(!Arc::ptr_eq(&restored.state, &recipient.state));
    assert!(!Arc::ptr_eq(
        &restored.state.tickets,
        &recipient.state.tickets
    ));
    restored.clear_alt_svc();
    assert_eq!(client.export_alt_svc().ok_or("disabled")?.len(), 2);
    assert_eq!(recipient.export_alt_svc().ok_or("disabled")?.len(), 1);
    Ok(())
}

#[test]
fn wrong_key_corruption_version_and_truncation_reject_without_mutation() -> TestResult {
    let client = builder(1).build()?;
    let snapshot = client.export_session(KEY)?;
    assert_eq!(
        client
            .restore_session(&snapshot, &[24; 32], &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Authentication
    );
    for (offset, kind) in [
        (8, SessionSnapshotErrorKind::Incompatible),
        (26, SessionSnapshotErrorKind::Authentication),
        (
            snapshot.as_bytes().len() - 1,
            SessionSnapshotErrorKind::Authentication,
        ),
    ] {
        let mut bytes = snapshot.as_bytes().to_vec();
        bytes[offset] ^= 1;
        assert_eq!(
            client
                .restore_session(&SessionSnapshot::from_bytes(&bytes)?, KEY, &[])
                .err()
                .ok_or("expected session checkpoint rejection")?
                .kind(),
            kind
        );
    }
    assert_eq!(
        client
            .restore_session(&SessionSnapshot::from_bytes(&[])?, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::InvalidSnapshot
    );
    assert_eq!(
        SessionSnapshot::from_bytes(&vec![0; MAX_BYTES + 1])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::TooLarge
    );
    assert!(client.export_alt_svc().ok_or("disabled")?.is_empty());
    Ok(())
}

#[test]
fn empty_ticket_checkpoint_still_binds_profile_trust_route_and_client_certificate() -> TestResult {
    let client = builder(1).build()?;
    let snapshot = client.export_session(KEY)?;
    let identity = rcgen::generate_simple_self_signed(Vec::<String>::new())?;
    let certificate = crate::ClientCertificate::from_pem(
        identity.cert.pem().as_bytes(),
        identity.signing_key.serialize_pem().as_bytes(),
    )?;
    let mut profile = chrome::v154_windows();
    profile = profile.with_cookie_placement(phantom_profile::CookiePlacement::last());
    let clients = [
        Client::builder(profile)
            .alt_svc(NonZeroUsize::MIN)
            .build()?,
        builder(1)
            .server_spki_pins(ServerSpkiPins::new(vec![[1; 32]])?)
            .build()?,
        builder(1)
            .proxy_server_spki_pins(ServerSpkiPins::new(vec![[2; 32]])?)
            .build()?,
        builder(1)
            .route(Route::http_proxy(HttpProxy::new("http://127.0.0.1:8080")?))
            .build()?,
        builder(1)
            .client_certificate_for("https://client.example", certificate)
            .build()?,
    ];
    for recipient in clients {
        assert_eq!(
            recipient
                .restore_session(&snapshot, KEY, &[])
                .err()
                .ok_or("expected session checkpoint rejection")?
                .kind(),
            SessionSnapshotErrorKind::Incompatible
        );
    }
    Ok(())
}

#[test]
fn disabled_discovery_and_smaller_capacity_reject_without_trimming() -> TestResult {
    let client = builder(2).build()?;
    client.import_alt_svc(&alternatives(
        2,
        SystemTime::now() + Duration::from_secs(600),
    ))?;
    let snapshot = client.export_session(KEY)?;
    let small = builder(1).build()?;
    assert_eq!(
        small
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Capacity
    );
    assert!(small.export_alt_svc().ok_or("disabled")?.is_empty());
    let disabled = Client::builder(chrome::v154_windows()).build()?;
    assert_eq!(
        disabled
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Disabled
    );
    Ok(())
}

#[test]
fn empty_enabled_discovery_remains_distinct_from_absence() -> TestResult {
    let enabled = builder(1).build()?;
    let disabled = Client::builder(chrome::v154_windows()).build()?;
    let snapshot = enabled.export_session(KEY)?;
    assert_eq!(
        disabled
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Disabled
    );
    let empty = disabled.export_session(KEY)?;
    assert!(
        enabled
            .restore_session(&empty, KEY, &[])?
            .export_alt_svc()
            .ok_or("disabled")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn authenticated_oversized_section_count_is_rejected_before_allocation() -> TestResult {
    let client = builder(1).build()?;
    let mut bytes = codec::Writer::new();
    bytes.raw(&0_u32.to_be_bytes())?; // Empty context.
    bytes.raw(&[0, 1])?; // No cookies, enabled alternatives.
    bytes.raw(&((MAX_ALTERNATIVES + 1) as u32).to_be_bytes())?;
    let snapshot = SessionSnapshot(envelope::seal(bytes.0, KEY)?);
    assert_eq!(
        client
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::TooLarge
    );
    Ok(())
}

#[cfg(not(feature = "cookies"))]
#[test]
fn cookie_section_is_rejected_when_cookie_support_is_not_compiled() -> TestResult {
    let client = builder(1).build()?;
    let mut bytes = codec::Writer::new();
    bytes.raw(&0_u32.to_be_bytes())?;
    bytes.raw(&[1])?;
    let snapshot = SessionSnapshot(envelope::seal(bytes.0, KEY)?);
    assert_eq!(
        client
            .restore_session(&snapshot, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Disabled
    );
    Ok(())
}

#[test]
fn default_route_credentials_are_explicitly_unsupported() -> TestResult {
    let proxy = HttpProxy::new("http://127.0.0.1:8080")?.with_basic_auth("user", "password")?;
    let client = builder(1).route(Route::http_proxy(proxy)).build()?;
    assert_eq!(
        client
            .export_session(KEY)
            .err()
            .ok_or("expected session checkpoint rejection")?
            .kind(),
        SessionSnapshotErrorKind::Unsupported
    );
    Ok(())
}

#[test]
fn expired_alternatives_are_pruned_without_capacity_failure_or_expiry_extension() -> TestResult {
    let client = builder(2).build()?;
    let mut state = codec::decode(&envelope::open(
        client.export_session(KEY)?.as_bytes(),
        KEY,
    )?)?;
    let expired = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let live_expiry = SystemTime::now() + Duration::from_secs(600);
    let mut entries = alternatives(1, live_expiry).entries().to_vec();
    entries.extend_from_slice(alternatives(2, expired).entries());
    state.alt_svc = Some(AltSvcSnapshot::new(entries));
    let snapshot = SessionSnapshot(envelope::seal(codec::encode(&state)?, KEY)?);
    let restored = builder(1).build()?.restore_session(&snapshot, KEY, &[])?;
    let exported = restored.export_alt_svc().ok_or("disabled")?;
    assert_eq!(exported.len(), 1);
    assert!(exported.entries()[0].expires_at() <= live_expiry);
    Ok(())
}

#[cfg(feature = "cookies")]
mod cookies {
    use super::*;
    use crate::{CookieJar, CookieLimits, CookieSnapshot, CookieSnapshotEntry, CookieSourceScheme};

    #[test]
    fn cookie_fields_order_and_partitioning_round_trip_without_sharing() -> TestResult {
        let source = builder(1).cookies().build()?;
        let jar = source.cookie_jar().ok_or("cookies disabled")?;
        jar.set_cookie(
            "https://example.com/",
            "first=long-sensitive-cookie-value-123; Secure; HttpOnly; SameSite=Strict; Path=/",
        )?;
        jar.set_cookie(
            "https://example.com/",
            "second=two; Secure; Partitioned; Path=/",
        )?;
        let before = source.export_cookies().ok_or("disabled")?;
        let snapshot = source.export_session(KEY)?;
        let secret = b"long-sensitive-cookie-value-123";
        assert!(
            !snapshot
                .as_bytes()
                .windows(secret.len())
                .any(|bytes| bytes == secret)
        );
        let recipient = builder(1).cookies().build()?;
        recipient
            .cookie_jar()
            .ok_or("disabled")?
            .set_cookie("https://example.com/", "other=value")?;
        let restored = recipient.restore_session(&snapshot, KEY, &[])?;
        assert_eq!(restored.export_cookies(), Some(before.clone()));
        assert_eq!(source.export_cookies(), Some(before));
        assert_eq!(recipient.export_cookies().ok_or("disabled")?.len(), 1);
        Ok(())
    }

    #[test]
    fn smaller_domain_cookie_limit_and_disabled_jar_reject_transactionally() -> TestResult {
        let source = builder(1).cookies().build()?;
        source
            .cookie_jar()
            .ok_or("disabled")?
            .set_cookie("https://example.com/", "a=1")?;
        source
            .cookie_jar()
            .ok_or("disabled")?
            .set_cookie("https://sub.example.com/", "b=2")?;
        let snapshot = source.export_session(KEY)?;
        let limits = CookieLimits::new(
            NonZeroUsize::new(4096).ok_or("zero")?,
            NonZeroUsize::MIN,
            NonZeroUsize::new(10).ok_or("zero")?,
        );
        let recipient = builder(1)
            .cookie_jar(CookieJar::with_limits(limits))
            .build()?;
        assert_eq!(
            recipient
                .restore_session(&snapshot, KEY, &[])
                .err()
                .ok_or("expected session checkpoint rejection")?
                .kind(),
            SessionSnapshotErrorKind::Capacity
        );
        assert!(recipient.export_cookies().ok_or("disabled")?.is_empty());
        assert_eq!(
            builder(1)
                .build()?
                .restore_session(&snapshot, KEY, &[])
                .err()
                .ok_or("expected session checkpoint rejection")?
                .kind(),
            SessionSnapshotErrorKind::Disabled
        );
        Ok(())
    }

    #[test]
    fn expired_duplicates_do_not_produce_false_cookie_capacity_errors() -> TestResult {
        let source = builder(1).cookies().build()?;
        let mut state = codec::decode(&envelope::open(
            source.export_session(KEY)?.as_bytes(),
            KEY,
        )?)?;
        let cookie = |value| {
            CookieSnapshotEntry::new(CookieSourceScheme::Https, "a", value, "example.com", "/")
        };
        state.cookies = Some(CookieSnapshot::new(vec![
            cookie("old"),
            cookie("new"),
            CookieSnapshotEntry::new(
                CookieSourceScheme::Https,
                "expired",
                "value",
                "example.com",
                "/",
            )
            .with_expires_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        ]));
        let snapshot = SessionSnapshot(envelope::seal(codec::encode(&state)?, KEY)?);
        let limits = CookieLimits::new(
            NonZeroUsize::new(4096).ok_or("zero")?,
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
        );
        let recipient = builder(1)
            .cookie_jar(CookieJar::with_limits(limits))
            .build()?;
        let restored = recipient.restore_session(&snapshot, KEY, &[])?;
        let exported = restored.export_cookies().ok_or("disabled")?;
        assert_eq!(exported.len(), 1);
        assert_eq!(exported.entries()[0].value(), "new");
        Ok(())
    }

    #[test]
    fn late_ticket_failure_never_exposes_imported_cookies() -> TestResult {
        let source = builder(1).cookies().build()?;
        source
            .cookie_jar()
            .ok_or("disabled")?
            .set_cookie("https://example.com/", "source=secret")?;
        let snapshot = source.export_session(KEY)?;
        let mut state = codec::decode(&envelope::open(snapshot.as_bytes(), KEY)?)?;
        state.tickets = SessionTicketSnapshot::from_bytes(b"invalid nested ticket envelope")?;
        let malformed = SessionSnapshot(envelope::seal(codec::encode(&state)?, KEY)?);
        let recipient = builder(1).cookies().build()?;
        recipient
            .cookie_jar()
            .ok_or("disabled")?
            .set_cookie("https://example.com/", "existing=retained")?;
        let before = recipient.export_cookies();
        let error = recipient
            .restore_session(&malformed, KEY, &[])
            .err()
            .ok_or("expected session checkpoint rejection")?;
        assert_eq!(error.kind(), SessionSnapshotErrorKind::Tickets);
        assert!(StdError::source(&error).is_some());
        assert_eq!(recipient.export_cookies(), before);
        assert_eq!(
            source.export_cookies().ok_or("disabled")?.entries()[0].value(),
            "secret"
        );
        Ok(())
    }
}
