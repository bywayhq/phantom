use btls::ssl::PreparedSessionPolicyFreeze;

use super::*;

fn endpoint(authority: &str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(authority.parse()?, 443)?)
}

fn unused_connector(fixture: &ImportFixture) -> TestResult<Http1TlsConnector> {
    Ok(Http1TlsConnector::new_with_additional_roots(
        fixture.profile.tls(),
        fixture.roots.iter().map(AsRef::as_ref),
    )?
    .with_isolated_session_cache())
}

fn before_use(
    owner: &TicketOwner,
    connector: &Http1TlsConnector,
    origin: &Endpoint,
    name: &str,
) -> Result<(), crate::session::tickets::TicketUseError> {
    owner.register_tcp_before_use(
        connector.session_ticket_cache(),
        TicketCacheBinding {
            origin,
            server_name: name,
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http1),
            route: &Route::Direct,
        },
    )
}

#[tokio::test]
async fn cold_tickets_materialize_once_before_first_tcp_use_and_preserve_another_owner()
-> TestResult {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = ImportFixture::for_version(version)?;
        let decoding = decoding_context()?;
        let source = fixture.owner()?;
        let first = fixture.store(&source, 443)?;
        let second = fixture.store(&source, 444)?;
        fixture.exchange(&first, false).await?;
        fixture.exchange(&second, false).await?;
        let recipient = fixture.owner()?;
        assert_eq!(
            recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?,
            0
        );
        assert!(recipient.registry().caches.is_empty());
        let before = cold_snapshot(&recipient)?;
        assert_eq!(before.owners.len(), 2);
        assert!(!before.owners[0].slots.is_empty());
        assert!(!before.owners[1].slots.is_empty());
        let target = unused_connector(&fixture)?;
        let origin = endpoint("127.0.0.1:443")?;
        before_use(&recipient, &target, &origin, NAME)?;
        assert_eq!(recipient.registry().caches.len(), 1);
        assert_eq!(store_header(&target)?, store_header(&first)?);
        let after = cold_snapshot(&recipient)?;
        assert_eq!(after.owners.len(), 1);
        assert_eq!(after.owners[0].authority, before.owners[1].authority);
        assert_eq!(after.owners[0].header, before.owners[1].header);
        assert_eq!(
            after.owners[0].original_index,
            before.owners[1].original_index
        );
        assert_eq!(after.owners[0].policy, before.owners[1].policy);
        assert_eq!(after.owners[0].witness, before.owners[1].witness);
        assert_eq!(
            after.owners[0]
                .slots
                .iter()
                .map(|s| s.physical_ordinal)
                .collect::<Vec<_>>(),
            before.owners[1]
                .slots
                .iter()
                .map(|s| s.physical_ordinal)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            after.native,
            before.owners[1]
                .slots
                .iter()
                .map(|slot| before.native[usize::from(slot.native_slot)])
                .collect::<Vec<_>>()
        );
        let target_header = store_header(&target)?;
        for _ in 0..2 {
            before_use(&recipient, &target, &origin, NAME)?;
            assert_eq!(recipient.registry().caches.len(), 1);
            assert_eq!(store_header(&target)?, target_header);
            assert_eq!(cold_snapshot(&recipient)?, after);
        }
        fixture.exchange(&target, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_shared_context_busy_keeps_custody_then_retry_materializes_and_resumes() -> TestResult
{
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = ImportFixture::for_version(version)?;
        let decoding = decoding_context()?;
        let source = fixture.owner()?;
        let source_store = fixture.store(&source, 443)?;
        fixture.exchange(&source_store, false).await?;
        let recipient = fixture.owner()?;
        let base = unused_connector(&fixture)?;
        let sibling = base.with_isolated_session_cache();
        let target = base.with_isolated_session_cache();
        let sibling_origin = endpoint("sibling.example:443")?;
        recipient.register(
            sibling.session_ticket_cache(),
            TicketCacheBinding {
                origin: &sibling_origin,
                server_name: "sibling.example",
                leg: TicketCacheLeg::Origin,
                protocol: Ok(TicketCacheProtocol::Http1),
                route: &Route::Direct,
            },
        );
        let binding = {
            let registry = recipient.registry();
            registry.caches[0]
                .native_binding
                .as_ref()
                .map_err(|error| *error)?
                .clone()
        };
        recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?;
        let before_cold = cold_snapshot(&recipient)?;
        let target_cache = target
            .session_ticket_cache()
            .ok_or("target cache missing")?
            .upgrade()
            .ok_or("target cache dead")?;
        assert!(matches!(
            SessionTicketCacheOwner::capture_tcp_stores(&[(&target_cache, NAME)]),
            Err(SessionTransferError::Policy)
        ));
        let prepared = PreparedSessionPolicyFreeze::new(&[&binding])?;
        let frozen = prepared.try_freeze()?;
        let origin = endpoint("127.0.0.1:443")?;
        for _ in 0..2 {
            let error = before_use(&recipient, &target, &origin, NAME)
                .err()
                .ok_or("accepted Busy binding")?;
            assert!(matches!(
                error.0,
                ImportError::Preparation(PreparationError::Backend)
            ));
            assert_eq!(cold_snapshot(&recipient)?, before_cold);
            let registry = recipient.registry();
            assert_eq!(registry.caches.len(), 2);
            assert!(matches!(
                registry.caches[1].native_binding,
                Err(PreparationError::Backend)
            ));
        }
        // The sibling guard really holds this target context's native lock.
        // The policy comes from its actual stored registration, never test bytes.
        let policy = {
            let registry = recipient.registry();
            let registration = registry.caches[1]
                .binding
                .as_ref()
                .map_err(|error| *error)?;
            let preparation = recipient
                .preparation
                .as_ref()
                .ok_or("preparation missing")?
                .as_ref()
                .map_err(|error| *error)?;
            preparation.configured_direct_tcp_policy(
                &registration.descriptor,
                registration.leg,
                registration.protocol,
                &registration.route,
            )?
        };
        assert!(matches!(
            target_cache.bind_tcp_transfer_policy(NAME, policy),
            Err(SessionTransferError::Busy)
        ));
        drop(frozen);
        assert!(matches!(
            SessionTicketCacheOwner::capture_tcp_stores(&[(&target_cache, NAME)]),
            Err(SessionTransferError::Policy)
        ));
        before_use(&recipient, &target, &origin, NAME)?;
        assert_eq!(store_header(&target)?, store_header(&source_store)?);
        assert!(recipient.registry().cold.is_none());
        let committed = store_header(&target)?;
        before_use(&recipient, &target, &origin, NAME)?;
        {
            let registry = recipient.registry();
            assert_eq!(registry.caches.len(), 2);
            assert!(registry.caches[1].native_binding.is_ok());
        }
        assert_eq!(store_header(&target)?, committed);
        fixture.exchange(&target, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn before_use_rejects_authority_and_name_collisions_and_applies_empty_intent() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let source_store = fixture.store(&source, 443)?;
    fixture.exchange(&source_store, false).await?;
    let snapshot = live_snapshot(&source, None)?;
    for (authority, name) in [("127.0.0.1", NAME), ("127.0.0.1:443", "other.example")] {
        let recipient = fixture.owner()?;
        recipient.import_tcp(&snapshot, &KEY, &decoding)?;
        let before = cold_snapshot(&recipient)?;
        let target = unused_connector(&fixture)?;
        let origin = endpoint(authority)?;
        let error = before_use(&recipient, &target, &origin, name)
            .err()
            .ok_or("accepted colliding owner")?;
        assert!(matches!(error.0, ImportError::OwnerMapping));
        assert_eq!(cold_snapshot(&recipient)?, before);
        assert_eq!(recipient.registry().caches.len(), 1);
        let cache = target
            .session_ticket_cache()
            .ok_or("target missing")?
            .upgrade()
            .ok_or("target dead")?;
        let stores = SessionTicketCacheOwner::capture_tcp_stores(&[(&cache, name)])?;
        assert_eq!(stores[0].header().record_count(), 0);
    }
    let empty_source = fixture.owner()?;
    let empty = fixture.store(&empty_source, 443)?;
    let recipient = fixture.owner()?;
    recipient.import_tcp(&live_snapshot(&empty_source, None)?, &KEY, &decoding)?;
    let target = fixture.store(&recipient, 443)?;
    fixture.exchange(&target, false).await?;
    assert!(store_header(&target)?.record_count() > 0);
    before_use(&recipient, &target, &endpoint("127.0.0.1:443")?, NAME)?;
    assert_eq!(store_header(&target)?, store_header(&empty)?);
    assert!(recipient.registry().cold.is_none());
    assert_eq!(recipient.registry().caches.len(), 1);
    fixture.exchange(&target, false).await?;
    Ok(())
}

#[tokio::test]
async fn clear_removes_mixed_live_and_cold_tickets_without_before_use_resurrection() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let first = fixture.store(&source, 443)?;
    let second = fixture.store(&source, 444)?;
    fixture.exchange(&first, false).await?;
    fixture.exchange(&second, false).await?;
    let recipient = fixture.owner()?;
    let live = fixture.store(&recipient, 443)?;
    recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?;
    let live_count = store_header(&live)?.record_count();
    let cold = cold_snapshot(&recipient)?;
    assert!(live_count > 0);
    assert_eq!(cold.owners.len(), 1);
    assert!(!cold.native.is_empty());
    assert_eq!(recipient.clear()?, live_count + cold.native.len());
    assert_eq!(recipient.clear()?, 0);
    assert!(recipient.registry().cold.is_none());
    assert_eq!(store_header(&live)?.record_count(), 0);
    let pending = unused_connector(&fixture)?;
    before_use(&recipient, &pending, &endpoint("127.0.0.1:444")?, NAME)?;
    assert_eq!(store_header(&pending)?.record_count(), 0);
    assert!(recipient.registry().cold.is_none());
    fixture.exchange(&live, false).await?;
    fixture.exchange(&pending, false).await?;
    Ok(())
}
