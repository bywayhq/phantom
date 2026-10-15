use super::super::super::*;
use super::peer::{Fixture, arrivals};
use crate::session_tickets::tcp_transfer::TcpSessionStoreHeader;
use crate::tls::test_support::{TEST_SERVER_NAME as NAME, TestResult};
use btls::ssl::{SslVersion, open_envelope, seal_envelope};

#[tokio::test]
async fn authenticated_replacement_preserves_three_orders_and_configured_limits() -> TestResult<()>
{
    for order in [
        TicketOrder::Newest,
        TicketOrder::OldestConnection,
        TicketOrder::Oldest,
    ] {
        for limit in [2, 10] {
            let source = Fixture::new(order, limit, SslVersion::TLS1_3)?;
            let recipient = Fixture::new(order, limit, SslVersion::TLS1_3)?;
            source.seed(3).await?;
            recipient.seed(1).await?;
            let expected = arrivals(&source.cache);
            let capture = recipient.cache.begin_handshake(NAME);
            let prepared = source.prepare(&recipient)?;
            let retired = TlsSessionOwner::replace_stores(vec![prepared])?;
            let actual = arrivals(&recipient.cache);
            assert_eq!(actual.0, expected.0);
            assert_eq!(actual.1, expected.1);
            assert!(!Arc::ptr_eq(&actual.2, &capture.generation));
            assert!(!capture.state().retired);
            assert!(retired.finish() > 0);
            assert!(capture.state().retired);
            let mut remaining = expected.0;
            while !remaining.is_empty() {
                let next = next_position(order, remaining.iter().copied().enumerate())
                    .ok_or("expected next missing")?;
                let before = arrivals(&recipient.cache).0;
                let ticket = recipient
                    .cache
                    .take(NAME)
                    .ok_or("imported ticket missing")?;
                assert!(ticket.is_authenticated());
                assert_eq!(before[next], remaining.remove(next));
                assert_eq!(arrivals(&recipient.cache).0, remaining);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn late_native_revocation_preserves_every_destination_and_generation() -> TestResult<()> {
    let source = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    source.seed(2).await?;
    let first = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    let second = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    first.seed(1).await?;
    second.seed(1).await?;
    let before = [arrivals(&first.cache), arrivals(&second.cache)];
    let prepared = vec![source.prepare(&first)?, source.prepare(&second)?];
    second.cache.scope().invalidate_transfer_policy();
    assert!(TlsSessionOwner::replace_stores(prepared).is_err());
    for (cache, expected) in [&first.cache, &second.cache].into_iter().zip(before) {
        let after = arrivals(cache);
        assert_eq!(after.0, expected.0);
        assert_eq!(after.1, expected.1);
        assert!(Arc::ptr_eq(&after.2, &expected.2));
    }
    Ok(())
}

#[tokio::test]
async fn restored_tls12_ticket_retains_its_actual_new_batch_and_reusable_policy() -> TestResult<()>
{
    let source = Fixture::new(TicketOrder::OldestConnection, 10, SslVersion::TLS1_2)?;
    let recipient = Fixture::new(TicketOrder::OldestConnection, 10, SslVersion::TLS1_2)?;
    source.seed(1).await?;
    let ticket = source.cache.take(NAME).ok_or("TLS 1.2 ticket missing")?;
    assert!(!ticket.should_be_single_use());
    let previous = source.cache.store().next_batch;
    source.cache.restore(NAME, ticket);
    assert_eq!(
        arrivals(&source.cache).0,
        [Arrival {
            batch: previous,
            sequence: 0
        }]
    );
    let prepared = source.prepare(&recipient)?;
    TlsSessionOwner::replace_stores(vec![prepared])?.finish();
    assert_eq!(
        arrivals(&recipient.cache).0,
        [Arrival {
            batch: previous,
            sequence: 0
        }]
    );
    let ticket = recipient
        .cache
        .take(NAME)
        .ok_or("imported TLS 1.2 ticket missing")?;
    assert!(!ticket.should_be_single_use());
    Ok(())
}

#[test]
fn empty_replacement_still_requires_live_native_binding_and_rejects_duplicates() -> TestResult<()> {
    let recipient = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let owner = recipient.cache.control().upgrade().ok_or("owner missing")?;
    let header = TcpSessionStoreHeader::parse(
        b"PHTCP001\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07",
    )?;
    let before = arrivals(&recipient.cache);
    let a = owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    let b = owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    assert!(matches!(
        TlsSessionOwner::replace_stores(vec![a, b]),
        Err(SessionTransferError::Policy)
    ));
    assert!(Arc::ptr_eq(&before.2, &arrivals(&recipient.cache).2));
    let capture = recipient.cache.begin_handshake(NAME);
    let valid = owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    let retired = TlsSessionOwner::replace_stores(vec![valid])?;
    assert_eq!(recipient.cache.store().next_batch, 7);
    assert_eq!(recipient.cache.len(), 0);
    assert!(!Arc::ptr_eq(&before.2, &arrivals(&recipient.cache).2));
    assert!(!capture.state().retired);
    assert_eq!(retired.finish(), 0);
    assert!(capture.state().retired);
    let before = arrivals(&recipient.cache);
    let prepared = owner.prepare_replacement(NAME.into(), header, Vec::new())?;
    recipient.cache.scope().invalidate_transfer_policy();
    assert!(matches!(
        TlsSessionOwner::replace_stores(vec![prepared]),
        Err(SessionTransferError::Policy)
    ));
    assert!(Arc::ptr_eq(&before.2, &arrivals(&recipient.cache).2));
    Ok(())
}

#[test]
fn configured_limit_and_unbound_source_do_not_gain_transfer_authority() -> TestResult<()> {
    let fixture = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let owner = fixture.cache.control().upgrade().ok_or("owner missing")?;
    let mismatched = TcpSessionStoreHeader::parse(
        b"PHTCP001\x00\x01\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    )?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), mismatched, Vec::new()),
        Err(SessionTransferError::Policy)
    ));
    let unbound = TlsSessionCache::new(2, TicketOrder::Newest, fixture.client.context().to_owned());
    let unbound_owner = unbound.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        TlsSessionOwner::capture_stores(&[(&unbound_owner, NAME)]),
        Err(SessionTransferError::Policy)
    ));
    assert!(matches!(
        TlsSessionOwner::capture_stores(&[(&owner, NAME), (&owner, NAME)]),
        Err(SessionTransferError::Policy)
    ));
    Ok(())
}

#[tokio::test]
async fn authenticated_but_malformed_storage_metadata_does_not_replace_live_tickets()
-> TestResult<()> {
    let source = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let recipient = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    source.seed(1).await?;
    recipient.seed(1).await?;
    let before = arrivals(&recipient.cache);
    let ticket = source.cache.take(NAME).ok_or("source missing")?;
    let record = source
        .binding
        .seal_session(&ticket, b"not a TCP storage frame", &[9; 32])?;
    let envelope = seal_envelope(&[record], &[9; 32])?;
    let mut verified = open_envelope(envelope.as_bytes(), &[9; 32], recipient.client.context())?;
    assert_eq!(verified.source_witness(0)?, &[0, 0]);
    let permit = verified.authorize_record(0, &recipient.binding)?;
    let header = TcpSessionStoreHeader::parse(
        b"PHTCP001\x00\x01\x00\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01",
    )?;
    let owner = recipient.cache.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), header, vec![permit]),
        Err(SessionTransferError::Malformed)
    ));
    let after = arrivals(&recipient.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}

#[test]
fn arrival_validation_preserves_holes_interleaving_saturation_and_exhaustion() {
    let prior = [
        Arrival {
            batch: 2,
            sequence: 4,
        },
        Arrival {
            batch: 7,
            sequence: 1,
        },
    ];
    assert!(
        transfer::validate_arrival(
            prior.into_iter(),
            Arrival {
                batch: 2,
                sequence: 6
            },
            9
        )
        .is_ok()
    );
    assert!(
        transfer::validate_arrival(
            prior.into_iter(),
            Arrival {
                batch: 2,
                sequence: 4
            },
            9
        )
        .is_err()
    );
    assert!(
        transfer::validate_arrival(
            prior.into_iter(),
            Arrival {
                batch: 2,
                sequence: 3
            },
            9
        )
        .is_err()
    );
    assert!(
        transfer::validate_arrival(
            std::iter::empty(),
            Arrival {
                batch: u64::MAX,
                sequence: 0
            },
            u64::MAX
        )
        .is_err()
    );
    assert!(
        transfer::validate_arrival(
            std::iter::empty(),
            Arrival {
                batch: u64::MAX - 1,
                sequence: 0
            },
            u64::MAX
        )
        .is_ok()
    );
    assert!(
        transfer::validate_arrival(
            [Arrival {
                batch: 2,
                sequence: u32::MAX
            }]
            .into_iter(),
            Arrival {
                batch: 2,
                sequence: u32::MAX
            },
            3
        )
        .is_ok()
    );
}
