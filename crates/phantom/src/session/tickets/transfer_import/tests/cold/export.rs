use btls::ssl::{PreparedSessionPolicyFreeze, SessionTransferError};

use super::*;
use crate::session::tickets::transfer::ExportError;

const EXPORT_KEY: [u8; 32] = [43; 32];

fn materialize(
    fixture: &ImportFixture,
    owner: &TicketOwner,
    port: u16,
) -> TestResult<Http1TlsConnector> {
    let connector = Http1TlsConnector::new_with_additional_roots(
        fixture.profile.tls(),
        fixture.roots.iter().map(AsRef::as_ref),
    )?
    .with_isolated_session_cache();
    let origin = Endpoint::new(format!("{NAME}:{port}").parse()?, 443)?;
    owner.register_before_use(
        connector.session_ticket_cache(),
        TicketCacheBinding {
            origin: &origin,
            server_name: NAME,
            leg: TicketCacheLeg::Origin,
            protocol: Ok(TicketCacheProtocol::Http1),
            route: &Route::Direct,
        },
    )?;
    Ok(connector)
}

#[tokio::test]
async fn mixed_export_preserves_original_cold_provenance_and_resumes_after_busy_retry() -> TestResult
{
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let fixture = ImportFixture::for_version(version)?;
        let decoding = decoding_context()?;
        let source = fixture.owner()?;
        let first = fixture.store(&source, 443)?;
        let second = fixture.store(&source, 444)?;
        fixture.exchange(&first, false).await?;
        fixture.exchange(&second, false).await?;
        let source_headers = (store_header(&first)?, store_header(&second)?);
        assert!(source_headers.0.record_count() > 0);
        assert!(source_headers.1.record_count() > 0);

        // Owner zero stays cold; owner one becomes live, reversing export order.
        let mixed = fixture.owner()?;
        let live = fixture.store(&mixed, 444)?;
        assert_eq!(
            mixed.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?,
            0
        );
        let live_before = store_header(&live)?;
        let cold_before = cold_snapshot(&mixed)?;
        assert_eq!(live_before, source_headers.1);
        assert_eq!(cold_before.owners.len(), 1);
        assert_eq!(cold_before.owners[0].authority, "127.0.0.1:443");
        assert_eq!(cold_before.owners[0].original_index, 0);
        assert_eq!(
            cold_before.owners[0].header,
            SessionTicketStoreHeader::Tcp(source_headers.0)
        );
        assert!(!cold_before.owners[0].slots.is_empty());

        let binding = {
            let registry = mixed.registry();
            registry.caches[0]
                .native_binding
                .as_ref()
                .map_err(|error| *error)?
                .clone()
        };
        let frozen = PreparedSessionPolicyFreeze::new(&[&binding])?.try_freeze()?;
        assert!(matches!(
            mixed.export(&EXPORT_KEY),
            Err(ExportError::Native(SessionTransferError::Busy))
        ));
        assert_eq!(cold_snapshot(&mixed)?, cold_before);
        drop(frozen);
        assert_eq!(store_header(&live)?, live_before);
        assert_eq!(
            (store_header(&first)?, store_header(&second)?),
            source_headers
        );

        let sealed = mixed.export(&EXPORT_KEY)?;
        assert_eq!(store_header(&live)?, live_before);
        assert_eq!(cold_snapshot(&mixed)?, cold_before);
        let opened = envelope::open_manifest(sealed.as_bytes(), &EXPORT_KEY)?;
        let owners = opened.owners().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[0].origin_port, 444);
        assert_eq!(
            owners[0].header,
            SessionTicketStoreHeader::Tcp(source_headers.1)
        );
        assert_eq!(owners[1].origin_port, 443);
        assert_eq!(owners[1].index, 1);
        assert_eq!(owners[1].record_owner_index, 0);
        assert_eq!(
            owners[1].header,
            SessionTicketStoreHeader::Tcp(source_headers.0)
        );
        assert_eq!(
            opened.record_count(),
            source_headers.0.record_count() + source_headers.1.record_count()
        );

        let native = btls::ssl::open_envelope(opened.native_ciphertext(), &EXPORT_KEY, &decoding)?;
        let cold_slots: Vec<_> = owners[1].slots().collect();
        assert_eq!(cold_slots.len(), cold_before.owners[0].slots.len());
        for (index, (slot, original)) in cold_slots
            .iter()
            .zip(&cold_before.owners[0].slots)
            .enumerate()
        {
            assert_eq!(
                usize::from(slot.native_slot),
                live_before.record_count() + index
            );
            assert_eq!(slot.physical_ordinal, original.physical_ordinal);
            let metadata_bytes = native.owner_metadata(usize::from(slot.native_slot))?;
            let metadata = TcpSessionRecordMetadata::parse(metadata_bytes)?;
            assert_eq!(metadata.ordinal(), usize::from(original.physical_ordinal));
            assert_eq!(metadata.payload(), b"PHTOW001\0\x01\0\0");
            assert_eq!(
                (
                    btls::sha::sha256(metadata_bytes),
                    btls::sha::sha256(native.source_witness(usize::from(slot.native_slot))?),
                ),
                cold_before.native[usize::from(original.native_slot)]
            );
        }

        let recipient = fixture.owner()?;
        assert_eq!(
            recipient.import_tcp(sealed.as_bytes(), &EXPORT_KEY, &decoding)?,
            0
        );
        assert!(recipient.registry().caches.is_empty());
        let recipient_cold = cold_snapshot(&recipient)?;
        assert_eq!(recipient_cold.owners.len(), 2);
        assert_eq!(recipient_cold.owners[1].original_index, 0);
        assert_eq!(
            recipient_cold.owners[1].header,
            SessionTicketStoreHeader::Tcp(source_headers.0)
        );
        let imported_first = materialize(&fixture, &recipient, 443)?;
        assert_eq!(store_header(&imported_first)?, source_headers.0);
        let remaining = cold_snapshot(&recipient)?;
        assert_eq!(remaining.owners.len(), 1);
        assert_eq!(remaining.owners[0].authority, "127.0.0.1:444");
        let imported_second = materialize(&fixture, &recipient, 444)?;
        assert_eq!(store_header(&imported_second)?, source_headers.1);
        assert!(recipient.registry().cold.is_none());
        assert_eq!(recipient.registry().caches.len(), 2);

        fixture.exchange(&imported_first, true).await?;
        fixture.exchange(&imported_second, true).await?;
        assert_eq!(store_header(&live)?, live_before);
        assert_eq!(cold_snapshot(&mixed)?, cold_before);
        assert_eq!(
            (store_header(&first)?, store_header(&second)?),
            source_headers
        );
    }
    Ok(())
}
