//! Verify authenticated ticket transfer over real QUIC v1 and v2 connections.

#![cfg(feature = "server")]

use std::{error::Error, sync::Arc};

use btls::ssl::{
    PreparedSessionPolicyFreeze, SessionTransferEnvelope, SslContext, open_envelope, seal_envelope,
};
use phantom_quic_btls::{
    QuicSessionRecordMetadata, QuicSessionStoreHeader, QuicSessionTicketCacheOwner,
};
use zeroize::Zeroizing;

use peer::{Client, Peers, Publication, with_cleanup};

#[path = "session_ticket_transfer/peer.rs"]
mod peer;

const HOST: &str = "foobar.com";
const APPLICATION: &[u8] = b"Q1 UDP application settings";
const PAYLOAD: &[u8] = b"Q1 UDP source owner";
const SNAPSHOT_KEY: [u8; 32] = [29; 32];
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn imported_udp_tickets_resume_once_per_record_without_consuming_source() -> TestResult {
    for version in [0x0000_0001, 0x6b33_43cf] {
        let peers = Peers::new(version)?;
        let result = transfer_and_resume(&peers).await;
        with_cleanup(result, peers.shutdown().await)?;
    }
    Ok(())
}

async fn transfer_and_resume(peers: &Peers) -> TestResult {
    let source = Client::new([7; 32])?;
    let recipient = Client::new([8; 32])?;
    assert!(!source.owner.same_cache(&recipient.owner));
    assert!(!source.config.has_ticket_for(HOST));
    assert!(!recipient.config.has_ticket_for(HOST));

    let first = peers.exchange(&source, Publication::Store).await?;
    assert!(!first.client.session_resumed());
    assert!(!first.server.session_resumed());
    assert_eq!(first.certificates.first(), Some(&peers.leaf_certificate));

    let snapshot = capture(&source.owner, &source.context)?;
    let count = snapshot.header.record_count();
    assert!((1..=4).contains(&count));
    assert_eq!(snapshot.header.excluded_expired_count(), 0);
    assert_eq!(snapshot.header.round_trip_time(), None);
    install(&recipient, &snapshot)?;

    let imported = capture(&recipient.owner, &recipient.context)?;
    assert_eq!(imported.header, snapshot.header);
    assert_eq!(imported.metadata, snapshot.metadata);

    let preserved = capture(&source.owner, &source.context)?;
    assert_eq!(preserved.header, snapshot.header);
    assert_eq!(preserved.metadata, snapshot.metadata);

    for remaining in (0..count).rev() {
        let resumed = peers.exchange(&recipient, Publication::Hold).await?;
        assert!(resumed.client.session_resumed());
        assert!(resumed.server.session_resumed());
        assert_eq!(resumed.certificates, first.certificates);
        assert_eq!(recipient.config.has_ticket_for(HOST), remaining != 0);
        assert_eq!(
            capture(&recipient.owner, &recipient.context)?
                .header
                .record_count(),
            remaining
        );
    }

    let exhausted = peers.exchange(&recipient, Publication::Hold).await?;
    assert!(!exhausted.client.session_resumed());
    assert!(!exhausted.server.session_resumed());
    assert_eq!(exhausted.certificates, first.certificates);
    assert!(!recipient.config.has_ticket_for(HOST));

    let preserved = peers.exchange(&source, Publication::Hold).await?;
    assert!(preserved.client.session_resumed());
    assert!(preserved.server.session_resumed());
    assert_eq!(preserved.certificates, first.certificates);
    assert_eq!(
        capture(&source.owner, &source.context)?
            .header
            .record_count(),
        count - 1
    );
    Ok(())
}

struct Snapshot {
    header: QuicSessionStoreHeader,
    envelope: SessionTransferEnvelope,
    metadata: Vec<Zeroizing<Vec<u8>>>,
}

fn capture(owner: &QuicSessionTicketCacheOwner, context: &SslContext) -> TestResult<Snapshot> {
    let mut plan = QuicSessionTicketCacheOwner::prepare_captures(&[(owner, HOST)])?
        .pop()
        .ok_or("capture plan absent")?;
    let binding = plan.binding().clone();
    let native_plan = PreparedSessionPolicyFreeze::new(&[&binding])?;
    let frozen = owner.freeze();
    let native = native_plan.try_freeze()?;
    let result = frozen.capture(&mut plan, &native);
    drop(native);
    drop(frozen);
    result?;

    let export = plan.into_export()?;
    let header = export.header();
    let mut records = Vec::new();
    for (ordinal, record) in export.into_records().into_iter().enumerate() {
        assert_eq!(record.ordinal(), ordinal);
        assert_eq!(record.application_state(), Some(APPLICATION));
        records.push(record.seal(PAYLOAD, &SNAPSHOT_KEY)?);
    }
    let envelope = seal_envelope(&records, &SNAPSHOT_KEY)?;
    let opened = open_envelope(envelope.as_bytes(), &SNAPSHOT_KEY, context)?;
    assert_eq!(opened.record_count(), header.record_count());

    let mut metadata = Vec::new();
    for index in 0..opened.record_count() {
        let bytes = opened.owner_metadata(index)?;
        let record = QuicSessionRecordMetadata::parse(bytes)?;
        assert_eq!(record.header(), header);
        assert_eq!(record.ordinal(), index);
        assert_eq!(record.hostname(), HOST);
        assert_eq!(record.application_state(), Some(APPLICATION));
        assert_eq!(record.payload(), PAYLOAD);
        assert_eq!(opened.source_witness(index)?, [0, 0]);
        record.validate_transport_parameters()?;
        metadata.push(Zeroizing::new(bytes.to_vec()));
    }
    Ok(Snapshot {
        header,
        envelope,
        metadata,
    })
}

fn install(client: &Client, snapshot: &Snapshot) -> TestResult {
    let mut opened = open_envelope(snapshot.envelope.as_bytes(), &SNAPSHOT_KEY, &client.context)?;
    let mut permits = Vec::new();
    for index in 0..opened.record_count() {
        assert_eq!(opened.owner_metadata(index)?, &*snapshot.metadata[index]);
        permits.push(opened.authorize_record(index, &client.binding)?);
    }
    let mut replacement =
        client
            .owner
            .prepare_replacement(Arc::from(HOST), snapshot.header, permits)?;
    let native_plan = PreparedSessionPolicyFreeze::new(&[&client.binding])?;
    // Keep retirement storage older than every guard, including on unwind.
    let retired;
    let mut frozen = client.owner.freeze();
    let native = native_plan.try_freeze()?;
    retired = frozen
        .validate_replacement(&mut replacement, &native)
        .map(|validated| validated.commit());
    drop(native);
    drop(frozen);
    assert_eq!(retired?.finish(), 0);
    Ok(())
}
