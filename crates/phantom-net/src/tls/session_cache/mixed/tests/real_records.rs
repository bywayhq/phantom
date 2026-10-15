//! Genuine native TCP and QUIC records at the shared frozen-store boundary.

mod quic_peer;

use std::{
    sync::{TryLockError, mpsc},
    thread,
    time::{Duration, Instant},
};

use btls::ssl::{SessionImportPermit, SslVersion, open_envelope, seal_envelope};
use phantom_quic_btls::QuicSessionRecordMetadata;

use super::super::*;
use crate::session_tickets::tcp_transfer::TcpSessionRecordMetadata;
use crate::tls::session_cache::tests::transaction::peer::{Fixture as TcpFixture, arrivals};
use crate::tls::test_support::{TEST_SERVER_NAME as TCP_NAME, TestResult};

const SOURCE_APPLICATION: &[u8] = b"mixed source application";
const OLD_APPLICATION: &[u8] = b"mixed old application";
const PAYLOAD: &[u8] = b"mixed fixture owner";
const SNAPSHOT_KEY: [u8; 32] = [53; 32];

struct Stores {
    tcp: TcpFixture,
    tcp_owner: TlsSessionOwner,
    quic: quic_peer::Fixture,
}

impl Stores {
    fn new() -> TestResult<Self> {
        Self::from_parts(
            TcpFixture::new(TicketOrder::Newest, 10, SslVersion::TLS1_3)?,
            quic_peer::Fixture::new()?,
        )
    }

    fn from_parts(tcp: TcpFixture, quic: quic_peer::Fixture) -> TestResult<Self> {
        let tcp_owner = tcp.cache.control().upgrade().ok_or("TCP owner absent")?;
        Ok(Self {
            tcp,
            tcp_owner,
            quic,
        })
    }

    fn fork_empty(&self) -> TestResult<Self> {
        Self::from_parts(self.tcp.fork_empty()?, self.quic.fork_empty()?)
    }

    async fn seed(&self, connections: usize, application: &[u8]) -> TestResult<()> {
        self.tcp.seed(connections).await?;
        self.quic.seed(application)?;
        Ok(())
    }

    fn exports(&self) -> Result<Vec<MixedSessionStoreExport>, SessionTransferError> {
        // Caller order differs from the required lock order.
        capture_stores(&[
            (MixedSessionOwner::Quic(&self.quic.owner), quic_peer::HOST),
            (MixedSessionOwner::Tcp(&self.tcp_owner), TCP_NAME),
        ])
    }

    fn prepare<'a>(
        &self,
        recipient: &'a Self,
    ) -> TestResult<Vec<PreparedMixedSessionReplacement<'a>>> {
        let mut prepared = Vec::new();
        for export in self.exports()? {
            let (owner, hostname, context, binding, header, records) = match export {
                MixedSessionStoreExport::Tcp(export) => {
                    let header = export.header();
                    let records = export
                        .into_records()
                        .into_iter()
                        .map(|record| record.seal(PAYLOAD, &SNAPSHOT_KEY))
                        .collect::<Result<Vec<_>, _>>()?;
                    (
                        MixedSessionOwner::Tcp(&recipient.tcp_owner),
                        TCP_NAME,
                        recipient.tcp.client.context(),
                        &recipient.tcp.binding,
                        MixedSessionStoreHeader::Tcp(header),
                        records,
                    )
                }
                MixedSessionStoreExport::Quic(export) => {
                    let header = export.header();
                    let records = export
                        .into_records()
                        .into_iter()
                        .map(|record| record.seal(PAYLOAD, &SNAPSHOT_KEY))
                        .collect::<Result<Vec<_>, _>>()?;
                    (
                        MixedSessionOwner::Quic(&recipient.quic.owner),
                        quic_peer::HOST,
                        &*recipient.quic.context,
                        &recipient.quic.binding,
                        MixedSessionStoreHeader::Quic(header),
                        records,
                    )
                }
            };
            assert!(!records.is_empty());
            let envelope = seal_envelope(&records, &SNAPSHOT_KEY)?;
            let mut opened = open_envelope(envelope.as_bytes(), &SNAPSHOT_KEY, context)?;
            let mut permits: Vec<SessionImportPermit> = Vec::new();
            for index in 0..records.len() {
                // Both real bindings explicitly configure the absent two-leg
                // witness. Parsing metadata alone never grants authority.
                assert_eq!(opened.source_witness(index)?, &[0, 0]);
                let metadata = opened.owner_metadata(index)?;
                match &header {
                    MixedSessionStoreHeader::Tcp(header) => {
                        let shape = TcpSessionRecordMetadata::parse(metadata)?;
                        assert_eq!(shape.header(), *header);
                        assert_eq!(shape.hostname(), hostname);
                        assert_eq!(shape.payload(), PAYLOAD);
                    }
                    MixedSessionStoreHeader::Quic(header) => {
                        let shape = QuicSessionRecordMetadata::parse(metadata)?;
                        assert_eq!(shape.header(), *header);
                        assert_eq!(shape.hostname(), hostname);
                        assert_eq!(shape.payload(), PAYLOAD);
                        shape.validate_transport_parameters()?;
                        assert_eq!(shape.application_state(), Some(SOURCE_APPLICATION));
                    }
                }
                permits.push(opened.authorize_record(index, binding)?);
            }
            prepared.push(PreparedMixedSessionReplacement::new(
                owner,
                Arc::from(hostname),
                header,
                permits,
            )?);
        }
        assert_eq!(prepared.len(), 2);
        Ok(prepared)
    }

    fn snapshot(&self) -> TestResult<Vec<Vec<Vec<u8>>>> {
        let mut snapshot = Vec::new();
        for export in self.exports()? {
            let (context, records) = match export {
                MixedSessionStoreExport::Tcp(export) => (
                    self.tcp.client.context(),
                    export
                        .into_records()
                        .into_iter()
                        .map(|record| record.seal(PAYLOAD, &SNAPSHOT_KEY))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                MixedSessionStoreExport::Quic(export) => (
                    &*self.quic.context,
                    export
                        .into_records()
                        .into_iter()
                        .map(|record| record.seal(PAYLOAD, &SNAPSHOT_KEY))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            };
            let envelope = seal_envelope(&records, &SNAPSHOT_KEY)?;
            let opened = open_envelope(envelope.as_bytes(), &SNAPSHOT_KEY, context)?;
            snapshot.push(
                (0..records.len())
                    .map(|index| opened.owner_metadata(index).map(<[u8]>::to_vec))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(snapshot)
    }
}

#[tokio::test]
async fn late_quic_owner_rejection_preserves_both_real_ticket_stores() -> TestResult<()> {
    let source = Stores::new()?;
    let recipient = source.fork_empty()?;
    let other = source.fork_empty()?;
    source.seed(2, SOURCE_APPLICATION).await?;
    recipient.seed(1, OLD_APPLICATION).await?;
    source
        .quic
        .config
        .record_round_trip_time(quic_peer::HOST, Duration::new(0, 12_345_678));
    recipient
        .quic
        .config
        .record_round_trip_time(quic_peer::HOST, Duration::from_millis(41));
    let source_before = source.snapshot()?;
    let recipient_before = recipient.snapshot()?;
    let tcp_before = arrivals(&recipient.tcp.cache);
    let capture = recipient.tcp.cache.begin_handshake(TCP_NAME);
    let pending_quic = recipient.quic.pending_ticket()?;
    let quic_before = recipient.quic.count();
    let mut prepared = source.prepare(&recipient)?;
    // This is the final validation in the TCP-first transaction: the real
    // QUIC plan belongs to recipient, but its supplied guard belongs to other.
    prepared[0].owner = MixedSessionOwner::Quic(&other.quic.owner);
    assert!(matches!(
        replace_stores(prepared),
        Err(SessionTransferError::Policy)
    ));
    let tcp_after = arrivals(&recipient.tcp.cache);
    assert_eq!(tcp_after.0, tcp_before.0);
    assert_eq!(tcp_after.1, tcp_before.1);
    assert!(Arc::ptr_eq(&tcp_after.2, &tcp_before.2));
    assert!(!capture.state().retired);
    assert_eq!(recipient.snapshot()?, recipient_before);
    assert_eq!(source.snapshot()?, source_before);
    assert_eq!(other.quic.count(), 0);

    // Prove the old tickets are still usable before allowing a held new ticket
    // to publish. Publication must then reach the same old QUIC generation.
    recipient.tcp.resume().await?;
    recipient.quic.resume()?;
    assert_eq!(recipient.quic.count(), quic_before - 1);
    assert!(pending_quic.store(OLD_APPLICATION));
    assert!(recipient.quic.count() > quic_before - 1);
    assert_eq!(source.snapshot()?, source_before);
    Ok(())
}

#[tokio::test]
async fn mixed_real_replacement_preserves_sources_and_defers_retirement_until_unlock()
-> TestResult<()> {
    let source = Stores::new()?;
    let recipient = source.fork_empty()?;
    source.seed(2, SOURCE_APPLICATION).await?;
    recipient.seed(1, OLD_APPLICATION).await?;
    source
        .quic
        .config
        .record_round_trip_time(quic_peer::HOST, Duration::new(0, 12_345_678));
    recipient
        .quic
        .config
        .record_round_trip_time(quic_peer::HOST, Duration::from_millis(41));
    let source_before = source.snapshot()?;
    let old_tcp = arrivals(&recipient.tcp.cache);
    let old_count = old_tcp.0.len() + recipient.quic.count();
    let capture = recipient.tcp.cache.begin_handshake(TCP_NAME);
    let retirement_probe = recipient.quic.pending_ticket()?;
    let pending_quic = recipient.quic.pending_ticket()?;
    let prepared = source.prepare(&recipient)?;
    let retired = replace_stores(prepared)?;
    let replaced = arrivals(&recipient.tcp.cache);
    assert!(!Arc::ptr_eq(&replaced.2, &old_tcp.2));
    assert!(!capture.state().retired);
    // The native/store guards have returned before deferred destruction and
    // publication retirement. A held TCP guard would make this check fail.
    assert!(recipient.tcp.cache.inner.store.try_lock().is_ok());
    // A held old-generation handle has not been marked refused yet, but its
    // late publication must not enter the newly replaced store.
    assert!(retirement_probe.store(OLD_APPLICATION));
    assert_eq!(recipient.snapshot()?, source_before);
    assert_eq!(source.snapshot()?, source_before);
    assert!(retired.finish() > old_count);
    assert!(capture.state().retired);
    assert!(!pending_quic.store(OLD_APPLICATION));

    recipient.tcp.resume().await?;
    recipient.quic.resume()?;
    assert_eq!(source.snapshot()?, source_before);
    // Actual source-issued sessions were copied, not consumed by capture or
    // replacement, and still resume against the same authenticated issuer.
    source.tcp.resume().await?;
    source.quic.resume()?;
    Ok(())
}

fn observes_tcp_first(
    stores: &Stores,
    operation: impl FnOnce() -> Result<usize, SessionTransferError> + Send,
) -> TestResult<usize> {
    thread::scope(|scope| {
        let held_quic = stores.quic.owner.freeze();
        let (start_tx, start_rx) = mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(10);
        let worker = thread::Builder::new()
            .name("mixed-ticket-order".into())
            .spawn_scoped(scope, move || {
                let started = start_tx.send(());
                let result = operation();
                (started, result)
            })?;
        let started = start_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let tcp_blocked = if started.is_ok() {
            loop {
                match stores.tcp.cache.inner.store.try_lock() {
                    Err(TryLockError::WouldBlock) => break Ok(true),
                    Err(TryLockError::Poisoned(_)) => break Err("TCP store poisoned"),
                    Ok(guard) => drop(guard),
                }
                if Instant::now() >= deadline {
                    break Ok(false);
                }
                thread::yield_now();
            }
        } else {
            Ok(false)
        };
        // Release before every assertion/error return and join the only worker.
        // Reversing the implementation's order can fail without stranding it.
        drop(held_quic);
        let joined = worker.join();
        started?;
        let (sent, result) = joined.map_err(|_| "mixed ticket worker panicked")?;
        sent?;
        let count = result?;
        assert!(tcp_blocked?, "operation waited on QUIC before locking TCP");
        Ok(count)
    })
}

#[tokio::test]
async fn real_mixed_replacement_and_clear_lock_tcp_before_a_held_quic_store() -> TestResult<()> {
    let source = Stores::new()?;
    let recipient = source.fork_empty()?;
    source.seed(2, SOURCE_APPLICATION).await?;
    recipient.seed(1, OLD_APPLICATION).await?;
    let prepared = source.prepare(&recipient)?;
    assert!(
        observes_tcp_first(&recipient, || {
            replace_stores(prepared).map(RetiredMixedSessionStores::finish)
        })? > 0
    );
    recipient.tcp.resume().await?;
    recipient.quic.resume()?;

    let owners = [
        crate::SessionTicketCache::quic(
            recipient
                .quic
                .config
                .session_ticket_cache()
                .ok_or("QUIC cache absent")?,
        )
        .upgrade()
        .ok_or("QUIC owner absent")?,
        crate::SessionTicketCache::tcp(recipient.tcp.cache.control())
            .upgrade()
            .ok_or("TCP owner absent")?,
    ];
    assert!(
        observes_tcp_first(&recipient, || {
            crate::SessionTicketCacheOwner::clear_stores(&owners)
        })? > 0
    );
    assert_eq!(recipient.tcp.cache.len(), 0);
    assert_eq!(recipient.quic.count(), 0);
    Ok(())
}
