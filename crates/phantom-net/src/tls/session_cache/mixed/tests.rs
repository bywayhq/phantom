mod real_records;

use super::*;
use btls::ssl::{SslConnector, SslContext, SslMethod, SslVerifyMode};
use phantom_quic_btls::QuicClientConfig;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NAME: &str = "mixed.example";

struct Stores {
    tcp: TlsSessionCache,
    quic: QuicClientConfig,
    tcp_owner: TlsSessionOwner,
    quic_owner: QuicSessionTicketCacheOwner,
    empty_quic_header: QuicSessionStoreHeader,
}

impl Stores {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut context = SslConnector::builder(SslMethod::tls())?;
        context.set_verify(SslVerifyMode::PEER);
        context.enable_scoped_client_sessions();
        let tcp = TlsSessionCache::new(
            10,
            TicketOrder::Newest,
            context.build().context().to_owned(),
        );
        let tcp_owner = tcp.control().upgrade().ok_or("missing TCP owner")?;
        let mut context = SslContext::builder(SslMethod::tls())?;
        context.set_verify(SslVerifyMode::PEER);
        QuicClientConfig::enable_session_resumption(&mut context)?;
        let quic = QuicClientConfig::new(context.build())
            .with_tls_profile(&phantom_profile::browser::chrome::v154_quic_tls())?
            .with_isolated_session_cache();
        let quic_owner = quic
            .session_ticket_cache()
            .and_then(|cache| cache.upgrade())
            .ok_or("missing QUIC owner")?;
        tcp_owner.bind_transfer_policy(
            NAME,
            SessionTransferPolicy::new(b"mixed TCP control", &[0, 0], None, &[7; 32])?,
        )?;
        quic_owner.bind_transfer_policy(
            NAME,
            SessionTransferPolicy::new(b"mixed QUIC control", &[0, 0], None, &[8; 32])?,
        )?;
        let empty_quic_header =
            match capture_stores(&[(MixedSessionOwner::Quic(&quic_owner), NAME)])?.pop() {
                Some(MixedSessionStoreExport::Quic(export)) => export.header(),
                _ => return Err("missing fresh QUIC store header".into()),
            };
        Ok(Self {
            tcp,
            quic,
            tcp_owner,
            quic_owner,
            empty_quic_header,
        })
    }

    fn tcp_header() -> TcpSessionStoreHeader {
        TcpSessionStoreHeader {
            order: 0,
            per_hostname: 10,
            physical: 0,
            records: 0,
            next_batch: 0,
        }
    }

    fn replacements(
        &self,
    ) -> Result<Vec<PreparedMixedSessionReplacement<'_>>, SessionTransferError> {
        Ok(vec![
            PreparedMixedSessionReplacement::new(
                MixedSessionOwner::Quic(&self.quic_owner),
                Arc::from(NAME),
                MixedSessionStoreHeader::Quic(self.empty_quic_header),
                Vec::new(),
            )?,
            PreparedMixedSessionReplacement::new(
                MixedSessionOwner::Tcp(&self.tcp_owner),
                Arc::from(NAME),
                MixedSessionStoreHeader::Tcp(Self::tcp_header()),
                Vec::new(),
            )?,
        ])
    }
}

#[test]
fn mixed_capture_preserves_input_transport_order_and_quic_rtt() -> TestResult {
    let stores = Stores::new()?;
    let rtt = std::time::Duration::new(3, 17);
    stores.quic.record_round_trip_time(NAME, rtt);
    let captured = capture_stores(&[
        (MixedSessionOwner::Quic(&stores.quic_owner), NAME),
        (MixedSessionOwner::Tcp(&stores.tcp_owner), NAME),
    ])?;
    assert_eq!(captured.len(), 2);
    assert!(matches!(&captured[0], MixedSessionStoreExport::Quic(export)
        if export.header().record_count() == 0 && export.header().round_trip_time() == Some(rtt)));
    assert!(matches!(&captured[1], MixedSessionStoreExport::Tcp(export)
        if export.header() == Stores::tcp_header()));
    let duplicate = capture_stores(&[
        (MixedSessionOwner::Quic(&stores.quic_owner), NAME),
        (MixedSessionOwner::Tcp(&stores.tcp_owner), NAME),
        (MixedSessionOwner::Quic(&stores.quic_owner), NAME),
    ]);
    assert!(matches!(duplicate, Err(SessionTransferError::Policy)));
    Ok(())
}

#[test]
fn final_quic_owner_rejection_preserves_earlier_tcp_generation_and_publication() -> TestResult {
    let stores = Stores::new()?;
    let other = Stores::new()?;
    let rtt = std::time::Duration::from_millis(23);
    stores.quic.record_round_trip_time(NAME, rtt);
    let mut replacements = stores.replacements()?;
    // Genuine plan for one owner, but deliberately supply a different real guard.
    replacements[0].owner = MixedSessionOwner::Quic(&other.quic_owner);
    let capture = stores.tcp.begin_handshake(NAME);
    let generation = Arc::clone(&capture.generation);
    let result = replace_stores(replacements);
    assert!(matches!(result, Err(SessionTransferError::Policy)));
    assert!(Arc::ptr_eq(&stores.tcp.store().generation, &generation));
    assert!(!capture.state().retired);
    assert!(stores.tcp.store().sessions.is_empty());
    assert_eq!(stores.quic_owner.freeze().retained_count(), 0);
    assert_eq!(other.quic_owner.freeze().retained_count(), 0);
    let snapshot = capture_stores(&[(MixedSessionOwner::Quic(&stores.quic_owner), NAME)])?;
    assert!(matches!(&snapshot[0], MixedSessionStoreExport::Quic(export)
        if export.header().round_trip_time() == Some(rtt)));
    Ok(())
}

#[test]
fn native_busy_preserves_both_stores_and_a_freshly_prepared_retry_succeeds() -> TestResult {
    let stores = Stores::new()?;
    let rtt = std::time::Duration::from_millis(41);
    stores.quic.record_round_trip_time(NAME, rtt);
    let binding = stores.tcp_owner.bind_transfer_policy(
        NAME,
        SessionTransferPolicy::new(b"mixed TCP control", &[0, 0], None, &[7; 32])?,
    )?;
    let capture = stores.tcp.begin_handshake(NAME);
    let generation = Arc::clone(&capture.generation);
    let bindings = [&binding];
    let native_plan = PreparedSessionPolicyFreeze::new(&bindings)?;
    let native = native_plan.try_freeze()?;
    let result = replace_stores(stores.replacements()?);
    drop(native);
    assert!(matches!(result, Err(SessionTransferError::Busy)));
    assert!(Arc::ptr_eq(&stores.tcp.store().generation, &generation));
    assert!(!capture.state().retired);
    let snapshot = capture_stores(&[(MixedSessionOwner::Quic(&stores.quic_owner), NAME)])?;
    assert!(matches!(&snapshot[0], MixedSessionStoreExport::Quic(export)
        if export.header().round_trip_time() == Some(rtt)));
    let retired = replace_stores(stores.replacements()?)?;
    assert!(!Arc::ptr_eq(&stores.tcp.store().generation, &generation));
    assert!(!capture.state().retired);
    assert_eq!(retired.finish(), 0);
    assert!(capture.state().retired);
    let snapshot = capture_stores(&[(MixedSessionOwner::Quic(&stores.quic_owner), NAME)])?;
    assert!(matches!(&snapshot[0], MixedSessionStoreExport::Quic(export)
        if export.header().round_trip_time().is_none()));
    Ok(())
}

#[test]
fn mixed_replacement_rejects_aliases_and_owner_header_kind_mismatch() -> TestResult {
    let stores = Stores::new()?;
    assert!(matches!(
        PreparedMixedSessionReplacement::new(
            MixedSessionOwner::Quic(&stores.quic_owner),
            Arc::from(NAME),
            MixedSessionStoreHeader::Tcp(Stores::tcp_header()),
            Vec::new(),
        ),
        Err(SessionTransferError::Policy)
    ));
    let mut replacements = stores.replacements()?;
    replacements.push(PreparedMixedSessionReplacement::new(
        MixedSessionOwner::Tcp(&stores.tcp_owner),
        Arc::from(NAME),
        MixedSessionStoreHeader::Tcp(Stores::tcp_header()),
        Vec::new(),
    )?);
    assert!(matches!(
        replace_stores(replacements),
        Err(SessionTransferError::Policy)
    ));
    assert!(stores.tcp.store().sessions.is_empty());
    Ok(())
}

#[test]
fn transfer_bounds_apply_to_the_combined_owner_and_record_counts() -> TestResult {
    check_totals(256, 2560)?;
    assert!(matches!(
        check_totals(257, 0),
        Err(SessionTransferError::TooLarge)
    ));
    assert!(matches!(
        check_totals(1, 2561),
        Err(SessionTransferError::TooLarge)
    ));
    let stores = Stores::new()?;
    let inputs = vec![(MixedSessionOwner::Tcp(&stores.tcp_owner), NAME); 257];
    assert!(matches!(
        capture_stores(&inputs),
        Err(SessionTransferError::TooLarge)
    ));
    Ok(())
}
