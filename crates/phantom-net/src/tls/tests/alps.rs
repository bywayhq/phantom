use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use btls::ssl::{AlpnError, Ssl, SslVersion, select_next_proto};
use phantom_profile::{
    TlsSettings, WebSocketSettings,
    browser::{
        chrome::{self, v154_tcp_tls},
        firefox,
    },
};
use phantom_testkit::tls::ClientHelloSummary;
use tokio::task::JoinHandle;
use tokio_btls::SslStream as BoringStream;
use tracing::{
    Dispatch, Event, Metadata, Subscriber, dispatcher,
    field::{Field, Visit},
    metadata::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::capture_connector_client_hello;
use crate::tls::{
    TlsConnector, TlsErrorKind, record_alps_negotiation,
    test_support::{
        H2_ALPN_WIRE, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, connect_local,
        loopback_listener,
    },
};

const H2: &[u8] = b"h2";

/// A connector cloned with a WebSocket policy's ALPN list sends the
/// ClientHello of a connector built from
/// `WebSocketConnectionPolicy::http1_tls_settings`: the same fields, with
/// only `http/1.1` offered and Chrome's ALPS offer dropped with `h2`. Both
/// ClientHellos are compared without GREASE values; Chrome permutes its
/// extensions on each connection, so only Firefox's order is compared as
/// sent.
#[tokio::test]
async fn a_connector_with_the_websocket_alpn_list_sends_the_policy_client_hello() -> TestResult<()>
{
    let recipes: [(TlsSettings, WebSocketSettings, bool); 2] = [
        (v154_tcp_tls(), chrome::v154_websocket(), false),
        (firefox::v157_tcp_tls(), firefox::v157_websocket(), true),
    ];
    for (tls, websocket, fixed_order) in recipes {
        let policy = &websocket.connection;
        let derived = TlsConnector::new(&tls)?.with_alpn_protocols(&policy.http1_alpn_protocols)?;
        let built = TlsConnector::new(&policy.http1_tls_settings(&tls))?;
        let derived = capture_connector_client_hello(&derived).await?.summary()?;
        let built = capture_connector_client_hello(&built).await?.summary()?;

        assert_eq!(derived.alpn_protocols(), [b"http/1.1".to_vec()]);
        assert_eq!(built.alpn_protocols(), derived.alpn_protocols());
        assert_eq!(Comparable::of(&derived), Comparable::of(&built));
        if fixed_order {
            assert_eq!(
                without_grease(derived.extension_types()),
                without_grease(built.extension_types())
            );
        }
        for alps in [ALPS_OLD_CODEPOINT, ALPS_NEW_CODEPOINT] {
            assert!(!derived.extension_types().contains(&alps));
        }
    }
    Ok(())
}

const ALPS_OLD_CODEPOINT: u16 = 0x4469;
const ALPS_NEW_CODEPOINT: u16 = 0x44cd;
const ECH: u16 = 0xfe0d;

/// The fields of a ClientHello that do not change between connections: its
/// values without GREASE, its extensions and their lengths sorted, and its
/// trust anchor IDs as a set. The GREASE ECH payload's length is left out,
/// since `EchGreasePayloadLength::BackendDefault` draws it on each
/// connection.
#[derive(Debug, Eq, PartialEq)]
struct Comparable {
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, usize)>,
    supported_groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    supported_versions: Vec<u16>,
    key_share_groups: Vec<u16>,
    trust_anchor_ids: Option<Vec<Vec<u8>>>,
}

impl Comparable {
    fn of(summary: &ClientHelloSummary) -> Self {
        let mut extensions = summary
            .extension_layout()
            .filter(|(extension, _)| !is_grease(*extension))
            .map(|(extension, length)| (extension, if extension == ECH { 0 } else { length }))
            .collect::<Vec<_>>();
        extensions.sort_unstable();
        let trust_anchor_ids = summary.requested_trust_anchor_ids().map(|ids| {
            let mut ids = ids.to_vec();
            ids.sort_unstable();
            ids
        });
        Self {
            cipher_suites: without_grease(summary.cipher_suites()),
            extensions,
            supported_groups: without_grease(summary.supported_groups()),
            ec_point_formats: summary.ec_point_formats().to_vec(),
            signature_algorithms: without_grease(summary.signature_algorithms()),
            supported_versions: without_grease(summary.supported_versions()),
            key_share_groups: without_grease(summary.key_share_groups()),
            trust_anchor_ids,
        }
    }
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

/// RFC 8701 GREASE values: both bytes equal, each `0x?a`.
const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

#[tokio::test]
async fn absent_alps_is_distinct_from_negotiated_empty_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_alps_server(&identity, None).await?;
    let connector = TlsConnector::new_with_roots(&v154_tcp_tls(), [identity.root_der()])?;

    let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.negotiated_alpn(), Some(H2));
    assert_eq!(stream.peer_application_settings(), None);

    let observed = tokio::time::timeout(TEST_TIMEOUT, server_task).await???;
    assert_eq!(observed, None);
    Ok(())
}

#[tokio::test]
async fn chromium_empty_alps_settings_are_preserved() -> TestResult<()> {
    let (client, server) = round_trip(&[], &[]).await?;
    assert_eq!(client, Some(Vec::new()));
    assert_eq!(server, Some(Vec::new()));
    Ok(())
}

#[tokio::test]
async fn nonempty_alps_settings_round_trip_exactly() -> TestResult<()> {
    let (client, server) = round_trip(b"client settings", b"server settings").await?;
    assert_eq!(client.as_deref(), Some(&b"server settings"[..]));
    assert_eq!(server.as_deref(), Some(&b"client settings"[..]));
    Ok(())
}

#[test]
fn oversized_alps_settings_fail_before_stream_io() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings
        .alps
        .as_mut()
        .ok_or("Chrome profile omitted ALPS")?
        .settings = vec![0; u16::MAX as usize + 1].into_boxed_slice();

    let error = match TlsConnector::new_with_roots(&settings, std::iter::empty::<&[u8]>()) {
        Ok(_) => return Err("oversized ALPS settings built a TLS connector".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), TlsErrorKind::InvalidConfiguration);
    assert_eq!(error.to_string(), "invalid TLS settings");
    let source = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<phantom_profile::InvalidTlsSettings>())
        .ok_or("TLS error omitted its original validator source")?;
    assert!(source.to_string().contains("alps.settings"));
    Ok(())
}

#[test]
fn handshake_trace_records_alps_state_without_payload() {
    let subscriber = AlpsSubscriber::default();
    let dispatch = Dispatch::new(subscriber.clone());
    let span = dispatcher::with_default(&dispatch, || {
        tracing::debug_span!(
            "test.tls.handshake",
            alps_negotiated = tracing::field::Empty,
            peer_application_settings_len = tracing::field::Empty,
        )
    });
    record_alps_negotiation(&span, Some(b"server settings"));

    let state = subscriber.state();
    assert_eq!(state.negotiated, Some(true));
    assert_eq!(state.peer_settings_len, Some(15));
    assert!(!state.saw_bytes, "trace exposed the opaque ALPS payload");
}

async fn round_trip(
    client_settings: &[u8],
    server_settings: &'static [u8],
) -> TestResult<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_alps_server(&identity, Some(server_settings)).await?;
    let mut settings = v154_tcp_tls();
    settings
        .alps
        .as_mut()
        .ok_or("Chrome profile omitted ALPS")?
        .settings = client_settings.into();
    let connector = TlsConnector::new_with_roots(&settings, [identity.root_der()])?;

    let stream = connect_local(&connector, address, TEST_SERVER_NAME).await??;
    assert_eq!(stream.negotiated_alpn(), Some(H2));
    let peer_settings = stream.peer_application_settings().map(ToOwned::to_owned);
    drop(stream);

    let observed = tokio::time::timeout(TEST_TIMEOUT, server_task).await???;
    Ok((peer_settings, observed))
}

async fn start_alps_server(
    identity: &TestIdentity,
    application_settings: Option<&'static [u8]>,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Option<Vec<u8>>>>)> {
    let mut acceptor = identity.acceptor_builder()?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();

    let (address, listener) = loopback_listener().await?;
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut ssl = Ssl::new(acceptor.context())?;
        if let Some(settings) = application_settings {
            ssl.add_application_settings_with_payload(H2, settings)?;
            ssl.set_alps_use_new_codepoint(true);
        }
        let mut stream = BoringStream::new(ssl, tcp)?;
        Pin::new(&mut stream).accept().await?;
        Ok(stream
            .ssl()
            .peer_application_settings()
            .map(ToOwned::to_owned))
    });
    Ok((address, task))
}

#[derive(Clone, Default)]
struct AlpsSubscriber {
    next_span_id: Arc<AtomicU64>,
    state: Arc<Mutex<TraceState>>,
}

#[derive(Default)]
struct TraceState {
    negotiated: Option<bool>,
    peer_settings_len: Option<u64>,
    saw_bytes: bool,
}

impl AlpsSubscriber {
    fn state(&self) -> MutexGuard<'_, TraceState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Subscriber for AlpsSubscriber {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let _ = attributes;
        Id::from_u64(self.next_span_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &Id, values: &Record<'_>) {
        let mut state = self.state();
        let mut visitor = AlpsVisitor::default();
        values.record(&mut visitor);
        if let Some(value) = visitor.negotiated {
            state.negotiated = Some(value);
        }
        if let Some(value) = visitor.peer_settings_len {
            state.peer_settings_len = Some(value);
        }
        state.saw_bytes |= visitor.saw_bytes;
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct AlpsVisitor {
    negotiated: Option<bool>,
    peer_settings_len: Option<u64>,
    saw_bytes: bool,
}

impl Visit for AlpsVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "alps_negotiated" {
            self.negotiated = Some(value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "peer_application_settings_len" {
            self.peer_settings_len = Some(value);
        }
    }

    fn record_bytes(&mut self, _field: &Field, _value: &[u8]) {
        self.saw_bytes = true;
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        match field.name() {
            "alps_negotiated" => self.negotiated = value.parse().ok(),
            "peer_application_settings_len" => self.peer_settings_len = value.parse().ok(),
            _ => {}
        }
    }
}
