use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use btls::ssl::{AlpnError, Ssl, SslVersion, select_next_proto};
use phantom_profile::chromium::v154_tls;
use tokio::task::JoinHandle;
use tokio_btls::SslStream as BoringStream;
use tracing::{
    Dispatch, Event, Metadata, Subscriber, dispatcher,
    field::{Field, Visit},
    metadata::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use crate::tls::{
    TlsConnector, TlsErrorKind, record_alps_negotiation,
    test_support::{
        H2_ALPN_WIRE, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, connect_local,
        loopback_listener,
    },
};

const H2: &[u8] = b"h2";

#[tokio::test]
async fn absent_alps_is_distinct_from_negotiated_empty_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, server_task) = start_alps_server(&identity, None).await?;
    let connector = TlsConnector::new_with_roots(&v154_tls(), [identity.root_der()])?;

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
    let mut settings = v154_tls();
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
    assert!(error.to_string().contains("alps.settings"));
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
    let mut settings = v154_tls();
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
