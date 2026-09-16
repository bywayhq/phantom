use std::{
    any::Any,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use assert_matches::assert_matches;

use super::*;

#[derive(Clone, Copy)]
enum Failure {
    Error,
    Unavailable,
}

struct FailingClientConfig {
    inner: Arc<dyn crypto::ClientConfig>,
    fail_on_call: usize,
    failure: Failure,
}

impl crypto::ClientConfig for FailingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let inner = self
            .inner
            .clone()
            .start_session(version, server_name, params)?;
        Ok(Box::new(FailingSession {
            inner,
            fail_on_call: self.fail_on_call,
            calls: AtomicUsize::new(0),
            failure: self.failure,
        }))
    }
}

struct FailingServerConfig {
    inner: Arc<dyn crypto::ServerConfig>,
    fail_on_call: usize,
    failure: Failure,
}

impl crypto::ServerConfig for FailingServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        Box::new(FailingSession {
            inner: self.inner.clone().start_session(version, params),
            fail_on_call: self.fail_on_call,
            calls: AtomicUsize::new(0),
            failure: self.failure,
        })
    }
}

struct FailingSession {
    inner: Box<dyn crypto::Session>,
    fail_on_call: usize,
    calls: AtomicUsize,
    failure: Failure,
}

impl crypto::Session for FailingSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Result<Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>>, TransportError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if call == self.fail_on_call {
            return match self.failure {
                Failure::Error => Err(TransportError::KEY_UPDATE_ERROR("injected failure")),
                Failure::Unavailable => Ok(None),
            };
        }
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

fn failing_client_config(fail_on_call: usize, failure: Failure) -> ClientConfig {
    ClientConfig::new(Arc::new(FailingClientConfig {
        inner: Arc::new(client_crypto()),
        fail_on_call,
        failure,
    }))
}

fn failing_server_config(fail_on_call: usize, failure: Failure) -> ServerConfig {
    ServerConfig::with_crypto(Arc::new(FailingServerConfig {
        inner: Arc::new(server_crypto()),
        fail_on_call,
        failure,
    }))
}

fn assert_internal_error(event: Option<Event>) {
    assert_matches!(
        event,
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(ref error),
        }) if error.code == TransportErrorCode::INTERNAL_ERROR
    );
}

#[test]
fn initial_1rtt_key_failure_closes_with_internal_error() {
    for failure in [Failure::Error, Failure::Unavailable] {
        let mut pair = Pair::default();
        let client = pair.begin_connect(failing_client_config(1, failure));
        pair.drive();

        let connection = pair.client_conn_mut(client);
        let events: Vec<_> = std::iter::from_fn(|| connection.poll()).collect();
        assert!(!events.iter().any(|event| matches!(event, Event::Connected)));
        assert_internal_error(
            events
                .into_iter()
                .find(|event| matches!(event, Event::ConnectionLost { .. })),
        );
    }
}

#[test]
fn forced_key_failure_preserves_key_state() {
    let mut pair = Pair::default();
    let (client, _) = pair.connect_with(failing_client_config(2, Failure::Error));
    let now = pair.time;
    let before = pair.client_conn_mut(client).key_update_state();

    pair.client_conn_mut(client).force_key_update();

    let connection = pair.client_conn_mut(client);
    let mut buffer = Vec::new();
    assert!(connection.poll_transmit(now, 1, &mut buffer).is_none());
    assert!(buffer.is_empty());
    assert_eq!(connection.key_update_state(), before);
    assert_internal_error(connection.poll());
}

#[test]
fn automatic_key_failure_emits_no_packet_and_preserves_key_state() {
    let mut pair = Pair::default();
    let (client, _) = pair.connect_with(failing_client_config(2, Failure::Error));
    let now = pair.time;
    let connection = pair.client_conn_mut(client);
    connection.exhaust_key_phase_for_test();
    connection.ping();
    let before = connection.key_update_state();
    let mut buffer = Vec::new();

    assert!(connection.poll_transmit(now, 1, &mut buffer).is_none());
    assert!(buffer.is_empty());
    assert_eq!(connection.key_update_state(), before);
    assert_internal_error(connection.poll());
}

#[test]
fn peer_key_failure_preserves_key_state() {
    let mut pair = Pair::new(Default::default(), failing_server_config(2, Failure::Error));
    let (client, server) = pair.connect();
    let before = pair.server_conn_mut(server).key_update_state();

    pair.client_conn_mut(client).force_key_update();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    pair.drive_server();

    let connection = pair.server_conn_mut(server);
    assert_eq!(connection.key_update_state(), before);
    assert_internal_error(connection.poll());
}
