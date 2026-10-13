use std::{
    any::Any,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use assert_matches::assert_matches;

use super::*;

struct FailingInitialClientConfig {
    inner: Arc<dyn crypto::ClientConfig>,
    fail_on_call: usize,
}

impl crypto::ClientConfig for FailingInitialClientConfig {
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
        Ok(Box::new(FailingInitialSession {
            inner,
            fail_on_call: self.fail_on_call,
            calls: AtomicUsize::new(0),
        }))
    }
}

struct FailingInitialSession {
    inner: Box<dyn crypto::Session>,
    fail_on_call: usize,
    calls: AtomicUsize,
}

impl crypto::Session for FailingInitialSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<crypto::Keys, crypto::CryptoError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if call == self.fail_on_call {
            return Err(crypto::CryptoError);
        }
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

fn failing_initial_client_config(fail_on_call: usize) -> ClientConfig {
    ClientConfig::new(Arc::new(FailingInitialClientConfig {
        inner: Arc::new(client_crypto()),
        fail_on_call,
    }))
}

#[test]
fn initial_key_failure_rejects_client_before_insertion() {
    let mut pair = Pair::default();
    let remote = pair.server.addr;
    let connections_before = pair.client.known_connections();
    let cids_before = pair.client.known_cids();

    let result = pair.client.connect(
        pair.time,
        failing_initial_client_config(1),
        remote,
        "localhost",
    );

    assert_matches!(result, Err(ConnectError::InitialCrypto));
    assert_eq!(pair.client.known_connections(), connections_before);
    assert_eq!(pair.client.known_cids(), cids_before);
}

#[test]
fn retry_key_failure_closes_without_changing_retry_state() {
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Wait);
    let client = pair.begin_connect(failing_initial_client_config(2));
    pair.drive_client();
    pair.server.drive_incoming(pair.time, pair.client.addr);
    let incoming = pair
        .server
        .waiting_incoming
        .pop()
        .expect("server did not receive client Initial");
    pair.server.retry(incoming);
    pair.drive_server();

    let before = pair.client_conn_mut(client).retry_state();
    pair.drive_client();
    let connection = pair.client_conn_mut(client);

    assert_eq!(connection.retry_state(), before);
    assert!(connection.is_closed());
    assert_matches!(
        connection.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(ref error),
        }) if error.code == TransportErrorCode::INTERNAL_ERROR
    );
    assert_eq!(pair.server.inbound.len(), 1, "client did not send a close");
}

struct FailingStartupClientConfig {
    error: ConnectError,
    calls: AtomicUsize,
}

impl crypto::ClientConfig for FailingStartupClientConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        _params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(self.error.clone())
    }
}

// Test-only IDs make wrapping and exhaustion deterministic.
struct SequentialClientIds(u8);

impl ConnectionIdGenerator for SequentialClientIds {
    fn generate_cid(&mut self) -> ConnectionId {
        let cid = ConnectionId::new(&[self.0]);
        self.0 = self.0.wrapping_add(1);
        cid
    }

    fn cid_len(&self) -> usize {
        1
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[test]
fn provider_startup_failures_retire_only_their_cids_and_preserve_errors() {
    for error in [
        ConnectError::CryptoProvider("fixture provider startup"),
        ConnectError::InvalidServerName("invalid fixture name".into()),
        ConnectError::InvalidTransportParameters("invalid fixture parameters".into()),
        ConnectError::TransportParameterEncoding("fixture entropy failure".into()),
    ] {
        for keep_connection in [false, true] {
            let mut endpoint_config = EndpointConfig::default();
            endpoint_config.cid_generator(|| Box::new(SequentialClientIds(0)));
            let mut endpoint = Endpoint::new(Arc::new(endpoint_config), None, true, None);
            let remote = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 4433);
            let now = Instant::now();
            let live_connection = keep_connection.then(|| {
                endpoint
                    .connect(now, client_config(), remote, "localhost")
                    .expect("valid provider startup")
            });
            let retained_connections = endpoint.open_connections();
            let retained_cids = endpoint.known_cids();
            assert_eq!(retained_connections, usize::from(keep_connection));
            assert_eq!(retained_cids, retained_connections);
            let provider = Arc::new(FailingStartupClientConfig {
                error: error.clone(),
                calls: AtomicUsize::new(0),
            });
            let config = ClientConfig::new(provider.clone());

            // More failures than a one-byte CID space can retain, including a wrap.
            for _ in 0..256 {
                let result = endpoint.connect(now, config.clone(), remote, "localhost");
                assert_matches!(result, Err(ref returned) if returned == &error);
                assert_eq!(endpoint.open_connections(), retained_connections);
                assert_eq!(endpoint.known_cids(), retained_cids);
            }
            assert_eq!(provider.calls.load(Ordering::Relaxed), 256);
            let connection = endpoint
                .connect(now, client_config(), remote, "localhost")
                .expect("valid startup after repeated provider failures");
            assert_eq!(endpoint.open_connections(), retained_connections + 1);
            assert_eq!(endpoint.known_cids(), retained_cids + 1);
            drop(connection);
            drop(live_connection);
        }
    }
}
