use std::{
    any::Any,
    net::{Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::BytesMut;
use rustls::quic::Version;

use super::*;
use crate::{
    crypto::{
        ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
        rustls::{configured_provider, initial_keys, initial_suite_from_provider},
    },
    packet::{FixedLengthConnectionIdParser, Header, InitialHeader, PacketNumber, QUIC_V2},
};

const QUIC_V1: u32 = 1;

fn endpoint_config(supported: &[u32], compatible: &[u32]) -> Arc<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config
        .supported_versions(supported.to_vec())
        .compatible_versions(compatible.to_vec());
    Arc::new(config)
}

fn pair_with(client: Arc<EndpointConfig>, server: Arc<EndpointConfig>) -> Pair {
    Pair::new_from_endpoint(
        Endpoint::new(client, None, true, None),
        Endpoint::new(server, Some(Arc::new(server_config())), true, None),
    )
}

fn long_header_type_bits(datagram: &[u8]) -> u8 {
    assert_ne!(datagram[0] & 0x80, 0, "not a long header packet");
    // Header protection masks only the low four bits of a long header's first byte.
    (datagram[0] & 0x30) >> 4
}

#[test]
fn quic_v2_long_header_types_follow_rfc_9369() {
    use crate::packet::LongType;

    let cid = ConnectionId::new(&[7; 8]);
    let cases = [
        (
            Header::Initial(InitialHeader {
                dst_cid: cid,
                src_cid: cid,
                token: Bytes::new(),
                number: PacketNumber::U8(0),
                version: QUIC_V2,
            }),
            0b01,
        ),
        (
            Header::Long {
                ty: LongType::ZeroRtt,
                dst_cid: cid,
                src_cid: cid,
                number: PacketNumber::U8(0),
                version: QUIC_V2,
            },
            0b10,
        ),
        (
            Header::Long {
                ty: LongType::Handshake,
                dst_cid: cid,
                src_cid: cid,
                number: PacketNumber::U8(0),
                version: QUIC_V2,
            },
            0b11,
        ),
        (
            Header::Retry {
                dst_cid: cid,
                src_cid: cid,
                version: QUIC_V2,
            },
            0b00,
        ),
    ];
    for (header, bits) in cases {
        let space = header.space();
        let mut buf = Vec::new();
        header.encode(&mut buf);
        buf.resize(buf.len() + 32, 0);
        assert_eq!((buf[0] & 0x30) >> 4, bits, "{space:?}");

        let (decoded, _) = PartialDecode::new(
            BytesMut::from(&buf[..]),
            &FixedLengthConnectionIdParser::new(8),
            &[QUIC_V2],
            false,
        )
        .unwrap();
        assert_eq!(decoded.version(), Some(QUIC_V2));
        if bits != 0b00 {
            assert_eq!(decoded.space(), Some(space));
        }
    }
}

#[test]
fn quic_v1_long_header_types_are_unchanged() {
    let cid = ConnectionId::new(&[7; 8]);
    let mut buf = Vec::new();
    Header::Initial(InitialHeader {
        dst_cid: cid,
        src_cid: cid,
        token: Bytes::new(),
        number: PacketNumber::U8(0),
        version: QUIC_V1,
    })
    .encode(&mut buf);
    assert_eq!(buf[0] & 0x30, 0);
}

#[test]
fn connects_directly_in_quic_v2() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    let mut pair = pair_with(
        endpoint_config(&versions, &[]),
        endpoint_config(&versions, &[]),
    );
    let mut config = client_config();
    config.version(QUIC_V2);
    let client_ch = pair.begin_connect(config);
    let now = pair.time;
    pair.client.drive_outgoing(now);
    let first = pair
        .client
        .outbound
        .front()
        .expect("client sent an Initial");
    assert_eq!(long_header_type_bits(&first.1), 0b01);
    assert_eq!(first.1[1..5], QUIC_V2.to_be_bytes());

    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );

    let stream = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, stream).write(b"v2").unwrap();
    pair.client_send(client_ch, stream).finish().unwrap();
    pair.drive();
    assert_matches!(
        pair.server_streams(server_ch).accept(Dir::Uni),
        Some(accepted) if accepted == stream
    );
}

#[test]
fn retry_is_authenticated_in_quic_v2() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    let mut pair = pair_with(
        endpoint_config(&versions, &[]),
        endpoint_config(&versions, &[]),
    );
    pair.server.handle_incoming = Box::new(validate_incoming);
    let mut config = client_config();
    config.version(QUIC_V2);
    let client_ch = pair.begin_connect(config);
    pair.drive();
    pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
}

/// What a [`SwitchingSession`] does when Quinn offers it another version.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Switching {
    /// Refuse, as a provider without version switching does.
    Refuse,
    /// Handshake in QUIC v2 but protect the first flight with QUIC v1 Initial keys until Quinn
    /// switches it, as a client that started in v1 would.
    ToV2,
    /// Handshake in QUIC v1 and only count switches: a switch would break the handshake.
    Count,
}

struct SwitchingClientConfig {
    inner: Arc<crypto::rustls::QuicClientConfig>,
    mode: Switching,
    switches: Arc<AtomicUsize>,
}

impl crypto::ClientConfig for SwitchingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        assert_eq!(version, QUIC_V1);
        let handshake_version = match self.mode {
            Switching::Count => QUIC_V1,
            Switching::Refuse | Switching::ToV2 => QUIC_V2,
        };
        let inner = self
            .inner
            .clone()
            .start_session(handshake_version, server_name, params)?;
        Ok(Box::new(SwitchingSession {
            inner,
            mode: self.mode,
            switched: false,
            switches: self.switches.clone(),
        }))
    }
}

struct SwitchingSession {
    inner: Box<dyn crypto::Session>,
    mode: Switching,
    switched: bool,
    switches: Arc<AtomicUsize>,
}

impl crypto::Session for SwitchingSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, crypto::CryptoError> {
        if self.switched || self.mode == Switching::Count {
            return self.inner.initial_keys(dst_cid, side);
        }
        let suite = initial_suite_from_provider(&configured_provider()).unwrap();
        Ok(initial_keys(Version::V1, *dst_cid, side, &suite))
    }

    fn initial_keys_for_version(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Option<Keys> {
        if self.mode == Switching::Refuse || version != QUIC_V2 {
            return None;
        }
        let suite = initial_suite_from_provider(&configured_provider()).unwrap();
        Some(initial_keys(Version::V2, *dst_cid, side, &suite))
    }

    fn switch_version(&mut self, version: u32) -> bool {
        if self.mode == Switching::Refuse || version != QUIC_V2 {
            return false;
        }
        self.switched = true;
        self.switches.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
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

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Result<Option<KeyPair<Box<dyn PacketKey>>>, TransportError> {
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
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

fn switching_client_config(mode: Switching) -> (ClientConfig, Arc<AtomicUsize>) {
    let switches = Arc::new(AtomicUsize::new(0));
    let config = ClientConfig::new(Arc::new(SwitchingClientConfig {
        inner: Arc::new(client_crypto()),
        mode,
        switches: switches.clone(),
    }));
    (config, switches)
}

/// Re-protects a client's QUIC v1 Initial as QUIC v2, standing in for a server that performs
/// compatible version negotiation (RFC 9368 section 2.3) on the client's first flight.
///
/// Packets coalesced after the Initial, such as 0-RTT, are dropped, as a v2-only server drops
/// packets of a version it does not support.
fn initial_v1_as_v2(datagram: &[u8]) -> Vec<u8> {
    let suite = initial_suite_from_provider(&configured_provider()).unwrap();
    let (partial, _) = PartialDecode::new(
        BytesMut::from(datagram),
        &FixedLengthConnectionIdParser::new(0),
        &[QUIC_V1],
        // A resumed client may grease the fixed bit (RFC 9287).
        true,
    )
    .unwrap();
    let dst_cid = *partial.dst_cid();
    let v1 = initial_keys(Version::V1, dst_cid, Side::Client, &suite);
    let mut packet = partial.finish(Some(&*v1.header.local)).unwrap();
    let number = packet.header.number().unwrap().expand(0);
    v1.packet
        .local
        .decrypt(number, &packet.header_data, &mut packet.payload)
        .unwrap();

    let Header::Initial(mut header) = packet.header else {
        panic!("client sent a non-Initial first packet");
    };
    header.version = QUIC_V2;
    let v2 = initial_keys(Version::V2, dst_cid, Side::Client, &suite);
    let mut buf = Vec::new();
    let encode = Header::Initial(header).encode(&mut buf);
    buf.extend_from_slice(&packet.payload);
    buf.resize(buf.len() + v2.packet.local.tag_len(), 0);
    encode.finish(
        &mut buf,
        &*v2.header.local,
        Some((number, &*v2.packet.local)),
    );
    // Packets coalesced after the Initial, such as 0-RTT, become zero padding, so the datagram
    // keeps the size a server requires of an Initial.
    buf.resize(buf.len().max(datagram.len()), 0);
    buf
}

/// Delivers the client's pending first flight to the server re-protected as v2.
///
/// Datagrams that start with a v1 0-RTT packet are lost on the way, as a v2-only server would
/// drop them.
fn deliver_first_flight_as_v2(pair: &mut Pair) {
    let now = pair.time;
    pair.client.drive_outgoing(now);
    for (_, datagram) in pair.client.outbound.drain(..) {
        assert_eq!(datagram[1..5], QUIC_V1.to_be_bytes());
        if datagram[0] & 0x30 != 0 {
            continue;
        }
        let rewritten = initial_v1_as_v2(&datagram);
        pair.server
            .inbound
            .push_back((now, None, rewritten.as_slice().into()));
    }
}

/// Starts a v1 client and delivers its first flight to a v2-only server as v2.
fn start_switched_connection(
    client_versions: &[u32],
    client_compatible: &[u32],
    server_compatible: &[u32],
    mode: Switching,
) -> (Pair, ConnectionHandle, Arc<AtomicUsize>) {
    let mut pair = pair_with(
        endpoint_config(client_versions, client_compatible),
        endpoint_config(&[QUIC_V2], server_compatible),
    );
    let (config, switches) = switching_client_config(mode);
    let client_ch = pair.begin_connect(config);
    deliver_first_flight_as_v2(&mut pair);
    pair.drive();
    (pair, client_ch, switches)
}

#[test]
fn server_moves_client_from_v1_to_v2() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    let (mut pair, client_ch, switches) =
        start_switched_connection(&versions, &[QUIC_V2], &[QUIC_V2], Switching::ToV2);

    assert_eq!(switches.load(Ordering::SeqCst), 1);
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    let stream = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, stream).write(b"hello").unwrap();
    pair.drive();
    assert_matches!(
        pair.server_streams(server_ch).accept(Dir::Bi),
        Some(accepted) if accepted == stream
    );
}

#[test]
fn switched_client_requires_server_version_information() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    // The server does not advertise version_information.
    let (mut pair, client_ch, switches) =
        start_switched_connection(&versions, &[QUIC_V2], &[], Switching::ToV2);

    assert_eq!(switches.load(Ordering::SeqCst), 1);
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(TransportError {
                code: TransportErrorCode::VERSION_NEGOTIATION_ERROR,
                ..
            })
        })
    );
}

#[test]
fn client_stays_in_its_version_without_compatible_versions() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    for (compatible, mode) in [
        (&[][..], Switching::ToV2),
        (&[QUIC_V2][..], Switching::Refuse),
    ] {
        let (mut pair, client_ch, switches) =
            start_switched_connection(&versions, compatible, &[QUIC_V2], mode);
        assert_eq!(switches.load(Ordering::SeqCst), 0);
        // The server's v2 answer is dropped. Once the client retransmits its v1 Initial, the
        // v2-only server answers with Version Negotiation.
        assert_matches!(
            pair.client_conn_mut(client_ch).poll(),
            Some(Event::ConnectionLost {
                reason: ConnectionError::VersionMismatch
            })
        );
    }
}

#[test]
fn version_information_round_trips() {
    let mut config = EndpointConfig::default();
    config
        .supported_versions(vec![QUIC_V2, QUIC_V1])
        .compatible_versions(vec![QUIC_V2]);
    let info = crate::transport_parameters::VersionInformation::local(QUIC_V1, &config);
    let params = TransportParameters {
        version_information: info,
        ..TransportParameters::default()
    };
    let mut buf = Vec::new();
    params.write(&mut buf);
    // The start version, then the compatible ones.
    assert_eq!(
        buf,
        [0x11, 0x0c, 0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf]
    );
    let read = TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap();
    assert_eq!(
        read.version_information.map(|info| info.chosen),
        Some(QUIC_V1)
    );

    // No compatible versions: the parameter is not written.
    let default = EndpointConfig::default();
    assert!(crate::transport_parameters::VersionInformation::local(QUIC_V1, &default).is_none());
}

#[test]
fn malformed_version_information_is_rejected() {
    use crate::transport_parameters::Error;

    for (side, encoded) in [
        (Side::Server, &[0x11, 0x03, 0, 0, 1][..]),
        (Side::Server, &[0x11, 0x04, 0, 0, 0, 0][..]),
        (Side::Server, &[0x11, 0x08, 0, 0, 0, 1, 0, 0, 0, 0][..]),
        // A client must list its Chosen Version among its Available Versions.
        (Side::Server, &[0x11, 0x04, 0, 0, 0, 1][..]),
        (Side::Server, &[0x11, 0x08, 0, 0, 0, 1, 0, 0, 0, 2][..]),
        (Side::Client, &[0x11, 0x08, 0, 0, 0, 0, 0, 0, 0, 1][..]),
    ] {
        assert!(
            matches!(
                TransportParameters::read(side, &mut &encoded[..]),
                Err(Error::Malformed | Error::IllegalValue)
            ),
            "{encoded:02x?}"
        );
    }
}

#[test]
fn a_server_may_list_no_available_versions() {
    // RFC 9368 section 3: a server's Available Versions may be empty.
    let encoded = [0x11, 0x04, 0, 0, 0, 1];
    let read = TransportParameters::read(Side::Client, &mut &encoded[..]).unwrap();
    assert_eq!(
        read.version_information.map(|info| info.chosen),
        Some(QUIC_V1)
    );
}

#[test]
fn an_initial_that_fails_authentication_does_not_switch_versions() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    let mut pair = pair_with(
        endpoint_config(&versions, &[QUIC_V2]),
        endpoint_config(&versions, &[]),
    );
    let (config, switches) = switching_client_config(Switching::Count);
    let client_ch = pair.begin_connect(config);
    let now = pair.time;
    pair.client.drive_outgoing(now);
    let first = &pair
        .client
        .outbound
        .front()
        .expect("client sent an Initial")
        .1;
    let destination_len = usize::from(first[5]);
    let source_len = usize::from(first[6 + destination_len]);
    let client_cid =
        ConnectionId::new(&first[7 + destination_len..7 + destination_len + source_len]);

    // A v2 Initial to the client, protected with keys of another connection ID.
    let suite = initial_suite_from_provider(&configured_provider()).unwrap();
    let forged_keys = initial_keys(
        Version::V2,
        ConnectionId::new(&[9; 8]),
        Side::Server,
        &suite,
    );
    let mut forged = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid: client_cid,
        src_cid: ConnectionId::new(&[7; 8]),
        token: Bytes::new(),
        number: PacketNumber::U8(0),
        version: QUIC_V2,
    })
    .encode(&mut forged);
    forged.push(0x01); // PING
    forged.resize(forged.len() + 40, 0);
    forged.resize(forged.len() + forged_keys.packet.local.tag_len(), 0);
    encode.finish(
        &mut forged,
        &*forged_keys.header.local,
        Some((0, &*forged_keys.packet.local)),
    );
    pair.client
        .inbound
        .push_back((now, None, forged.as_slice().into()));

    pair.drive();
    assert_eq!(switches.load(Ordering::SeqCst), 0);
    pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
}

#[test]
fn a_switch_rejects_outstanding_early_data() {
    let _guard = subscribe();
    let mut pair = pair_with(
        endpoint_config(&[QUIC_V1, QUIC_V2], &[QUIC_V2]),
        endpoint_config(&[QUIC_V2], &[QUIC_V2]),
    );
    let (config, switches) = switching_client_config(Switching::ToV2);

    // The first connection receives a v2 session ticket.
    let first = pair.begin_connect(config.clone());
    deliver_first_flight_as_v2(&mut pair);
    pair.drive();
    pair.server.assert_accept();
    pair.client
        .connections
        .get_mut(&first)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );

    // The second starts in v1 with 0-RTT data, and the server moves it to v2.
    let second = pair.begin_connect(config);
    assert!(pair.client_conn_mut(second).has_0rtt());
    let early = pair.client_streams(second).open(Dir::Uni).unwrap();
    pair.client_send(second, early).write(b"early").unwrap();
    deliver_first_flight_as_v2(&mut pair);
    pair.drive();

    assert_eq!(switches.load(Ordering::SeqCst), 2);
    assert_matches!(
        pair.client_conn_mut(second).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.client_conn_mut(second).poll(), Some(Event::Connected));
    assert!(!pair.client_conn_mut(second).accepted_0rtt());

    // The application sends again in 1-RTT, and the data arrives.
    let server_ch = pair.server.assert_accept();
    let stream = pair.client_streams(second).open(Dir::Uni).unwrap();
    pair.client_send(second, stream).write(b"again").unwrap();
    pair.client_send(second, stream).finish().unwrap();
    pair.drive();
    let accepted = pair
        .server_streams(server_ch)
        .accept(Dir::Uni)
        .expect("stream arrived");
    let mut recv = pair.server_recv(server_ch, accepted);
    let mut chunks = recv.read(true).unwrap();
    let chunk = chunks.next(usize::MAX).unwrap().expect("data arrived");
    assert_eq!(chunk.bytes, &b"again"[..]);
    let _ = chunks.finalize();
}
