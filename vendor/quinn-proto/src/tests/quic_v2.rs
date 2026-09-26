use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
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

/// A rustls client session that runs its handshake in QUIC v2 but protects its first flight
/// with QUIC v1 Initial keys until Quinn switches it, as a client that started in v1 would.
struct SwitchingClientConfig {
    inner: Arc<crypto::rustls::QuicClientConfig>,
    switches: bool,
    switched: Arc<AtomicBool>,
}

impl crypto::ClientConfig for SwitchingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        assert_eq!(version, QUIC_V1);
        let inner = self
            .inner
            .clone()
            .start_session(QUIC_V2, server_name, params)?;
        Ok(Box::new(SwitchingSession {
            inner,
            switches: self.switches,
            switched: self.switched.clone(),
        }))
    }
}

struct SwitchingSession {
    inner: Box<dyn crypto::Session>,
    switches: bool,
    switched: Arc<AtomicBool>,
}

impl crypto::Session for SwitchingSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, crypto::CryptoError> {
        if self.switched.load(Ordering::SeqCst) {
            return self.inner.initial_keys(dst_cid, side);
        }
        let suite = initial_suite_from_provider(&configured_provider()).unwrap();
        Ok(initial_keys(Version::V1, *dst_cid, side, &suite))
    }

    fn switch_version(&mut self, version: u32) -> bool {
        if !self.switches || version != QUIC_V2 {
            return false;
        }
        self.switched.store(true, Ordering::SeqCst);
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

fn switching_client_config(switches: bool) -> (ClientConfig, Arc<AtomicBool>) {
    let switched = Arc::new(AtomicBool::new(false));
    let config = ClientConfig::new(Arc::new(SwitchingClientConfig {
        inner: Arc::new(client_crypto()),
        switches,
        switched: switched.clone(),
    }));
    (config, switched)
}

/// Re-protects a client's QUIC v1 Initial as QUIC v2, standing in for a server that performs
/// compatible version negotiation (RFC 9368 section 2.3) on the client's first flight.
fn initial_v1_as_v2(datagram: &[u8]) -> Vec<u8> {
    let suite = initial_suite_from_provider(&configured_provider()).unwrap();
    let (partial, rest) = PartialDecode::new(
        BytesMut::from(datagram),
        &FixedLengthConnectionIdParser::new(0),
        &[QUIC_V1],
        false,
    )
    .unwrap();
    assert!(rest.is_none(), "one Initial per datagram");
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
    buf
}

/// Starts a v1 client and delivers its first flight to a v2-only server as v2.
fn start_switched_connection(
    client_versions: &[u32],
    client_compatible: &[u32],
    server_compatible: &[u32],
    client_switches: bool,
) -> (Pair, ConnectionHandle, Arc<AtomicBool>) {
    let mut pair = pair_with(
        endpoint_config(client_versions, client_compatible),
        endpoint_config(&[QUIC_V2], server_compatible),
    );
    let (config, switched) = switching_client_config(client_switches);
    let client_ch = pair.begin_connect(config);
    let now = pair.time;
    pair.client.drive_outgoing(now);
    for (_, datagram) in pair.client.outbound.drain(..) {
        assert_eq!(datagram[1..5], QUIC_V1.to_be_bytes());
        let rewritten = initial_v1_as_v2(&datagram);
        pair.server
            .inbound
            .push_back((now, None, rewritten.as_slice().into()));
    }
    pair.drive();
    (pair, client_ch, switched)
}

#[test]
fn server_moves_client_from_v1_to_v2() {
    let _guard = subscribe();
    let versions = [QUIC_V1, QUIC_V2];
    let (mut pair, client_ch, switched) =
        start_switched_connection(&versions, &[QUIC_V2], &[QUIC_V2], true);

    assert!(switched.load(Ordering::SeqCst));
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
    let (mut pair, client_ch, switched) =
        start_switched_connection(&versions, &[QUIC_V2], &[], true);

    assert!(switched.load(Ordering::SeqCst));
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
    for (compatible, switches) in [(&[][..], true), (&[QUIC_V2][..], false)] {
        let (mut pair, client_ch, switched) =
            start_switched_connection(&versions, compatible, &[QUIC_V2], switches);
        assert!(!switched.load(Ordering::SeqCst));
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
    assert_eq!(
        buf,
        [0x11, 0x0c, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1]
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
        // A client reading a server's parameter requires it to list the chosen version.
        (Side::Client, &[0x11, 0x04, 0, 0, 0, 1][..]),
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
