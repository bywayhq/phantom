use std::sync::{Arc, Mutex};

use bytes::Buf;

use crate::{cid_queue::CidQueue, coding::BufExt};

use super::*;

/// Records the transport parameters Quinn hands to the crypto provider.
struct RecordingClientConfig {
    inner: Arc<dyn crypto::ClientConfig>,
    params: Arc<Mutex<Option<TransportParameters>>>,
}

impl crypto::ClientConfig for RecordingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        *self.params.lock().unwrap() = Some(*params);
        self.inner
            .clone()
            .start_session(version, server_name, params)
    }
}

fn recording_client_config(
    transport: TransportConfig,
) -> (ClientConfig, Arc<Mutex<Option<TransportParameters>>>) {
    let params = Arc::new(Mutex::new(None));
    let mut config = ClientConfig::new(Arc::new(RecordingClientConfig {
        inner: Arc::new(client_crypto()),
        params: params.clone(),
    }));
    config.transport_config(Arc::new(transport));
    (config, params)
}

fn written_ids(params: &TransportParameters) -> Vec<u64> {
    let mut encoded = Vec::new();
    params.write(&mut encoded);
    let mut ids = Vec::new();
    let mut buf = encoded.as_slice();
    while !buf.is_empty() {
        let id = buf.get_var().unwrap();
        let len = buf.get_var().unwrap() as usize;
        buf.advance(len);
        ids.push(id);
    }
    ids
}

#[test]
fn configured_limits_are_advertised() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport
        .max_ack_delay(Duration::from_millis(20))
        .unwrap()
        .active_connection_id_limit(Some(8))
        .unwrap()
        .stream_receive_window(VarInt::from_u32(12_582_912))
        .bidi_remote_stream_receive_window(Some(VarInt::from_u32(1_048_576)))
        .uni_stream_receive_window(Some(VarInt::from_u32(1_048_577)));
    let (config, params) = recording_client_config(transport);
    let mut pair = Pair::default();
    pair.begin_connect(config);

    let params = params.lock().unwrap().expect("session started");
    assert_eq!(params.max_ack_delay, VarInt(20));
    assert_eq!(params.active_connection_id_limit, VarInt(8));
    assert_eq!(
        params.initial_max_stream_data_bidi_local,
        VarInt(12_582_912)
    );
    assert_eq!(
        params.initial_max_stream_data_bidi_remote,
        VarInt(1_048_576)
    );
    assert_eq!(params.initial_max_stream_data_uni, VarInt(1_048_577));
    let ids = written_ids(&params);
    assert!(ids.contains(&0x0b), "max_ack_delay is advertised");
    assert!(
        ids.contains(&0x0e),
        "active_connection_id_limit is advertised"
    );
}

#[test]
fn default_limits_keep_upstream_parameters() {
    let (config, params) = recording_client_config(TransportConfig::default());
    let mut pair = Pair::default();
    pair.begin_connect(config);

    let params = params.lock().unwrap().expect("session started");
    assert_eq!(params.max_ack_delay, VarInt(25));
    assert_eq!(
        params.active_connection_id_limit,
        VarInt(CidQueue::LEN as u64)
    );
    assert_eq!(
        params.initial_max_stream_data_bidi_remote,
        params.initial_max_stream_data_bidi_local
    );
    assert_eq!(
        params.initial_max_stream_data_uni,
        params.initial_max_stream_data_bidi_local
    );
    assert!(!written_ids(&params).contains(&0x0b));
}

#[test]
fn invalid_limits_are_rejected() {
    let mut transport = TransportConfig::default();
    assert_eq!(
        transport
            .max_ack_delay(Duration::from_millis(1 << 14))
            .err(),
        Some(InvalidTransportLimit::MaxAckDelay)
    );
    assert_eq!(
        transport.max_ack_delay(Duration::from_micros(1_500)).err(),
        Some(InvalidTransportLimit::MaxAckDelay)
    );
    for limit in [0, 1, 9] {
        assert_eq!(
            transport.active_connection_id_limit(Some(limit)).err(),
            Some(InvalidTransportLimit::ActiveConnectionIdLimit)
        );
    }
    assert_eq!(
        transport.min_initial_datagram_size(1_199).err(),
        Some(InvalidTransportLimit::InitialDatagramTooSmall)
    );
}

#[test]
fn peer_initiated_uni_stream_honors_its_own_window() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport
        .stream_receive_window(VarInt::from_u32(64_000))
        .uni_stream_receive_window(Some(VarInt::from_u32(2_000)));
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect_with(config);

    let stream = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
    // The server may send only the client's uni window, not its larger bidi window.
    let written = pair
        .server_send(server_ch, stream)
        .write(&[0xab; 5_000])
        .unwrap();
    assert_eq!(written, 2_000);
    pair.drive();

    assert_matches!(
        pair.client_streams(client_ch).accept(Dir::Uni),
        Some(accepted) if accepted == stream
    );
    let mut recv = pair.client_recv(client_ch, stream);
    let mut chunks = recv.read(false).unwrap();
    let mut received = 0;
    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
        received += chunk.bytes.len();
    }
    let _ = chunks.finalize();
    assert_eq!(received, 2_000);
}

#[test]
fn larger_connection_id_limit_accepts_more_peer_cids() {
    let initial = ConnectionId::new(&[0; 8]);
    let mut queue = CidQueue::with_limit(initial, 8);
    for sequence in 1..8 {
        let cid = frame::NewConnectionId {
            sequence,
            id: ConnectionId::new(&[sequence as u8; 8]),
            reset_token: ResetToken::from([sequence as u8; RESET_TOKEN_SIZE]),
            retire_prior_to: 0,
        };
        assert_eq!(queue.insert(cid), Ok(None));
    }
    let over = frame::NewConnectionId {
        sequence: 8,
        id: ConnectionId::new(&[8; 8]),
        reset_token: ResetToken::from([8; RESET_TOKEN_SIZE]),
        retire_prior_to: 0,
    };
    assert_eq!(
        queue.insert(over),
        Err(crate::cid_queue::InsertError::ExceedsLimit)
    );
}

/// `RESET_STREAM_AT` for the server's first bidirectional stream: error code 0, final size
/// 4, Reliable Size 0.
const RESET_STREAM_AT: [u8; 5] = [0x24, 0x01, 0x00, 0x04, 0x00];

#[test]
fn reset_stream_at_is_an_unknown_frame_unless_advertised() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    // The whole frame, then the frame type with its body cut off
    for frames in [&RESET_STREAM_AT[..], &RESET_STREAM_AT[..2]] {
        let errors = [
            conn.process_frames_for_test(now, frames).unwrap_err(),
            conn.process_early_frames_for_test(now, true, frames)
                .unwrap_err(),
            conn.process_early_frames_for_test(now, false, frames)
                .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error.code, TransportErrorCode::FRAME_ENCODING_ERROR);
            assert_eq!(error.reason, "invalid frame ID");
            assert_eq!(error.frame, Some(frame::FrameType::RESET_STREAM_AT));
        }
    }
}

#[test]
fn reset_stream_at_is_accepted_when_advertised() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut transport = TransportConfig::default();
    transport.reset_stream_at(true);
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let (client_ch, _) = pair.connect_with(config);
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    conn.process_frames_for_test(now, &RESET_STREAM_AT).unwrap();
    // A known frame type that Initial and Handshake packets may not carry
    let error = conn
        .process_early_frames_for_test(now, true, &RESET_STREAM_AT)
        .unwrap_err();
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn client_initial_datagrams_are_padded_to_configured_size() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport.initial_mtu(1_252);
    transport.min_initial_datagram_size(1_252).unwrap();
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    pair.begin_connect(config);
    let now = pair.time;
    pair.client.drive_outgoing(now);

    let initial_sizes = pair
        .client
        .outbound
        .iter()
        .filter(|(_, datagram)| datagram[0] & 0xf0 == 0xc0)
        .map(|(transmit, _)| transmit.size)
        .collect::<Vec<_>>();
    assert!(!initial_sizes.is_empty());
    assert!(initial_sizes.iter().all(|size| *size == 1_252));
}

#[test]
fn initial_padding_never_exceeds_the_datagram() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport.min_initial_datagram_size(1_400).unwrap();
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    pair.begin_connect(config);
    let now = pair.time;
    pair.client.drive_outgoing(now);

    let (transmit, _) = pair
        .client
        .outbound
        .front()
        .expect("client sent an Initial");
    assert_eq!(transmit.size, usize::from(INITIAL_MTU));
}

#[test]
fn draft02_rejects_invalid_ignore_order_bytes() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut transport = TransportConfig::default();
    transport.ack_frequency_draft(AckFrequencyDraft::Draft02);
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let (client_ch, _) = pair.connect_with(config);
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    for flag in 2..=u8::MAX {
        // Sequence 0, tolerance 2, delay 1000 us, followed by padding and PING.
        // Enough padding follows to expose an accidental 2-, 4-, or 8-byte read.
        let mut frames = vec![0x40, 0xaf, 0, 2, 0x43, 0xe8, flag];
        frames.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        let error = conn
            .process_frames_for_test(now, &frames)
            .expect_err("invalid one-byte Ignore Order was accepted");
        assert_eq!(error.code, TransportErrorCode::FRAME_ENCODING_ERROR);
    }
}

#[test]
fn draft02_canonical_ignore_order_keeps_following_ping() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut transport = TransportConfig::default();
    transport.ack_frequency_draft(AckFrequencyDraft::Draft02);
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let (client_ch, _) = pair.connect_with(config);
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    for flag in [0, 1] {
        let before = conn.stats().frame_rx;
        let frames = [0x40, 0xaf, flag, 2, 0x43, 0xe8, flag, 0, 1];
        conn.process_frames_for_test(now, &frames).unwrap();
        assert_eq!(conn.stats().frame_rx.ping, before.ping + 1);
        assert_eq!(
            conn.stats().frame_rx.ack_frequency,
            before.ack_frequency + 1
        );
    }
}

#[test]
fn draft07_accepts_each_reordering_varint_width_and_following_ping() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    for (tag, width) in [(0, 1), (0x40, 2), (0x80, 4), (0xc0, 8)] {
        let before = conn.stats().frame_rx;
        let mut frames = vec![0x40, 0xaf, 0, 1, 0x43, 0xe8];
        let mut reordering = vec![0; width];
        reordering[0] = tag;
        reordering[width - 1] |= 1;
        frames.extend_from_slice(&reordering);
        frames.extend_from_slice(&[0, 1]);
        conn.process_frames_for_test(now, &frames).unwrap();
        assert_eq!(conn.stats().frame_rx.ping, before.ping + 1);
        assert_eq!(
            conn.stats().frame_rx.ack_frequency,
            before.ack_frequency + 1
        );
    }
}
