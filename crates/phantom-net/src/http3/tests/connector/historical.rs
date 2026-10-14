use std::collections::BTreeMap;

use phantom_profile::browser::edge;
use quinn_proto::{VarInt, coding::Codec};

use super::{
    ClientHelloSummary, Cursor, Http3Connector, Side, TestResult, TransportParameters,
    assert_connector_matches_quic_client_hello, client_hello_extension, crypto, fixture_hex,
};

const STARTUP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
));
const HELLOS: [&str; 2] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/quic-client-hello-1.txt"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/quic-client-hello-2.txt"
    )),
];

#[test]
fn historical_edge_153_quic_client_hello_matches_both_retained_captures() -> TestResult<()> {
    let connector = historical_connector()?;
    for fixture in HELLOS {
        assert_connector_matches_quic_client_hello(&connector, STARTUP, fixture)?;
    }
    Ok(())
}

#[test]
fn historical_edge_153_quic_parameters_match_retained_values_and_widths() -> TestResult<()> {
    let connector = historical_connector()?;
    let parameters = TransportParameters::read(
        Side::Server,
        &mut Cursor::new(fixture_hex(STARTUP, "transport_parameters_hex")?),
    )?;
    let mut session = crypto::ClientConfig::start_session(
        connector.test_crypto(),
        1,
        "server.phantom.test",
        &parameters,
    )?;
    let mut handshake = Vec::new();
    assert!(session.write_handshake(&mut handshake).is_none());
    let summary = ClientHelloSummary::from_handshake_bytes(&handshake)?;
    assert_eq!(
        summary.server_name(),
        Some(b"server.phantom.test".as_slice())
    );
    let actual = client_hello_extension(&handshake, 0x39).ok_or("QUIC parameters missing")?;
    let expected = fixture_hex(STARTUP, "transport_parameters_hex")?;
    assert_eq!(parameter_fields(actual)?, parameter_fields(&expected)?);
    Ok(())
}

fn historical_connector() -> TestResult<Http3Connector> {
    Ok(Http3Connector::new(
        &edge::v153_quic_tls(),
        &edge::v153_quic(),
        &edge::v153_http3(),
        &edge::v153_http3_request(),
    )?)
}

type ParameterFields = BTreeMap<u64, (usize, usize, Vec<u8>)>;

fn parameter_fields(mut bytes: &[u8]) -> TestResult<ParameterFields> {
    let mut fields = BTreeMap::new();
    let mut grease = 0;
    while !bytes.is_empty() {
        let (identifier, id_width) = read_varint(&mut bytes)?;
        let (length, length_width) = read_varint(&mut bytes)?;
        let length = usize::try_from(length)?;
        let value = bytes.get(..length).ok_or("truncated QUIC parameter")?;
        bytes = &bytes[length..];
        // Reserved identifiers and their payloads vary on each connection.
        if identifier % 31 == 27 {
            assert_eq!(id_width, 8);
            assert_eq!(length_width, 1);
            assert!(length <= 15);
            grease += 1;
            continue;
        }
        let mut value = value.to_vec();
        if identifier == 17 {
            assert_eq!(value.len(), 12);
            assert_eq!(&value[..4], &[0, 0, 0, 1]);
            let mut reserved = 0;
            for version in value[4..].as_chunks_mut::<4>().0 {
                if version.iter().all(|byte| byte & 0x0f == 0x0a) {
                    version.fill(0x0a);
                    reserved += 1;
                }
            }
            assert_eq!(reserved, 1);
            // Available versions are permuted; their values and widths remain.
            let mut available = value[4..].as_chunks::<4>().0.to_vec();
            available.sort_unstable();
            value.truncate(4);
            for version in available {
                value.extend(version);
            }
        }
        assert!(
            fields
                .insert(identifier, (id_width, length_width, value))
                .is_none()
        );
    }
    assert_eq!(grease, 1);
    Ok(fields)
}

fn read_varint(bytes: &mut &[u8]) -> TestResult<(u64, usize)> {
    let before = bytes.len();
    let value = VarInt::decode(bytes)?.into_inner();
    Ok((value, before - bytes.len()))
}
