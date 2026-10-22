use super::{SNAPSHOTS, TestResult, field, unhex};
use phantom_profile::{
    Http2Priority, Http2PseudoHeader as H2, Http2Setting, Http3PseudoHeader as H3, Http3Setting,
    NamedGroup as G, SignatureScheme as S, TlsSettings, browser,
    client_hello::{ClientHelloSummary, is_grease},
};

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn compare_tls(settings: &TlsSettings, hello: &ClientHelloSummary) -> TestResult {
    settings.validate()?;
    assert_eq!(
        settings
            .cipher_suites
            .iter()
            .map(|suite| suite.iana_id())
            .collect::<Vec<_>>(),
        without_grease(hello.cipher_suites())
    );
    assert_eq!(
        settings.groups,
        [G::X25519MlKem768, G::X25519, G::Secp256r1, G::Secp384r1]
    );
    assert_eq!(without_grease(hello.supported_groups()), [4588, 29, 23, 24]);
    assert_eq!(settings.key_shares, [G::X25519MlKem768, G::X25519]);
    assert_eq!(without_grease(hello.key_share_groups()), [4588, 29]);
    let schemes: TestResult<Vec<_>> = settings
        .signature_schemes
        .iter()
        .map(|scheme| {
            Ok(match scheme {
                S::MlDsa44 => 0x0904,
                S::MlDsa65 => 0x0905,
                S::MlDsa87 => 0x0906,
                S::EcdsaSecp256r1Sha256 => 0x0403,
                S::RsaPssRsaeSha256 => 0x0804,
                S::RsaPkcs1Sha256 => 0x0401,
                S::EcdsaSecp384r1Sha384 => 0x0503,
                S::RsaPssRsaeSha384 => 0x0805,
                S::RsaPkcs1Sha384 => 0x0501,
                S::RsaPssRsaeSha512 => 0x0806,
                S::RsaPkcs1Sha512 => 0x0601,
                S::RsaPkcs1Sha1 => 0x0201,
                _ => return Err("unexpected recipe signature scheme".into()),
            })
        })
        .collect();
    assert_eq!(schemes?, without_grease(hello.signature_algorithms()));
    assert_eq!(
        settings
            .alpn_protocols
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&[u8]>>(),
        hello
            .alpn_protocols()
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>()
    );
    let versions = without_grease(hello.supported_versions());
    assert_eq!(
        versions.first().copied(),
        Some(settings.versions.max().protocol_id())
    );
    assert_eq!(
        versions.last().copied(),
        Some(settings.versions.min().protocol_id())
    );
    let anchors = settings
        .requested_trust_anchor_ids
        .as_ref()
        .ok_or("missing trust anchors")?;
    assert_eq!(anchors.orders().len(), 1);
    assert_eq!(
        anchors.orders()[0]
            .as_slice()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&[u8]>>(),
        hello
            .requested_trust_anchor_ids()
            .ok_or("missing captured anchors")?
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn windows156_tls_matches_fresh_tcp_and_quic_hellos() -> TestResult {
    let selected = browser::chrome::v156_windows();
    let h3 = selected.http3().ok_or("missing HTTP/3")?;
    for capture in SNAPSHOTS {
        let record = unhex(field(capture, "tls.record_0_hex")?)?;
        let hello =
            ClientHelloSummary::from_handshake_bytes(record.get(5..).ok_or("short TLS record")?)?;
        compare_tls(selected.tls(), &hello)?;
        let handshake = unhex(field(capture, "quic_client_hello.handshake_hex")?)?;
        let hello = ClientHelloSummary::from_handshake_bytes(&handshake)?;
        compare_tls(h3.tls(), &hello)?;
    }
    Ok(())
}

fn varint(bytes: &mut &[u8]) -> TestResult<u64> {
    let first = *bytes.first().ok_or("missing varint")?;
    let width = 1_usize << (first >> 6);
    let value = bytes
        .get(..width)
        .ok_or("truncated varint")?
        .iter()
        .skip(1)
        .fold(u64::from(first & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    *bytes = &bytes[width..];
    Ok(value)
}

#[test]
fn windows156_http2_and_http3_startup_match_retained_frame_bytes() -> TestResult {
    let selected = browser::chrome::v156_windows();
    let h2 = selected.http2().ok_or("missing HTTP/2")?;
    let h3 = selected.http3().ok_or("missing HTTP/3")?;
    for capture in SNAPSHOTS {
        let settings = unhex(field(capture, "h2.frame_0_hex")?)?;
        assert_eq!(
            settings.get(..9),
            Some([0, 0, 24, 4, 0, 0, 0, 0, 0].as_slice())
        );
        let (entries, remainder) = settings
            .get(9..)
            .ok_or("missing SETTINGS")?
            .as_chunks::<6>();
        assert!(remainder.is_empty());
        let captured: TestResult<Vec<_>> = entries
            .iter()
            .map(|entry| {
                let value = u32::from_be_bytes(entry[2..].try_into()?);
                Ok(match u16::from_be_bytes(entry[..2].try_into()?) {
                    1 => Http2Setting::HeaderTableSize(value),
                    2 => Http2Setting::EnablePush(value != 0),
                    4 => Http2Setting::InitialWindowSize(value),
                    6 => Http2Setting::MaxHeaderListSize(value),
                    _ => return Err("unexpected captured HTTP/2 setting".into()),
                })
            })
            .collect();
        assert_eq!(h2.initial_settings, captured?);
        let update = unhex(field(capture, "h2.frame_1_hex")?)?;
        assert_eq!(
            update.get(..9),
            Some([0, 0, 4, 8, 0, 0, 0, 0, 0].as_slice())
        );
        let increment = u32::from_be_bytes(update.get(9..).ok_or("missing window")?.try_into()?);
        assert_eq!(h2.initial_connection_window_size, 65_535 + increment);
        assert_eq!(
            h2.headers_priority,
            Some(Http2Priority {
                dependency_stream_id: 0,
                weight: 256,
                exclusive: true,
            })
        );
        assert_eq!(
            h2.pseudo_header_order,
            [H2::Method, H2::Authority, H2::Scheme, H2::Path]
        );
        assert_eq!(
            h3.request().pseudo_header_order,
            [H3::Method, H3::Authority, H3::Scheme, H3::Path]
        );
        assert!(
            field(capture, "request_0_field_order")?
                .starts_with(":method,:authority,:scheme,:path,")
        );
        assert!(
            field(capture, "h2.client_frame_2")?.contains("exclusive:true,depends_on:0,weight:256")
        );
        let bytes = unhex(field(capture, "h3.settings_frame_hex")?)?;
        let mut input = bytes.as_slice();
        assert_eq!(varint(&mut input)?, 4);
        assert_eq!(usize::try_from(varint(&mut input)?)?, input.len());
        let mut settings = Vec::new();
        while !input.is_empty() {
            let id = varint(&mut input)?;
            let value = varint(&mut input)?;
            settings.push(match id {
                1 => Http3Setting::QpackMaxTableCapacity(value),
                6 => Http3Setting::MaxFieldSectionSize(value),
                7 => Http3Setting::QpackBlockedStreams(value),
                51 => {
                    assert_eq!(value, 1);
                    Http3Setting::H3Datagram(true)
                }
                grease if grease >= 33 && (grease - 33).is_multiple_of(31) => {
                    Http3Setting::RandomizedGrease
                }
                _ => return Err("unexpected captured HTTP/3 setting".into()),
            });
        }
        assert_eq!(h3.http3().initial_settings, settings);
    }
    Ok(())
}

#[test]
fn windows156_quic_initial_parameter_values_match_retained_crypto() -> TestResult {
    let selected = browser::chrome::v156_windows();
    let h3 = selected.http3().ok_or("missing HTTP/3")?;
    let settings = h3.quic_transport();
    for capture in SNAPSHOTS {
        let bytes = unhex(field(capture, "h3.transport_parameters_hex")?)?;
        let hello = unhex(field(capture, "quic_client_hello.handshake_hex")?)?;
        assert!(hello.windows(bytes.len()).any(|window| window == bytes));
        let mut input = bytes.as_slice();
        let mut observed = Vec::new();
        while !input.is_empty() {
            let id = varint(&mut input)?;
            let length = usize::try_from(varint(&mut input)?)?;
            let value = input.get(..length).ok_or("short transport parameter")?;
            input = &input[length..];
            if matches!(id, 1 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 32) {
                let mut value_input = value;
                let value = varint(&mut value_input)?;
                assert!(value_input.is_empty());
                observed.push((id, value));
            }
        }
        observed.sort_unstable();
        assert_eq!(
            observed,
            [
                (1, settings.max_idle_timeout_ms),
                (3, settings.max_udp_payload_size),
                (4, settings.initial_max_data),
                (5, settings.initial_max_stream_data_bidi_local),
                (6, settings.initial_max_stream_data_bidi_remote),
                (7, settings.initial_max_stream_data_uni),
                (8, settings.initial_max_streams_bidi),
                (9, settings.initial_max_streams_uni),
                (
                    32,
                    settings
                        .max_datagram_frame_size
                        .ok_or("missing DATAGRAM limit")?
                ),
            ]
        );
    }
    Ok(())
}
