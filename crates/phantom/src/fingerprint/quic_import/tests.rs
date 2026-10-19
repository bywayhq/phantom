use super::*;
use phantom_profile::browser::chrome;

fn value(value: u64, width: usize) -> Vec<u8> {
    let mut bytes = value.to_be_bytes()[8 - width..].to_vec();
    bytes[0] |= match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    bytes
}

fn parameter(id: u64, payload: &[u8], output: &mut Vec<u8>) {
    output.extend(value(id, if id < 64 { 1 } else { 8 }));
    output.extend(value(payload.len() as u64, 2));
    output.extend(payload);
}

fn block(base: &ClientProfile) -> Vec<u8> {
    let settings = base
        .http3()
        .unwrap_or_else(|| panic!("http3"))
        .quic_transport();
    let mut bytes = Vec::new();
    for (id, value_number) in [
        (4, settings.initial_max_data),
        (1, settings.max_idle_timeout_ms),
        (3, settings.max_udp_payload_size),
        (5, settings.initial_max_stream_data_bidi_local),
        (6, settings.initial_max_stream_data_bidi_remote),
        (7, settings.initial_max_stream_data_uni),
        (8, settings.initial_max_streams_bidi),
        (9, settings.initial_max_streams_uni),
        (0x0b, settings.max_ack_delay_ms),
        (0x0e, settings.active_connection_id_limit),
    ] {
        parameter(id, &value(value_number, 8), &mut bytes);
    }
    if let Some(limit) = settings.max_datagram_frame_size {
        parameter(0x20, &value(limit, 8), &mut bytes);
    }
    parameter(0x0f, &[7; 8], &mut bytes);
    bytes
}

fn base() -> ClientProfile {
    let base = chrome::v154_windows();
    let mut document = super::super::export::describe(&base)
        .unwrap_or_else(|error| panic!("describe: {error}"))
        .0;
    let settings = &mut document["profile"]["http3"]["quic_transport"];
    settings["min_ack_delay_us"] = serde_json::Value::Null;
    settings["reset_stream_at"] = false.into();
    let parameters = settings["wire_parameters"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("parameters"));
    parameters.retain(|parameter| {
        !matches!(
            parameter["kind"]["kind"].as_str(),
            Some("MinAckDelay" | "ResetStreamAt")
        )
    });
    super::super::import_profile_json(
        &serde_json::to_vec(&document).unwrap_or_else(|error| panic!("encode: {error}")),
    )
    .unwrap_or_else(|error| panic!("base: {error}"))
}

#[test]
fn imports_values_order_and_nonminimal_widths_without_captured_connection_ids() {
    let base = base();
    let imported = import_quic_transport_profile(&block(&base), &base)
        .unwrap_or_else(|error| panic!("import: {error}"));
    let settings = imported
        .profile()
        .http3()
        .unwrap_or_else(|| panic!("http3"))
        .quic_transport();
    assert_eq!(settings.parameter_order, QuicTransportParameterOrder::Fixed);
    assert!(matches!(
        settings.wire_parameters[0].kind,
        Parameter::InitialMaxData {
            value_width: QuicVarIntWidth::Eight
        }
    ));
    assert_eq!(
        settings.wire_parameters[0].length_width,
        QuicVarIntWidth::Two
    );
    assert!(matches!(
        settings
            .wire_parameters
            .last()
            .unwrap_or_else(|| panic!("cid"))
            .kind,
        Parameter::InitialSourceConnectionId { length: 8 }
    ));
    assert_eq!(
        settings.initial_max_data,
        base.http3()
            .unwrap_or_else(|| panic!("http3"))
            .quic_transport()
            .initial_max_data
    );
    assert!(
        imported
            .observed_fields()
            .any(|field| field == "http3.quic_transport.initial_max_data")
    );
    assert!(
        imported
            .supplemented_fields()
            .any(|field| field == "http3.tls")
    );
    assert!(
        imported
            .supplemented_fields()
            .any(|field| field == "http3.quic_transport.early_data")
    );
}

#[test]
fn rejects_truncation_duplicates_unknown_parameters_and_invalid_limits() {
    let base = base();
    let mut duplicate = block(&base);
    parameter(4, &[0], &mut duplicate);
    let mut unknown = Vec::new();
    parameter(0x1234, &[0], &mut unknown);
    for (input, kind) in [
        (vec![0x40], Kind::MalformedDescription),
        (vec![1, 10, 0], Kind::MalformedDescription),
        (duplicate, Kind::DuplicateField),
        (unknown, Kind::UnsupportedSetting),
        (vec![0; 65537], Kind::TooLarge),
    ] {
        assert_eq!(
            import_quic_transport_profile(&input, &base)
                .err()
                .unwrap_or_else(|| panic!("reject"))
                .kind(),
            kind
        );
    }
    let mut remaining = &[0x40, 0x01][..];
    assert_eq!(
        varint(&mut remaining).unwrap_or_else(|error| panic!("nonminimal: {error}")),
        (1, QuicVarIntWidth::Two)
    );
    assert!(remaining.is_empty());
}
