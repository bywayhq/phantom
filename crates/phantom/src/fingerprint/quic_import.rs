//! Import supported QUIC parameter bytes without freezing connection identity.

use phantom_profile::{
    ClientProfile, QuicTransportParameter, QuicTransportParameterKind as Parameter,
    QuicTransportParameterOrder, QuicTransportSettings, QuicVarIntWidth,
};

use super::{FingerprintImportError, FingerprintImportErrorKind as Kind, ImportedProfile, Result};

const ROOT: &str = "http3.quic_transport";

/// Imports an ordered QUIC transport-parameter block using an explicit base.
///
/// Input is the payload of TLS extension 57, without its TLS framing. Applies
/// supported numeric parameters, order, integer widths and source-connection-ID
/// length. Connection ID bytes are discarded and generated afresh at runtime.
/// Other TLS, HTTP/3, packet and transport settings remain explicit supplements.
///
/// Omitted parameters retain the base's settings, which must permit omission
/// under QUIC's wire defaults. Reserved parameters and Version Information
/// need runtime generation policies; use the complete JSON importer for those.
/// This imports a transport description, not an exact browser profile.
///
/// # Errors
///
/// Rejects input over 64 KiB, over 64 parameters, malformed varints or lengths,
/// duplicate and unsupported identifiers, invalid limits, and an absent HTTP/3
/// base. Unknown parameter payloads are never ignored. No network I/O occurs.
pub fn import_quic_transport_profile(
    input: &[u8],
    base: &ClientProfile,
) -> Result<ImportedProfile> {
    if input.len() > 64 * 1024 {
        return Err(error(Kind::TooLarge, ROOT));
    }
    let mut settings = base
        .http3()
        .ok_or_else(|| error(Kind::MissingField, "http3"))?
        .quic_transport()
        .clone();
    let mut remaining = input;
    let mut seen = Vec::new();
    let mut observed = vec![
        "http3.quic_transport.wire_parameters",
        "http3.quic_transport.parameter_order",
    ];
    settings.wire_parameters.clear();
    settings.parameter_order = QuicTransportParameterOrder::Fixed;
    while !remaining.is_empty() {
        if seen.len() == 64 {
            return Err(error(
                Kind::TooLarge,
                "http3.quic_transport.wire_parameters",
            ));
        }
        let (id, id_width) = varint(&mut remaining)?;
        if seen.contains(&id) {
            return Err(error(
                Kind::DuplicateField,
                "http3.quic_transport.wire_parameters",
            ));
        }
        seen.push(id);
        let (length, length_width) = varint(&mut remaining)?;
        let length = usize::try_from(length).map_err(|_| error(Kind::TooLarge, ROOT))?;
        let data = remaining
            .get(..length)
            .ok_or_else(|| error(Kind::MalformedDescription, ROOT))?;
        remaining = &remaining[length..];
        let (kind, field) = parameter(id, data, &mut settings)?;
        if let Some(field) = field {
            observed.push(field);
        }
        settings.wire_parameters.push(QuicTransportParameter {
            kind,
            id_width,
            length_width,
        });
    }
    settings
        .validate()
        .map_err(|source| FingerprintImportError::native(ROOT, source))?;
    let mut document = super::export::describe(base)?.0;
    document["profile"]["http3"]["quic_transport"] = super::export::quic_settings(&settings)?;
    ImportedProfile::from_document(document, &observed)
}

fn parameter(
    id: u64,
    data: &[u8],
    settings: &mut QuicTransportSettings,
) -> Result<(Parameter, Option<&'static str>)> {
    if id == 0x0f {
        let length = u8::try_from(data.len())
            .ok()
            .filter(|length| *length <= 20)
            .ok_or_else(|| {
                error(
                    Kind::InvalidValue,
                    "http3.quic_transport.initial_source_connection_id",
                )
            })?;
        return Ok((Parameter::InitialSourceConnectionId { length }, None));
    }
    if id == 0x1d {
        if !data.is_empty() {
            return Err(error(
                Kind::InvalidValue,
                "http3.quic_transport.reset_stream_at",
            ));
        }
        settings.reset_stream_at = true;
        return Ok((
            Parameter::ResetStreamAt,
            Some("http3.quic_transport.reset_stream_at"),
        ));
    }
    if !matches!(id, 1 | 3..=9 | 0x0b | 0x0e | 0x20) {
        return Err(error(
            Kind::UnsupportedSetting,
            "http3.quic_transport.wire_parameters.identifier",
        ));
    }
    let mut remaining = data;
    let (value, value_width) = varint(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(error(
            Kind::MalformedDescription,
            "http3.quic_transport.wire_parameters.value",
        ));
    }
    macro_rules! numeric {
        ($field:ident, $variant:ident) => {{
            settings.$field = value;
            (
                Parameter::$variant { value_width },
                Some(concat!("http3.quic_transport.", stringify!($field))),
            )
        }};
    }
    Ok(match id {
        1 => numeric!(max_idle_timeout_ms, MaxIdleTimeout),
        3 => numeric!(max_udp_payload_size, MaxUdpPayloadSize),
        4 => numeric!(initial_max_data, InitialMaxData),
        5 => numeric!(
            initial_max_stream_data_bidi_local,
            InitialMaxStreamDataBidiLocal
        ),
        6 => numeric!(
            initial_max_stream_data_bidi_remote,
            InitialMaxStreamDataBidiRemote
        ),
        7 => numeric!(initial_max_stream_data_uni, InitialMaxStreamDataUni),
        8 => numeric!(initial_max_streams_bidi, InitialMaxStreamsBidi),
        9 => numeric!(initial_max_streams_uni, InitialMaxStreamsUni),
        0x0b => numeric!(max_ack_delay_ms, MaxAckDelay),
        0x0e => numeric!(active_connection_id_limit, ActiveConnectionIdLimit),
        0x20 => {
            settings.max_datagram_frame_size = Some(value);
            (
                Parameter::MaxDatagramFrameSize { value_width },
                Some("http3.quic_transport.max_datagram_frame_size"),
            )
        }
        _ => return Err(error(Kind::UnsupportedSetting, ROOT)),
    })
}

fn varint(input: &mut &[u8]) -> Result<(u64, QuicVarIntWidth)> {
    let first = *input
        .first()
        .ok_or_else(|| error(Kind::MalformedDescription, ROOT))?;
    let (length, width) = match first >> 6 {
        0 => (1, QuicVarIntWidth::One),
        1 => (2, QuicVarIntWidth::Two),
        2 => (4, QuicVarIntWidth::Four),
        _ => (8, QuicVarIntWidth::Eight),
    };
    let bytes = input
        .get(..length)
        .ok_or_else(|| error(Kind::MalformedDescription, ROOT))?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[length..];
    Ok((value, width))
}

fn error(kind: Kind, field: &str) -> FingerprintImportError {
    FingerprintImportError::new(kind, field)
}

#[cfg(test)]
mod tests;
