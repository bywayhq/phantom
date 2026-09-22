use std::sync::Arc;

use phantom_profile::{
    Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder, Http3Settings,
};
use phantom_quic_btls::QuicClientConfig;

use super::{Http3Error, Http3ErrorKind};

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
const H3_DATAGRAM: u64 = 0x33;
const GREASE_ENTROPY_LEN: usize = 8;
/// Largest decoded response field section accepted on any connection.
///
/// Sizes use the RFC 9114 Section 4.2.2 measure (name and value lengths plus
/// 32 per field line). An implementation may refuse a larger header section
/// whether or not it advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`, so this
/// bound is local only and never changes the SETTINGS frame. The value equals
/// the limit Chromium advertises.
const LOCAL_MAX_FIELD_SECTION_SIZE: u64 = 262_144;

pub(super) fn builder(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
) -> Result<h3::client::Builder, Http3Error> {
    builder_with_entropy(settings, crypto, fill_grease_entropy)
}

fn builder_with_entropy(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
    fill_entropy: impl FnMut(&mut [u8]) -> Result<(), Http3Error>,
) -> Result<h3::client::Builder, Http3Error> {
    validate(settings, crypto)?;

    let wire_settings = materialize(settings, fill_entropy)?;
    let mut builder = h3::client::builder();
    // Profiles own every GREASE emission visible on the wire.
    builder.send_grease(false);
    builder.ordered_settings(&wire_settings).map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile is incompatible with the protocol engine",
            error,
        )
    })?;
    // The ordered list above is the complete wire SETTINGS frame; this call
    // only replaces the decoder's local ceiling and must follow it.
    builder.max_field_section_size(local_max_field_section_size(settings));
    match settings.qpack_encoding {
        Http3QpackEncoding::Stateless => {}
        Http3QpackEncoding::Dynamic => {
            builder.enable_dynamic_qpack(true);
        }
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported QPACK policy",
            ));
        }
    }
    match settings.qpack_decoder_stream {
        Http3QpackDecoderStream::Eager => {}
        Http3QpackDecoderStream::OnFeedback => {
            builder.defer_qpack_decoder_stream(true);
        }
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported QPACK decoder stream policy",
            ));
        }
    }
    Ok(builder)
}

pub(super) fn validate(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
) -> Result<(), Http3Error> {
    settings.validate().map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile settings are invalid",
            error,
        )
    })?;
    if settings.receives_datagrams() && !crypto.receives_datagrams() {
        return Err(Http3Error::without_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 Datagram support requires QUIC DATAGRAM receive support",
        ));
    }
    if settings.initial_settings.iter().any(|setting| {
        !matches!(
            setting,
            Http3Setting::QpackMaxTableCapacity(_)
                | Http3Setting::MaxFieldSectionSize(_)
                | Http3Setting::QpackBlockedStreams(_)
                | Http3Setting::H3Datagram(_)
                | Http3Setting::RandomizedGrease
        )
    }) {
        return Err(Http3Error::without_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile contains an unsupported setting",
        ));
    }
    match settings.qpack_encoding {
        Http3QpackEncoding::Stateless | Http3QpackEncoding::Dynamic => {}
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported QPACK policy",
            ));
        }
    }
    match settings.qpack_decoder_stream {
        Http3QpackDecoderStream::Eager | Http3QpackDecoderStream::OnFeedback => {}
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported QPACK decoder stream policy",
            ));
        }
    }
    match settings.setting_order {
        Http3SettingOrder::Fixed | Http3SettingOrder::Ascending => {}
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported ordering policy",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_for_connector(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
) -> Result<(), Http3Error> {
    builder_with_entropy(settings, crypto, |output| {
        output.fill(0);
        Ok(())
    })
    .map(|_| ())
}

#[cfg(test)]
pub(super) fn builder_for_test(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
    entropy: [u8; GREASE_ENTROPY_LEN],
) -> Result<h3::client::Builder, Http3Error> {
    builder_with_entropy(settings, crypto, |output| {
        output.copy_from_slice(&entropy);
        Ok(())
    })
}

/// Returns the decoded field-section ceiling: the advertised limit when it is
/// smaller than the local bound, otherwise the local bound.
fn local_max_field_section_size(settings: &Http3Settings) -> u64 {
    settings
        .initial_settings
        .iter()
        .find_map(|setting| match *setting {
            Http3Setting::MaxFieldSectionSize(value) => Some(value),
            _ => None,
        })
        .map_or(LOCAL_MAX_FIELD_SECTION_SIZE, |advertised| {
            advertised.min(LOCAL_MAX_FIELD_SECTION_SIZE)
        })
}

fn materialize(
    settings: &Http3Settings,
    mut fill_entropy: impl FnMut(&mut [u8]) -> Result<(), Http3Error>,
) -> Result<Vec<(u64, u64)>, Http3Error> {
    let mut entries = Vec::with_capacity(settings.initial_settings.len());
    for setting in &settings.initial_settings {
        entries.push(match *setting {
            Http3Setting::QpackMaxTableCapacity(value) => (QPACK_MAX_TABLE_CAPACITY, value),
            Http3Setting::MaxFieldSectionSize(value) => (MAX_FIELD_SECTION_SIZE, value),
            Http3Setting::QpackBlockedStreams(value) => (QPACK_BLOCKED_STREAMS, value),
            Http3Setting::H3Datagram(enabled) => (H3_DATAGRAM, u64::from(enabled)),
            Http3Setting::RandomizedGrease => {
                let mut entropy = [0_u8; GREASE_ENTROPY_LEN];
                fill_entropy(&mut entropy)?;
                randomized_grease(entropy)
            }
            _ => {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::Configuration,
                    "HTTP/3 profile contains an unsupported setting",
                ));
            }
        });
    }

    match settings.setting_order {
        Http3SettingOrder::Fixed => {}
        Http3SettingOrder::Ascending => entries.sort_unstable_by_key(|(identifier, _)| *identifier),
        _ => {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Configuration,
                "HTTP/3 profile contains an unsupported ordering policy",
            ));
        }
    }
    Ok(entries)
}

fn fill_grease_entropy(entropy: &mut [u8]) -> Result<(), Http3Error> {
    btls::rand::rand_bytes(entropy).map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Local,
            "failed to generate HTTP/3 GREASE",
            error,
        )
    })
}

fn randomized_grease(entropy: [u8; GREASE_ENTROPY_LEN]) -> (u64, u64) {
    let [a, b, c, d, e, f, g, h] = entropy;
    let identifier_seed = u32::from_ne_bytes([a, b, c, d]);
    let value = u32::from_ne_bytes([e, f, g, h]);
    (31 * u64::from(identifier_seed) + 33, u64::from(value))
}

#[cfg(test)]
pub(super) fn materialize_for_test(
    settings: &Http3Settings,
    entropy: [u8; GREASE_ENTROPY_LEN],
) -> Result<Vec<(u64, u64)>, Http3Error> {
    settings.validate().map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile settings are invalid",
            error,
        )
    })?;
    materialize(settings, |output| {
        output.copy_from_slice(&entropy);
        Ok(())
    })
}
