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

pub(super) fn builder(
    settings: &Http3Settings,
    crypto: &Arc<QuicClientConfig>,
) -> Result<h3::client::Builder, Http3Error> {
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

    let wire_settings = materialize(settings, randomized_grease)?;
    let mut builder = h3::client::builder();
    builder.ordered_settings(&wire_settings).map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile is incompatible with the protocol engine",
            error,
        )
    })?;
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

fn materialize(
    settings: &Http3Settings,
    mut grease: impl FnMut() -> Result<(u64, u64), Http3Error>,
) -> Result<Vec<(u64, u64)>, Http3Error> {
    let mut entries = Vec::with_capacity(settings.initial_settings.len());
    for setting in &settings.initial_settings {
        entries.push(match *setting {
            Http3Setting::QpackMaxTableCapacity(value) => (QPACK_MAX_TABLE_CAPACITY, value),
            Http3Setting::MaxFieldSectionSize(value) => (MAX_FIELD_SECTION_SIZE, value),
            Http3Setting::QpackBlockedStreams(value) => (QPACK_BLOCKED_STREAMS, value),
            Http3Setting::H3Datagram(enabled) => (H3_DATAGRAM, u64::from(enabled)),
            Http3Setting::RandomizedGrease => grease()?,
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

fn randomized_grease() -> Result<(u64, u64), Http3Error> {
    let mut entropy = [0_u8; 8];
    btls::rand::rand_bytes(&mut entropy).map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Local,
            "failed to generate HTTP/3 GREASE",
            error,
        )
    })?;
    let [a, b, c, d, e, f, g, h] = entropy;
    let identifier_seed = u32::from_ne_bytes([a, b, c, d]);
    let value = u32::from_ne_bytes([e, f, g, h]);
    Ok((31 * u64::from(identifier_seed) + 33, u64::from(value)))
}

#[cfg(test)]
pub(super) fn materialize_for_test(
    settings: &Http3Settings,
    grease: (u64, u64),
) -> Result<Vec<(u64, u64)>, Http3Error> {
    settings.validate().map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 profile settings are invalid",
            error,
        )
    })?;
    materialize(settings, || Ok(grease))
}
