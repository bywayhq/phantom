//! Complete HTTP/3 description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    Http3AltUsed, Http3ClientSettings, Http3CookieCrumbs, Http3PseudoHeader,
    Http3QpackDecoderStream, Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder,
    Http3RequestSettings, Http3Setting, Http3SettingOrder, Http3Settings,
};

pub(super) fn parse(v: &Value) -> Result<Http3ClientSettings> {
    v.record(&["tls", "quic_transport", "http3", "request"], "http3")?;
    Ok(Http3ClientSettings::new(
        super::tls::parse(v.member("tls", "http3.tls")?)?,
        super::quic::parse(v.member("quic_transport", "http3.quic_transport")?)?,
        settings(v.member("http3", "http3.http3")?)?,
        request(v.member("request", "http3.request")?)?,
    ))
}
pub(super) fn settings(v: &Value) -> Result<Http3Settings> {
    v.record(
        &[
            "initial_settings",
            "setting_order",
            "qpack_encoding",
            "qpack_decoder_stream",
            "qpack_encoder_stream",
            "qpack_stream_order",
            "reserved_frame_after_settings",
        ],
        "http3.http3",
    )?;
    let settings = Http3Settings {
        initial_settings: v
            .member("initial_settings", "http3.initial_settings")?
            .list("http3.initial_settings", setting)?,
        setting_order: setting_order(v.member("setting_order", "http3.setting_order")?)?,
        qpack_encoding: qpack_encoding(v.member("qpack_encoding", "http3.qpack_encoding")?)?,
        qpack_decoder_stream: qpack_decoder_stream(
            v.member("qpack_decoder_stream", "http3.qpack_decoder_stream")?,
        )?,
        qpack_encoder_stream: qpack_encoder_stream(
            v.member("qpack_encoder_stream", "http3.qpack_encoder_stream")?,
        )?,
        qpack_stream_order: qpack_stream_order(
            v.member("qpack_stream_order", "http3.qpack_stream_order")?,
        )?,
        reserved_frame_after_settings: v
            .member(
                "reserved_frame_after_settings",
                "http3.reserved_frame_after_settings",
            )?
            .boolean("http3.reserved_frame_after_settings")?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("http3.http3", error))?;
    Ok(settings)
}

pub(super) fn request(v: &Value) -> Result<Http3RequestSettings> {
    v.record(
        &[
            "pseudo_header_order",
            "extended_connect_pseudo_header_order",
            "cookie_crumbs",
            "alt_used",
        ],
        "http3.request",
    )?;
    let settings = Http3RequestSettings {
        pseudo_header_order: v
            .member("pseudo_header_order", "http3.request.pseudo_header_order")?
            .list("http3.request.pseudo_header_order", pseudo)?,
        extended_connect_pseudo_header_order: v
            .member(
                "extended_connect_pseudo_header_order",
                "http3.request.extended_connect_pseudo_header_order",
            )?
            .optional(|v| v.list("http3.request.extended_connect_pseudo_header_order", pseudo))?,
        cookie_crumbs: cookie_crumbs(v.member("cookie_crumbs", "http3.request.cookie_crumbs")?)?,
        alt_used: alt_used(v.member("alt_used", "http3.request.alt_used")?)?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("http3.request", error))?;
    Ok(settings)
}

fn setting_order(v: &Value) -> Result<Http3SettingOrder> {
    match v.text("http3.setting_order")? {
        "Fixed" => Ok(Http3SettingOrder::Fixed),
        "Ascending" => Ok(Http3SettingOrder::Ascending),
        _ => Err(json::unsupported("http3.setting_order")),
    }
}

fn qpack_encoding(v: &Value) -> Result<Http3QpackEncoding> {
    match v.text("http3.qpack_encoding")? {
        "Stateless" => Ok(Http3QpackEncoding::Stateless),
        "Dynamic" => Ok(Http3QpackEncoding::Dynamic),
        "DynamicUnmatchedNames" => Ok(Http3QpackEncoding::DynamicUnmatchedNames),
        _ => Err(json::unsupported("http3.qpack_encoding")),
    }
}

fn qpack_decoder_stream(v: &Value) -> Result<Http3QpackDecoderStream> {
    match v.text("http3.qpack_decoder_stream")? {
        "Eager" => Ok(Http3QpackDecoderStream::Eager),
        "OnFeedback" => Ok(Http3QpackDecoderStream::OnFeedback),
        _ => Err(json::unsupported("http3.qpack_decoder_stream")),
    }
}

fn qpack_encoder_stream(v: &Value) -> Result<Http3QpackEncoderStream> {
    match v.text("http3.qpack_encoder_stream")? {
        "Eager" => Ok(Http3QpackEncoderStream::Eager),
        "OnFirstInstruction" => Ok(Http3QpackEncoderStream::OnFirstInstruction),
        _ => Err(json::unsupported("http3.qpack_encoder_stream")),
    }
}

fn qpack_stream_order(v: &Value) -> Result<Http3QpackStreamOrder> {
    match v.text("http3.qpack_stream_order")? {
        "EncoderFirst" => Ok(Http3QpackStreamOrder::EncoderFirst),
        "DecoderFirst" => Ok(Http3QpackStreamOrder::DecoderFirst),
        _ => Err(json::unsupported("http3.qpack_stream_order")),
    }
}

fn cookie_crumbs(v: &Value) -> Result<Http3CookieCrumbs> {
    match v.text("http3.cookie_crumbs")? {
        "Whole" => Ok(Http3CookieCrumbs::Whole),
        "Split" => Ok(Http3CookieCrumbs::Split),
        _ => Err(json::unsupported("http3.cookie_crumbs")),
    }
}

fn alt_used(v: &Value) -> Result<Http3AltUsed> {
    match v.text("http3.alt_used")? {
        "Omit" => Ok(Http3AltUsed::Omit),
        "Append" => Ok(Http3AltUsed::Append),
        "ValidatedMapping" => Ok(Http3AltUsed::ValidatedMapping),
        _ => Err(json::unsupported("http3.alt_used")),
    }
}

fn pseudo(v: &Value) -> Result<Http3PseudoHeader> {
    match v.text("http3.request.pseudo_header_order")? {
        "Method" => Ok(Http3PseudoHeader::Method),
        "Authority" => Ok(Http3PseudoHeader::Authority),
        "Scheme" => Ok(Http3PseudoHeader::Scheme),
        "Path" => Ok(Http3PseudoHeader::Path),
        "Protocol" => Ok(Http3PseudoHeader::Protocol),
        _ => Err(json::unsupported("http3.request.pseudo_header_order")),
    }
}

fn setting(v: &Value) -> Result<Http3Setting> {
    v.record(&["kind", "value"], "http3.initial_settings")?;
    let value = v.member("value", "http3.initial_settings.value")?;
    match v
        .member("kind", "http3.initial_settings.kind")?
        .text("http3.initial_settings.kind")?
    {
        "EnableConnectProtocol" => Ok(Http3Setting::EnableConnectProtocol(
            value.boolean("http3.initial_settings.value")?,
        )),
        "EnableWebTransportDraft02" => Ok(Http3Setting::EnableWebTransportDraft02(
            value.boolean("http3.initial_settings.value")?,
        )),
        "H3Datagram" => Ok(Http3Setting::H3Datagram(
            value.boolean("http3.initial_settings.value")?,
        )),
        "H3DatagramDraft04" => Ok(Http3Setting::H3DatagramDraft04(
            value.boolean("http3.initial_settings.value")?,
        )),
        "MaxFieldSectionSize" => Ok(Http3Setting::MaxFieldSectionSize(
            value.number("http3.initial_settings.value")?,
        )),
        "QpackBlockedStreams" => Ok(Http3Setting::QpackBlockedStreams(
            value.number("http3.initial_settings.value")?,
        )),
        "QpackMaxTableCapacity" => Ok(Http3Setting::QpackMaxTableCapacity(
            value.number("http3.initial_settings.value")?,
        )),
        "RandomizedGrease" => {
            value.null("http3.initial_settings.value")?;
            Ok(Http3Setting::RandomizedGrease)
        }
        _ => Err(json::unsupported("http3.initial_settings.kind")),
    }
}
