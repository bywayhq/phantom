use super::{
    Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream,
    Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings, Http3Setting,
    Http3SettingOrder, Http3Settings, InvalidHttp3RequestSettings, InvalidHttp3Settings,
};

fn settings() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(65_536),
            Http3Setting::MaxFieldSectionSize(262_144),
            Http3Setting::QpackBlockedStreams(100),
            Http3Setting::H3Datagram(true),
            Http3Setting::RandomizedGrease,
        ],
        setting_order: Http3SettingOrder::Ascending,
        qpack_encoding: Http3QpackEncoding::Dynamic,
        qpack_decoder_stream: Http3QpackDecoderStream::OnFeedback,
        qpack_encoder_stream: Http3QpackEncoderStream::OnFirstInstruction,
        qpack_stream_order: Http3QpackStreamOrder::DecoderFirst,
    }
}

fn request_settings() -> Http3RequestSettings {
    Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
        cookie_crumbs: Http3CookieCrumbs::Whole,
    }
}

fn extended_connect_order() -> Vec<Http3PseudoHeader> {
    vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]
}

#[test]
fn extended_connect_order_requires_each_pseudo_exactly_once() {
    let mut valid = request_settings();
    valid.extended_connect_pseudo_header_order = Some(extended_connect_order());
    assert_eq!(valid.validate(), Ok(()));

    let mut missing = request_settings();
    let mut order = extended_connect_order();
    order.retain(|header| *header != Http3PseudoHeader::Protocol);
    missing.extended_connect_pseudo_header_order = Some(order);
    assert_request_field(missing.validate(), "extended_connect_pseudo_header_order");

    let mut duplicate = request_settings();
    let mut order = extended_connect_order();
    order[4] = Http3PseudoHeader::Method;
    duplicate.extended_connect_pseudo_header_order = Some(order);
    assert_request_field(duplicate.validate(), "extended_connect_pseudo_header_order");
}

#[test]
fn ordinary_request_order_rejects_protocol() {
    let mut settings = request_settings();
    settings.pseudo_header_order[3] = Http3PseudoHeader::Protocol;
    assert_request_field(settings.validate(), "pseudo_header_order");
}

#[test]
fn requires_each_get_pseudo_header_once() {
    let mut missing = request_settings();
    missing.pseudo_header_order.pop();
    assert_request_field(missing.validate(), "pseudo_header_order");

    let mut duplicate = request_settings();
    duplicate.pseudo_header_order[3] = Http3PseudoHeader::Method;
    assert_request_field(duplicate.validate(), "pseudo_header_order");
}

#[test]
fn accepts_owned_customizable_settings() -> Result<(), Box<dyn std::error::Error>> {
    let mut settings = settings();
    settings.initial_settings[1] = Http3Setting::MaxFieldSectionSize(65_536);
    settings.setting_order = Http3SettingOrder::Fixed;
    settings.qpack_encoding = Http3QpackEncoding::Stateless;
    settings.qpack_decoder_stream = Http3QpackDecoderStream::Eager;

    settings.validate()?;
    assert!(settings.receives_datagrams());
    assert_eq!(settings.qpack_encoding, Http3QpackEncoding::Stateless);
    assert_eq!(
        settings.qpack_decoder_stream,
        Http3QpackDecoderStream::Eager
    );
    Ok(())
}

#[test]
fn rejects_duplicate_initial_settings() {
    let mut settings = settings();
    settings
        .initial_settings
        .push(Http3Setting::QpackBlockedStreams(1));

    assert_field(settings.validate(), "initial_settings");
}

#[test]
fn validates_qpack_capacity_at_backend_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut maximum = settings();
    maximum.initial_settings[0] = Http3Setting::QpackMaxTableCapacity((1 << 30) - 1);
    maximum.validate()?;

    let mut overflow = settings();
    overflow.initial_settings[0] = Http3Setting::QpackMaxTableCapacity(1 << 30);
    assert_field(
        overflow.validate(),
        "initial_settings.qpack_max_table_capacity",
    );
    Ok(())
}

#[test]
fn rejects_values_outside_quic_varint_range() {
    for (index, invalid) in [
        (1, Http3Setting::MaxFieldSectionSize(1 << 62)),
        (2, Http3Setting::QpackBlockedStreams(1 << 62)),
    ] {
        let mut settings = settings();
        settings.initial_settings[index] = invalid;
        assert_field(settings.validate(), "initial_settings");
    }
}

#[test]
fn datagram_support_requires_true_setting() {
    let mut settings = settings();
    settings.initial_settings[3] = Http3Setting::H3Datagram(false);
    assert!(!settings.receives_datagrams());

    settings.initial_settings.remove(3);
    assert!(!settings.receives_datagrams());
}

fn assert_field(result: Result<(), InvalidHttp3Settings>, expected_field: &'static str) {
    assert_eq!(
        result.as_ref().map_err(InvalidHttp3Settings::field),
        Err(expected_field)
    );
}

fn assert_request_field(
    result: Result<(), InvalidHttp3RequestSettings>,
    expected_field: &'static str,
) {
    assert_eq!(
        result.as_ref().map_err(InvalidHttp3RequestSettings::field),
        Err(expected_field)
    );
}
