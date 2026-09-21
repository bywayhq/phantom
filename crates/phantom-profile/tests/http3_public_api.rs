//! Public HTTP/3 profile construction checks.

use phantom_profile::http3::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3RequestSettings,
    Http3Setting, Http3SettingOrder, Http3Settings,
};

#[test]
fn downstream_code_can_build_and_customize_an_http3_profile() {
    let mut settings = Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(4_096),
            Http3Setting::QpackBlockedStreams(16),
            Http3Setting::MaxFieldSectionSize(65_536),
            Http3Setting::RandomizedGrease,
        ],
        setting_order: Http3SettingOrder::Ascending,
        qpack_encoding: Http3QpackEncoding::Dynamic,
        qpack_decoder_stream: Http3QpackDecoderStream::OnFeedback,
    };
    let mut request = Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
    };

    assert!(settings.validate().is_ok());

    settings
        .initial_settings
        .retain(|setting| !matches!(setting, Http3Setting::RandomizedGrease));
    settings.setting_order = Http3SettingOrder::Fixed;
    settings.qpack_encoding = Http3QpackEncoding::Stateless;
    settings.qpack_decoder_stream = Http3QpackDecoderStream::Eager;
    request.pseudo_header_order.swap(0, 1);

    assert!(settings.validate().is_ok());
    assert!(request.validate().is_ok());
    assert_eq!(settings.qpack_encoding, Http3QpackEncoding::Stateless);
    assert_eq!(
        request.pseudo_header_order,
        [
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ]
    );
}
