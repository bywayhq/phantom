use http::{Method, Version, header::CONNECTION};
use phantom_profile::{Http2PseudoHeader, chromium::v152_http2};

use super::super::{
    Http2Error, OriginForm, RequestHeader, prepare_extended_connect,
    translate_extended_connect_settings,
};

#[test]
fn prepares_websocket_extended_connect_with_ordered_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let request = prepare_extended_connect(
        "example.test",
        OriginForm::parse("/socket?encoding=binary")?,
        vec![
            RequestHeader::new("sec-websocket-version", "13"),
            RequestHeader::new("x-repeat", "first"),
            RequestHeader::new("x-repeat", "second"),
        ],
    )?;

    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.version(), Version::HTTP_2);
    assert_eq!(
        request.uri().to_string(),
        "https://example.test/socket?encoding=binary"
    );
    assert_eq!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .ok_or("missing protocol extension")?
            .as_str(),
        "websocket"
    );
    let ordered = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("missing ordered fields")?;
    assert_eq!(ordered.as_slice()[1].1.as_bytes(), b"first");
    assert_eq!(ordered.as_slice()[2].1.as_bytes(), b"second");
    Ok(())
}

#[test]
fn rejects_forbidden_and_non_lowercase_fields_before_io() -> Result<(), Box<dyn std::error::Error>>
{
    let target = OriginForm::parse("/")?;
    assert!(matches!(
        prepare_extended_connect(
            "example.test",
            target.clone(),
            vec![RequestHeader::new(CONNECTION.as_str(), "upgrade")],
        ),
        Err(Http2Error::ForbiddenHeader { .. })
    ));
    assert!(matches!(
        prepare_extended_connect(
            "example.test",
            target,
            vec![RequestHeader::new("Sec-WebSocket-Version", "13")],
        ),
        Err(Http2Error::InvalidHeaderName { index: 0 })
    ));
    Ok(())
}

#[test]
fn exact_extended_connect_order_is_explicit() -> Result<(), Box<dyn std::error::Error>> {
    let mut settings = v152_http2();
    assert!(matches!(
        translate_extended_connect_settings(&settings),
        Err(Http2Error::MissingExtendedConnectPseudoHeaderOrder)
    ));

    settings.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Protocol,
    ]);
    translate_extended_connect_settings(&settings)?;
    Ok(())
}
