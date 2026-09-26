use ::http2::{
    ext::HeadersFrameOverrides,
    frame::{PseudoId, PseudoOrder, StreamDependency, StreamId},
};
use http::{Method, Version, header::CONNECTION};
use phantom_profile::{
    Http2Priority, Http2PseudoHeader, chromium::v154_http2, firefox::v156_http2,
};

use super::super::{
    Http2Error, OriginForm, RequestHeader, extended_connect_overrides, prepare_extended_connect,
    priority_overrides, translate_extended_connect_settings, translate_settings,
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
    let mut settings = v154_http2();
    settings.extended_connect_pseudo_header_order = None;
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

#[test]
fn extended_connect_overrides_carry_the_profile_order_and_priority()
-> Result<(), Box<dyn std::error::Error>> {
    let chrome = extended_connect_overrides(&v154_http2())?;
    assert_eq!(
        chrome,
        HeadersFrameOverrides::new()
            .pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                        PseudoId::Path,
                        PseudoId::Protocol,
                    ])
                    .build()
            )
            .stream_dependency(StreamDependency::new(StreamId::zero(), 146, true))
    );
    let firefox = extended_connect_overrides(&v156_http2())?;
    assert_eq!(
        firefox,
        HeadersFrameOverrides::new()
            .pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Path,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                        PseudoId::Protocol,
                    ])
                    .build()
            )
            .stream_dependency(StreamDependency::new(StreamId::zero(), 21, false))
    );

    // Without a separate priority the connection's ordinary HEADERS priority
    // remains in effect for the CONNECT stream.
    let mut settings = v154_http2();
    settings.extended_connect_priority = None;
    let overrides = extended_connect_overrides(&settings)?;
    assert_eq!(
        overrides,
        HeadersFrameOverrides::new().pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Method,
                    PseudoId::Authority,
                    PseudoId::Scheme,
                    PseudoId::Path,
                    PseudoId::Protocol,
                ])
                .build()
        )
    );

    let mut settings = v154_http2();
    settings.extended_connect_pseudo_header_order = None;
    assert!(matches!(
        extended_connect_overrides(&settings),
        Err(Http2Error::MissingExtendedConnectPseudoHeaderOrder)
    ));
    Ok(())
}

#[test]
fn extended_connect_priority_cannot_depend_on_the_first_stream() {
    let mut settings = v154_http2();
    settings.extended_connect_priority = Some(Http2Priority {
        dependency_stream_id: 1,
        weight: 147,
        exclusive: true,
    });
    assert!(matches!(
        extended_connect_overrides(&settings),
        Err(Http2Error::InvalidPriorityDependency { stream_id: 1 })
    ));
    assert!(matches!(
        translate_settings(&settings),
        Err(Http2Error::InvalidPriorityDependency { stream_id: 1 })
    ));
}

#[test]
fn request_priority_overrides_replace_only_the_stream_dependency() -> Result<(), Http2Error> {
    let fetch = Http2Priority {
        dependency_stream_id: 0,
        weight: 220,
        exclusive: true,
    };
    assert_eq!(
        priority_overrides(fetch, 1)?,
        HeadersFrameOverrides::new().stream_dependency(StreamDependency::new(
            StreamId::zero(),
            219,
            true
        ))
    );
    let lowest = Http2Priority {
        dependency_stream_id: 0,
        weight: 1,
        exclusive: false,
    };
    assert_eq!(
        priority_overrides(lowest, 1)?,
        HeadersFrameOverrides::new().stream_dependency(StreamDependency::new(
            StreamId::zero(),
            0,
            false
        ))
    );

    for (dependency_stream_id, weight) in [(0, 0), (0, 257), (0x8000_0000, 220)] {
        assert!(matches!(
            priority_overrides(
                Http2Priority {
                    dependency_stream_id,
                    weight,
                    exclusive: true,
                },
                1
            ),
            Err(Http2Error::InvalidPriority { .. })
        ));
    }
    Ok(())
}

/// A per-request dependency on the connection's first stream is refused,
/// whichever stream that is; the other odd stream is an ordinary dependency.
#[test]
fn request_priority_refuses_a_dependency_on_the_first_stream() -> Result<(), Http2Error> {
    let on = |dependency_stream_id| Http2Priority {
        dependency_stream_id,
        weight: 220,
        exclusive: true,
    };
    for (first, other) in [(1, 3), (3, 1)] {
        assert!(matches!(
            priority_overrides(on(first), first),
            Err(Http2Error::InvalidPriorityDependency { stream_id }) if stream_id == first
        ));
        priority_overrides(on(other), first)?;
    }
    Ok(())
}
