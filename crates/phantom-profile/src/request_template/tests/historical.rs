use crate::Http3PseudoHeader;
use crate::browser::edge;
use crate::request_template::capture::decode_hex;

use super::{Capture, CaptureResult, Protocol, assert_all_match, observed};

const WEBSOCKET: [&str; 2] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/edge/153.0.4234.48/windows-11-26200/accept.txt"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/edge/153.0.4234.48/windows-11-26200/h1-accept.txt"
    )),
];

#[test]
fn historical_edge_153_navigation_matches_retained_h1_h2_h3_requests() -> CaptureResult<()> {
    let template = edge::v153_windows_navigation_template();
    template.validate()?;
    let hints = edge::v153_windows_client_hints();
    for fixture in WEBSOCKET {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("client")?, "Microsoft Edge");
        assert_eq!(capture.value("client_version")?, "153.0.4234.48");
        assert_eq!(capture.value("repeat_count")?, "3");
    }
    let (http1, http2) = observed(&[&WEBSOCKET], "page", "document")?;
    assert_eq!(http1.len(), 3);
    assert_eq!(http2.len(), 3);
    let priorities = Capture::parse(WEBSOCKET[0])?.http2_priorities("document")?;
    assert_eq!(priorities.len(), 3);
    for priority in priorities {
        assert_eq!(
            priority.map(crate::Http2RequestPriority::Fixed),
            template.http2_priority
        );
    }
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        3,
        "historical edge h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        3,
        "historical edge h2",
    );
    let startup = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
    ));
    let capture = Capture::parse(startup)?;
    let expected_order = (0..4)
        .map(|index| {
            let (name, _) = capture
                .value(&format!("request_header_{index}"))?
                .split_once(':')
                .ok_or("H3 field has no separator")?;
            match decode_hex(name)?.as_str() {
                ":method" => Ok(Http3PseudoHeader::Method),
                ":authority" => Ok(Http3PseudoHeader::Authority),
                ":scheme" => Ok(Http3PseudoHeader::Scheme),
                ":path" => Ok(Http3PseudoHeader::Path),
                _ => Err("unexpected ordinary H3 pseudo-header".into()),
            }
        })
        .collect::<CaptureResult<Vec<_>>>()?;
    assert_eq!(
        edge::v153_http3_request().pseudo_header_order,
        expected_order
    );
    let http3 = [capture.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "historical edge h3",
    );
    Ok(())
}

#[test]
fn historical_edge_153_no_store_fetch_matches_retained_h1_h2_requests() -> CaptureResult<()> {
    let template = edge::v153_windows_fetch_no_store_template();
    template.validate()?;
    let hints = edge::v153_windows_client_hints();
    let (http1, http2) = observed(&[&WEBSOCKET], "done", "empty")?;
    assert_eq!(http1.len(), 3);
    assert_eq!(http2.len(), 3);
    let priorities = Capture::parse(WEBSOCKET[0])?.http2_priorities("empty")?;
    assert_eq!(priorities.len(), 3);
    for priority in priorities {
        assert_eq!(
            priority.map(crate::Http2RequestPriority::Fixed),
            template.http2_priority
        );
    }
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        3,
        "historical edge fetch h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        3,
        "historical edge fetch h2",
    );
    assert_eq!(template.http3_fields, None);
    Ok(())
}
