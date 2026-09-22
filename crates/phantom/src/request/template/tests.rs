use phantom_net::request::RequestHeader;
use phantom_profile::{RequestField, RequestTemplate, chromium, edge, firefox};

use super::{ProtocolScope, check, expand, is_grease_brand, user_agent_products};
use crate::{HttpProtocol, RequestErrorKind};

const CHROME_153: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";
const EDGE_153: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";
const FIREFOX_156: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";

fn exact(protocol: HttpProtocol) -> ProtocolScope {
    ProtocolScope {
        exact: Some(protocol),
        alt_svc: false,
        content_decoding: false,
    }
}

fn names(headers: &[RequestHeader]) -> Vec<&str> {
    headers.iter().map(RequestHeader::name).collect()
}

fn kind(
    template: &RequestTemplate,
    scope: ProtocolScope,
    caller: &[RequestHeader],
    hints: Option<&phantom_profile::ClientHintSettings>,
) -> Option<RequestErrorKind> {
    check(template, scope, caller, hints)
        .err()
        .map(|error| error.kind())
}

#[test]
fn caller_fields_take_template_positions_and_spelling() {
    let template = chromium::v153_windows_fetch_no_store_template();
    let caller = [
        RequestHeader::new("x-trace", "1"),
        RequestHeader::new("referer", "https://example.test/page"),
        RequestHeader::new("accept-language", "de-DE,de;q=0.9").sensitive(),
    ];
    let expanded = expand(&template.http1_fields, &caller, None);

    assert_eq!(
        names(&expanded),
        [
            "Connection",
            "Pragma",
            "Cache-Control",
            "User-Agent",
            "Accept",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Referer",
            "Accept-Encoding",
            "Accept-Language",
            "x-trace",
        ]
    );
    assert_eq!(expanded[3].value(), CHROME_153.as_bytes());
    assert_eq!(expanded[8].value(), b"https://example.test/page");
    assert_eq!(expanded[10].value(), b"de-DE,de;q=0.9");
    assert!(expanded[10].is_sensitive());
}

#[test]
fn unfilled_caller_slots_emit_nothing_and_hint_values_wait_for_the_connection() {
    let template = edge::v153_windows_fetch_no_store_template();
    let expanded = expand(
        &template.http2_fields,
        &[],
        Some(&edge::v153_windows_client_hints()),
    );
    assert_eq!(
        names(&expanded),
        [
            "pragma",
            "cache-control",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
}

#[test]
fn caller_hints_fill_the_block_in_profile_order() {
    let template = chromium::v153_windows_navigation_template();
    let caller = [
        RequestHeader::new("Sec-CH-UA-Platform", "\"Windows\""),
        RequestHeader::new("sec-ch-ua", "\"Chromium\";v=\"153\""),
    ];
    let hints = chromium::v153_windows_client_hints();
    let expanded = expand(&template.http2_fields, &caller, Some(&hints));
    assert_eq!(
        names(&expanded)[..3],
        [
            "sec-ch-ua",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests"
        ]
    );
}

#[test]
fn built_in_templates_agree_with_their_own_identity_and_client_hints() {
    let cases = [
        (
            chromium::v153_windows_navigation_template(),
            Some(chromium::v153_windows_client_hints()),
            CHROME_153,
        ),
        (
            chromium::v153_windows_fetch_no_store_template(),
            Some(chromium::v153_windows_client_hints()),
            CHROME_153,
        ),
        (
            edge::v153_windows_navigation_template(),
            Some(edge::v153_windows_client_hints()),
            EDGE_153,
        ),
        (
            edge::v153_windows_fetch_no_store_template(),
            Some(edge::v153_windows_client_hints()),
            EDGE_153,
        ),
        (
            firefox::v156_windows_navigation_template(),
            None,
            FIREFOX_156,
        ),
        (
            firefox::v156_windows_fetch_no_store_template(),
            None,
            FIREFOX_156,
        ),
    ];
    for (template, hints, user_agent) in cases {
        for fields in [&template.http1_fields, &template.http2_fields] {
            for field in fields {
                if let RequestField::Literal { name, value } = field {
                    if name.eq_ignore_ascii_case("user-agent") {
                        assert_eq!(&**value, user_agent);
                    }
                }
            }
        }
        let caller = [RequestHeader::new("User-Agent", user_agent)];
        assert_eq!(
            kind(
                &template,
                exact(HttpProtocol::Http2),
                &caller,
                hints.as_ref()
            ),
            None
        );
    }
}

#[test]
fn user_agent_of_another_browser_or_version_is_rejected() {
    let chrome = chromium::v153_windows_navigation_template();
    let edge = edge::v153_windows_navigation_template();
    let firefox = firefox::v156_windows_navigation_template();
    let headless = CHROME_153.replace(" Chrome/", " HeadlessChrome/");
    let older = CHROME_153.replace("Chrome/153", "Chrome/152");
    let edge_headless = EDGE_153.replace(" Chrome/", " HeadlessChrome/");
    for (template, user_agent) in [
        (&chrome, older.as_str()),
        (&chrome, headless.as_str()),
        (&chrome, EDGE_153),
        (&chrome, FIREFOX_156),
        (&edge, CHROME_153),
        (&edge, edge_headless.as_str()),
        (&firefox, CHROME_153),
        (
            &firefox,
            "Mozilla/5.0 (rv:155.0) Gecko/20100101 Firefox/155.0",
        ),
    ] {
        let caller = [RequestHeader::new("user-agent", user_agent)];
        assert_eq!(
            kind(template, exact(HttpProtocol::Http1), &caller, None),
            Some(RequestErrorKind::IdentityMismatch),
            "{user_agent}"
        );
    }
}

#[test]
fn brand_lists_that_contradict_the_template_are_rejected() {
    let chrome = chromium::v153_windows_navigation_template();
    let firefox = firefox::v156_windows_navigation_template();
    let edge_brands = r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#;
    for (template, name, value) in [
        (&chrome, "sec-ch-ua", edge_brands),
        (
            &chrome,
            "sec-ch-ua",
            r#""Google Chrome";v="152", "Chromium";v="152""#,
        ),
        (&chrome, "Sec-CH-UA", "not a list ("),
        (
            &chrome,
            "sec-ch-ua-full-version-list",
            r#""Google Chrome";v="152.0.1.2", "Chromium";v="153.0.1.2""#,
        ),
        (&firefox, "sec-ch-ua", edge_brands),
    ] {
        let caller = [RequestHeader::new(name, value)];
        assert_eq!(
            kind(template, exact(HttpProtocol::Http2), &caller, None),
            Some(RequestErrorKind::IdentityMismatch),
            "{value}"
        );
    }

    // A profile whose own hints name Edge contradicts a Chrome template.
    assert_eq!(
        kind(
            &chrome,
            exact(HttpProtocol::Http2),
            &[],
            Some(&edge::v153_windows_client_hints())
        ),
        Some(RequestErrorKind::IdentityMismatch)
    );
    assert_eq!(
        kind(
            &firefox,
            exact(HttpProtocol::Http2),
            &[],
            Some(&chromium::v153_windows_client_hints())
        ),
        Some(RequestErrorKind::IdentityMismatch)
    );
}

#[test]
fn brand_lists_with_extra_brands_are_rejected() {
    let chrome = chromium::v153_windows_navigation_template();
    let edge = edge::v153_windows_navigation_template();
    for (template, value) in [
        (
            &chrome,
            r#""Google Chrome";v="153", "Microsoft Edge";v="153", "Chromium";v="153""#,
        ),
        (
            &edge,
            r#""Microsoft Edge";v="153", "Google Chrome";v="153", "Chromium";v="153""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153", "Opera";v="153""#,
        ),
        // Two GREASE brands, a repeated brand, and a GREASE-like brand with
        // a version Chromium never chooses.
        (
            &chrome,
            r#""Google Chrome";v="153", "Not_A Brand";v="8", "Not?A_Brand";v="24", "Chromium";v="153""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="153", "Chromium";v="153", "Chromium";v="153""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="153", "Not_A Brand";v="153", "Chromium";v="153""#,
        ),
    ] {
        let caller = [RequestHeader::new("sec-ch-ua", value)];
        assert_eq!(
            kind(template, exact(HttpProtocol::Http2), &caller, None),
            Some(RequestErrorKind::IdentityMismatch),
            "{value}"
        );
    }

    // One GREASE brand is allowed, and so is none.
    for value in [
        r#""Chromium";v="153", "Not?A_Brand";v="24", "Google Chrome";v="153""#,
        r#""Google Chrome";v="153", "Chromium";v="153""#,
    ] {
        let caller = [RequestHeader::new("sec-ch-ua", value)];
        assert_eq!(
            kind(&chrome, exact(HttpProtocol::Http2), &caller, None),
            None,
            "{value}"
        );
    }
}

#[test]
fn grease_brands_follow_chromiums_algorithm() {
    // Chrome 152 and 153 values from the retained client-hint captures.
    assert!(is_grease_brand("Not?A_Brand", Some(24)));
    assert!(is_grease_brand("Not_A Brand", Some(8)));
    assert!(is_grease_brand("Not(A:Brand", Some(99)));
    assert!(!is_grease_brand("Not_A Brand", None));
    assert!(!is_grease_brand("Not_A Brand", Some(153)));
    assert!(!is_grease_brand("NotXA Brand", Some(8)));
    assert!(!is_grease_brand("Not A Brand ", Some(8)));
    assert!(!is_grease_brand("Microsoft Edge", Some(8)));
}

#[test]
fn a_request_that_may_use_http3_needs_an_http3_list() {
    let fetch = chromium::v153_windows_fetch_no_store_template();
    let navigation = chromium::v153_windows_navigation_template();
    let negotiated = |alt_svc| ProtocolScope {
        exact: None,
        alt_svc,
        content_decoding: false,
    };

    assert_eq!(
        kind(&fetch, exact(HttpProtocol::Http3), &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );
    assert_eq!(
        kind(&fetch, negotiated(true), &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );
    assert_eq!(kind(&fetch, negotiated(false), &[], None), None);
    assert_eq!(
        kind(&navigation, exact(HttpProtocol::Http3), &[], None),
        None
    );
    assert_eq!(kind(&navigation, negotiated(true), &[], None), None);
}

#[test]
fn invalid_templates_and_disagreeing_accept_encoding_are_rejected() {
    let mut template = firefox::v156_windows_navigation_template();
    template.http2_fields.push(RequestField::caller("cookie"));
    assert_eq!(
        kind(&template, exact(HttpProtocol::Http2), &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );

    let mut template = firefox::v156_windows_navigation_template();
    template.http2_fields[3] = RequestField::literal("accept-encoding", "gzip");
    let decoding = ProtocolScope {
        content_decoding: true,
        ..exact(HttpProtocol::Http2)
    };
    assert_eq!(
        kind(&template, decoding, &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );
    assert_eq!(kind(&template, exact(HttpProtocol::Http2), &[], None), None);
}

#[test]
fn user_agent_products_skip_comments() {
    assert_eq!(
        user_agent_products(EDGE_153),
        [
            ("Mozilla", "5.0"),
            ("AppleWebKit", "537.36"),
            ("Chrome", "153.0.0.0"),
            ("Safari", "537.36"),
            ("Edg", "153.0.0.0"),
        ]
    );
    assert_eq!(
        user_agent_products(FIREFOX_156),
        [
            ("Mozilla", "5.0"),
            ("Gecko", "20100101"),
            ("Firefox", "156.0")
        ]
    );
}
