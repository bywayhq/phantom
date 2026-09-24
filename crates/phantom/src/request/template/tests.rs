use phantom_net::request::RequestHeader;
use phantom_profile::{RequestField, RequestTemplate, chromium, edge, firefox};

use super::{ProtocolScope, check, expand, grease_brand, user_agent_products};
use crate::{HttpProtocol, RequestErrorKind};

const CHROME_154: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
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
    let template = chromium::v154_windows_fetch_no_store_template();
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
    assert_eq!(expanded[3].value(), CHROME_154.as_bytes());
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
    let template = chromium::v154_windows_navigation_template();
    let caller = [
        RequestHeader::new("Sec-CH-UA-Platform", "\"Windows\""),
        RequestHeader::new("sec-ch-ua", "\"Chromium\";v=\"154\""),
    ];
    let hints = chromium::v154_windows_client_hints();
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
            chromium::v154_windows_navigation_template(),
            Some(chromium::v154_windows_client_hints()),
            CHROME_154,
        ),
        (
            chromium::v154_windows_fetch_no_store_template(),
            Some(chromium::v154_windows_client_hints()),
            CHROME_154,
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
                if let RequestField::Literal { name, value } = field
                    && name.eq_ignore_ascii_case("user-agent")
                {
                    assert_eq!(&**value, user_agent);
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
    let chrome = chromium::v154_windows_navigation_template();
    let edge = edge::v153_windows_navigation_template();
    let firefox = firefox::v156_windows_navigation_template();
    let headless = CHROME_154.replace(" Chrome/", " HeadlessChrome/");
    let older = CHROME_154.replace("Chrome/154", "Chrome/153");
    let edge_headless = EDGE_153.replace(" Chrome/", " HeadlessChrome/");
    for (template, user_agent) in [
        (&chrome, older.as_str()),
        (&chrome, headless.as_str()),
        (&chrome, EDGE_153),
        (&chrome, FIREFOX_156),
        (&edge, CHROME_154),
        (&edge, edge_headless.as_str()),
        (&firefox, CHROME_154),
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
fn a_required_user_agent_that_nobody_supplies_is_rejected() {
    let edge = edge::v153_windows_navigation_template();
    let edge_hints = edge::v153_windows_client_hints();
    let referer = [RequestHeader::new("referer", "https://example.test/")];
    for template in [&edge, &edge::v153_windows_fetch_no_store_template()] {
        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            assert_eq!(
                kind(template, exact(protocol), &referer, Some(&edge_hints)),
                Some(RequestErrorKind::IdentityMismatch),
                "{protocol:?}"
            );
        }
    }
    let caller = [RequestHeader::new("User-Agent", EDGE_153)];
    assert_eq!(
        kind(
            &edge,
            exact(HttpProtocol::Http2),
            &caller,
            Some(&edge_hints)
        ),
        None
    );

    // Templates with a literal User-Agent need no caller value.
    for template in [
        chromium::v154_windows_navigation_template(),
        firefox::v156_windows_fetch_no_store_template(),
    ] {
        assert_eq!(kind(&template, exact(HttpProtocol::Http1), &[], None), None);
    }

    // A literal on some protocol lists is not enough.
    let mut template = chromium::v154_windows_navigation_template();
    template.http2_fields[2] = RequestField::caller("user-agent");
    assert_eq!(
        kind(&template, exact(HttpProtocol::Http1), &[], None),
        Some(RequestErrorKind::IdentityMismatch)
    );
}

#[test]
fn brand_lists_that_contradict_the_template_are_rejected() {
    let chrome = chromium::v154_windows_navigation_template();
    let firefox = firefox::v156_windows_navigation_template();
    let edge_brands = r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#;
    for (template, name, value) in [
        (&chrome, "sec-ch-ua", edge_brands),
        (
            &chrome,
            "sec-ch-ua",
            r#""Google Chrome";v="153", "Chromium";v="153""#,
        ),
        (&chrome, "Sec-CH-UA", "not a list ("),
        (
            &chrome,
            "sec-ch-ua-full-version-list",
            r#""Google Chrome";v="154.0.1.2", "Chromium";v="153.0.1.2""#,
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
            Some(&chromium::v154_windows_client_hints())
        ),
        Some(RequestErrorKind::IdentityMismatch)
    );
}

#[test]
fn brand_lists_with_extra_brands_are_rejected() {
    let chrome = chromium::v154_windows_navigation_template();
    let edge = edge::v153_windows_navigation_template();
    for (template, value) in [
        (
            &chrome,
            r#""Google Chrome";v="154", "Microsoft Edge";v="154", "Chromium";v="154""#,
        ),
        (
            &edge,
            r#""Microsoft Edge";v="153", "Google Chrome";v="153", "Chromium";v="153""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="154", "Not A(Brand";v="99", "Chromium";v="154", "Opera";v="154""#,
        ),
        // Two GREASE brands, a repeated brand, and a GREASE-like brand with
        // a version Chromium never chooses.
        (
            &chrome,
            r#""Google Chrome";v="154", "Not A(Brand";v="99", "Not?A_Brand";v="24", "Chromium";v="154""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="154", "Chromium";v="154", "Chromium";v="154""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="154", "Not A(Brand";v="154", "Chromium";v="154""#,
        ),
        // Well-shaped GREASE brands Chromium derives from another major
        // version: Chrome 152's brand, Chrome 154's brand with 152's version,
        // and a brand no 154 build sends.
        (
            &chrome,
            r#""Chromium";v="154", "Not?A_Brand";v="24", "Google Chrome";v="154""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="154", "Not A(Brand";v="24", "Chromium";v="154""#,
        ),
        (
            &chrome,
            r#""Google Chrome";v="154", "Not(A:Brand";v="99", "Chromium";v="154""#,
        ),
        (
            &edge,
            r#""Microsoft Edge";v="153", "Not?A_Brand";v="24", "Chromium";v="153""#,
        ),
    ] {
        let caller = [RequestHeader::new("sec-ch-ua", value)];
        assert_eq!(
            kind(template, exact(HttpProtocol::Http2), &caller, None),
            Some(RequestErrorKind::IdentityMismatch),
            "{value}"
        );
    }

    // Chrome 154's own GREASE brand is allowed once, and so is none.
    for value in [
        r#""Chromium";v="154", "Not A(Brand";v="99", "Google Chrome";v="154""#,
        r#""Google Chrome";v="154", "Chromium";v="154""#,
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
fn grease_brand_is_derived_from_the_major_version() {
    // The 154 value is the one in the retained Chrome 154 client-hint
    // capture; the neighbouring versions come from the same algorithm.
    assert_eq!(grease_brand(154), ("Not A(Brand".to_owned(), 99));
    assert_eq!(grease_brand(152), ("Not?A_Brand".to_owned(), 24));
    assert_eq!(grease_brand(153), ("Not_A Brand".to_owned(), 8));
    // The index wraps from the last character to the first, and the
    // version cycles through all three choices.
    assert_eq!(grease_brand(10), ("Not_A Brand".to_owned(), 99));
    assert_eq!(grease_brand(155), ("Not(A:Brand".to_owned(), 24));
}

#[test]
fn a_referer_on_a_navigation_template_goes_after_every_template_field() {
    let caller = [RequestHeader::new("referer", "https://example.test/")];
    for (fields, last) in [
        (
            chromium::v154_windows_navigation_template().http1_fields,
            "Accept-Language",
        ),
        (
            chromium::v154_windows_navigation_template().http2_fields,
            "priority",
        ),
        (
            firefox::v156_windows_navigation_template().http1_fields,
            "Priority",
        ),
        (
            firefox::v156_windows_navigation_template().http2_fields,
            "te",
        ),
    ] {
        let expanded = expand(&fields, &caller, None);
        assert_eq!(names(&expanded).last(), Some(&"referer"), "{last}");
        assert_eq!(names(&expanded)[expanded.len() - 2], last);
    }
}

#[test]
fn default_profile_hints_need_a_template_with_a_hint_slot() {
    use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    // No brand list, so the identity check passes and only placement fails.
    let platform_only = ClientHintSettings::new(vec![ClientHint::new(
        "sec-ch-ua-platform",
        "\"Windows\"",
        ClientHintDelivery::Default,
    )]);
    let requested_only = ClientHintSettings::new(vec![ClientHint::new(
        "sec-ch-ua-arch",
        "\"x86\"",
        ClientHintDelivery::AcceptCh,
    )]);
    let firefox = firefox::v156_windows_navigation_template();
    assert_eq!(
        kind(
            &firefox,
            exact(HttpProtocol::Http2),
            &[],
            Some(&platform_only)
        ),
        Some(RequestErrorKind::RequestTemplate)
    );
    // `check` allows a requested-only hint, because `prepare` refuses it
    // when it would be sent.
    assert_eq!(
        kind(
            &firefox,
            exact(HttpProtocol::Http2),
            &[],
            Some(&requested_only)
        ),
        None
    );
    assert_eq!(kind(&firefox, exact(HttpProtocol::Http2), &[], None), None);
    // A Chromium template has slots for the same profile.
    assert_eq!(
        kind(
            &chromium::v154_windows_navigation_template(),
            exact(HttpProtocol::Http2),
            &[],
            Some(&platform_only)
        ),
        None
    );
}

#[test]
fn a_caller_requested_hint_needs_a_template_that_places_it() {
    let hints = chromium::v154_windows_client_hints();
    let caller = [
        RequestHeader::new("referer", "https://example.com/"),
        RequestHeader::new("Sec-CH-UA-Arch", "\"x86\""),
    ];
    // Refused before I/O whatever the scheme: `check` sees no origin.
    assert_eq!(
        kind(
            &chromium::v154_windows_fetch_no_store_template(),
            exact(HttpProtocol::Http1),
            &caller,
            Some(&hints)
        ),
        Some(RequestErrorKind::RequestTemplate)
    );
    // The navigation template captures the requested-hint position, and a
    // default hint from the caller is never a requested one.
    assert_eq!(
        kind(
            &chromium::v154_windows_navigation_template(),
            exact(HttpProtocol::Http1),
            &caller,
            Some(&hints)
        ),
        None
    );
    let default_hint = [RequestHeader::new("sec-ch-ua-mobile", "?0")];
    assert_eq!(
        kind(
            &chromium::v154_windows_fetch_no_store_template(),
            exact(HttpProtocol::Http1),
            &default_hint,
            Some(&hints)
        ),
        None
    );
}

#[test]
fn a_request_that_may_use_http3_needs_an_http3_list() {
    let fetch = chromium::v154_windows_fetch_no_store_template();
    let navigation = chromium::v154_windows_navigation_template();
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
