use phantom_net::request::RequestHeader;
use phantom_profile::{RequestField, RequestTemplate, chromium, edge, firefox};

use super::{PreparedRequestTemplate, ProtocolScope, check, expand};
use crate::{HttpProtocol, RequestErrorKind};

const CHROME_154: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const EDGE_153: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";

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
    let prepared = PreparedRequestTemplate::new(template.clone())
        .unwrap_or_else(|error| panic!("template is invalid: {error}"));
    check(&prepared, scope, caller, hints)
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
    let expanded = expand(&template.http1_fields, &caller, None, true);

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
        true,
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
    let expanded = expand(&template.http2_fields, &caller, Some(&hints), true);
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
fn built_in_templates_validate_and_place_their_own_client_hints() {
    let edge_user_agent = [RequestHeader::new("User-Agent", EDGE_153)];
    let cases = [
        (
            chromium::v154_windows_navigation_template(),
            Some(chromium::v154_windows_client_hints()),
            &[][..],
        ),
        (
            chromium::v154_windows_fetch_no_store_template(),
            Some(chromium::v154_windows_client_hints()),
            &[][..],
        ),
        (
            edge::v153_windows_navigation_template(),
            Some(edge::v153_windows_client_hints()),
            &edge_user_agent[..],
        ),
        (
            edge::v153_windows_fetch_no_store_template(),
            Some(edge::v153_windows_client_hints()),
            &edge_user_agent[..],
        ),
        (firefox::v156_windows_navigation_template(), None, &[][..]),
        (
            firefox::v156_windows_fetch_no_store_template(),
            None,
            &[][..],
        ),
    ];
    for (template, hints, caller) in cases {
        assert_eq!(
            kind(
                &template,
                exact(HttpProtocol::Http2),
                caller,
                hints.as_ref()
            ),
            None
        );
    }
}

#[test]
fn a_required_caller_slot_left_empty_is_rejected() {
    let edge = edge::v153_windows_navigation_template();
    let edge_hints = edge::v153_windows_client_hints();
    let referer = [RequestHeader::new("referer", "https://example.test/")];
    for template in [&edge, &edge::v153_windows_fetch_no_store_template()] {
        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            assert_eq!(
                kind(template, exact(protocol), &referer, Some(&edge_hints)),
                Some(RequestErrorKind::RequestTemplate),
                "{protocol:?}"
            );
        }
    }
    // Any value fills the slot; the client does not parse it.
    let caller = [RequestHeader::new("user-agent", "anything")];
    assert_eq!(
        kind(
            &edge,
            exact(HttpProtocol::Http2),
            &caller,
            Some(&edge_hints)
        ),
        None
    );

    // An optional caller slot may stay empty.
    let mut template = chromium::v154_windows_navigation_template();
    let user_agent = template
        .http2_fields
        .iter()
        .position(|field| field.name() == Some("user-agent"))
        .unwrap_or_default();
    template.http2_fields[user_agent] = RequestField::caller("user-agent");
    assert_eq!(kind(&template, exact(HttpProtocol::Http2), &[], None), None);
    // A required slot on one protocol list is required on every request.
    template.http2_fields[user_agent] = RequestField::required_caller("user-agent");
    assert_eq!(
        kind(&template, exact(HttpProtocol::Http1), &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );
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
        let expanded = expand(&fields, &caller, None, true);
        assert_eq!(names(&expanded).last(), Some(&"referer"), "{last}");
        assert_eq!(names(&expanded)[expanded.len() - 2], last);
    }
}

#[test]
fn default_profile_hints_need_a_template_with_a_hint_slot() {
    use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

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
fn invalid_templates_fail_to_prepare_and_disagreeing_accept_encoding_is_rejected() {
    let mut template = firefox::v156_windows_navigation_template();
    template.http2_fields.push(RequestField::caller("cookie"));
    assert_eq!(
        PreparedRequestTemplate::new(template)
            .err()
            .map(|error| error.field()),
        Some("http2_fields")
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
fn an_untrustworthy_url_drops_fetch_metadata_and_advanced_codings() {
    let template = firefox::v156_windows_navigation_template();
    let plaintext = expand(&template.http1_fields, &[], None, false);
    assert_eq!(
        names(&plaintext),
        [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "Upgrade-Insecure-Requests",
            "Priority",
        ]
    );
    assert_eq!(plaintext[3].value(), b"gzip, deflate");

    let loopback = expand(&template.http1_fields, &[], None, true);
    assert_eq!(
        names(&loopback)[5..],
        [
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Priority",
        ]
    );
    assert_eq!(loopback[3].value(), b"gzip, deflate, br, zstd");
}

#[test]
fn caller_fields_keep_trust_dependent_positions_on_either_url() {
    let template = chromium::v154_windows_navigation_template();
    let caller = [
        RequestHeader::new("accept-encoding", "br"),
        RequestHeader::new("sec-fetch-site", "cross-site"),
    ];
    for trustworthy in [false, true] {
        let expanded = expand(&template.http1_fields, &caller, None, trustworthy);
        let site = names(&expanded)
            .iter()
            .position(|name| *name == "Sec-Fetch-Site");
        assert_eq!(site, Some(4), "{trustworthy}");
        let encoding = expanded
            .iter()
            .find(|field| field.name() == "Accept-Encoding")
            .map(RequestHeader::value);
        assert_eq!(encoding, Some(&b"br"[..]), "{trustworthy}");
    }
}

#[test]
fn prepared_templates_report_the_accept_encoding_for_each_trust() {
    for template in [
        chromium::v154_windows_navigation_template(),
        chromium::v154_windows_fetch_no_store_template(),
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
        firefox::v156_windows_navigation_template(),
        firefox::v156_windows_fetch_no_store_template(),
    ] {
        let prepared = PreparedRequestTemplate::new(template)
            .unwrap_or_else(|error| panic!("template is invalid: {error}"));
        assert_eq!(prepared.accept_encoding(false), Some("gzip, deflate"));
        assert_eq!(
            prepared.accept_encoding(true),
            Some("gzip, deflate, br, zstd")
        );
        let decoding = ProtocolScope {
            content_decoding: true,
            ..exact(HttpProtocol::Http2)
        };
        assert_eq!(
            // Edge templates leave `User-Agent` to the caller.
            check(
                &prepared,
                decoding,
                &[RequestHeader::new("user-agent", EDGE_153)],
                None
            )
            .err()
            .map(|e| e.kind()),
            None
        );
    }

    // The lists must agree for each kind of URL, not only for one.
    let mut template = firefox::v156_windows_navigation_template();
    template.http2_fields[3] =
        RequestField::by_trust("accept-encoding", "gzip, deflate, br, zstd", "gzip");
    let decoding = ProtocolScope {
        content_decoding: true,
        ..exact(HttpProtocol::Http2)
    };
    assert_eq!(
        kind(&template, decoding, &[], None),
        Some(RequestErrorKind::RequestTemplate)
    );
}

#[test]
fn a_forwarded_caller_proxy_authorization_takes_the_preemptive_slot() {
    use super::{Forwarding, expand_on_route};

    let caller = [
        RequestHeader::new("x-trace", "1"),
        RequestHeader::new("proxy-authorization", "Basic caller").sensitive(),
    ];
    let forwarded = Forwarding {
        forwarded: true,
        credentials: None,
    };
    for (template, before) in [
        (
            chromium::v154_windows_navigation_template(),
            "Upgrade-Insecure-Requests",
        ),
        (firefox::v156_windows_navigation_template(), "Connection"),
    ] {
        let (expanded, placed) =
            expand_on_route(&template.http1_fields, &caller, None, false, forwarded);
        assert!(!placed);
        let fields = names(&expanded);
        let position = fields
            .iter()
            .position(|name| *name == "Proxy-Authorization")
            .unwrap_or_else(|| panic!("caller field was not placed: {fields:?}"));
        assert_eq!(fields[position + 1], before);
        assert_eq!(fields.last(), Some(&"x-trace"));
        assert!(expanded[position].is_sensitive());
    }

    // A request that no proxy forwards keeps the caller's order.
    let (expanded, _) = expand_on_route(
        &chromium::v154_windows_navigation_template().http1_fields,
        &caller,
        None,
        false,
        Forwarding::default(),
    );
    assert_eq!(names(&expanded).last(), Some(&"proxy-authorization"));
}
