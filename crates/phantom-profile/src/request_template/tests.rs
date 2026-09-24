use super::{
    RequestField, RequestTemplate,
    capture::{Capture, CaptureResult, Fields},
    client_hint_placement,
};
use crate::{
    ClientHintSettings, chromium, client_hints::navigation_capture::NavigationCapture, edge,
    firefox,
};

macro_rules! fixture {
    ($($part:literal),+) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/",
            $($part),+
        ))
    };
}

macro_rules! sse_set {
    ($browser:literal) => {
        [
            sse_set!(@one $browser, "default-delay"),
            sse_set!(@one $browser, "empty-id-resets"),
            sse_set!(@one $browser, "id-then-close"),
            sse_set!(@one $browser, "idle-headers-only-90s"),
            sse_set!(@one $browser, "invalid-retry-ignored"),
            sse_set!(@one $browser, "non-ascii-id"),
            sse_set!(@one $browser, "reconnect-204"),
            sse_set!(@one $browser, "reconnect-404"),
            sse_set!(@one $browser, "reconnect-500"),
            sse_set!(@one $browser, "reconnect-wrong-content-type"),
            sse_set!(@one $browser, "redirect-307-then-close"),
            sse_set!(@one $browser, "reset-before-head"),
            sse_set!(@one $browser, "retry-0"),
            sse_set!(@one $browser, "retry-100"),
            sse_set!(@one $browser, "retry-750"),
            sse_set!(@one $browser, "retry-persists-across-reconnect"),
            sse_set!(@one $browser, "set-cookie-then-close"),
        ]
    };
    (@one $browser:literal, $scenario:literal) => {
        fixture!("sse/", $browser, "/windows-11-26200/", $scenario, ".txt")
    };
}

macro_rules! websocket_set {
    ($browser:literal) => {
        [
            websocket_set!(@one $browser, "accept"),
            websocket_set!(@one $browser, "accept-deflate"),
            websocket_set!(@one $browser, "extension-mismatch"),
            websocket_set!(@one $browser, "fresh-origin"),
            websocket_set!(@one $browser, "h1-accept"),
            websocket_set!(@one $browser, "h1-accept-deflate"),
            websocket_set!(@one $browser, "no-connect-protocol"),
            websocket_set!(@one $browser, "refused-stream"),
            websocket_set!(@one $browser, "reject-403"),
        ]
    };
    (@one $browser:literal, $scenario:literal) => {
        fixture!("websocket/", $browser, "/windows-11-26200/", $scenario, ".txt")
    };
}

const CHROME_SSE: [&str; 17] = sse_set!("chrome/153.0.8010.48");
const FIREFOX_SSE: [&str; 17] = sse_set!("firefox/156.0");
const CHROME_WEBSOCKET: [&str; 9] = websocket_set!("chrome/153.0.8010.48");
const EDGE_WEBSOCKET: [&str; 9] = websocket_set!("edge/153.0.4234.48");
const FIREFOX_WEBSOCKET: [&str; 9] = websocket_set!("firefox/156.0");
const CHROME_HEADFUL_SSE: &str =
    fixture!("sse/chrome/153.0.8010.48/windows-11-26200/launch-mode/retry-750-headful.txt");
const CHROME_HEADLESS_SSE: &str =
    fixture!("sse/chrome/153.0.8010.48/windows-11-26200/launch-mode/retry-750-headless.txt");
const CHROME_HTTP3: &str =
    fixture!("http3/chrome/153.0.8010.48/windows-11-26200/client-startup.txt");
const EDGE_HTTP3: &str = fixture!("http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt");
const CHROME_CLIENT_HINTS: &str =
    fixture!("client-hints/chrome/153.0.8010.48/windows-11-26200/navigation.txt");
const EDGE_CLIENT_HINTS: &str =
    fixture!("client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt");
const CHROME_154_SSE: [&str; 17] = sse_set!("chrome/154.0.8037.58");
const CHROME_154_WEBSOCKET: [&str; 9] = websocket_set!("chrome/154.0.8037.58");
const CHROME_154_HEADFUL_SSE: &str =
    fixture!("sse/chrome/154.0.8037.58/windows-11-26200/launch-mode/retry-750-headful.txt");
const CHROME_154_HEADLESS_SSE: &str =
    fixture!("sse/chrome/154.0.8037.58/windows-11-26200/launch-mode/retry-750-headless.txt");
const CHROME_154_HTTP3: &str =
    fixture!("http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt");
const CHROME_154_CLIENT_HINTS: &str =
    fixture!("client-hints/chrome/154.0.8037.58/windows-11-26200/navigation.txt");

/// Which protocol list of a template a capture is compared with.
#[derive(Clone, Copy, Debug)]
enum Protocol {
    Http1,
    Http2,
    Http3,
}

fn fields(template: &RequestTemplate, protocol: Protocol) -> &[RequestField] {
    match protocol {
        Protocol::Http1 => &template.http1_fields,
        Protocol::Http2 => &template.http2_fields,
        Protocol::Http3 => template.http3_fields.as_deref().unwrap_or(&[]),
    }
}

/// Collects the requests of one kind from a capture set, per protocol.
fn observed(
    sets: &[&[&str]],
    http1_kind: &str,
    http2_destination: &str,
) -> CaptureResult<(Vec<Fields>, Vec<Fields>)> {
    let mut http1 = Vec::new();
    let mut http2 = Vec::new();
    for fixture in sets.iter().flat_map(|set| set.iter()) {
        let capture = Capture::parse(fixture)?;
        http1.extend(capture.http1_requests(http1_kind)?);
        http2.extend(capture.http2_requests(http2_destination)?);
    }
    Ok((http1, http2))
}

/// Asserts that one observed request is exactly what `fields` emits.
///
/// Literal fields must match name and value, caller slots only the name, and
/// client-hint slots the profile's value. Captures ran headless, so a literal
/// `User-Agent` may also appear with Chrome's `HeadlessChrome` product.
fn assert_matches(
    fields: &[RequestField],
    hints: Option<&ClientHintSettings>,
    request: &Fields,
    label: &str,
) {
    let hint_value = |name: &str| {
        hints
            .and_then(|hints| hints.hints().iter().find(|hint| hint.name() == name))
            .map(|hint| String::from_utf8_lossy(hint.value()).into_owned())
    };
    let slotted: Vec<&str> = fields
        .iter()
        .filter_map(|field| match field {
            RequestField::ClientHint { name } => Some(&**name),
            _ => None,
        })
        .collect();
    let mut observed = request.iter().peekable();
    for field in fields {
        match field {
            RequestField::Literal { name, value } => {
                let (seen_name, seen_value) = observed
                    .next()
                    .unwrap_or_else(|| panic!("{label}: missing {name}"));
                assert_eq!(seen_name, &**name, "{label}");
                let headless = value.replace(" Chrome/", " HeadlessChrome/");
                assert!(
                    seen_value == &**value
                        || (name.eq_ignore_ascii_case("user-agent") && seen_value == &headless),
                    "{label}: {name} was {seen_value:?}"
                );
            }
            RequestField::Caller { name } => {
                if observed.peek().is_some_and(|(seen, _)| seen == &**name) {
                    observed.next();
                }
            }
            RequestField::ClientHint { name } => {
                if let Some((_, value)) = observed.next_if(|(seen, _)| seen == &**name) {
                    assert_eq!(Some(value.clone()), hint_value(name), "{label}: {name}");
                }
            }
            RequestField::ClientHints => {
                let mut profile = hints.into_iter().flat_map(|hints| hints.hints());
                while let Some((name, value)) = observed.next_if(|(seen, _)| {
                    hint_value(seen).is_some() && !slotted.contains(&seen.as_str())
                }) {
                    assert!(
                        profile.any(|hint| hint.name() == name),
                        "{label}: {name} is out of profile order"
                    );
                    assert_eq!(Some(value.clone()), hint_value(name), "{label}: {name}");
                }
            }
        }
    }
    assert_eq!(observed.next(), None, "{label}: unexpected trailing field");
}

fn assert_all_match(
    template: &RequestTemplate,
    protocol: Protocol,
    hints: Option<&ClientHintSettings>,
    requests: &[Fields],
    minimum: usize,
    label: &str,
) {
    assert!(
        requests.len() >= minimum,
        "{label}: {} requests, expected at least {minimum}",
        requests.len()
    );
    for request in requests {
        assert_matches(fields(template, protocol), hints, request, label);
    }
}

#[test]
fn every_template_recipe_is_valid() {
    for template in [
        chromium::v153_windows_navigation_template(),
        chromium::v153_windows_fetch_no_store_template(),
        chromium::v154_windows_navigation_template(),
        chromium::v154_windows_fetch_no_store_template(),
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
        firefox::v156_windows_navigation_template(),
        firefox::v156_windows_fetch_no_store_template(),
    ] {
        assert_eq!(template.validate(), Ok(()));
    }
}

#[test]
fn chrome_153_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = chromium::v153_windows_navigation_template();
    let hints = chromium::v153_windows_client_hints();
    let (http1, http2) = observed(&[&CHROME_SSE, &CHROME_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        170,
        "chrome h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "chrome h2",
    );
    let http3 = [Capture::parse(CHROME_HTTP3)?.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "chrome h3",
    );
    Ok(())
}

#[test]
fn chrome_153_navigation_user_agent_is_the_headful_capture_value() -> CaptureResult<()> {
    let template = chromium::v153_windows_navigation_template();
    let literal = |fields: &[RequestField]| {
        fields.iter().find_map(|field| match field {
            RequestField::Literal { name, value } if name.eq_ignore_ascii_case("user-agent") => {
                Some(value.to_string())
            }
            _ => None,
        })
    };
    let expected = literal(&template.http1_fields);
    assert_eq!(literal(&template.http2_fields), expected);
    assert_eq!(
        literal(template.http3_fields.as_deref().unwrap_or(&[])),
        expected
    );

    let headful = Capture::parse(CHROME_HEADFUL_SSE)?.http1_requests("page")?;
    assert_eq!(headful.len(), 5);
    for request in &headful {
        let user_agent = request.iter().find(|(name, _)| name == "User-Agent");
        assert_eq!(user_agent.map(|(_, value)| value.clone()), expected);
    }
    let headless = Capture::parse(CHROME_HEADLESS_SSE)?.http1_requests("page")?;
    assert!(!headless.is_empty());
    for request in &headless {
        assert!(request.iter().any(
            |(name, value)| name == "User-Agent" && value.contains("HeadlessChrome/153.0.0.0")
        ));
    }
    Ok(())
}

#[test]
fn chrome_154_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = chromium::v154_windows_navigation_template();
    let hints = chromium::v154_windows_client_hints();
    let (http1, http2) = observed(
        &[&CHROME_154_SSE, &CHROME_154_WEBSOCKET],
        "page",
        "document",
    )?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        170,
        "chrome 154 h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "chrome 154 h2",
    );
    let http3 = [Capture::parse(CHROME_154_HTTP3)?.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "chrome 154 h3",
    );
    Ok(())
}

#[test]
fn chrome_154_navigation_user_agent_is_the_headful_capture_value() -> CaptureResult<()> {
    let template = chromium::v154_windows_navigation_template();
    let literal = |fields: &[RequestField]| {
        fields.iter().find_map(|field| match field {
            RequestField::Literal { name, value } if name.eq_ignore_ascii_case("user-agent") => {
                Some(value.to_string())
            }
            _ => None,
        })
    };
    let expected = literal(&template.http1_fields);
    assert_eq!(literal(&template.http2_fields), expected);
    assert_eq!(
        literal(template.http3_fields.as_deref().unwrap_or(&[])),
        expected
    );

    let headful = Capture::parse(CHROME_154_HEADFUL_SSE)?.http1_requests("page")?;
    assert_eq!(headful.len(), 5);
    for request in &headful {
        let user_agent = request.iter().find(|(name, _)| name == "User-Agent");
        assert_eq!(user_agent.map(|(_, value)| value.clone()), expected);
    }
    let headless = Capture::parse(CHROME_154_HEADLESS_SSE)?.http1_requests("page")?;
    assert!(!headless.is_empty());
    for request in &headless {
        assert!(request.iter().any(
            |(name, value)| name == "User-Agent" && value.contains("HeadlessChrome/154.0.0.0")
        ));
    }
    Ok(())
}

#[test]
fn chrome_154_fetch_matches_every_captured_no_store_fetch() -> CaptureResult<()> {
    let template = chromium::v154_windows_fetch_no_store_template();
    let hints = chromium::v154_windows_client_hints();
    let (http1, http2) = observed(&[&CHROME_154_WEBSOCKET], "done", "empty")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "chrome 154",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "chrome 154",
    );
    assert_eq!(template.http3_fields, None);
    Ok(())
}

#[test]
fn edge_153_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = edge::v153_windows_navigation_template();
    let hints = edge::v153_windows_client_hints();
    let (http1, http2) = observed(&[&EDGE_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "edge h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "edge h2",
    );
    let http3 = [Capture::parse(EDGE_HTTP3)?.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "edge h3",
    );
    Ok(())
}

#[test]
fn firefox_156_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = firefox::v156_windows_navigation_template();
    let (http1, http2) = observed(&[&FIREFOX_SSE, &FIREFOX_WEBSOCKET], "page", "document")?;
    assert_all_match(&template, Protocol::Http1, None, &http1, 170, "firefox h1");
    assert_all_match(&template, Protocol::Http2, None, &http2, 18, "firefox h2");
    assert_eq!(template.http3_fields, None);
    Ok(())
}

#[test]
fn chromium_153_fetch_matches_every_captured_no_store_fetch() -> CaptureResult<()> {
    for (template, hints, set, label) in [
        (
            chromium::v153_windows_fetch_no_store_template(),
            chromium::v153_windows_client_hints(),
            &CHROME_WEBSOCKET,
            "chrome",
        ),
        (
            edge::v153_windows_fetch_no_store_template(),
            edge::v153_windows_client_hints(),
            &EDGE_WEBSOCKET,
            "edge",
        ),
    ] {
        let (http1, http2) = observed(&[set], "done", "empty")?;
        assert_all_match(&template, Protocol::Http1, Some(&hints), &http1, 6, label);
        assert_all_match(&template, Protocol::Http2, Some(&hints), &http2, 18, label);
        assert!(http1.iter().chain(&http2).all(|request| {
            request
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("referer"))
        }));
        assert_eq!(template.http3_fields, None);
    }
    Ok(())
}

#[test]
fn firefox_156_fetch_matches_every_captured_no_store_fetch() -> CaptureResult<()> {
    let template = firefox::v156_windows_fetch_no_store_template();
    let (http1, http2) = observed(&[&FIREFOX_WEBSOCKET], "done", "empty")?;
    assert_all_match(&template, Protocol::Http1, None, &http1, 6, "firefox h1");
    assert_all_match(&template, Protocol::Http2, None, &http2, 18, "firefox h2");
    Ok(())
}

#[test]
fn only_templates_with_a_requested_hint_capture_claim_its_placement() {
    // The client-hint capture recorded Chrome and Edge navigations after
    // `Accept-CH`; no capture recorded a fetch after it.
    for (template, placed) in [
        (chromium::v153_windows_navigation_template(), true),
        (edge::v153_windows_navigation_template(), true),
        (chromium::v153_windows_fetch_no_store_template(), false),
        (edge::v153_windows_fetch_no_store_template(), false),
        (firefox::v156_windows_navigation_template(), false),
        (firefox::v156_windows_fetch_no_store_template(), false),
    ] {
        assert_eq!(template.requested_client_hint_placement, placed);
    }
}

#[test]
fn http2_priority_matches_every_captured_request_of_the_kind() -> CaptureResult<()> {
    let cases: [(RequestTemplate, &[&str], &str, u16); 6] = [
        (
            chromium::v153_windows_navigation_template(),
            &CHROME_WEBSOCKET,
            "document",
            256,
        ),
        (
            chromium::v153_windows_fetch_no_store_template(),
            &CHROME_WEBSOCKET,
            "empty",
            220,
        ),
        (
            edge::v153_windows_navigation_template(),
            &EDGE_WEBSOCKET,
            "document",
            256,
        ),
        (
            edge::v153_windows_fetch_no_store_template(),
            &EDGE_WEBSOCKET,
            "empty",
            220,
        ),
        (
            firefox::v156_windows_navigation_template(),
            &FIREFOX_WEBSOCKET,
            "document",
            42,
        ),
        (
            firefox::v156_windows_fetch_no_store_template(),
            &FIREFOX_WEBSOCKET,
            "empty",
            22,
        ),
    ];
    for (template, set, destination, weight) in cases {
        let mut priorities = Vec::new();
        for fixture in set {
            priorities.extend(Capture::parse(fixture)?.http2_priorities(destination)?);
        }
        assert!(
            priorities.len() >= 18,
            "{destination}: {}",
            priorities.len()
        );
        assert_eq!(template.http2_priority.map(|p| p.weight), Some(weight));
        for priority in priorities {
            assert_eq!(priority, template.http2_priority, "{destination}");
        }
    }

    // The fetch weights differ from the connection recipes' HEADERS
    // priority, so the template, not the H2 settings, must supply them.
    assert_ne!(
        chromium::v153_windows_fetch_no_store_template().http2_priority,
        chromium::v153_http2().headers_priority
    );
    assert_ne!(
        firefox::v156_windows_fetch_no_store_template().http2_priority,
        firefox::v156_http2().headers_priority
    );
    Ok(())
}

#[test]
fn chromium_navigation_hint_block_holds_accept_ch_hints_in_profile_order() -> CaptureResult<()> {
    for (fixture, hints) in [
        (CHROME_CLIENT_HINTS, chromium::v153_windows_client_hints()),
        (
            CHROME_154_CLIENT_HINTS,
            chromium::v154_windows_client_hints(),
        ),
        (EDGE_CLIENT_HINTS, edge::v153_windows_client_hints()),
    ] {
        use crate::ClientHintDelivery::Default;

        let capture = NavigationCapture::parse(fixture)?;
        let profile_names: Vec<&str> = hints.hints().iter().map(|hint| hint.name()).collect();
        let template_names = |requested: bool| {
            let mut names = vec!["Connection"];
            names.extend(profile_names.iter().copied().filter(|name| {
                requested
                    || hints
                        .hints()
                        .iter()
                        .any(|hint| hint.name() == *name && hint.delivery() == Default)
            }));
            names
        };
        let template = edge::v153_windows_navigation_template();
        let runs: usize = capture.value("repeat_count")?.parse()?;
        for run in 0..runs {
            // The first navigation is the full template on a fresh origin.
            let first: Vec<&str> = capture
                .value(&format!("run_{run}_first_field_order"))?
                .split(',')
                .collect();
            let mut expected = vec!["Host"];
            expected.extend(template_names(false));
            expected.extend(
                template
                    .http1_fields
                    .iter()
                    .skip(2)
                    .filter_map(RequestField::name),
            );
            assert_eq!(first, expected);

            // The second navigation follows `Accept-CH`: every requested hint
            // joins the block after `Connection`, in profile order.
            let second: Vec<&str> = capture
                .value(&format!("run_{run}_second_field_order"))?
                .split(',')
                .collect();
            let block_end = 1 + template_names(true).len();
            assert_eq!(second[1..block_end], template_names(true)[..]);
            assert_eq!(second[block_end], "Upgrade-Insecure-Requests");
        }
    }
    Ok(())
}

#[test]
fn validation_rejects_generated_repeated_and_misplaced_fields() {
    let mut template = chromium::v153_windows_navigation_template();
    template.http2_fields[1] = RequestField::literal("Upgrade-Insecure-Requests", "1");
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http2_fields")
    );

    for name in ["Host", "Cookie", "Content-Length", "Alt-Used"] {
        let mut template = firefox::v156_windows_navigation_template();
        template.http1_fields.push(RequestField::caller(name));
        assert!(template.validate().is_err(), "{name}");
    }

    // The jar's `Cookie` is placed by the profile's `CookiePlacement`, so no
    // template list may carry the field in any spelling.
    for field in [
        RequestField::caller("COOKIE"),
        RequestField::literal("Cookie", "a=b"),
    ] {
        let mut template = chromium::v153_windows_navigation_template();
        template.http1_fields.push(field);
        assert!(template.validate().is_err(), "HTTP/1.1 Cookie");
    }
    for protocol in [Protocol::Http2, Protocol::Http3] {
        let mut template = chromium::v153_windows_navigation_template();
        let list = match protocol {
            Protocol::Http2 => &mut template.http2_fields,
            _ => template.http3_fields.get_or_insert_with(Vec::new),
        };
        list.push(RequestField::literal("cookie", "a=b"));
        assert_eq!(
            template.validate().map_err(|error| error.reason()),
            Err("Host, Cookie, Alt-Used, and body framing fields are generated by the client"),
            "{protocol:?} cookie"
        );
    }

    let mut template = firefox::v156_windows_navigation_template();
    template
        .http1_fields
        .push(RequestField::literal("accept", "*/*"));
    assert!(template.validate().is_err());

    let mut template = firefox::v156_windows_navigation_template();
    template.http1_fields.push(RequestField::ClientHints);
    assert!(template.validate().is_err(), "hint slot at the end");

    let mut template = chromium::v153_windows_fetch_no_store_template();
    template
        .http2_fields
        .retain(|field| field != &RequestField::ClientHints);
    assert!(template.validate().is_err(), "single slots need a block");

    let mut template = chromium::v153_windows_navigation_template();
    template.http1_fields.swap(1, 2);
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http1_fields"),
        "hints placed differently on HTTP/1.1"
    );

    let mut template = chromium::v153_windows_navigation_template();
    template
        .identity
        .excluded_user_agent_products
        .push("Chrome".into());
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("identity")
    );

    for (dependency_stream_id, weight) in [(3, 220), (0, 0), (0, 257)] {
        let mut template = chromium::v153_windows_fetch_no_store_template();
        template.http2_priority = Some(crate::Http2Priority {
            dependency_stream_id,
            weight,
            exclusive: true,
        });
        assert_eq!(
            template.validate().map_err(|error| error.field()),
            Err("http2_priority"),
            "{dependency_stream_id} {weight}"
        );
    }
}

/// The presets' lowercase neighbour names are compared ASCII
/// case-insensitively, so they also find the templates' HTTP/1.1 spellings.
#[test]
fn cookie_placement_presets_find_their_neighbours_in_every_template_list() {
    let neighbour = |placement: &crate::CookiePlacement, fields: &[RequestField]| {
        let names: Vec<&str> = fields.iter().filter_map(RequestField::name).collect();
        placement
            .insertion_index(names.iter().copied())
            .map(|index| names[index].to_ascii_lowercase())
    };

    // Firefox: before the first `Upgrade-Insecure-Requests` or `Sec-Fetch-*`
    // field, which follows `Referer` on the fetch as in the SSE capture.
    let placement = firefox::v156_cookie_placement();
    for (template, expected) in [
        (
            firefox::v156_windows_navigation_template(),
            "upgrade-insecure-requests",
        ),
        (
            firefox::v156_windows_fetch_no_store_template(),
            "sec-fetch-dest",
        ),
    ] {
        for protocol in [Protocol::Http1, Protocol::Http2] {
            assert_eq!(
                neighbour(&placement, fields(&template, protocol)).as_deref(),
                Some(expected),
                "Firefox {protocol:?}"
            );
        }
    }

    // Chromium: last on HTTP/1.1, which sends no `Priority`; before the
    // final `priority` field on HTTP/2 and HTTP/3.
    let placement = chromium::v153_cookie_placement();
    for template in [
        chromium::v153_windows_navigation_template(),
        chromium::v153_windows_fetch_no_store_template(),
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
    ] {
        assert_eq!(neighbour(&placement, &template.http1_fields), None);
        for list in [Some(&template.http2_fields), template.http3_fields.as_ref()]
            .into_iter()
            .flatten()
        {
            assert_eq!(neighbour(&placement, list).as_deref(), Some("priority"));
            assert_eq!(list.last().and_then(RequestField::name), Some("priority"));
        }
    }
}

#[test]
fn validation_rejects_connection_specific_fields_on_http2_and_http3() {
    for name in ["connection", "keep-alive", "proxy-connection", "upgrade"] {
        let mut template = firefox::v156_windows_navigation_template();
        template
            .http2_fields
            .push(RequestField::literal(name, "value"));
        assert_eq!(
            template.validate().map_err(|error| error.field()),
            Err("http2_fields"),
            "{name}"
        );

        let mut template = chromium::v153_windows_navigation_template();
        if let Some(fields) = &mut template.http3_fields {
            fields.push(RequestField::caller(name));
        }
        assert_eq!(
            template.validate().map_err(|error| error.field()),
            Err("http3_fields"),
            "{name}"
        );
    }

    // Firefox's captured `te: trailers` is the one allowed `te` value.
    let mut template = firefox::v156_windows_navigation_template();
    assert_eq!(template.validate(), Ok(()));
    if let Some(te) = template.http2_fields.last_mut() {
        *te = RequestField::literal("te", "gzip");
    }
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http2_fields")
    );
    if let Some(te) = template.http2_fields.last_mut() {
        *te = RequestField::caller("te");
    }
    assert!(template.validate().is_err(), "a caller te value is unknown");

    // HTTP/1.1 lists keep `Connection: keep-alive`.
    assert!(
        chromium::v153_windows_navigation_template()
            .http1_fields
            .contains(&RequestField::literal("Connection", "keep-alive"))
    );
}

#[test]
fn client_hint_placement_names_fields_up_to_the_first_literal() {
    let chrome =
        client_hint_placement(&chromium::v153_windows_fetch_no_store_template().http1_fields);
    let edge = client_hint_placement(&edge::v153_windows_fetch_no_store_template().http2_fields);
    let names = |slots: &[super::ClientHintSlot]| {
        slots
            .iter()
            .map(|slot| {
                (
                    slot.hint.as_deref().map(str::to_owned),
                    slot.followed_by.join(","),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&chrome),
        [
            (
                Some("sec-ch-ua-platform".to_owned()),
                "user-agent".to_owned()
            ),
            (Some("sec-ch-ua".to_owned()), "accept".to_owned()),
            (Some("sec-ch-ua-mobile".to_owned()), "accept".to_owned()),
            (None, "accept".to_owned()),
        ]
    );
    // Edge's caller `user-agent` slot may be empty, so the hint also names
    // the literal after it.
    assert_eq!(names(&edge)[0].1, "user-agent,accept");
}

#[test]
fn comparison_rejects_another_browsers_request() -> CaptureResult<()> {
    let (firefox_pages, _) = observed(&[&FIREFOX_WEBSOCKET], "page", "document")?;
    let chrome = chromium::v153_windows_navigation_template();
    let hints = chromium::v153_windows_client_hints();
    let outcome = std::panic::catch_unwind(|| {
        assert_matches(
            &chrome.http1_fields,
            Some(&hints),
            &firefox_pages[0],
            "cross",
        );
    });
    assert!(outcome.is_err());
    Ok(())
}
