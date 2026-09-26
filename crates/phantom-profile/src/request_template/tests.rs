use super::{
    RequestField, RequestTemplate,
    capture::{Capture, CaptureResult, Fields},
    client_hint_placement,
};
use crate::{
    ClientHintSettings, brave, brave_android, chrome_android, chromium,
    client_hints::navigation_capture::NavigationCapture, edge, firefox, opera,
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
        websocket_set!($browser, "windows-11-26200")
    };
    ($browser:literal, $host:literal) => {
        [
            websocket_set!(@one $browser, $host, "accept"),
            websocket_set!(@one $browser, $host, "accept-deflate"),
            websocket_set!(@one $browser, $host, "extension-mismatch"),
            websocket_set!(@one $browser, $host, "fresh-origin"),
            websocket_set!(@one $browser, $host, "h1-accept"),
            websocket_set!(@one $browser, $host, "h1-accept-deflate"),
            websocket_set!(@one $browser, $host, "no-connect-protocol"),
            websocket_set!(@one $browser, $host, "refused-stream"),
            websocket_set!(@one $browser, $host, "reject-403"),
        ]
    };
    (@one $browser:literal, $host:literal, $scenario:literal) => {
        fixture!("websocket/", $browser, "/", $host, "/", $scenario, ".txt")
    };
}

const CHROME_SSE: [&str; 17] = sse_set!("chrome/154.0.8037.58");
const FIREFOX_SSE: [&str; 17] = sse_set!("firefox/156.0");
const CHROME_WEBSOCKET: [&str; 9] = websocket_set!("chrome/154.0.8037.58");
const EDGE_WEBSOCKET: [&str; 9] = websocket_set!("edge/153.0.4234.48");
const FIREFOX_WEBSOCKET: [&str; 9] = websocket_set!("firefox/156.0");
const BRAVE_WEBSOCKET: [&str; 9] = websocket_set!("brave/154.1.96.59");
/// Every Brave proxy route scenario, three runs each.
const BRAVE_PROXY: [&str; 20] = [
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/direct-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/direct-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-nostore-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-nostore-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-remembered-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-auth-secure-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/http-proxy-secure-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-nostore-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-nostore-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-remembered-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-auth-secure-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-hostname.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-loopback.txt"),
    fixture!("proxy/brave/154.1.96.59/windows-11-26200/https-proxy-secure-hostname.txt"),
];
const OPERA_WEBSOCKET: [&str; 9] = websocket_set!("opera/135.0.5973.92");
const CHROME_ANDROID_WEBSOCKET: [&str; 9] =
    websocket_set!("chrome-android/153.0.8010.52", "android-35-emulator");
const BRAVE_ANDROID_WEBSOCKET: [&str; 9] =
    websocket_set!("brave-android/153.1.95.104", "android-35-emulator");
const CHROME_HEADFUL_SSE: &str =
    fixture!("sse/chrome/154.0.8037.58/windows-11-26200/launch-mode/retry-750-headful.txt");
const CHROME_HEADLESS_SSE: &str =
    fixture!("sse/chrome/154.0.8037.58/windows-11-26200/launch-mode/retry-750-headless.txt");
const CHROME_HTTP3: &str =
    fixture!("http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt");
const EDGE_HTTP3: &str = fixture!("http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt");
const BRAVE_HTTP3: &str = fixture!("http3/brave/154.1.96.59/windows-11-26200/client-startup.txt");
const OPERA_HTTP3: &str = fixture!("http3/opera/135.0.5973.92/windows-11-26200/client-startup.txt");
const CHROME_CLIENT_HINTS: &str =
    fixture!("client-hints/chrome/154.0.8037.58/windows-11-26200/navigation.txt");
const EDGE_CLIENT_HINTS: &str =
    fixture!("client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt");
const BRAVE_CLIENT_HINTS: &str =
    fixture!("client-hints/brave/154.1.96.59/windows-11-26200/navigation.txt");
const OPERA_CLIENT_HINTS: &str =
    fixture!("client-hints/opera/135.0.5973.92/windows-11-26200/navigation.txt");
const BRAVE_ANDROID_CLIENT_HINTS: &str =
    fixture!("client-hints/brave-android/153.1.95.104/android-35-emulator/navigation.txt");
const CHROME_ANDROID_CLIENT_HINTS: &str =
    fixture!("client-hints/chrome-android/153.0.8010.52/android-35-emulator/navigation.txt");
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
            // Every retained capture read here loaded a `127.0.0.1` page,
            // which browsers treat as potentially trustworthy.
            RequestField::ByTrust {
                name,
                trustworthy: Some(value),
                ..
            } => {
                let (seen_name, seen_value) = observed
                    .next()
                    .unwrap_or_else(|| panic!("{label}: missing {name}"));
                assert_eq!(seen_name, &**name, "{label}");
                assert_eq!(seen_value, &**value, "{label}: {name}");
            }
            RequestField::ByTrust { name, .. } => {
                assert!(
                    observed.peek().is_none_or(|(seen, _)| seen != &**name),
                    "{label}: {name} is sent only to other URLs"
                );
            }
            // No capture read here went through an HTTP proxy.
            RequestField::ByForwarding {
                name,
                unforwarded: Some(value),
                ..
            } => {
                let (seen_name, seen_value) = observed
                    .next()
                    .unwrap_or_else(|| panic!("{label}: missing {name}"));
                assert_eq!(seen_name, &**name, "{label}");
                assert_eq!(seen_value, &**value, "{label}: {name}");
            }
            RequestField::ByForwarding { name, .. } => {
                assert!(
                    observed.peek().is_none_or(|(seen, _)| seen != &**name),
                    "{label}: {name} is sent only through a forwarding proxy"
                );
            }
            // Nor did any carry proxy credentials.
            RequestField::ProxyAuthorization { name, .. } => {
                assert!(
                    observed.peek().is_none_or(|(seen, _)| seen != &**name),
                    "{label}: {name} is sent only to an HTTP proxy"
                );
            }
            RequestField::Caller { name, .. } => {
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
        chromium::v154_windows_navigation_template(),
        chromium::v154_windows_fetch_no_store_template(),
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
        brave::v154_windows_navigation_template(),
        brave::v154_windows_fetch_no_store_template(),
        opera::v135_windows_navigation_template(),
        opera::v135_windows_fetch_no_store_template(),
        firefox::v156_windows_navigation_template(),
        firefox::v156_windows_fetch_no_store_template(),
        chrome_android::v153_android_navigation_template(),
        chrome_android::v153_android_fetch_no_store_template(),
        brave_android::v153_android_navigation_template(),
        brave_android::v153_android_fetch_no_store_template(),
    ] {
        assert_eq!(template.validate(), Ok(()));
    }
}

#[test]
fn chrome_154_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = chromium::v154_windows_navigation_template();
    let hints = chromium::v154_windows_client_hints();
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
            |(name, value)| name == "User-Agent" && value.contains("HeadlessChrome/154.0.0.0")
        ));
    }
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

/// The Android captures loaded their pages by typing the URL into the address
/// bar, so each carries `Sec-Fetch-User` like a desktop address-bar load.
#[test]
fn chrome_android_153_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = chrome_android::v153_android_navigation_template();
    let hints = chrome_android::v153_android_client_hints("sdk_gphone64_x86_64");
    let (http1, http2) = observed(&[&CHROME_ANDROID_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "chrome android h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "chrome android h2",
    );
    Ok(())
}

#[test]
fn brave_154_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = brave::v154_windows_navigation_template();
    let hints = brave::v154_windows_client_hints();
    let (http1, http2) = observed(&[&BRAVE_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "brave h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "brave h2",
    );
    let http3 = [Capture::parse(BRAVE_HTTP3)?.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "brave h3",
    );
    Ok(())
}

#[test]
fn opera_135_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = opera::v135_windows_navigation_template();
    let hints = opera::v135_windows_client_hints();
    let (http1, http2) = observed(&[&OPERA_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "opera h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "opera h2",
    );
    let http3 = [Capture::parse(OPERA_HTTP3)?.http3_request()?];
    assert_all_match(
        &template,
        Protocol::Http3,
        Some(&hints),
        &http3,
        1,
        "opera h3",
    );
    Ok(())
}

/// Brave draws the `q` value of its second `Accept-Language` entry per
/// browser session, so its templates leave the field to the caller. In the
/// 87 WebSocket and proxy route runs, every request of one run carries one
/// value, and the runs together show all five values.
#[test]
fn brave_154_accept_language_is_one_drawn_value_per_session() -> CaptureResult<()> {
    use std::collections::BTreeSet;

    let allowed: BTreeSet<String> = ["0.5", "0.6", "0.7", "0.8", "0.9"]
        .iter()
        .map(|q| format!("en-US,en;q={q}"))
        .collect();
    let mut seen = BTreeSet::new();
    let mut runs = 0;
    for fixture in BRAVE_WEBSOCKET.iter().chain(&BRAVE_PROXY) {
        for run in Capture::parse(fixture)?.accept_language_by_run()? {
            assert_eq!(run.len(), 1, "{run:?}");
            seen.extend(run);
            runs += 1;
        }
    }
    assert_eq!(runs, 87);
    assert_eq!(seen, allowed);
    for template in [
        brave::v154_windows_navigation_template(),
        brave::v154_windows_fetch_no_store_template(),
    ] {
        let slots: Vec<&RequestField> = template
            .http1_fields
            .iter()
            .chain(&template.http2_fields)
            .chain(template.http3_fields.iter().flatten())
            .filter(|field| {
                field
                    .name()
                    .is_some_and(|name| name.eq_ignore_ascii_case("accept-language"))
            })
            .collect();
        assert!(!slots.is_empty());
        for field in slots {
            assert!(matches!(field, RequestField::Caller { required: true, .. }));
        }
    }
    Ok(())
}

#[test]
fn brave_android_153_navigation_matches_every_captured_page_request() -> CaptureResult<()> {
    let template = brave_android::v153_android_navigation_template();
    let hints = brave_android::v153_android_client_hints();
    let (http1, http2) = observed(&[&BRAVE_ANDROID_WEBSOCKET], "page", "document")?;
    assert_all_match(
        &template,
        Protocol::Http1,
        Some(&hints),
        &http1,
        6,
        "brave android h1",
    );
    assert_all_match(
        &template,
        Protocol::Http2,
        Some(&hints),
        &http2,
        18,
        "brave android h2",
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
fn chromium_family_fetch_matches_every_captured_no_store_fetch() -> CaptureResult<()> {
    for (template, hints, set, label) in [
        (
            chromium::v154_windows_fetch_no_store_template(),
            chromium::v154_windows_client_hints(),
            &CHROME_WEBSOCKET,
            "chrome",
        ),
        (
            edge::v153_windows_fetch_no_store_template(),
            edge::v153_windows_client_hints(),
            &EDGE_WEBSOCKET,
            "edge",
        ),
        (
            brave::v154_windows_fetch_no_store_template(),
            brave::v154_windows_client_hints(),
            &BRAVE_WEBSOCKET,
            "brave",
        ),
        (
            opera::v135_windows_fetch_no_store_template(),
            opera::v135_windows_client_hints(),
            &OPERA_WEBSOCKET,
            "opera",
        ),
        (
            chrome_android::v153_android_fetch_no_store_template(),
            chrome_android::v153_android_client_hints("sdk_gphone64_x86_64"),
            &CHROME_ANDROID_WEBSOCKET,
            "chrome android",
        ),
        (
            brave_android::v153_android_fetch_no_store_template(),
            brave_android::v153_android_client_hints(),
            &BRAVE_ANDROID_WEBSOCKET,
            "brave android",
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
        (chromium::v154_windows_navigation_template(), true),
        (edge::v153_windows_navigation_template(), true),
        (chromium::v154_windows_fetch_no_store_template(), false),
        (edge::v153_windows_fetch_no_store_template(), false),
        (brave::v154_windows_navigation_template(), true),
        (brave::v154_windows_fetch_no_store_template(), false),
        (opera::v135_windows_navigation_template(), true),
        (opera::v135_windows_fetch_no_store_template(), false),
        (chrome_android::v153_android_navigation_template(), true),
        (brave_android::v153_android_navigation_template(), true),
        (brave_android::v153_android_fetch_no_store_template(), false),
        (
            chrome_android::v153_android_fetch_no_store_template(),
            false,
        ),
        (firefox::v156_windows_navigation_template(), false),
        (firefox::v156_windows_fetch_no_store_template(), false),
    ] {
        assert_eq!(template.requested_client_hint_placement, placed);
    }
}

#[test]
fn http2_priority_matches_every_captured_request_of_the_kind() -> CaptureResult<()> {
    let cases: [(RequestTemplate, &[&str], &str, u16); 14] = [
        (
            chromium::v154_windows_navigation_template(),
            &CHROME_WEBSOCKET,
            "document",
            256,
        ),
        (
            chromium::v154_windows_fetch_no_store_template(),
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
            brave::v154_windows_navigation_template(),
            &BRAVE_WEBSOCKET,
            "document",
            256,
        ),
        (
            brave::v154_windows_fetch_no_store_template(),
            &BRAVE_WEBSOCKET,
            "empty",
            220,
        ),
        (
            opera::v135_windows_navigation_template(),
            &OPERA_WEBSOCKET,
            "document",
            256,
        ),
        (
            opera::v135_windows_fetch_no_store_template(),
            &OPERA_WEBSOCKET,
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
        (
            chrome_android::v153_android_navigation_template(),
            &CHROME_ANDROID_WEBSOCKET,
            "document",
            256,
        ),
        (
            chrome_android::v153_android_fetch_no_store_template(),
            &CHROME_ANDROID_WEBSOCKET,
            "empty",
            220,
        ),
        (
            brave_android::v153_android_navigation_template(),
            &BRAVE_ANDROID_WEBSOCKET,
            "document",
            256,
        ),
        (
            brave_android::v153_android_fetch_no_store_template(),
            &BRAVE_ANDROID_WEBSOCKET,
            "empty",
            220,
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
        chromium::v154_windows_fetch_no_store_template().http2_priority,
        chromium::v154_http2().headers_priority
    );
    assert_ne!(
        firefox::v156_windows_fetch_no_store_template().http2_priority,
        firefox::v156_http2().headers_priority
    );
    Ok(())
}

#[test]
fn chromium_navigation_hint_block_holds_accept_ch_hints_in_profile_order() -> CaptureResult<()> {
    // Each capture is compared with its own browser's template, so Brave's
    // `Sec-GPC` after `Accept` is part of the expected order.
    for (fixture, hints, template) in [
        (
            CHROME_CLIENT_HINTS,
            chromium::v154_windows_client_hints(),
            chromium::v154_windows_navigation_template(),
        ),
        (
            EDGE_CLIENT_HINTS,
            edge::v153_windows_client_hints(),
            edge::v153_windows_navigation_template(),
        ),
        (
            BRAVE_CLIENT_HINTS,
            brave::v154_windows_client_hints(),
            brave::v154_windows_navigation_template(),
        ),
        (
            OPERA_CLIENT_HINTS,
            opera::v135_windows_client_hints(),
            opera::v135_windows_navigation_template(),
        ),
        (
            CHROME_ANDROID_CLIENT_HINTS,
            chrome_android::v153_android_client_hints("sdk_gphone64_x86_64"),
            chrome_android::v153_android_navigation_template(),
        ),
        (
            BRAVE_ANDROID_CLIENT_HINTS,
            brave_android::v153_android_client_hints(),
            brave_android::v153_android_navigation_template(),
        ),
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
                    .skip_while(|field| **field != RequestField::ClientHints)
                    .skip(1)
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
    let mut template = chromium::v154_windows_navigation_template();
    template.http2_fields[2] = RequestField::literal("Upgrade-Insecure-Requests", "1");
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
        let mut template = chromium::v154_windows_navigation_template();
        template.http1_fields.push(field);
        assert!(template.validate().is_err(), "HTTP/1.1 Cookie");
    }
    for protocol in [Protocol::Http2, Protocol::Http3] {
        let mut template = chromium::v154_windows_navigation_template();
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

    let mut template = chromium::v154_windows_fetch_no_store_template();
    template
        .http2_fields
        .retain(|field| field != &RequestField::ClientHints);
    assert!(template.validate().is_err(), "single slots need a block");

    let mut template = chromium::v154_windows_navigation_template();
    let block = template
        .http1_fields
        .iter()
        .position(|field| *field == RequestField::ClientHints)
        .unwrap_or_default();
    template.http1_fields.swap(block, block + 1);
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http1_fields"),
        "hints placed differently on HTTP/1.1"
    );

    for (dependency_stream_id, weight) in [(3, 220), (0, 0), (0, 257)] {
        let mut template = chromium::v154_windows_fetch_no_store_template();
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
    let placement = chromium::v154_cookie_placement();
    for template in [
        chromium::v154_windows_navigation_template(),
        chromium::v154_windows_fetch_no_store_template(),
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

        let mut template = chromium::v154_windows_navigation_template();
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

    // HTTP/1.1 lists keep `Connection: keep-alive`, and Chromium's also
    // `Proxy-Connection: keep-alive` for a forwarded request.
    let http1 = chromium::v154_windows_navigation_template().http1_fields;
    assert!(http1.contains(&RequestField::unless_forwarded("Connection", "keep-alive")));
    assert!(http1.contains(&RequestField::when_forwarded(
        "Proxy-Connection",
        "keep-alive"
    )));
    assert!(
        firefox::v156_windows_navigation_template()
            .http1_fields
            .contains(&RequestField::literal("Connection", "keep-alive"))
    );
}

#[test]
fn client_hint_placement_names_fields_up_to_the_first_literal() {
    let chrome =
        client_hint_placement(&chromium::v154_windows_fetch_no_store_template().http1_fields);
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
    let chrome = chromium::v154_windows_navigation_template();
    let hints = chromium::v154_windows_client_hints();
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

/// Returns the fields a template list sends when the caller supplies none
/// and no client hint is sent.
fn emitted(fields: &[RequestField], trustworthy: bool) -> Vec<(&str, &str)> {
    fields
        .iter()
        .filter_map(|field| Some((field.name()?, field.default_value(trustworthy)?)))
        .collect()
}

fn names<'a>(fields: &[(&'a str, &str)]) -> Vec<&'a str> {
    fields.iter().map(|(name, _)| *name).collect()
}

fn value<'a>(fields: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

// Field names, after `Host` and the pseudo-header fields, of the page and
// `fetch()` requests in the proxy route captures of Chrome 154.0.8037.58,
// Edge 153.0.4234.48, and Firefox 156.0 on Windows 11 build 26200:
// `fixtures/proxy/<browser>/<version>/windows-11-26200/direct-hostname.txt`
// for HTTP/1.1 and `https-proxy-hostname.txt` for HTTP/2, each three runs
// that agree, to the plaintext origin `origin.phantom.test`. Chrome and Edge
// send the same names. Client hints and caller slots are left out; the
// captured `fetch()` used the default cache mode, so the no-store `Pragma`
// and `Cache-Control` fields are added where the templates place them.
const CHROMIUM_NAMED_NAVIGATION_H1: &[&str] = &[
    "Connection",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
];
const CHROMIUM_NAMED_NAVIGATION_H2: &[&str] = &[
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "priority",
];
const CHROMIUM_NAMED_FETCH_H1: &[&str] = &[
    "Connection",
    "Pragma",
    "Cache-Control",
    "User-Agent",
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
];
const CHROMIUM_NAMED_FETCH_H2: &[&str] = &[
    "pragma",
    "cache-control",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "priority",
];
const FIREFOX_NAMED_NAVIGATION_H1: &[&str] = &[
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "Connection",
    "Upgrade-Insecure-Requests",
    "Priority",
];
const FIREFOX_NAMED_NAVIGATION_H2: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "upgrade-insecure-requests",
    "priority",
    "te",
];
const FIREFOX_NAMED_FETCH_H1: &[&str] = &[
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "Connection",
    "Priority",
    "Pragma",
    "Cache-Control",
];
const FIREFOX_NAMED_FETCH_H2: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "priority",
    "pragma",
    "cache-control",
    "te",
];

#[test]
fn templates_send_the_captured_plaintext_named_origin_fields() {
    let without = |list: &[&'static str], name: &str| -> Vec<&'static str> {
        list.iter()
            .copied()
            .filter(|field| !field.eq_ignore_ascii_case(name))
            .collect()
    };
    let cases = [
        (
            "chrome navigation",
            chromium::v154_windows_navigation_template(),
            CHROMIUM_NAMED_NAVIGATION_H1.to_vec(),
            CHROMIUM_NAMED_NAVIGATION_H2.to_vec(),
        ),
        (
            "chrome fetch",
            chromium::v154_windows_fetch_no_store_template(),
            CHROMIUM_NAMED_FETCH_H1.to_vec(),
            CHROMIUM_NAMED_FETCH_H2.to_vec(),
        ),
        // Edge leaves `User-Agent` to the caller, so it is absent here.
        (
            "edge navigation",
            edge::v153_windows_navigation_template(),
            without(CHROMIUM_NAMED_NAVIGATION_H1, "user-agent"),
            without(CHROMIUM_NAMED_NAVIGATION_H2, "user-agent"),
        ),
        (
            "edge fetch",
            edge::v153_windows_fetch_no_store_template(),
            without(CHROMIUM_NAMED_FETCH_H1, "user-agent"),
            without(CHROMIUM_NAMED_FETCH_H2, "user-agent"),
        ),
        (
            "firefox navigation",
            firefox::v156_windows_navigation_template(),
            FIREFOX_NAMED_NAVIGATION_H1.to_vec(),
            FIREFOX_NAMED_NAVIGATION_H2.to_vec(),
        ),
        (
            "firefox fetch",
            firefox::v156_windows_fetch_no_store_template(),
            FIREFOX_NAMED_FETCH_H1.to_vec(),
            FIREFOX_NAMED_FETCH_H2.to_vec(),
        ),
    ];
    for (label, template, http1, http2) in cases {
        for (protocol, expected) in [(Protocol::Http1, http1), (Protocol::Http2, http2)] {
            let plaintext = emitted(fields(&template, protocol), false);
            assert_eq!(names(&plaintext), expected, "{label} {protocol:?}");
            assert_eq!(
                value(&plaintext, "accept-encoding"),
                Some("gzip, deflate"),
                "{label} {protocol:?}"
            );

            // A trustworthy URL gets the loopback shape the replay tests
            // above compare with the retained captures.
            let trustworthy = emitted(fields(&template, protocol), true);
            assert_eq!(
                value(&trustworthy, "accept-encoding"),
                Some("gzip, deflate, br, zstd"),
                "{label} {protocol:?}"
            );
            let fetch_metadata: Vec<&str> = names(&trustworthy)
                .into_iter()
                .filter(|name| !expected.contains(name))
                .collect();
            assert!(
                !fetch_metadata.is_empty()
                    && fetch_metadata
                        .iter()
                        .all(|name| name.to_ascii_lowercase().starts_with("sec-fetch-")),
                "{label} {protocol:?}: {fetch_metadata:?}"
            );
        }
    }
}

#[test]
fn validation_rejects_a_trust_dependent_field_without_values() {
    let mut template = firefox::v156_windows_navigation_template();
    template.http1_fields.push(RequestField::ByTrust {
        name: "X-Probe".into(),
        trustworthy: None,
        untrustworthy: None,
    });
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http1_fields")
    );

    let mut template = firefox::v156_windows_navigation_template();
    template
        .http1_fields
        .push(RequestField::by_trust("X-Probe", "a", "b\r\n"));
    assert!(template.validate().is_err());

    // A trust-dependent entry does not end a client-hint slot's neighbours.
    let mut template = firefox::v156_windows_navigation_template();
    template.http1_fields.push(RequestField::ClientHints);
    template
        .http1_fields
        .push(RequestField::trustworthy_only("Sec-Fetch-Probe", "?1"));
    assert!(template.validate().is_err());
}

#[test]
fn validation_rejects_a_forwarding_dependent_field_without_values() {
    let mut template = chromium::v154_windows_navigation_template();
    template.http1_fields.push(RequestField::ByForwarding {
        name: "X-Probe".into(),
        unforwarded: None,
        forwarded: None,
    });
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http1_fields")
    );

    let mut template = chromium::v154_windows_navigation_template();
    template
        .http1_fields
        .push(RequestField::when_forwarded("X-Probe", "a\r\n"));
    assert!(template.validate().is_err());

    // `Proxy-Connection` is connection-specific, so HTTP/2 refuses it.
    let mut template = chromium::v154_windows_navigation_template();
    template.http2_fields.push(RequestField::when_forwarded(
        "proxy-connection",
        "keep-alive",
    ));
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http2_fields")
    );
}

// Field names after `Host` of the forwarded navigation and `fetch()` in
// `fixtures/proxy/{chrome,edge}/*/windows-11-26200/http-proxy-hostname.txt`,
// three agreeing runs each: Chromium replaces `Connection: keep-alive` with
// `Proxy-Connection: keep-alive` in the same position and changes nothing
// else. Firefox's `http-proxy-hostname.txt` requests match its direct ones.
#[test]
fn chromium_templates_swap_connection_for_proxy_connection_only_when_forwarded() {
    let forwarded = |fields: &[RequestField]| -> Vec<(String, String)> {
        fields
            .iter()
            .filter_map(|field| {
                let value = match field {
                    RequestField::ByForwarding { forwarded, .. } => forwarded.as_deref(),
                    other => other.default_value(false),
                }?;
                Some((field.name()?.to_owned(), value.to_owned()))
            })
            .collect()
    };
    let direct = |fields: &[RequestField]| -> Vec<(String, String)> {
        emitted(fields, false)
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    };
    for template in [
        chromium::v154_windows_navigation_template(),
        chromium::v154_windows_fetch_no_store_template(),
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
    ] {
        let mut expected = direct(&template.http1_fields);
        let connection = expected
            .iter_mut()
            .find(|(name, _)| name == "Connection")
            .unwrap_or_else(|| panic!("Chromium sends Connection directly"));
        connection.0 = "Proxy-Connection".to_owned();
        assert_eq!(forwarded(&template.http1_fields), expected);
        assert_eq!(
            expected[0],
            ("Proxy-Connection".to_owned(), "keep-alive".to_owned())
        );
        // HTTP/2 has no connection field to swap.
        assert_eq!(
            forwarded(&template.http2_fields),
            direct(&template.http2_fields)
        );
    }
    for template in [
        firefox::v156_windows_navigation_template(),
        firefox::v156_windows_fetch_no_store_template(),
    ] {
        assert_eq!(
            forwarded(&template.http1_fields),
            direct(&template.http1_fields)
        );
    }
}

#[test]
fn validation_rejects_overlapping_or_misnamed_credentials_slots() {
    use super::ProxyAuthorizationAttempt::{Every, Preemptive, Replay};

    let with = |slots: &[(&str, super::ProxyAuthorizationAttempt)]| {
        let mut template = firefox::v156_windows_navigation_template();
        template
            .http1_fields
            .retain(|field| !matches!(field, RequestField::ProxyAuthorization { .. }));
        for (name, attempt) in slots {
            template
                .http1_fields
                .push(RequestField::proxy_authorization(*name, *attempt));
        }
        template.validate().map_err(|error| error.field())
    };
    assert_eq!(with(&[("Proxy-Authorization", Every)]), Ok(()));
    assert_eq!(
        with(&[
            ("Proxy-Authorization", Preemptive),
            ("Proxy-Authorization", Replay)
        ]),
        Ok(())
    );
    for slots in [
        &[
            ("Proxy-Authorization", Every),
            ("Proxy-Authorization", Replay),
        ][..],
        &[
            ("Proxy-Authorization", Replay),
            ("Proxy-Authorization", Replay),
        ],
        &[("Authorization", Every)],
    ] {
        assert_eq!(with(slots), Err("http1_fields"), "{slots:?}");
    }

    // A literal of the same name repeats the slot's field.
    let mut template = chromium::v154_windows_navigation_template();
    template
        .http1_fields
        .push(RequestField::literal("Proxy-Authorization", "Basic x"));
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http1_fields")
    );

    // HTTP/3 is never forwarded.
    let mut template = chromium::v154_windows_navigation_template();
    if let Some(fields) = &mut template.http3_fields {
        fields.insert(
            0,
            RequestField::proxy_authorization("proxy-authorization", Every),
        );
    }
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http3_fields")
    );
}

#[test]
fn validation_checks_the_spelling_of_every_credentials_slot() {
    use super::ProxyAuthorizationAttempt::Replay;

    let mut template = firefox::v156_windows_navigation_template();
    let replay = template
        .http2_fields
        .iter()
        .position(|field| {
            matches!(
                field,
                RequestField::ProxyAuthorization {
                    attempt: Replay,
                    ..
                }
            )
        })
        .unwrap_or_else(|| panic!("Firefox has a replay slot"));
    template.http2_fields[replay] =
        RequestField::proxy_authorization("Proxy-Authorization", Replay);
    assert_eq!(
        template.validate().map_err(|error| error.field()),
        Err("http2_fields")
    );

    // The same slot in lowercase is valid, and so is a repeat of the name
    // by a second slot on HTTP/1.1.
    template.http2_fields[replay] =
        RequestField::proxy_authorization("proxy-authorization", Replay);
    assert_eq!(template.validate(), Ok(()));
}

const CHROME_ANDROID_DIRECT: [(&str, bool); 2] = [
    (
        fixture!("proxy/chrome-android/153.0.8010.52/android-35-emulator/direct-hostname.txt"),
        false,
    ),
    (
        fixture!("proxy/chrome-android/153.0.8010.52/android-35-emulator/direct-loopback.txt"),
        true,
    ),
];
const BRAVE_ANDROID_DIRECT: [(&str, bool); 2] = [
    (
        fixture!("proxy/brave-android/153.1.95.104/android-35-emulator/direct-hostname.txt"),
        false,
    ),
    (
        fixture!("proxy/brave-android/153.1.95.104/android-35-emulator/direct-loopback.txt"),
        true,
    ),
];

/// Every page load in the Android direct proxy-route captures is the
/// navigation template for its origin: to `127.0.0.1` with the default
/// hints and the trustworthy fields, and to `origin.phantom.test` without
/// hints, `Sec-Fetch-*`, or the `br` and `zstd` codings. A caller slot is
/// compared by name only.
#[test]
fn android_navigation_follows_origin_trust_in_the_direct_captures() -> CaptureResult<()> {
    for (template, hints, fixtures, version) in [
        (
            chrome_android::v153_android_navigation_template(),
            chrome_android::v153_android_client_hints("sdk_gphone64_x86_64"),
            CHROME_ANDROID_DIRECT,
            "153.0.8010.52",
        ),
        (
            brave_android::v153_android_navigation_template(),
            brave_android::v153_android_client_hints(),
            BRAVE_ANDROID_DIRECT,
            "153.1.95.104",
        ),
    ] {
        assert_direct_pages_match(&template, &hints, &fixtures, version)?;
    }
    Ok(())
}

fn assert_direct_pages_match(
    template: &RequestTemplate,
    hints: &ClientHintSettings,
    fixtures: &[(&str, bool)],
    version: &str,
) -> CaptureResult<()> {
    let default_hints: Vec<(&str, String)> = hints
        .hints()
        .iter()
        .filter(|hint| hint.delivery() == crate::ClientHintDelivery::Default)
        .map(|hint| {
            (
                hint.name(),
                String::from_utf8_lossy(hint.value()).into_owned(),
            )
        })
        .collect();
    for &(fixture, trustworthy) in fixtures {
        // `None` as the value marks a caller slot: only the name is compared.
        let mut expected: Vec<(String, Option<String>)> = Vec::new();
        for field in &template.http1_fields {
            match field {
                RequestField::ClientHints => {
                    if trustworthy {
                        expected.extend(
                            default_hints
                                .iter()
                                .map(|(name, value)| ((*name).to_owned(), Some(value.clone()))),
                        );
                    }
                }
                RequestField::Caller { name, .. } => expected.push((name.to_string(), None)),
                _ => {
                    if let (Some(name), Some(value)) =
                        (field.name(), field.default_value(trustworthy))
                    {
                        expected.push((name.to_owned(), Some(value.to_owned())));
                    }
                }
            }
        }
        let fields: std::collections::BTreeMap<&str, &str> = fixture
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let value = |key: &str| -> CaptureResult<&str> {
            fields
                .get(key)
                .copied()
                .ok_or_else(|| format!("capture omitted {key}").into())
        };
        assert_eq!(value("client_version")?, version);
        assert_eq!(value("launch_mode")?, "android-typed");
        let mut pages = 0;
        for run in 0..value("repeat_count")?.parse::<usize>()? {
            for index in 0..value(&format!("run_{run}_request_count"))?.parse::<usize>()? {
                let prefix = format!("run_{run}_request_{index}");
                if !value(&prefix)?.contains("kind:page") {
                    continue;
                }
                let mut observed = Vec::new();
                for header in 0..value(&format!("{prefix}_header_count"))?.parse::<usize>()? {
                    let raw = value(&format!("{prefix}_header_{header}"))?;
                    let bytes = (0..raw.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&raw[at..at + 2], 16))
                        .collect::<Result<Vec<_>, _>>()?;
                    let line = String::from_utf8(bytes)?;
                    let (name, field) = line.split_once(": ").ok_or("H1 field has no `: `")?;
                    observed.push((name.to_owned(), field.to_owned()));
                }
                assert_eq!(
                    observed.first().map(|(name, _)| name.as_str()),
                    Some("Host")
                );
                assert_eq!(
                    observed.len(),
                    expected.len() + 1,
                    "{version} {trustworthy}"
                );
                for ((name, seen), (expected_name, expected_value)) in
                    observed[1..].iter().zip(&expected)
                {
                    assert_eq!(name, expected_name, "{version} trustworthy: {trustworthy}");
                    if let Some(expected_value) = expected_value {
                        assert_eq!(seen, expected_value, "{version} {name}");
                    }
                }
                pages += 1;
            }
        }
        assert_eq!(pages, 3, "{version}");
    }
    Ok(())
}
