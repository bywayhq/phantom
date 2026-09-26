use std::collections::BTreeMap;

use super::{
    v154_http2, v154_http3_tls, v154_macos_client_hints, v154_tls, v154_windows_client_hints,
};
use crate::client_hints::navigation_capture::{NavigationCapture, changed_hints, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};

const INITIAL_CONNECTION_WINDOW: u32 = 65_535;
const V154_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/chrome/154.0.8037.58/windows-11-26200/navigation.txt"
));
const V154_MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/chrome/154.0.8037.58/macos-15.5-arm64/navigation.txt"
));
const V154_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/trust-anchor-orders.txt"
));
const V154_CLIENT_HELLO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt"
));
const V154_HTTP2_STARTUP_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/chrome/154.0.8037.58/windows-11-26200/client-startup.txt"
));
const V154_SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/chrome/154.0.8037.58/windows-11-26200/accept.txt"
));

#[test]
fn chrome_recipes_keep_the_backend_ech_grease_aead_policy() {
    // Chrome always advertises AES-128-GCM; with `aes_hardware` set, the
    // backend default produces exactly that choice.
    for settings in [v154_tls(), v154_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

#[test]
fn chrome_154_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v154_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(V154_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "154.0.8037.58");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    assert_eq!(settings.hints().len(), 11);
    Ok(())
}

#[test]
fn chrome_154_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(V154_MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "154.0.8037.58");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

/// macOS changes only the platform hints.
#[test]
fn chrome_154_macos_client_hints_differ_from_windows_only_in_platform_data() {
    let changed = changed_hints(&v154_windows_client_hints(), &v154_macos_client_hints());
    assert_eq!(
        changed,
        [
            ("sec-ch-ua-arch", r#""arm""#),
            ("sec-ch-ua-platform", r#""macOS""#),
            ("sec-ch-ua-platform-version", r#""15.5.0""#),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
}

/// Chromium commit `942bda4298c1` sorts the trust-anchor ID list before
/// encoding it, so Chrome 154 emits one order in every browser process. The
/// recipe therefore carries the ascending list, not a most-frequent one.
#[test]
fn chrome_154_tls_trust_anchor_ids_are_sorted_and_shared_by_every_process()
-> Result<(), Box<dyn std::error::Error>> {
    let fields = V154_TRUST_ANCHOR_ORDERS
        .lines()
        .map(|line| line.split_once('=').ok_or("fixture line is missing `=`"))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    assert_eq!(
        fields.get("format"),
        Some(&"phantom-trust-anchor-orders-v1")
    );
    assert_eq!(fields.get("browser"), Some(&"Google Chrome"));
    assert_eq!(fields.get("browser_version"), Some(&"154.0.8037.58"));
    let processes: usize = required(&fields, "process_count")?.parse()?;
    let distinct: usize = required(&fields, "distinct_order_count")?.parse()?;
    assert_eq!(processes, 60);
    assert_eq!(distinct, 1, "Chrome 154 must emit one trust-anchor order");
    let sequence = required(&fields, "process_orders")?
        .split(',')
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sequence.len(), processes);
    assert!(sequence.iter().all(|&order| order == 0));

    let (count, ids) = required(&fields, "order_0")?
        .strip_prefix("count:")
        .and_then(|rest| rest.split_once(",ids:"))
        .ok_or("order line is malformed")?;
    assert_eq!(count.parse::<usize>()?, processes);
    let observed = ids
        .split(',')
        .map(decode_hex)
        .collect::<Result<Vec<_>, _>>()?;

    let recipe = v154_tls()
        .requested_trust_anchor_ids
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?
        .iter()
        .map(|id| id.to_vec())
        .collect::<Vec<_>>();
    assert_eq!(recipe.len(), 28);
    assert_eq!(recipe, observed);
    assert!(
        recipe.is_sorted(),
        "the Chrome 154 list must be in ascending byte order"
    );
    assert_eq!(
        v154_http3_tls().requested_trust_anchor_ids,
        v154_tls().requested_trust_anchor_ids
    );
    Ok(())
}

/// Every retained Chrome 154 desktop capture that keeps whole ClientHellos,
/// over TCP and QUIC, on Windows and macOS. Each file holds one browser
/// process, or one per `run_<n>_` prefix.
const V154_CLIENT_HELLO_CAPTURES: &[(&str, &str)] = &[
    ("tls/client-hello", V154_CLIENT_HELLO),
    (
        "tls/ech-accept",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-accept.txt"
        )),
    ),
    (
        "tls/ech-reject",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-reject.txt"
        )),
    ),
    (
        "tls/ech-quic-accept",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-quic-accept.txt"
        )),
    ),
    (
        "tls/ech-quic-reject",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-quic-reject.txt"
        )),
    ),
    (
        "tls/resumption-issue-once",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-issue-once.txt"
        )),
    ),
    (
        "tls/resumption-methods",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-methods.txt"
        )),
    ),
    (
        "tls/resumption-methods-http1",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-methods-http1.txt"
        )),
    ),
    (
        "tls/resumption-no-early-data",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-no-early-data.txt"
        )),
    ),
    (
        "tls/resumption-origins",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-origins.txt"
        )),
    ),
    (
        "tls/resumption-parallel",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-parallel.txt"
        )),
    ),
    (
        "tls/resumption-partition",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-partition.txt"
        )),
    ),
    (
        "tls/resumption-sequential",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-sequential.txt"
        )),
    ),
    (
        "tls/resumption-sequential-http1",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/resumption-sequential-http1.txt"
        )),
    ),
    (
        "tls/macos/resumption-sequential",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/chrome/154.0.8037.58/macos-15.5-arm64/resumption-sequential.txt"
        )),
    ),
    (
        "http3/quic-client-hello-1",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt"
        )),
    ),
    (
        "http3/quic-client-hello-2",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-2.txt"
        )),
    ),
    (
        "http3/macos/quic-client-hello-1",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/macos-15.5-arm64/quic-client-hello-1.txt"
        )),
    ),
    (
        "http3/resumption-accept",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-accept.txt"
        )),
    ),
    (
        "http3/resumption-accept-delayed",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-accept-delayed.txt"
        )),
    ),
    (
        "http3/resumption-reject",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-reject.txt"
        )),
    ),
    (
        "http3/resumption-streams-accept",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-streams-accept.txt"
        )),
    ),
    (
        "http3/resumption-streams-reject",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-streams-reject.txt"
        )),
    ),
];

/// Chromium sorts the list once, when it builds the SSL configuration
/// (`EncodeTlsRequestedTrustAnchorIDList`, `net/cert/x509_util.cc:708-717` at
/// 154.0.8037.58), and every connection sends those bytes. The 60-process
/// aggregate shows one order across processes; these captures show it within
/// a process, up to 13 connections from one browser.
#[test]
fn chrome_154_trust_anchor_ids_match_every_retained_client_hello_in_every_process()
-> Result<(), Box<dyn std::error::Error>> {
    let ids = v154_tls()
        .requested_trust_anchor_ids
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?;
    let mut list = Vec::new();
    for id in &ids {
        list.push(u8::try_from(id.len())?);
        list.extend_from_slice(id);
    }
    let mut expected = u16::try_from(list.len())?.to_be_bytes().to_vec();
    expected.extend_from_slice(&list);

    let mut hellos_per_process = BTreeMap::<String, usize>::new();
    for (name, capture) in V154_CLIENT_HELLO_CAPTURES {
        for (key, value) in capture.lines().filter_map(|line| line.split_once('=')) {
            let is_hello = key.ends_with("client_hello_hex")
                || key == "handshake_hex"
                || (key.contains("record_") && key.ends_with("_hex"));
            if !is_hello {
                continue;
            }
            let hello = decode_hex(value)?;
            let extension = client_hello_extension(&hello, 0xca34)
                .map_err(|error| format!("{name} {key}: {error}"))?;
            assert_eq!(
                extension,
                Some(expected.as_slice()),
                "{name} {key} carries a different trust-anchor list than the recipe"
            );
            let process = key
                .strip_prefix("run_")
                .and_then(|rest| rest.split_once('_'))
                .map_or_else(|| (*name).to_owned(), |(run, _)| format!("{name}/{run}"));
            *hellos_per_process.entry(process).or_default() += 1;
        }
    }

    // Pin the corpus so that a renamed fixture key cannot skip captures.
    assert_eq!(hellos_per_process.len(), 23);
    assert_eq!(hellos_per_process.values().sum::<usize>(), 132);
    assert_eq!(hellos_per_process.values().filter(|&&n| n > 1).count(), 18);
    assert_eq!(hellos_per_process.values().max(), Some(&13));
    Ok(())
}

/// Returns the body of one extension of a ClientHello handshake message,
/// with or without its TLS record header.
fn client_hello_extension(
    hello: &[u8],
    extension_type: u16,
) -> Result<Option<&[u8]>, Box<dyn std::error::Error>> {
    fn skip(bytes: &[u8], len: usize) -> Result<&[u8], Box<dyn std::error::Error>> {
        Ok(bytes.get(len..).ok_or("truncated ClientHello")?)
    }
    fn length(bytes: &[u8], width: usize) -> Result<usize, Box<dyn std::error::Error>> {
        let bytes = bytes.get(..width).ok_or("truncated length")?;
        Ok(bytes
            .iter()
            .fold(0, |value, &byte| value << 8 | usize::from(byte)))
    }

    let mut rest = if hello.first() == Some(&0x16) {
        skip(hello, 5)?
    } else {
        hello
    };
    if rest.first() != Some(&0x01) {
        return Err("not a ClientHello".into());
    }
    // Handshake header, legacy version, and random.
    rest = skip(rest, 4 + 2 + 32)?;
    rest = skip(rest, 1 + length(rest, 1)?)?;
    rest = skip(rest, 2 + length(rest, 2)?)?;
    rest = skip(rest, 1 + length(rest, 1)?)?;
    let extensions_length = length(rest, 2)?;
    let mut extensions = rest
        .get(2..2 + extensions_length)
        .ok_or("truncated extensions")?;
    while !extensions.is_empty() {
        let kind = length(extensions, 2)?;
        let body_length = length(skip(extensions, 2)?, 2)?;
        let body = extensions
            .get(4..4 + body_length)
            .ok_or("truncated extension body")?;
        if kind == usize::from(extension_type) {
            return Ok(Some(body));
        }
        extensions = skip(extensions, 4 + body_length)?;
    }
    Ok(None)
}

#[test]
fn chrome_154_http2_recipe_matches_windows_captures() -> Result<(), Box<dyn std::error::Error>> {
    let startup = V154_HTTP2_STARTUP_FIXTURE
        .lines()
        .map(|line| line.split_once('=').ok_or("fixture line is missing `=`"))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    assert_eq!(startup.get("browser"), Some(&"Google Chrome"));
    assert_eq!(startup.get("browser_version"), Some(&"154.0.8037.58"));

    let settings = v154_http2();
    settings.validate()?;
    assert_eq!(
        required(&startup, "initial_settings")?,
        "0x0001:65536,0x0002:0,0x0004:6291456,0x0006:262144"
    );
    let increment: u32 = required(&startup, "connection_window_update")?.parse()?;
    assert_eq!(
        settings.initial_connection_window_size,
        INITIAL_CONNECTION_WINDOW
            .checked_add(increment)
            .ok_or("connection window overflow")?
    );

    let capture = SessionCapture::parse(V154_SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "154.0.8037.58");
    assert_eq!(capture.value("scenario")?, "accept");
    // Chromium source states the limit; the capture servers all state 100.
    assert_eq!(
        settings.streams,
        Http2StreamSettings {
            first_stream_id: 1,
            assumed_max_concurrent_streams: Some(100),
            max_concurrent_streams_cap: Some(256),
        }
    );
    // Navigation HEADERS carry no extended CONNECT shape, and one block shows
    // only the static-name choice; the WebSocket recipe tests compare the whole
    // encoder identity with every captured CONNECT.
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

#[test]
fn chrome_154_tls_recipes_are_valid() -> Result<(), Box<dyn std::error::Error>> {
    let settings = v154_tls();
    settings.validate()?;
    let alps = settings.alps.ok_or("Chrome TLS profile omitted ALPS")?;
    assert_eq!(alps.protocol.as_ref(), b"h2");
    assert!(alps.settings.is_empty());
    assert!(alps.use_new_codepoint);

    let http3 = v154_http3_tls();
    http3.validate()?;
    assert_eq!(http3.min_version, crate::tls::TlsVersion::Tls13);
    assert_eq!(http3.max_version, crate::tls::TlsVersion::Tls13);
    assert_eq!(http3.alpn_protocols, [Box::from(&b"h3"[..])]);
    assert!(http3.session_tickets);
    let alps = http3.alps.ok_or("Chrome HTTP/3 TLS profile omitted ALPS")?;
    assert_eq!(alps.protocol.as_ref(), b"h3");
    assert!(alps.settings.is_empty());
    assert!(alps.use_new_codepoint);
    Ok(())
}

fn required<'a>(
    fields: &'a BTreeMap<&str, &str>,
    key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing fixture field {key}").into())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal value".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&value[index..index + 2], 16)?))
        .collect()
}

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn chrome_154_macos_http2_session_capture_matches_the_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/chrome/154.0.8037.58/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("scenario")?, "accept");
    let settings = v154_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
