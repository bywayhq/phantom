use std::collections::BTreeMap;

use super::{
    v154_http2, v154_http3_tls, v154_macos_client_hints, v154_tls, v154_windows_client_hints,
};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

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

/// Besides the build, macOS changes only the platform hints.
#[test]
fn chrome_154_macos_client_hints_differ_from_windows_only_in_platform_data() {
    let values = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| {
                (
                    hint.name().to_owned(),
                    String::from_utf8_lossy(hint.value()).into_owned(),
                )
            })
            .collect::<Vec<_>>()
    };
    let windows = values(v154_windows_client_hints());
    let macos = values(v154_macos_client_hints());
    assert_eq!(windows.len(), macos.len());
    let changed: Vec<_> = windows
        .iter()
        .zip(&macos)
        .filter(|(windows, macos)| windows != macos)
        .map(|(_, (name, value))| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("sec-ch-ua-arch", r#""arm""#),
            ("sec-ch-ua-platform", r#""macOS""#),
            ("sec-ch-ua-platform-version", r#""15.5.0""#),
        ]
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

/// The same sorted list appears in the retained ClientHello, which the
/// aggregate order fixture does not contain.
#[test]
fn chrome_154_trust_anchor_extension_matches_the_retained_client_hello()
-> Result<(), Box<dyn std::error::Error>> {
    let ids = v154_tls()
        .requested_trust_anchor_ids
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?;
    let mut list = String::new();
    for id in &ids {
        list.push_str(&format!("{:02x}", id.len()));
        for byte in id.iter() {
            list.push_str(&format!("{byte:02x}"));
        }
    }
    let list_length = ids.iter().map(|id| id.len() + 1).sum::<usize>();
    let extension = format!("ca34{:04x}{list_length:04x}{list}", list_length + 2);
    let record = V154_CLIENT_HELLO
        .lines()
        .find_map(|line| line.strip_prefix("record_0_hex="))
        .ok_or("fixture omitted record_0_hex")?;
    assert!(
        record.contains(&extension),
        "the retained ClientHello does not carry the recipe's trust-anchor extension"
    );
    Ok(())
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
