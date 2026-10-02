use super::{v135_macos_client_hints, v136_http3_tls, v136_tls, v136_windows_client_hints};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/136.0.6008.52/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.92/macos-15.5-arm64/navigation.txt"
));
const TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/tls/opera/136.0.6008.52/windows-11-26200/trust-anchor-orders.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/opera/136.0.6008.52/windows-11-26200/accept.txt"
));

#[test]
fn opera_136_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v136_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn opera_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v136_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn opera_136_recipes_keep_the_backend_ech_grease_aead_policy() {
    for settings in [v136_tls(), v136_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

/// Opera 136 sends the Chromium offers with its own 32 trust-anchor IDs: the
/// TCP offer in one order per process, the QUIC offer in one per connection.
#[test]
fn opera_136_tls_recipes_are_chromium_s_with_opera_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let opera = v136_tls();
    opera.validate()?;
    let ids = opera
        .requested_trust_anchor_ids
        .clone()
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?;
    assert_eq!(ids.len(), 32);
    let mut expected = chromium::v154_tls();
    let chrome_ids = expected
        .requested_trust_anchor_ids
        .clone()
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?;
    assert!(chrome_ids.iter().all(|id| ids.contains(id)));
    let mut added = ids
        .iter()
        .filter(|id| !chrome_ids.contains(id))
        .map(|id| id.as_ref())
        .collect::<Vec<_>>();
    added.sort_unstable();
    assert_eq!(
        added,
        [
            &[0xd6, 0x79, 0x09, 0x02][..],
            &[0xd6, 0x79, 0x09, 0x03],
            &[0xd6, 0x79, 0x09, 0x09],
            &[0xd6, 0x79, 0x09, 0x0e],
        ]
    );
    expected.requested_trust_anchor_ids = Some(ids.clone());
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);

    let opera = v136_http3_tls();
    opera.validate()?;
    let quic_ids = opera
        .requested_trust_anchor_ids
        .clone()
        .ok_or("Opera 136 H3 recipe omitted trust-anchor IDs")?;
    let sorted = |ids: &[Box<[u8]>]| {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids
    };
    assert_eq!(sorted(&quic_ids), sorted(&ids));
    let mut expected = chromium::v154_http3_tls();
    expected.requested_trust_anchor_ids = Some(quic_ids);
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);
    Ok(())
}

struct TrustAnchorOrders<'a>(std::collections::HashMap<&'a str, &'a str>);

impl<'a> TrustAnchorOrders<'a> {
    fn value(&self, key: &str) -> Result<&'a str, String> {
        self.0
            .get(key)
            .copied()
            .ok_or_else(|| format!("trust-anchor orders omit {key}"))
    }
}

fn order_ids(value: &str) -> Result<Vec<Box<[u8]>>, Box<dyn std::error::Error>> {
    let (_, ids) = value.split_once(",ids:").ok_or("order has no ids")?;
    ids.split(',')
        .map(|id| {
            (0..id.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&id[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map(Vec::into_boxed_slice)
                .map_err(Into::into)
        })
        .collect()
}

fn order_count(value: &str) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(value
        .strip_prefix("count:")
        .and_then(|rest| rest.split(',').next())
        .ok_or("order has no count")?
        .parse()?)
}

/// The TCP recipe carries the order most of the 29 retained processes used,
/// and the QUIC recipe the most frequent of the 20 retained QUIC ClientHellos,
/// which every process varied between its connections.
#[test]
fn opera_136_trust_anchor_orders_are_the_most_frequent_retained_ones()
-> Result<(), Box<dyn std::error::Error>> {
    let orders = TrustAnchorOrders(
        TRUST_ANCHOR_ORDERS
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect(),
    );
    assert_eq!(orders.value("format")?, "phantom-trust-anchor-orders-v1");
    assert_eq!(orders.value("browser")?, "Opera");
    assert_eq!(orders.value("browser_version")?, "136.0.6008.52");
    assert_eq!(orders.value("process_count")?, "29");
    let top = orders.value("order_0")?;
    assert!(order_count(top)? > order_count(orders.value("order_1")?)?);
    assert_eq!(v136_tls().requested_trust_anchor_ids, Some(order_ids(top)?));
    // Every TCP process kept one order on all of its connections.
    let tcp_processes = (0..29)
        .map(|index| orders.value(&format!("process_{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        tcp_processes
            .iter()
            .all(|process| process.contains(",order:"))
    );

    assert_eq!(orders.value("quic_client_hello_count")?, "20");
    let quic_top = orders.value("quic_order_0")?;
    assert_eq!(order_count(quic_top)?, 2);
    assert_eq!(order_count(orders.value("quic_order_1")?)?, 1);
    assert_eq!(
        v136_http3_tls().requested_trust_anchor_ids,
        Some(order_ids(quic_top)?)
    );
    // A process that opened several QUIC connections used several orders.
    for index in 3..6 {
        let process = orders.value(&format!("quic_process_{index}"))?;
        let (_, sequence) = process.split_once(",orders:").ok_or("no orders")?;
        let distinct = sequence
            .split(' ')
            .collect::<std::collections::HashSet<_>>();
        assert!(distinct.len() > 1, "{process}");
    }
    Ok(())
}

#[test]
fn opera_136_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = chromium::v154_http2();
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
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

#[test]
fn opera_135_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v135_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.92");
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

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn opera_135_macos_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/opera/135.0.5973.92/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("scenario")?, "accept");
    let settings = chromium::v154_http2();
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
