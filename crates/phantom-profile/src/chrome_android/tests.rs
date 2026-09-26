use std::collections::BTreeMap;

use super::{
    v153_android_client_hints, v153_android_fetch_no_store_template,
    v153_android_navigation_template, v153_http2, v153_http3_tls, v153_tls, v153_websocket,
};
use crate::chromium;
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{Http2HpackSettings, Http2Settings, session_capture::SessionCapture};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/chrome-android/153.0.8010.52/android-35-emulator/navigation.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/chrome-android/153.0.8010.52/android-35-emulator/accept.txt"
));
const TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/tls/chrome-android/153.0.8010.52/android-35-emulator/trust-anchor-orders.txt"
));
const QUIC_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http3/chrome-android/153.0.8010.52/android-35-emulator/trust-anchor-orders.txt"
));
const ANDROID_EMULATOR: &str = "Android 15 (API 35) sdk_gphone64_x86_64 emulator AE3A.240806.036";

#[test]
fn chrome_android_153_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v153_android_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "153.0.8010.52");
    assert_eq!(capture.value("operating_system")?, ANDROID_EMULATOR);
    assert_eq!(capture.value("launch_mode")?, "android-typed");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn chrome_android_153_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v153_android_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn chrome_android_153_reuses_the_desktop_http2_and_websocket_recipes() {
    assert_eq!(v153_http2(), chromium::v154_http2());
    assert_eq!(v153_websocket(), chromium::v154_websocket());
}

#[test]
fn chrome_android_153_templates_change_only_the_user_agent() {
    for (android, windows) in [
        (
            v153_android_navigation_template(),
            chromium::v154_windows_navigation_template(),
        ),
        (
            v153_android_fetch_no_store_template(),
            chromium::v154_windows_fetch_no_store_template(),
        ),
    ] {
        assert_eq!(android.validate(), Ok(()));
        let android_user_agent = user_agents(&android);
        assert_eq!(
            android_user_agent.len(),
            android.http3_fields.map_or(2, |_| 3)
        );
        assert!(
            android_user_agent
                .iter()
                .all(|value| value.contains("(Linux; Android 10; K)")
                    && value.ends_with("Chrome/153.0.0.0 Mobile Safari/537.36"))
        );
        assert_ne!(android_user_agent, user_agents(&windows));
    }
}

fn user_agents(template: &crate::RequestTemplate) -> Vec<String> {
    template
        .http1_fields
        .iter()
        .chain(&template.http2_fields)
        .chain(template.http3_fields.iter().flatten())
        .filter_map(|field| match field {
            crate::RequestField::Literal { name, value }
                if name.eq_ignore_ascii_case("user-agent") =>
            {
                Some(value.to_string())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn chrome_android_153_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Google Chrome");
    assert_eq!(capture.value("client_version")?, "153.0.8010.52");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = v153_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Parses a `phantom-trust-anchor-orders-v1` fixture into its orders, most
/// frequent first, with the process count of each.
fn trust_anchor_orders(fixture: &str) -> TestResult<(usize, Vec<(usize, Vec<Vec<u8>>)>)> {
    let fields = fixture
        .lines()
        .map(|line| line.split_once('=').ok_or("fixture line is missing `=`"))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    assert_eq!(
        fields.get("format"),
        Some(&"phantom-trust-anchor-orders-v1")
    );
    assert_eq!(fields.get("browser_version"), Some(&"153.0.8010.52"));
    let processes: usize = fields
        .get("process_count")
        .ok_or("no process_count")?
        .parse()?;
    let distinct: usize = fields
        .get("distinct_order_count")
        .ok_or("no distinct_order_count")?
        .parse()?;
    let mut orders = Vec::new();
    for index in 0..distinct {
        let (count, ids) = fields
            .get(format!("order_{index}").as_str())
            .and_then(|order| order.strip_prefix("count:"))
            .and_then(|rest| rest.split_once(",ids:"))
            .ok_or("order line is malformed")?;
        let ids = ids
            .split(',')
            .map(|id| {
                (0..id.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&id[at..at + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        orders.push((count.parse()?, ids));
    }
    assert_eq!(
        orders.iter().map(|(count, _)| count).sum::<usize>(),
        processes
    );
    Ok((processes, orders))
}

fn recipe_ids(settings: &crate::TlsSettings) -> TestResult<Vec<Vec<u8>>> {
    Ok(settings
        .requested_trust_anchor_ids
        .as_ref()
        .ok_or("recipe omitted trust-anchor IDs")?
        .iter()
        .map(|id| id.to_vec())
        .collect())
}

fn sorted(mut ids: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    ids.sort_unstable();
    ids
}

/// Every TCP process sent one order; the recipe carries it, and it holds the
/// desktop recipe's 28 identifiers.
#[test]
fn chrome_android_153_tcp_trust_anchor_order_is_shared_by_every_process() -> TestResult {
    let (processes, orders) = trust_anchor_orders(TRUST_ANCHOR_ORDERS)?;
    assert!(processes >= 60, "{processes} processes");
    assert_eq!(orders.len(), 1, "every TCP process sent one order");
    let recipe = recipe_ids(&v153_tls())?;
    assert_eq!(recipe, orders[0].1);
    assert_eq!(sorted(recipe), recipe_ids(&chromium::v154_tls())?);
    Ok(())
}

/// The QUIC processes did not share an order. The recipe carries the most
/// frequent captured order, and every captured order holds the same
/// identifiers.
#[test]
fn chrome_android_153_quic_trust_anchor_order_is_one_captured_order() -> TestResult {
    let (_, orders) = trust_anchor_orders(QUIC_TRUST_ANCHOR_ORDERS)?;
    assert!(orders.len() > 1, "the QUIC order varies between processes");
    let desktop = recipe_ids(&chromium::v154_http3_tls())?;
    for (_, order) in &orders {
        assert_eq!(sorted(order.clone()), desktop);
    }
    // The recipe carries the order sent most often.
    let recipe = recipe_ids(&v153_http3_tls())?;
    assert_eq!(recipe, orders[0].1);
    assert!(orders[0].0 > orders[1].0);
    assert_ne!(recipe, recipe_ids(&v153_tls())?);
    Ok(())
}

/// Apart from the trust-anchor order and the ECH lookup that no Android
/// capture covers, the TLS recipes are the desktop Chromium recipes.
#[test]
fn chrome_android_153_tls_recipes_change_only_the_trust_anchor_order() -> TestResult {
    for (android, desktop) in [
        (v153_tls(), chromium::v154_tls()),
        (v153_http3_tls(), chromium::v154_http3_tls()),
    ] {
        android.validate()?;
        assert!(!android.ech_from_https_records);
        let mut expected = desktop;
        expected.requested_trust_anchor_ids = android.requested_trust_anchor_ids.clone();
        expected.ech_from_https_records = false;
        assert_eq!(android, expected);
    }
    Ok(())
}
