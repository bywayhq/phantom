//! Chromium-family (Chrome, Edge, Brave, and Opera) TLS differential tests.

use phantom_profile::{
    TlsSettings, TrustAnchorIds, TrustAnchorOrders,
    browser::{
        brave,
        chrome::{self, v154_tcp_tls},
        edge, opera,
    },
};
use phantom_testkit::tls::{ClientHelloCapture, ClientHelloSummary, is_grease};

use super::{
    capture_client_hello_from, capture_client_hello_from_server_name, capture_client_hellos_from,
    client_hello_fixture,
};
use crate::tls::test_support::{TEST_SERVER_NAME, TestResult};

const CHROME_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/",
    "windows-11-26200/client-hello.txt"
));
const CHROME_154_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/",
    "windows-11-26200/trust-anchor-orders.txt"
));
const EDGE_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/edge/154.0.4258.37/",
    "windows-11-26200/client-hello.txt"
));
const BRAVE_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/brave/154.1.96.59/",
    "windows-11-26200/client-hello.txt"
));
const OPERA_136_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/opera/136.0.6008.52/",
    "windows-11-26200/client-hello.txt"
));
const CHROME_ANDROID_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome-android/154.0.8037.57/",
    "android-17-pixel7-emulator/client-hello.txt"
));
const BRAVE_ANDROID_153_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/brave-android/153.1.95.104/",
    "android-17-pixel7-emulator/client-hello.txt"
));
const OPERA_ANDROID_102_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/opera-android/102.1.5206.90382/",
    "android-17-pixel7-emulator/client-hello.txt"
));
/// Three fresh Edge for Android processes, for GREASE and extension order.
const EDGE_ANDROID_153_FIXTURES: [&str; 3] = [
    include_str!(concat!(
        "../../../../../fixtures/tls/edge-android/153.0.4234.49/",
        "android-17-pixel7-emulator/client-hello.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/tls/edge-android/153.0.4234.49/",
        "android-17-pixel7-emulator/client-hello-2.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/tls/edge-android/153.0.4234.49/",
        "android-17-pixel7-emulator/client-hello-3.txt"
    )),
];
const GREASE_SENTINEL: u16 = 0x0a0a;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn chrome_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(CHROME_154_FIXTURE, &v154_tcp_tls(), Some(28)).await
}

/// Chrome 154 sorts its trust-anchor list before encoding it, so every
/// browser process emits the one order the recipe carries.
#[tokio::test]
async fn chrome_154_tls_recipe_emits_the_sorted_trust_anchor_order() -> TestResult<()> {
    let fields = |key: &str| {
        CHROME_154_TRUST_ANCHOR_ORDERS
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::to_owned)
    };
    assert_eq!(fields("distinct_order_count=").as_deref(), Some("1"));
    assert_eq!(fields("process_count=").as_deref(), Some("60"));
    let encoded = fields("order_0=")
        .and_then(|order| order.split_once(",ids:").map(|(_, ids)| ids.to_owned()))
        .ok_or("trust-anchor order fixture omitted order_0")?;
    let expected = encoded
        .split(',')
        .map(|id| {
            (0..id.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&id[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sorted = expected.clone();
    sorted.sort_unstable();
    assert_eq!(expected, sorted, "the captured order is not ascending");

    let actual = capture_client_hello_from(&v154_tcp_tls())
        .await?
        .summary()?;
    let actual = actual
        .requested_trust_anchor_ids()
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?
        .to_vec();
    assert_eq!(actual, expected);
    Ok(())
}

/// Chrome 154 for Android sends the desktop Chrome 154 ClientHello, its
/// sorted trust-anchor IDs included.
#[tokio::test]
async fn chrome_android_154_tls_recipe_matches_android_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(
        CHROME_ANDROID_154_FIXTURE,
        &chrome::v154_android_tcp_tls(),
        Some(28),
    )
    .await
}

/// Edge 153 for Android sends the Chromium ClientHello without trust-anchor
/// IDs, as desktop Edge 153 does, in every retained process.
#[tokio::test]
async fn edge_android_153_tls_recipe_matches_every_android_capture() -> TestResult<()> {
    for fixture in EDGE_ANDROID_153_FIXTURES {
        assert_recipe_matches_fixture(fixture, &edge::v153_android_tcp_tls(), None).await?;
    }
    Ok(())
}

/// Brave for Android sends the desktop Brave ClientHello: no trust-anchor IDs.
#[tokio::test]
async fn brave_android_153_tls_recipe_matches_android_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(
        BRAVE_ANDROID_153_FIXTURE,
        &brave::v153_android_tcp_tls(),
        None,
    )
    .await
}

/// Opera for Android sends Chrome's ClientHello without trust-anchor IDs,
/// signature-algorithm GREASE included; its captures reached `localhost`.
#[tokio::test]
async fn opera_android_102_tls_recipe_matches_android_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(
        OPERA_ANDROID_102_FIXTURE,
        &opera::v102_android_tcp_tls(),
        None,
    )
    .await
}

/// Edge 154 sends the Chromium ClientHello without trust-anchor IDs.
#[tokio::test]
async fn edge_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(EDGE_154_FIXTURE, &edge::v154_tcp_tls(), None).await
}

/// Brave 154 sends the Chrome 154 ClientHello without trust-anchor IDs.
#[tokio::test]
async fn brave_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(BRAVE_154_FIXTURE, &brave::v154_tcp_tls(), None).await
}

/// Opera 136 sends the Chrome 154 ClientHello with Chromium 152's 32
/// trust-anchor IDs, in an order drawn per process. The retained process's
/// order is one the recipe draws from, and so is the order the connector
/// emits.
#[tokio::test]
async fn opera_136_tls_recipe_matches_windows_capture() -> TestResult<()> {
    let settings = opera::v136_tcp_tls();
    assert_recipe_matches_fixture(OPERA_136_FIXTURE, &settings, Some(32)).await?;
    let orders = recipe_trust_anchor_orders(&settings)?;
    let expected = client_hello_fixture::capture(OPERA_136_FIXTURE)
        .await?
        .summary()?
        .requested_trust_anchor_ids()
        .ok_or("Opera 136 capture omitted trust-anchor IDs")?
        .to_vec();
    assert!(orders.contains(&expected));
    let actual = capture_client_hello_from(&settings)
        .await?
        .summary()?
        .requested_trust_anchor_ids()
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?
        .to_vec();
    assert!(orders.contains(&actual));
    Ok(())
}

/// Opera 136 keeps one trust-anchor order for every TCP connection of a
/// process and draws another in the next process. A connector stands for
/// the process: each sends one of the recipe's retained orders on all of its
/// connections, and separate connectors draw different ones.
#[tokio::test]
async fn opera_136_tcp_trust_anchor_order_is_drawn_once_per_connector() -> TestResult<()> {
    let settings = opera::v136_tcp_tls();
    let orders = recipe_trust_anchor_orders(&settings)?;
    let mut drawn = Vec::new();
    for _ in 0..12 {
        let mut connector_orders = Vec::new();
        for capture in capture_client_hellos_from(&settings, TEST_SERVER_NAME, 3).await? {
            connector_orders.push(
                capture
                    .summary()?
                    .requested_trust_anchor_ids()
                    .ok_or("Opera 136 recipe omitted trust-anchor IDs")?
                    .to_vec(),
            );
        }
        connector_orders.dedup();
        let [order] = connector_orders.as_slice() else {
            return Err("one connector sent more than one trust-anchor order".into());
        };
        assert!(orders.contains(order));
        drawn.push(order.clone());
    }
    // The most frequent of the 29 listed orders appears 5 times, so twelve
    // alike draws have a probability below 10^-9.
    drawn.sort_unstable();
    drawn.dedup();
    assert!(drawn.len() > 1);
    Ok(())
}

/// A list drawn per connection gets a new draw on each connection of one
/// connector: every connection sends one of the listed orders, and the
/// connections do not all send the same one.
#[tokio::test]
async fn per_connection_trust_anchor_order_is_drawn_for_each_tcp_connection() -> TestResult<()> {
    let mut settings = opera::v136_tcp_tls();
    let listed = settings
        .requested_trust_anchor_ids
        .take()
        .ok_or("Opera 136 recipe omitted trust-anchor IDs")?
        .orders()
        .to_vec();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(
        TrustAnchorOrders::new(listed)?,
    ));
    let orders = recipe_trust_anchor_orders(&settings)?;
    let mut emitted = Vec::new();
    for capture in capture_client_hellos_from(&settings, TEST_SERVER_NAME, 16).await? {
        let order = capture
            .summary()?
            .requested_trust_anchor_ids()
            .ok_or("per-connection list omitted trust-anchor IDs")?
            .to_vec();
        assert!(orders.contains(&order));
        emitted.push(order);
    }
    // The most frequent of the 29 listed orders appears 5 times, so sixteen
    // alike draws have a probability below (5/29)^15, about 4 * 10^-12.
    emitted.sort_unstable();
    emitted.dedup();
    assert!(emitted.len() > 1);
    Ok(())
}

fn recipe_trust_anchor_orders(settings: &TlsSettings) -> TestResult<Vec<Vec<Vec<u8>>>> {
    Ok(settings
        .requested_trust_anchor_ids
        .as_ref()
        .ok_or("recipe omitted trust-anchor IDs")?
        .orders()
        .iter()
        .map(|order| order.as_slice().iter().map(|id| id.to_vec()).collect())
        .collect())
}

/// Chromium-family browsers advertise HKDF-SHA256 with AES-128-GCM on every
/// connection; their recipes keep the backend default AEAD policy.
#[tokio::test]
async fn chromium_recipes_emit_aes_128_gcm_ech_grease_on_every_connection() -> TestResult<()> {
    const AES_128_GCM: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x01];
    for settings in [
        v154_tcp_tls(),
        edge::v154_tcp_tls(),
        brave::v154_tcp_tls(),
        opera::v136_tcp_tls(),
        chrome::v154_android_tcp_tls(),
        edge::v153_android_tcp_tls(),
        brave::v153_android_tcp_tls(),
        opera::v102_android_tcp_tls(),
    ] {
        assert!(
            settings
                .ech
                .grease()
                .map_or(&[][..], phantom_profile::EchGreaseSettings::aeads)
                .is_empty()
        );
        for capture in capture_client_hellos_from(&settings, TEST_SERVER_NAME, 64).await? {
            assert_eq!(
                client_hello_fixture::ech_cipher_suite(capture.handshake_bytes())?,
                AES_128_GCM
            );
        }
    }
    Ok(())
}

async fn assert_recipe_matches_fixture(
    fixture: &str,
    settings: &TlsSettings,
    trust_anchor_id_count: Option<usize>,
) -> TestResult<()> {
    // The emulator captures of a browser that takes no switches reached
    // `localhost`; every other capture used the test name.
    let server_name = fixture
        .lines()
        .find_map(|line| line.strip_prefix("hostname="))
        .unwrap_or(TEST_SERVER_NAME);
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture = capture_client_hello_from_server_name(settings, server_name).await?;

    assert_eq!(
        actual_capture.records().len(),
        expected_capture.records().len()
    );

    let expected = expected_capture.summary()?;
    let actual = actual_capture.summary()?;
    assert_eq!(actual_capture.records().len(), 1);
    assert_eq!(
        record_length_without_ech(&actual_capture, &actual)?,
        record_length_without_ech(&expected_capture, &expected)?
    );

    assert_eq!(actual.legacy_version(), expected.legacy_version());
    assert_eq!(
        normalize_grease(actual.cipher_suites()),
        normalize_grease(expected.cipher_suites())
    );
    assert_eq!(
        normalize_grease(actual.supported_groups()),
        normalize_grease(expected.supported_groups())
    );
    assert_eq!(actual.ec_point_formats(), expected.ec_point_formats());
    assert_eq!(
        normalize_grease(actual.signature_algorithms()),
        normalize_grease(expected.signature_algorithms())
    );
    assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
    assert_eq!(
        normalize_grease(actual.supported_versions()),
        normalize_grease(expected.supported_versions())
    );
    assert_eq!(
        normalize_grease(actual.key_share_groups()),
        normalize_grease(expected.key_share_groups())
    );
    assert_eq!(actual.server_name(), expected.server_name());
    assert_eq!(actual.server_name(), Some(server_name.as_bytes()));
    // Cross-capture comparison is membership only; the Chrome 154 order test
    // pins the exact order the connector emits.
    assert_eq!(
        sorted_trust_anchor_ids(&actual),
        sorted_trust_anchor_ids(&expected)
    );
    assert_eq!(
        actual.requested_trust_anchor_ids().map(<[_]>::len),
        trust_anchor_id_count
    );
    // Every retained Chrome sample uses HKDF-SHA256 with AES-128-GCM.
    assert_eq!(
        client_hello_fixture::ech_cipher_suite(actual_capture.handshake_bytes())?,
        client_hello_fixture::ech_cipher_suite(expected_capture.handshake_bytes())?
    );

    // Chrome permutes eligible extensions on each connection. Sorting only this
    // vector compares exact membership and count without inventing a stable order.
    assert_eq!(
        actual.extension_types().len(),
        expected.extension_types().len()
    );
    assert_eq!(
        grease_count(actual.extension_types()),
        grease_count(expected.extension_types())
    );
    assert_eq!(
        normalized_extensions(actual.extension_types()),
        normalized_extensions(expected.extension_types())
    );
    assert_eq!(
        stable_extension_layout(&actual),
        stable_extension_layout(&expected)
    );
    assert_eq!(
        actual.extension_types().contains(&TRUST_ANCHORS_EXTENSION),
        trust_anchor_id_count.is_some()
    );
    Ok(())
}

#[tokio::test]
async fn omitted_trust_anchor_ids_omit_the_extension() -> TestResult<()> {
    let mut settings = v154_tcp_tls();
    settings.requested_trust_anchor_ids = None;

    let summary = capture_client_hello_from(&settings).await?.summary()?;
    assert!(!summary.extension_types().contains(&TRUST_ANCHORS_EXTENSION));
    Ok(())
}

fn sorted_trust_anchor_ids(summary: &ClientHelloSummary) -> Option<Vec<Vec<u8>>> {
    summary.requested_trust_anchor_ids().map(|ids| {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids
    })
}

fn normalize_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .map(|&value| {
            if is_grease(value) {
                GREASE_SENTINEL
            } else {
                value
            }
        })
        .collect()
}

fn normalized_extensions(values: &[u16]) -> Vec<u16> {
    let mut extensions = normalize_grease(values);
    extensions.sort_unstable();
    extensions
}

fn grease_count(values: &[u16]) -> usize {
    values.iter().filter(|&&value| is_grease(value)).count()
}

fn stable_extension_layout(summary: &ClientHelloSummary) -> Vec<(u16, usize)> {
    let mut layout = summary
        .extension_layout()
        .filter(|(extension_type, _)| *extension_type != 0xfe0d)
        .map(|(extension_type, payload_length)| {
            (
                if is_grease(extension_type) {
                    GREASE_SENTINEL
                } else {
                    extension_type
                },
                payload_length,
            )
        })
        .collect::<Vec<_>>();
    layout.sort_unstable();
    layout
}

fn record_length_without_ech(
    capture: &ClientHelloCapture,
    summary: &ClientHelloSummary,
) -> TestResult<usize> {
    let ech_payload_length = summary
        .extension_layout()
        .find_map(|(extension_type, payload_length)| {
            (extension_type == 0xfe0d).then_some(payload_length)
        })
        .ok_or("ClientHello has no ECH GREASE extension")?;
    let record = capture
        .records()
        .first()
        .ok_or("ClientHello capture has no TLS record")?;

    // Pinned BoringSSL deliberately chooses the ECH GREASE payload estimate at
    // random in 32-byte increments. Only that payload length is normalized;
    // every other extension payload length is compared exactly above.
    record
        .fragment()
        .len()
        .checked_sub(ech_payload_length)
        .ok_or_else(|| "ECH payload is larger than its TLS record".into())
}
