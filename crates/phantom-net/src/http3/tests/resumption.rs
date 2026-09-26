use std::time::Duration;

use tokio::time::timeout;

use super::super::{Http3Connection, Http3Connector};
use super::{TEST_TIMEOUT, TestResult, server_endpoint};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};
use phantom_profile::chromium;

fn trusting_connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )?)
}

/// Accepts QUIC connections, sends each an empty SETTINGS frame, and holds
/// it until the client closes it.
///
/// A client stores a connection's tickets only once the server's SETTINGS
/// arrive, to keep them with the tickets.
fn spawn_server(endpoint: quinn::Endpoint) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await
                    && let Ok(mut control) = connection.open_uni().await
                {
                    let _ = control.write_all(&[0x00, 0x04, 0x00]).await;
                    connection.closed().await;
                }
            });
        }
    })
}

async fn connect(
    connector: &Http3Connector,
    address: std::net::SocketAddr,
) -> TestResult<Http3Connection> {
    Ok(timeout(
        TEST_TIMEOUT,
        connector.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??)
}

/// Waits until the server's NewSessionTicket has reached the client cache.
async fn wait_for_ticket(connector: &Http3Connector) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        while !connector.has_ticket_for(TEST_SERVER_NAME) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "no session ticket arrived".into())
}

#[tokio::test(flavor = "current_thread")]
async fn second_connection_to_one_origin_and_route_resumes() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let connector = trusting_connector(&identity)?.with_isolated_session_cache();
    assert!(connector.resumes_sessions());

    let first = connect(&connector, address).await?;
    assert!(!first.session_resumed());
    wait_for_ticket(&connector).await?;
    let second = connect(&connector, address).await?;
    assert!(second.session_resumed());

    drop((first, second));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_ticket_learned_on_one_route_is_not_presented_on_another() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let base = trusting_connector(&identity)?;
    // The client pool gives each origin-and-route entry its own clone.
    let learned_route = base.with_isolated_session_cache();
    let other_route = base.with_isolated_session_cache();

    let first = connect(&learned_route, address).await?;
    wait_for_ticket(&learned_route).await?;
    assert!(!other_route.has_ticket_for(TEST_SERVER_NAME));
    let other = connect(&other_route, address).await?;
    assert!(!other.session_resumed());
    // Neither the shared base connector nor the other route consumed it.
    let unshared = connect(&base, address).await?;
    assert!(!unshared.session_resumed());
    assert!(learned_route.has_ticket_for(TEST_SERVER_NAME));

    drop((first, other, unshared));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_connection_from_an_isolated_clone_is_usable_by_its_base() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let base = trusting_connector(&identity)?;
    let isolated = base.with_isolated_session_cache();

    let connection = connect(&isolated, address).await?;
    assert!(base.can_reuse(&connection).await);

    drop(connection);
    server.abort();
    Ok(())
}

/// The retained Chrome 154 QUIC ClientHellos come from fresh processes, so a
/// resumed offer is compared against them: it must add `pre_shared_key`, last,
/// and change nothing else the capture fixes. This server's tickets do not
/// permit early data, so `early_data` stays absent.
#[tokio::test(flavor = "current_thread")]
async fn resumed_chrome_154_client_hello_keeps_the_captured_shape() -> TestResult<()> {
    use super::connector::{
        CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_CLIENT_HELLO_2, CHROME_154_H3_STARTUP,
        PRE_SHARED_KEY, assert_client_hello_matches_capture,
    };
    const EARLY_DATA: u16 = 42;
    const PSK_KEY_EXCHANGE_MODES: u16 = 45;

    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = spawn_server(endpoint);
    let connector = trusting_connector(&identity)?.with_isolated_session_cache();

    let fresh = assert_client_hello_matches_capture(
        &connector,
        CHROME_154_H3_STARTUP,
        CHROME_154_H3_CLIENT_HELLO_1,
        &[],
    )?;
    assert!(fresh.contains(&PSK_KEY_EXCHANGE_MODES));
    for client_hello in [CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_CLIENT_HELLO_2] {
        let connection = connect(&connector, address).await?;
        wait_for_ticket(&connector).await?;
        let resumed = assert_client_hello_matches_capture(
            &connector,
            CHROME_154_H3_STARTUP,
            client_hello,
            &[PRE_SHARED_KEY],
        )?;
        assert!(!resumed.contains(&EARLY_DATA));
        drop(connection);
    }

    server.abort();
    Ok(())
}

const CHROME_154_RESUMPTION: [&str; 3] = [
    include_str!(concat!(
        "../../../../../fixtures/http3/chrome/154.0.8037.58/",
        "windows-11-26200/resumption-accept.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/chrome/154.0.8037.58/",
        "windows-11-26200/resumption-accept-delayed.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/chrome/154.0.8037.58/",
        "windows-11-26200/resumption-reject.txt"
    )),
];
const EDGE_154_RESUMPTION: [&str; 3] = [
    include_str!(concat!(
        "../../../../../fixtures/http3/edge/154.0.4258.37/",
        "windows-11-26200/resumption-accept.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/edge/154.0.4258.37/",
        "windows-11-26200/resumption-accept-delayed.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/edge/154.0.4258.37/",
        "windows-11-26200/resumption-reject.txt"
    )),
];

const BRAVE_154_RESUMPTION: [&str; 3] = [
    include_str!(concat!(
        "../../../../../fixtures/http3/brave/154.1.96.59/",
        "windows-11-26200/resumption-accept.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/brave/154.1.96.59/",
        "windows-11-26200/resumption-accept-delayed.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/brave/154.1.96.59/",
        "windows-11-26200/resumption-reject.txt"
    )),
];
const OPERA_135_RESUMPTION: [&str; 3] = [
    include_str!(concat!(
        "../../../../../fixtures/http3/opera/135.0.5973.92/",
        "windows-11-26200/resumption-accept.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/opera/135.0.5973.92/",
        "windows-11-26200/resumption-accept-delayed.txt"
    )),
    include_str!(concat!(
        "../../../../../fixtures/http3/opera/135.0.5973.92/",
        "windows-11-26200/resumption-reject.txt"
    )),
];

const EARLY_DATA: u16 = 0x2a;
const PSK_KEY_EXCHANGE_MODES: u16 = 0x2d;
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
const ALPS: u16 = 0x44cd;
const VERSION_INFORMATION: u64 = 0x11;
const INITIAL_RTT: u64 = 0x3127;

/// Replays each browser's resumed connections from the retained resumption
/// captures against Phantom's resumed ClientHello for the same recipe.
///
/// A connection first learns a ticket that permits early data and records
/// its round-trip time. The next ClientHello must then carry the captured
/// extension set, with `early_data` and, last, `pre_shared_key`; the captured
/// cipher suites, groups, signature algorithms, ALPN, ALPS, PSK modes, and
/// trust anchors; and the captured transport parameters, including
/// `initial_rtt_us` as a minimal-length varint. Values that are random per
/// connection (key shares, GREASE, connection IDs, the reserved version's
/// position, and the measured round-trip time) are compared by shape.
#[tokio::test(flavor = "current_thread")]
async fn resumed_chromium_client_hellos_match_the_resumption_captures() -> TestResult<()> {
    use super::connector::{
        BRAVE_154_H3_STARTUP, CHROME_154_H3_STARTUP, EDGE_154_H3_STARTUP, OPERA_135_H3_STARTUP,
    };
    use super::early_data::{Served, learn_ticket};
    use phantom_profile::{brave, edge, opera};

    for (tls, startup, captures) in [
        (
            chromium::v154_http3_tls(),
            CHROME_154_H3_STARTUP,
            CHROME_154_RESUMPTION,
        ),
        (
            edge::v154_http3_tls(),
            EDGE_154_H3_STARTUP,
            EDGE_154_RESUMPTION,
        ),
        (
            brave::v154_http3_tls(),
            BRAVE_154_H3_STARTUP,
            BRAVE_154_RESUMPTION,
        ),
        (
            opera::v135_http3_tls(),
            OPERA_135_H3_STARTUP,
            OPERA_135_RESUMPTION,
        ),
    ] {
        let identity = TestIdentity::generate()?;
        let connector = Http3Connector::new_with_additional_roots(
            &tls,
            &chromium::v154_quic(),
            &chromium::v154_http3(),
            &chromium::v154_http3_request(),
            [identity.root_der()],
        )?
        .with_isolated_session_cache();
        assert!(connector.sends_early_data());
        let (_address, _endpoint, server) =
            learn_ticket(&identity, &connector, &Served::default()).await?;

        let resumed = resumed_client_hello(&connector, startup)?;
        let mut compared = 0;
        for capture in captures {
            for captured in resumed_captured_client_hellos(capture)? {
                assert_resumed_client_hello_matches(&resumed, &captured)?;
                compared += 1;
            }
        }
        assert!(compared >= 3, "too few resumed captures were compared");
        server.abort();
    }
    Ok(())
}

/// Starts one QUIC session from `connector` and returns its ClientHello.
fn resumed_client_hello(connector: &Http3Connector, startup: &str) -> TestResult<Vec<u8>> {
    use std::io::Cursor;

    use quinn_proto::{Side, crypto, transport_parameters::TransportParameters};

    let parameters = TransportParameters::read(
        Side::Server,
        &mut Cursor::new(super::connector::fixture_hex(
            startup,
            "transport_parameters_hex",
        )?),
    )?;
    let mut session = crypto::ClientConfig::start_session(
        connector.test_crypto(),
        1,
        TEST_SERVER_NAME,
        &parameters,
    )?;
    let mut handshake = Vec::new();
    assert!(session.write_handshake(&mut handshake).is_none());
    Ok(handshake)
}

/// Returns the raw ClientHellos of the resumed connections a capture keeps.
fn resumed_captured_client_hellos(capture: &str) -> TestResult<Vec<Vec<u8>>> {
    let fields: std::collections::BTreeMap<&str, &str> = capture
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let mut client_hellos = Vec::new();
    for (key, value) in &fields {
        let Some(connection) = key.strip_suffix("_client_hello_hex") else {
            continue;
        };
        if fields.get(format!("{connection}_resumed").as_str()) != Some(&"true") {
            continue;
        }
        client_hellos.push(super::connector::fixture_hex(
            &format!("{key}={value}"),
            key,
        )?);
    }
    Ok(client_hellos)
}

fn assert_resumed_client_hello_matches(actual: &[u8], expected: &[u8]) -> TestResult<()> {
    use super::connector::{PRE_SHARED_KEY, client_hello_extension, sorted_trust_anchor_ids};
    use phantom_testkit::tls::ClientHelloSummary;

    let actual_summary = ClientHelloSummary::from_handshake_bytes(actual)?;
    let expected_summary = ClientHelloSummary::from_handshake_bytes(expected)?;
    assert_eq!(
        actual_summary.cipher_suites(),
        expected_summary.cipher_suites()
    );
    assert_eq!(
        actual_summary.supported_versions(),
        expected_summary.supported_versions()
    );
    assert_eq!(
        actual_summary.supported_groups(),
        expected_summary.supported_groups()
    );
    assert_eq!(
        actual_summary.key_share_groups(),
        expected_summary.key_share_groups()
    );
    assert_eq!(
        actual_summary.signature_algorithms(),
        expected_summary.signature_algorithms()
    );
    assert_eq!(
        actual_summary.alpn_protocols(),
        expected_summary.alpn_protocols()
    );
    assert_eq!(
        sorted_trust_anchor_ids(&actual_summary),
        sorted_trust_anchor_ids(&expected_summary)
    );

    // Extension order is permuted per connection, apart from the last one.
    let mut actual_extensions = actual_summary.extension_types().to_vec();
    let mut expected_extensions = expected_summary.extension_types().to_vec();
    assert_eq!(actual_extensions.last(), Some(&PRE_SHARED_KEY));
    assert_eq!(expected_extensions.last(), Some(&PRE_SHARED_KEY));
    actual_extensions.sort_unstable();
    expected_extensions.sort_unstable();
    assert_eq!(actual_extensions, expected_extensions);
    assert!(actual_extensions.contains(&EARLY_DATA));
    for extension in [EARLY_DATA, PSK_KEY_EXCHANGE_MODES, ALPS] {
        assert_eq!(
            client_hello_extension(actual, extension),
            client_hello_extension(expected, extension),
            "extension {extension:#06x}"
        );
    }

    let actual_parameters = transport_parameters(
        client_hello_extension(actual, QUIC_TRANSPORT_PARAMETERS)
            .ok_or("Phantom omitted QUIC transport parameters")?,
    )?;
    let expected_parameters = transport_parameters(
        client_hello_extension(expected, QUIC_TRANSPORT_PARAMETERS)
            .ok_or("the capture omitted QUIC transport parameters")?,
    )?;
    assert_eq!(
        parameter_shapes(&actual_parameters),
        parameter_shapes(&expected_parameters)
    );
    for parameter in &actual_parameters {
        let captured = || {
            expected_parameters
                .iter()
                .find(|captured| captured.id == parameter.id)
                .ok_or("the capture omitted a Phantom parameter")
        };
        match parameter.id {
            // The chosen version, then the available versions with one
            // reserved version at a random position.
            VERSION_INFORMATION => {
                let captured = captured()?;
                assert_eq!(parameter.value.get(..4), captured.value.get(..4));
                let mut actual_available = available_versions(&parameter.value[4..]);
                let mut expected_available = available_versions(&captured.value[4..]);
                actual_available.sort_unstable();
                expected_available.sort_unstable();
                assert_eq!(actual_available, expected_available);
            }
            INITIAL_RTT => {
                let (value, encoded_len) =
                    decode_varint(&parameter.value).ok_or("initial_rtt_us is not a varint")?;
                assert_eq!(encoded_len, parameter.value.len());
                assert!(value > 0);
                assert_eq!(encoded_len, minimal_varint_len(value));
            }
            id if is_reserved(id) => {}
            id => assert_eq!(parameter.value, captured()?.value, "parameter {id:#x}"),
        }
    }
    Ok(())
}

struct TransportParameter {
    id: u64,
    id_len: usize,
    length_len: usize,
    value: Vec<u8>,
}

fn transport_parameters(mut encoded: &[u8]) -> TestResult<Vec<TransportParameter>> {
    let mut parameters = Vec::new();
    while !encoded.is_empty() {
        let (id, id_len) = decode_varint(encoded).ok_or("truncated parameter id")?;
        encoded = &encoded[id_len..];
        let (len, length_len) = decode_varint(encoded).ok_or("truncated parameter length")?;
        encoded = &encoded[length_len..];
        let len = usize::try_from(len)?;
        let value = encoded.get(..len).ok_or("truncated parameter value")?;
        parameters.push(TransportParameter {
            id,
            id_len,
            length_len,
            value: value.to_vec(),
        });
        encoded = &encoded[len..];
    }
    Ok(parameters)
}

/// Sorted identifiers with their id and length widths and, where the value
/// is not random per connection, its length. Reserved identifiers share one
/// class.
fn parameter_shapes(parameters: &[TransportParameter]) -> Vec<(u64, usize, usize, Option<usize>)> {
    let mut shapes: Vec<_> = parameters
        .iter()
        .map(|parameter| {
            let reserved = is_reserved(parameter.id);
            (
                if reserved { 27 } else { parameter.id },
                parameter.id_len,
                parameter.length_len,
                (!reserved && parameter.id != INITIAL_RTT).then_some(parameter.value.len()),
            )
        })
        .collect();
    shapes.sort_unstable();
    shapes
}

/// Available versions, with a reserved version as `None`.
fn available_versions(encoded: &[u8]) -> Vec<Option<u32>> {
    encoded
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| {
            let version = u32::from_be_bytes(*word);
            (version & 0x0f0f_0f0f != 0x0a0a_0a0a).then_some(version)
        })
        .collect()
}

fn is_reserved(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

fn decode_varint(encoded: &[u8]) -> Option<(u64, usize)> {
    let first = *encoded.first()?;
    let len = 1_usize << (first >> 6);
    let rest = encoded.get(1..len)?;
    let value = rest.iter().fold(u64::from(first & 0x3f), |value, byte| {
        (value << 8) | u64::from(*byte)
    });
    Some((value, len))
}

fn minimal_varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}
