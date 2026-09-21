//! Fixture-backed tests of profile WebSocket connection choice and openings.
//!
//! Each test drives `Client::websocket_with_profile_policy` against a loopback
//! origin and compares what the origin observed with a retained Chrome 153,
//! Edge 153, or Firefox 156 capture from `fixtures/websocket/`.
#![cfg(feature = "websocket")]

#[path = "websocket_profile/fixture.rs"]
mod fixture;
#[path = "websocket_profile/server.rs"]
mod server;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[allow(dead_code)]
#[path = "support/websocket.rs"]
mod websocket_support;

use std::sync::Arc;

use http::Version;
use phantom::{
    BuildErrorKind, Client, RequestHeader, WebSocket, WebSocketErrorKind, WebSocketHeader,
    WebSocketMessage, WebSocketRequestBuilder,
    profile::{ClientProfile, Http2Settings, WebSocketField, WebSocketSettings, chromium, firefox},
};

use fixture::{Capture, Representation};
use server::{Behavior, ConnectionLog, H2Headers, Reply, TestServer};
use tls_support::{TestIdentity, tls_settings};
use websocket_support::bounded;

pub(crate) type TestResult<T> = tls_support::TestResult<T>;

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/websocket/",
            $path
        ))
    };
}

const CHROME_ACCEPT: &str = fixture!("chrome/153.0.8010.48/windows-11-26200/accept.txt");
const CHROME_FRESH: &str = fixture!("chrome/153.0.8010.48/windows-11-26200/fresh-origin.txt");
const CHROME_NO_CONNECT: &str =
    fixture!("chrome/153.0.8010.48/windows-11-26200/no-connect-protocol.txt");
const CHROME_H1: &str = fixture!("chrome/153.0.8010.48/windows-11-26200/h1-accept.txt");
const FIREFOX_H1: &str = fixture!("firefox/156.0/windows-11-26200/h1-accept.txt");
const EDGE_ACCEPT: &str = fixture!("edge/153.0.4234.48/windows-11-26200/accept.txt");
const EDGE_FRESH: &str = fixture!("edge/153.0.4234.48/windows-11-26200/fresh-origin.txt");
const FIREFOX_ACCEPT: &str = fixture!("firefox/156.0/windows-11-26200/accept.txt");
const FIREFOX_FRESH: &str = fixture!("firefox/156.0/windows-11-26200/fresh-origin.txt");
const FIREFOX_NO_CONNECT: &str = fixture!("firefox/156.0/windows-11-26200/no-connect-protocol.txt");

/// HPACK differences between Phantom's encoder and Chromium's for CONNECT.
///
/// Chromium inserts only `:authority` into the dynamic table; Phantom's
/// encoder also inserts `:method CONNECT` and `:protocol`. See
/// `docs/websocket.md`.
const CHROMIUM_HPACK_DIFFERENCES: &[(&str, &str, &str, &str)] = &[
    (":method", "kind", "without-indexing", "incremental"),
    (":protocol", "kind", "without-indexing", "incremental"),
];

/// HPACK differences between Phantom's encoder and Firefox's for CONNECT.
///
/// Firefox names `:method` and `:path` with the last matching static entry
/// (3 and 5); Phantom's encoder uses the first (2 and 4).
const FIREFOX_HPACK_DIFFERENCES: &[(&str, &str, &str, &str)] =
    &[(":method", "index", "3", "2"), (":path", "index", "5", "4")];

#[tokio::test]
async fn chromium_reuses_a_capable_pooled_session_with_the_captured_connect_shape() -> TestResult<()>
{
    for (fixture, client_name) in [
        (CHROME_ACCEPT, "Google Chrome"),
        (EDGE_ACCEPT, "Microsoft Edge"),
    ] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("client")?, client_name);
        assert_reuses_session(
            &capture,
            chromium::v153_http2(),
            chromium::v153_websocket(),
            CHROMIUM_HPACK_DIFFERENCES,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn firefox_reuses_a_capable_pooled_session_with_the_captured_connect_shape() -> TestResult<()>
{
    assert_reuses_session(
        &Capture::parse(FIREFOX_ACCEPT)?,
        firefox::v156_http2(),
        firefox::v156_websocket(),
        FIREFOX_HPACK_DIFFERENCES,
    )
    .await
}

#[tokio::test]
async fn chromium_without_a_session_upgrades_on_a_new_http1_only_connection() -> TestResult<()> {
    for fixture in [CHROME_FRESH, EDGE_FRESH] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("scenario")?, "fresh-origin");
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
            let settings = chromium::v153_websocket();
            let client = profile_client(&identity, chromium::v153_http2(), settings.clone())?;

            let socket = upgrade_like(&client, &server, &capture, &settings).await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1, "Chromium opened an extra connection");
            assert_http1_upgrade(&connections[0], &capture)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn chromium_with_an_incapable_session_upgrades_on_a_new_http1_only_connection()
-> TestResult<()> {
    let capture = Capture::parse(CHROME_NO_CONNECT)?;
    assert_incapable_session_upgrades(&capture, chromium::v153_http2(), chromium::v153_websocket())
        .await
}

#[tokio::test]
async fn firefox_with_an_incapable_session_upgrades_on_a_new_http1_only_connection()
-> TestResult<()> {
    let capture = Capture::parse(FIREFOX_NO_CONNECT)?;
    assert_incapable_session_upgrades(&capture, firefox::v156_http2(), firefox::v156_websocket())
        .await
}

#[tokio::test]
async fn firefox_without_a_session_opens_a_new_http2_connection() -> TestResult<()> {
    let capture = Capture::parse(FIREFOX_FRESH)?;
    assert_eq!(capture.value("scenario")?, "fresh-origin");
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let settings = firefox::v156_websocket();
        let client = profile_client(&identity, firefox::v156_http2(), settings.clone())?;
        let connect = capture.connect()?;

        let socket = connect_like(&client, &server, &connect, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        let connection = &connections[0];
        assert_eq!(
            connection.alpn_offer.join(";"),
            capture.websocket_alpn_offer()?
        );
        assert_eq!(connection.protocol.as_deref(), Some("h2"));
        assert!(connection.h1.is_empty());
        assert_eq!(methods(connection), ["CONNECT"]);
        assert_connect_matches(&connection.h2[0], &connect, FIREFOX_HPACK_DIFFERENCES)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_websocket_upgrades_with_the_captured_http1_fields() -> TestResult<()> {
    for (fixture, http2, settings) in [
        (
            CHROME_H1,
            chromium::v153_http2(),
            chromium::v153_websocket(),
        ),
        (FIREFOX_H1, firefox::v156_http2(), firefox::v156_websocket()),
    ] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("socket_scheme")?, "ws");
        bounded(async {
            let identity = TestIdentity::generate()?;
            let server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
            let client = profile_client(&identity, http2, settings.clone())?;
            let upgrade = capture.upgrade()?;
            let path = upgrade
                .request_line
                .split(' ')
                .nth(1)
                .ok_or("request line has no target")?;
            let builder =
                client.websocket_with_profile_policy(&format!("ws://{}{path}", server.address))?;
            let builder = fill_callers(builder, &settings.http1_fields, &upgrade.fields);
            let socket = with_profile_compression(builder, &settings)?
                .connect()
                .await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1);
            assert_http1_upgrade(&connections[0], &capture)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_connect_on_a_pooled_session_is_returned_without_fallback() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::Reject,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v153_http2(),
            chromium::v153_websocket(),
        )?;
        ordinary_get(&client, &server).await?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("rejected CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        assert_eq!(
            error.response().map(|response| response.status()),
            Some(http::StatusCode::FORBIDDEN)
        );

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "rejection opened another connection");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn refused_connect_stream_is_not_retried() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::RefuseStream,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v153_http2(),
            chromium::v153_websocket(),
        )?;
        ordinary_get(&client, &server).await?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("refused CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "refusal opened another connection");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn new_http2_connection_without_the_peer_setting_fails_without_http1_fallback()
-> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect_protocol: false,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(&identity, firefox::v156_http2(), firefox::v156_websocket())?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("peer without extended CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "failure opened another connection");
        assert_eq!(connections[0].protocol.as_deref(), Some("h2"));
        assert!(connections[0].h2.is_empty(), "CONNECT HEADERS were sent");
        assert!(connections[0].h1.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_http1_upgrade_is_returned_without_another_connection() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            upgrade: Reply::Reject,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v153_http2(),
            chromium::v153_websocket(),
        )?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("rejected Upgrade opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].alpn_offer, ["http/1.1"]);
        assert_eq!(connections[0].h1.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http2_uses_the_profile_template_and_connect_priority() -> TestResult<()> {
    let capture = Capture::parse(FIREFOX_FRESH)?;
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let settings = firefox::v156_websocket();
        let client = profile_client(&identity, firefox::v156_http2(), settings.clone())?;
        let connect = capture.connect()?;
        let path = pseudo_value(&connect.pseudo, ":path")?;
        let builder = client.websocket_with_protocol(
            phantom::HttpProtocol::Http2,
            &format!("wss://{}{path}", server.address),
        )?;
        let builder = fill_callers(builder, &settings.http2_fields, &connect.fields);
        let socket = with_profile_compression(builder, &settings)?
            .connect()
            .await?;
        exchange(socket).await?;

        let connections = server.connections()?;
        let expected = expected_fields(&connect.fields);
        assert_eq!(connections[0].h2[0].fields, expected);
        assert_eq!(connections[0].h2[0].priority, Some(connect.priority));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn profile_policy_requires_websocket_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let profile = ClientProfile::new(tls_settings()).with_http2(chromium::v153_http2());
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
    let error = match client.websocket_with_profile_policy("wss://127.0.0.1/") {
        Ok(_) => return Err("profile without WebSocket settings chose a policy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::ProtocolUnavailable);
    Ok(())
}

#[tokio::test]
async fn profile_policy_rejects_a_replaced_field_sequence_before_io() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = profile_client(
            &identity,
            chromium::v153_http2(),
            chromium::v153_websocket(),
        )?;
        let error = match websocket(&client, &server)?
            .headers(vec![WebSocketHeader::field(RequestHeader::new(
                "sec-websocket-version",
                "13",
            ))])
            .connect()
            .await
        {
            Ok(_) => return Err("replaced policy sequence opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
        assert!(server.connections()?.is_empty());
        Ok(())
    })
    .await
}

#[test]
fn websocket_policy_needs_an_extended_connect_order() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_http2())
        .with_websocket(chromium::v153_websocket());
    let error = match Client::builder(profile).build() {
        Ok(_) => return Err("policy without an extended CONNECT order was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

async fn assert_reuses_session(
    capture: &Capture,
    http2: Http2Settings,
    settings: WebSocketSettings,
    hpack_differences: &[(&str, &str, &str, &str)],
) -> TestResult<()> {
    assert_eq!(capture.value("scenario")?, "accept");
    let ordinary_priority = http2.headers_priority.map(|priority| {
        (
            priority.exclusive,
            priority.dependency_stream_id,
            priority.weight,
        )
    });
    let ordinary_pseudo = http2.pseudo_header_order.len();
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = profile_client(&identity, http2, settings.clone())?;
        let connect = capture.connect()?;

        ordinary_get(&client, &server).await?;
        let socket = connect_like(&client, &server, &connect, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        // The session still serves ordinary requests with their own shape
        // while the WebSocket stream is open.
        ordinary_get(&client, &server).await?;
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "WebSocket did not reuse the session");
        let connection = &connections[0];
        assert_eq!(methods(connection), ["GET", "CONNECT", "GET"]);
        assert_eq!(
            connection
                .h2
                .iter()
                .map(|headers| headers.stream_id)
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
        assert_connect_matches(&connection.h2[1], &connect, hpack_differences)?;
        for ordinary in [&connection.h2[0], &connection.h2[2]] {
            assert_eq!(ordinary.priority, ordinary_priority);
            assert_eq!(ordinary.pseudo.len(), ordinary_pseudo);
        }
        Ok(())
    })
    .await
}

async fn assert_incapable_session_upgrades(
    capture: &Capture,
    http2: Http2Settings,
    settings: WebSocketSettings,
) -> TestResult<()> {
    assert_eq!(capture.value("scenario")?, "no-connect-protocol");
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect_protocol: false,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(&identity, http2, settings.clone())?;

        ordinary_get(&client, &server).await?;
        let socket = upgrade_like(&client, &server, capture, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0].protocol.as_deref(), Some("h2"));
        assert_eq!(
            methods(&connections[0]),
            ["GET"],
            "CONNECT reached an incapable session"
        );
        assert_http1_upgrade(&connections[1], capture)?;
        Ok(())
    })
    .await
}

fn assert_http1_upgrade(connection: &ConnectionLog, capture: &Capture) -> TestResult<()> {
    let upgrade = capture.upgrade()?;
    let offer = if connection.alpn_offer.is_empty() {
        "none".to_owned()
    } else {
        connection.alpn_offer.join(";")
    };
    assert_eq!(offer, capture.websocket_alpn_offer()?);
    if capture.value("socket_scheme")? == "wss" {
        assert_eq!(connection.protocol.as_deref(), Some("http/1.1"));
    }
    assert!(connection.h2.is_empty());
    let [request] = connection.h1.as_slice() else {
        return Err("expected exactly one H1 opening".into());
    };
    assert_eq!(request.request_line, upgrade.request_line);
    let expected = expected_fields(&upgrade.fields);
    assert_eq!(
        request
            .fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    // Host carries this server's authority and the key is fresh per opening.
    for ((name, value), (_, captured)) in request.fields.iter().zip(&expected) {
        if name != "Host" && name != "Sec-WebSocket-Key" {
            assert_eq!(value, captured, "{name}");
        }
    }
    Ok(())
}

fn assert_connect_matches(
    observed: &H2Headers,
    connect: &fixture::CapturedConnect,
    hpack_differences: &[(&str, &str, &str, &str)],
) -> TestResult<()> {
    assert_eq!(observed.method, "CONNECT");
    assert_eq!(observed.priority, Some(connect.priority));
    assert_eq!(
        observed
            .pseudo
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        connect
            .pseudo
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(observed.fields, expected_fields(&connect.fields));

    let mut differences = Vec::new();
    for ((name, ours), (_, _, captured)) in observed.pseudo.iter().zip(&connect.pseudo) {
        if ours.kind != captured.kind {
            differences.push((
                name.clone(),
                "kind",
                captured.kind.clone(),
                ours.kind.clone(),
            ));
        } else if captured.index <= 61 && ours.index != captured.index {
            differences.push((
                name.clone(),
                "index",
                captured.index.to_string(),
                ours.index.to_string(),
            ));
        }
    }
    let expected = hpack_differences
        .iter()
        .map(|(name, aspect, captured, ours)| {
            (
                (*name).to_owned(),
                *aspect,
                (*captured).to_owned(),
                (*ours).to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(differences, expected, "HPACK representation differences");
    Ok(())
}

/// Captured fields, less the compression offer when it cannot be generated.
fn expected_fields(fields: &[(String, String)]) -> Vec<(String, String)> {
    fields
        .iter()
        .filter(|(name, _)| {
            cfg!(feature = "websocket-deflate")
                || !name.eq_ignore_ascii_case("sec-websocket-extensions")
        })
        .cloned()
        .collect()
}

fn profile_client(
    identity: &TestIdentity,
    http2: Http2Settings,
    websocket: WebSocketSettings,
) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(http2)
        .with_websocket(websocket);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn ordinary_get(client: &Client, server: &TestServer) -> TestResult<()> {
    let response = client
        .get_negotiated(&format!("https://{}/page", server.address))?
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    Ok(())
}

fn websocket(client: &Client, server: &TestServer) -> TestResult<WebSocketRequestBuilder> {
    Ok(client.websocket_with_profile_policy(&format!("wss://{}/echo", server.address))?)
}

async fn connect_like(
    client: &Client,
    server: &TestServer,
    connect: &fixture::CapturedConnect,
    settings: &WebSocketSettings,
) -> TestResult<WebSocket> {
    let path = pseudo_value(&connect.pseudo, ":path")?;
    let builder =
        client.websocket_with_profile_policy(&format!("wss://{}{path}", server.address))?;
    let builder = fill_callers(builder, &settings.http2_fields, &connect.fields);
    Ok(with_profile_compression(builder, settings)?
        .connect()
        .await?)
}

async fn upgrade_like(
    client: &Client,
    server: &TestServer,
    capture: &Capture,
    settings: &WebSocketSettings,
) -> TestResult<WebSocket> {
    let upgrade = capture.upgrade()?;
    let path = upgrade
        .request_line
        .split(' ')
        .nth(1)
        .ok_or("request line has no target")?;
    let builder =
        client.websocket_with_profile_policy(&format!("wss://{}{path}", server.address))?;
    let builder = fill_callers(builder, &settings.http1_fields, &upgrade.fields);
    Ok(with_profile_compression(builder, settings)?
        .connect()
        .await?)
}

/// Supplies the captured value for every caller slot the template names.
fn fill_callers(
    mut builder: WebSocketRequestBuilder,
    template: &[WebSocketField],
    captured: &[(String, String)],
) -> WebSocketRequestBuilder {
    for field in template {
        let WebSocketField::Caller { name } = field else {
            continue;
        };
        if let Some((_, value)) = captured
            .iter()
            .find(|(captured, _)| captured.eq_ignore_ascii_case(name))
        {
            builder = builder.header(RequestHeader::new(name.clone(), value.as_str()));
        }
    }
    builder
}

#[cfg(feature = "websocket-deflate")]
fn with_profile_compression(
    builder: WebSocketRequestBuilder,
    settings: &WebSocketSettings,
) -> TestResult<WebSocketRequestBuilder> {
    Ok(builder.permessage_deflate(phantom::PerMessageDeflate::from_profile(settings)?))
}

#[cfg(not(feature = "websocket-deflate"))]
fn with_profile_compression(
    builder: WebSocketRequestBuilder,
    _settings: &WebSocketSettings,
) -> TestResult<WebSocketRequestBuilder> {
    Ok(builder)
}

async fn exchange(mut socket: WebSocket) -> TestResult<()> {
    socket
        .send(WebSocketMessage::Text("profile".into()))
        .await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("profile".into())
    );
    Ok(())
}

fn methods(connection: &ConnectionLog) -> Vec<&str> {
    connection
        .h2
        .iter()
        .map(|headers| headers.method.as_str())
        .collect()
}

fn pseudo_value<'a>(
    pseudo: &'a [(String, String, Representation)],
    name: &str,
) -> TestResult<&'a str> {
    pseudo
        .iter()
        .find(|(candidate, _, _)| candidate == name)
        .map(|(_, value, _)| value.as_str())
        .ok_or_else(|| format!("capture omitted {name}").into())
}
