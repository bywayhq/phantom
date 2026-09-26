//! Built-in WebSocket openings on plaintext `ws://` origins.
//!
//! Browsers treat a loopback origin as potentially trustworthy and a named
//! plaintext origin as not. Each test opens a `ws://` WebSocket with the
//! Chrome 154, Edge 153, or Firefox 156 recipe, supplying only the persona and
//! page fields (`User-Agent`, `Origin`, `Accept-Language`) from the capture,
//! and compares the Upgrade the origin received with the proxy route capture
//! of that browser: `direct-loopback.txt` for `ws://127.0.0.1` and
//! `http-proxy-hostname.txt` for `ws://origin.phantom.test`. The captured
//! Upgrade inside a proxy tunnel equals the direct one.
//!
//! The test suite has no resolver override, so the named origin is reached
//! through a loopback HTTP CONNECT proxy that forwards the tunnel to the test
//! origin. The URL keeps the capture's port, so `Host` and the request line
//! match the capture byte for byte.

use crate::support::tls as tls_support;
use crate::support::websocket as websocket_support;
use crate::websocket_profile::fixture;
use crate::websocket_profile::server;

use std::net::Ipv4Addr;

use phantom::{
    Client, HttpProxy, RequestHeader, Route, WebSocketMessage, WebSocketRequestBuilder,
    profile::{ClientProfile, Http2Settings, WebSocketField, WebSocketSettings, chromium, firefox},
};
use tokio::net::TcpListener;

use fixture::Capture;
use server::{Behavior, TestServer};
use tls_support::tls_settings;
use websocket_support::{bounded, forward_one_connect};

pub(crate) type TestResult<T> = tls_support::TestResult<T>;

macro_rules! proxy_fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/proxy/",
            $path
        ))
    };
}

const CHROME_LOOPBACK: &str =
    proxy_fixture!("chrome/154.0.8037.58/windows-11-26200/direct-loopback.txt");
const CHROME_NAMED: &str =
    proxy_fixture!("chrome/154.0.8037.58/windows-11-26200/http-proxy-hostname.txt");
const EDGE_LOOPBACK: &str =
    proxy_fixture!("edge/153.0.4234.48/windows-11-26200/direct-loopback.txt");
const EDGE_NAMED: &str =
    proxy_fixture!("edge/153.0.4234.48/windows-11-26200/http-proxy-hostname.txt");
const FIREFOX_LOOPBACK: &str = proxy_fixture!("firefox/156.0/windows-11-26200/direct-loopback.txt");
const FIREFOX_NAMED: &str =
    proxy_fixture!("firefox/156.0/windows-11-26200/http-proxy-hostname.txt");

/// One browser's recipe and its captures for each kind of origin.
struct Case {
    client: &'static str,
    http2: Http2Settings,
    settings: WebSocketSettings,
    loopback: &'static str,
    named: &'static str,
}

fn cases() -> [Case; 3] {
    [
        Case {
            client: "Google Chrome",
            http2: chromium::v154_http2(),
            settings: chromium::v154_websocket(),
            loopback: CHROME_LOOPBACK,
            named: CHROME_NAMED,
        },
        Case {
            client: "Microsoft Edge",
            http2: chromium::v154_http2(),
            settings: chromium::v154_websocket(),
            loopback: EDGE_LOOPBACK,
            named: EDGE_NAMED,
        },
        Case {
            client: "Mozilla Firefox",
            http2: firefox::v156_http2(),
            settings: firefox::v156_websocket(),
            loopback: FIREFOX_LOOPBACK,
            named: FIREFOX_NAMED,
        },
    ]
}

/// How the test starts the opening.
#[derive(Clone, Copy, Debug)]
enum Builder {
    /// `Client::websocket`, exactly HTTP/1.1.
    Exact,
    /// `Client::websocket_with_profile_policy`.
    ProfilePolicy,
}

#[tokio::test]
async fn built_in_websocket_openings_send_the_captured_loopback_fields() -> TestResult<()> {
    for case in cases() {
        for builder in [Builder::Exact, Builder::ProfilePolicy] {
            let capture = Capture::parse(case.loopback)?;
            assert_eq!(capture.value("client")?, case.client);
            assert_eq!(capture.value("scenario")?, "direct-loopback");
            bounded(async {
                let server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
                let upgrade = capture.upgrade()?;
                let path = target(&upgrade.request_line)?;
                let url = format!("ws://{}{path}", server.address);
                open(&case, builder, &url, Route::direct(), &upgrade.fields).await?;

                let authority = server.address.to_string();
                let expected = expected_fields(&upgrade.fields, Some(&authority));
                assert_opening(&server, &upgrade.request_line, &expected, &case, builder)
            })
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn built_in_websocket_openings_send_the_captured_named_origin_fields() -> TestResult<()> {
    for case in cases() {
        for builder in [Builder::Exact, Builder::ProfilePolicy] {
            let capture = Capture::parse(case.named)?;
            assert_eq!(capture.value("client")?, case.client);
            assert_eq!(capture.value("scenario")?, "http-proxy-hostname");
            bounded(async {
                let server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
                let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let route = Route::http_proxy(HttpProxy::new(&format!(
                    "http://{}",
                    proxy_listener.local_addr()?
                ))?);
                let proxy = tokio::spawn(forward_one_connect(proxy_listener, server.address));
                let upgrade = capture.upgrade()?;
                let host = upgrade
                    .fields
                    .iter()
                    .find_map(|(name, value)| (name == "Host").then_some(value.as_str()))
                    .ok_or("capture has no Host")?;
                assert!(host.starts_with("origin.phantom.test:"), "{host}");
                let path = target(&upgrade.request_line)?;
                let url = format!("ws://{host}{path}");
                open(&case, builder, &url, route, &upgrade.fields).await?;

                let connect = String::from_utf8(proxy.await??)?;
                assert!(
                    connect.starts_with(&format!("CONNECT {host} HTTP/1.1\r\n")),
                    "{connect}"
                );
                let expected = expected_fields(&upgrade.fields, None);
                assert_opening(&server, &upgrade.request_line, &expected, &case, builder)
            })
            .await?;
        }
    }
    Ok(())
}

/// A caller `Accept-Encoding` replaces the recipe's value for either kind of
/// origin, in the recipe's position.
#[tokio::test]
async fn caller_accept_encoding_replaces_the_recipe_value_in_place() -> TestResult<()> {
    bounded(async {
        let [chrome, ..] = cases();
        let server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
        let client = profile_client(&chrome, Route::direct())?;
        let socket = client
            .websocket(&format!("ws://{}/echo", server.address))?
            .header(RequestHeader::new("accept-encoding", "identity"))
            .connect()
            .await?;
        exchange(socket).await?;

        let connections = server.connections()?;
        let [connection] = connections.as_slice() else {
            return Err("expected one connection".into());
        };
        let fields = &connection.h1.first().ok_or("no opening")?.fields;
        let encodings = fields
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .collect::<Vec<_>>();
        assert_eq!(
            encodings,
            [&("Accept-Encoding".to_owned(), "identity".to_owned())]
        );
        let position = |name: &str| fields.iter().position(|(field, _)| field == name);
        assert_eq!(
            position("Accept-Encoding"),
            position("Sec-WebSocket-Version").map(|index| index + 1)
        );
        Ok(())
    })
    .await
}

/// Opens one WebSocket, filling only the recipe's caller slots from the
/// capture, and exchanges one message.
async fn open(
    case: &Case,
    builder: Builder,
    url: &str,
    route: Route,
    captured: &[(String, String)],
) -> TestResult<()> {
    let settings = &case.settings;
    let client = profile_client(case, route)?;
    let mut request = match builder {
        Builder::Exact => client.websocket(url)?,
        Builder::ProfilePolicy => client.websocket_with_profile_policy(url)?,
    };
    for field in &settings.http1_fields {
        let WebSocketField::Caller { name } = field else {
            continue;
        };
        if let Some((_, value)) = captured
            .iter()
            .find(|(captured, _)| captured.eq_ignore_ascii_case(name))
        {
            request = request.header(RequestHeader::new(name.clone(), value.as_str()));
        }
    }
    let socket = with_profile_compression(request, settings)?
        .connect()
        .await?;
    exchange(socket).await
}

fn assert_opening(
    server: &TestServer,
    request_line: &str,
    expected: &[(String, String)],
    case: &Case,
    builder: Builder,
) -> TestResult<()> {
    let connections = server.connections()?;
    let [connection] = connections.as_slice() else {
        return Err(format!("{} {builder:?}: expected one connection", case.client).into());
    };
    let [opening] = connection.h1.as_slice() else {
        return Err(format!("{} {builder:?}: expected one opening", case.client).into());
    };
    assert_eq!(
        opening.request_line, request_line,
        "{} {builder:?}",
        case.client
    );
    // The key is fresh for every opening.
    let observed = opening
        .fields
        .iter()
        .map(|(name, value)| {
            let value = if name == "Sec-WebSocket-Key" {
                String::new()
            } else {
                value.clone()
            };
            (name.clone(), value)
        })
        .collect::<Vec<_>>();
    assert_eq!(observed, expected, "{} {builder:?}", case.client);
    Ok(())
}

/// The captured fields with the key blanked, `Host` replaced by `authority`
/// when the test origin's address differs from the capture's, and the
/// compression offer removed when it cannot be generated.
fn expected_fields(fields: &[(String, String)], authority: Option<&str>) -> Vec<(String, String)> {
    fields
        .iter()
        .filter(|(name, _)| {
            cfg!(feature = "websocket-deflate")
                || !name.eq_ignore_ascii_case("sec-websocket-extensions")
        })
        .map(|(name, value)| {
            let value = match name.as_str() {
                "Sec-WebSocket-Key" => String::new(),
                "Host" => authority.map_or_else(|| value.clone(), str::to_owned),
                _ => value.clone(),
            };
            (name.clone(), value)
        })
        .collect()
}

fn target(request_line: &str) -> TestResult<&str> {
    Ok(request_line
        .split(' ')
        .nth(1)
        .ok_or("request line has no target")?)
}

fn profile_client(case: &Case, route: Route) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(case.http2.clone())
        .with_websocket(case.settings.clone());
    Ok(Client::builder(profile).route(route).build()?)
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

async fn exchange(mut socket: phantom::WebSocket) -> TestResult<()> {
    socket.send(WebSocketMessage::Text("trust".into())).await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("trust".into())
    );
    Ok(())
}
