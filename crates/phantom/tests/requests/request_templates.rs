//! Fixture-backed wire tests of browser request templates.
//!
//! Each test sends a templated request to a loopback origin over HTTP/1.1,
//! HTTP/2, or HTTP/3 and compares the ordered fields the origin received with
//! the same request kind in a retained Chrome 154, Edge 153, or Firefox 156
//! capture, and on HTTP/2 also the HEADERS priority. The captures ran
//! headless, so their `User-Agent` names `HeadlessChrome`; the comparison
//! uses the headful `Chrome` product.

#[path = "request_templates/fixture.rs"]
mod fixture;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;
#[path = "request_templates/wire.rs"]
mod wire;

use std::{
    future::poll_fn,
    net::Ipv4Addr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, ContentCoding, ContentDecoding, HttpProtocol,
    HttpProxy, PreparedRequestTemplate, RedirectPolicy, RequestErrorKind, RequestHeader,
    ResponseInfo, Route, Socks5Proxy,
    profile::{
        ClientHintSettings, ClientProfile, CookiePlacement, Http2Settings, RequestTemplate, brave,
        brave_android, chrome_android, chromium, edge, firefox, opera,
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use fixture::{Capture, Fields};
use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, accept_tls, read_head, tls_settings};
use wire::{Priority, RecordingIo, headers_priority};

pub(crate) type TestResult<T> = tls_support::TestResult<T>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/",
            $path
        ))
    };
}

const CHROME_H1: &str = fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/h1-accept.txt");
const CHROME_H2: &str = fixture!("websocket/chrome/154.0.8037.58/windows-11-26200/accept.txt");
const CHROME_H3: &str = fixture!("http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt");
const EDGE_H1: &str = fixture!("websocket/edge/153.0.4234.48/windows-11-26200/h1-accept.txt");
const EDGE_H2: &str = fixture!("websocket/edge/153.0.4234.48/windows-11-26200/accept.txt");
const EDGE_H3: &str = fixture!("http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt");
const BRAVE_H1: &str = fixture!("websocket/brave/154.1.96.59/windows-11-26200/h1-accept.txt");
const BRAVE_H2: &str = fixture!("websocket/brave/154.1.96.59/windows-11-26200/accept.txt");
const BRAVE_H3: &str = fixture!("http3/brave/154.1.96.59/windows-11-26200/client-startup.txt");
const OPERA_H1: &str = fixture!("websocket/opera/135.0.5973.92/windows-11-26200/h1-accept.txt");
const OPERA_H2: &str = fixture!("websocket/opera/135.0.5973.92/windows-11-26200/accept.txt");
const OPERA_H3: &str = fixture!("http3/opera/135.0.5973.92/windows-11-26200/client-startup.txt");
const BRAVE_ANDROID_H1: &str =
    fixture!("websocket/brave-android/153.1.95.104/android-35-emulator/h1-accept.txt");
const BRAVE_ANDROID_H2: &str =
    fixture!("websocket/brave-android/153.1.95.104/android-35-emulator/accept.txt");
const BRAVE_ANDROID_H3: &str =
    fixture!("http3/brave-android/153.1.95.104/android-35-emulator/client-startup.txt");
const CHROME_ANDROID_H1: &str =
    fixture!("websocket/chrome-android/153.0.8010.52/android-35-emulator/h1-accept.txt");
const CHROME_ANDROID_H2: &str =
    fixture!("websocket/chrome-android/153.0.8010.52/android-35-emulator/accept.txt");
const CHROME_ANDROID_H3: &str =
    fixture!("http3/chrome-android/153.0.8010.52/android-35-emulator/client-startup.txt");
const FIREFOX_H1: &str = fixture!("websocket/firefox/156.0/windows-11-26200/h1-accept.txt");
const FIREFOX_H2: &str = fixture!("websocket/firefox/156.0/windows-11-26200/accept.txt");

/// One browser's recipes and the capture each protocol is compared with.
struct Browser {
    http2: Http2Settings,
    hints: Option<ClientHintSettings>,
    http1_capture: &'static str,
    http2_capture: &'static str,
    http3_capture: Option<&'static str>,
}

fn chrome() -> Browser {
    Browser {
        http2: chromium::v154_http2(),
        hints: Some(chromium::v154_windows_client_hints()),
        http1_capture: CHROME_H1,
        http2_capture: CHROME_H2,
        http3_capture: Some(CHROME_H3),
    }
}

fn edge() -> Browser {
    Browser {
        http2: chromium::v154_http2(),
        hints: Some(edge::v153_windows_client_hints()),
        http1_capture: EDGE_H1,
        http2_capture: EDGE_H2,
        http3_capture: Some(EDGE_H3),
    }
}

fn brave() -> Browser {
    Browser {
        http2: chromium::v154_http2(),
        hints: Some(brave::v154_windows_client_hints()),
        http1_capture: BRAVE_H1,
        http2_capture: BRAVE_H2,
        http3_capture: Some(BRAVE_H3),
    }
}

fn opera() -> Browser {
    Browser {
        http2: chromium::v154_http2(),
        hints: Some(opera::v135_windows_client_hints()),
        http1_capture: OPERA_H1,
        http2_capture: OPERA_H2,
        http3_capture: Some(OPERA_H3),
    }
}

fn brave_android() -> Browser {
    Browser {
        http2: brave_android::v153_http2(),
        hints: Some(brave_android::v153_android_client_hints()),
        http1_capture: BRAVE_ANDROID_H1,
        http2_capture: BRAVE_ANDROID_H2,
        http3_capture: Some(BRAVE_ANDROID_H3),
    }
}

fn chrome_android() -> Browser {
    Browser {
        http2: chrome_android::v153_http2(),
        hints: Some(chrome_android::v153_android_client_hints(
            "sdk_gphone64_x86_64",
        )),
        http1_capture: CHROME_ANDROID_H1,
        http2_capture: CHROME_ANDROID_H2,
        http3_capture: Some(CHROME_ANDROID_H3),
    }
}

fn firefox() -> Browser {
    Browser {
        http2: firefox::v156_http2(),
        hints: None,
        http1_capture: FIREFOX_H1,
        http2_capture: FIREFOX_H2,
        http3_capture: None,
    }
}

/// Which captured request a template reproduces.
#[derive(Clone, Copy)]
enum Kind {
    /// The page navigation: H1 `page`, H2/H3 `sec-fetch-dest: document`.
    Navigation,
    /// The no-store report fetch: H1 `done`, H2 `sec-fetch-dest: empty`.
    Fetch,
}

/// Returns the HTTP/2 HEADERS priority of the captured request.
fn captured_priority(browser: &Browser, kind: Kind) -> TestResult<Option<Priority>> {
    let destination = match kind {
        Kind::Navigation => "document",
        Kind::Fetch => "empty",
    };
    Capture::parse(browser.http2_capture)?.http2_priority(destination)
}

fn captured(browser: &Browser, kind: Kind, protocol: HttpProtocol) -> TestResult<Fields> {
    let (http1_kind, destination) = match kind {
        Kind::Navigation => ("page", "document"),
        Kind::Fetch => ("done", "empty"),
    };
    let fields = match protocol {
        HttpProtocol::Http1 => Capture::parse(browser.http1_capture)?.http1_request(http1_kind)?,
        HttpProtocol::Http2 => Capture::parse(browser.http2_capture)?.http2_request(destination)?,
        HttpProtocol::Http3 => {
            Capture::parse(browser.http3_capture.ok_or("no H3 capture")?)?.http3_request()?
        }
        _ => return Err("no capture for this protocol".into()),
    };
    Ok(fields
        .into_iter()
        .map(|(name, value)| (name, value.replace("HeadlessChrome/", "Chrome/")))
        .collect())
}

/// What the origin received: ordered fields and, on HTTP/2, the HEADERS
/// priority.
struct Observed {
    fields: Fields,
    priority: Option<Priority>,
}

/// Sends one templated request and returns what the origin received.
///
/// Caller values come from the capture itself for every field a template
/// leaves to the caller: `Referer` always, `User-Agent` when the template has
/// no captured value, and Brave's `Accept-Language`, whose `q` value Brave
/// draws per session.
async fn send(
    browser: &Browser,
    template: RequestTemplate,
    protocol: HttpProtocol,
    expected: &Fields,
) -> TestResult<Observed> {
    let mut caller = Vec::new();
    for (name, value) in expected {
        let slot = protocol_fields(&template, protocol).iter().find(|field| {
            field
                .name()
                .is_some_and(|slot| slot.eq_ignore_ascii_case(name))
        });
        if matches!(slot, Some(phantom::profile::RequestField::Caller { .. })) {
            caller.push(RequestHeader::new(name.to_ascii_lowercase(), value));
        }
    }
    send_with(
        browser,
        template,
        protocol,
        caller,
        CookiePlacement::last(),
        |builder, _| Ok(builder),
    )
    .await
}

/// Sends one templated request with `caller` fields from a client whose
/// profile has `cookie_placement` and whose builder `configure` adjusts for
/// the origin URL, and returns what the origin received.
async fn send_with(
    browser: &Browser,
    template: RequestTemplate,
    protocol: HttpProtocol,
    caller: Vec<RequestHeader>,
    cookie_placement: CookiePlacement,
    configure: impl FnOnce(ClientBuilder, &str) -> TestResult<ClientBuilder>,
) -> TestResult<Observed> {
    let identity = TestIdentity::generate()?;
    let (client_done, wait_for_client) = oneshot::channel();
    let (url, server) = match protocol {
        HttpProtocol::Http1 => serve_http1(&identity).await?,
        HttpProtocol::Http2 => serve_http2(&identity, wait_for_client).await?,
        HttpProtocol::Http3 => serve_http3(&identity, wait_for_client)?,
        _ => return Err("no test origin for this protocol".into()),
    };
    let mut profile = ClientProfile::new(tls_settings())
        .with_http2(browser.http2.clone())
        .with_http3(client_settings())
        .with_cookie_placement(cookie_placement);
    if let Some(hints) = &browser.hints {
        profile = profile.with_client_hints(hints.clone());
    }
    let builder = Client::builder(profile).add_root_certificate_der(identity.root_der.clone());
    let client = configure(builder, &url)?.build()?;

    let response = client
        .get(protocol, &url)?
        .template(&PreparedRequestTemplate::new(template)?)
        .headers(caller)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    let _ = client_done.send(());
    server.await?
}

fn protocol_fields(
    template: &RequestTemplate,
    protocol: HttpProtocol,
) -> &[phantom::profile::RequestField] {
    match protocol {
        HttpProtocol::Http1 => &template.http1_fields,
        HttpProtocol::Http2 => &template.http2_fields,
        HttpProtocol::Http3 => template.http3_fields.as_deref().unwrap_or(&[]),
        _ => &[],
    }
}

type Server = tokio::task::JoinHandle<TestResult<Observed>>;

async fn serve_http1(identity: &TestIdentity) -> TestResult<(String, Server)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/", listener.local_addr()?);
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok(Observed {
            fields: http1_fields(head)?,
            priority: None,
        })
    });
    Ok((url, server))
}

/// Returns the fields of an HTTP/1.1 request head without `Host`.
fn http1_fields(head: Vec<u8>) -> TestResult<Fields> {
    let head = String::from_utf8(head)?;
    let mut fields = Vec::new();
    for line in head.trim_end().split("\r\n").skip(1) {
        let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
        if !name.eq_ignore_ascii_case("host") {
            fields.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok(fields)
}

async fn serve_http2(
    identity: &TestIdentity,
    wait_for_client: oneshot::Receiver<()>,
) -> TestResult<(String, Server)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let server = tokio::spawn(async move {
        let wire = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingIo {
            inner: accept_tls(listener, acceptor).await?,
            read: Arc::clone(&wire),
        };
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("HTTP/2 connection closed before a request")??;
        let priority = headers_priority(
            &wire.lock().map_err(|_| "wire lock was poisoned")?,
            u32::from(respond.stream_id()),
        )?;
        let fields = request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .ok_or("HTTP/2 request has no ordered fields")?
            .as_slice()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
            true,
        )?;
        tokio::select! {
            result = poll_fn(|context| connection.poll_closed(context)) => result?,
            _ = wait_for_client => {}
        }
        Ok(Observed { fields, priority })
    });
    Ok((url, server))
}

fn serve_http3(
    identity: &TestIdentity,
    wait_for_client: oneshot::Receiver<()>,
) -> TestResult<(String, Server)> {
    let (address, endpoint) = server_endpoint(identity)?;
    let server = tokio::spawn(async move {
        let (request, mut stream, _connection) = accept_request(&endpoint).await?;
        // The decoder appends fields in wire order and names are distinct,
        // so map iteration keeps that order.
        let fields = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = wait_for_client.await;
        Ok(Observed {
            fields,
            priority: None,
        })
    });
    Ok((format!("https://{address}/"), server))
}

async fn assert_reproduces(
    browser: Browser,
    template: fn() -> RequestTemplate,
    kind: Kind,
    protocols: &[HttpProtocol],
) -> TestResult<()> {
    for &protocol in protocols {
        let expected = captured(&browser, kind, protocol)?;
        let observed = timeout(
            TEST_TIMEOUT,
            send(&browser, template(), protocol, &expected),
        )
        .await
        .map_err(|_| format!("{protocol:?} request timed out"))??;
        assert_eq!(observed.fields, expected, "{protocol:?}");
        if protocol == HttpProtocol::Http2 {
            let priority = captured_priority(&browser, kind)?;
            assert!(priority.is_some(), "the capture carries HEADERS priority");
            assert_eq!(observed.priority, priority, "HTTP/2 HEADERS priority");
        }
    }
    Ok(())
}

const ALL: &[HttpProtocol] = &[
    HttpProtocol::Http1,
    HttpProtocol::Http2,
    HttpProtocol::Http3,
];
const TCP: &[HttpProtocol] = &[HttpProtocol::Http1, HttpProtocol::Http2];

#[tokio::test]
async fn chrome_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        chrome(),
        chromium::v154_windows_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn edge_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        edge(),
        edge::v153_windows_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn brave_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        brave(),
        brave::v154_windows_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn opera_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        opera(),
        opera::v135_windows_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn brave_android_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        brave_android(),
        brave_android::v153_android_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn brave_android_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        brave_android(),
        brave_android::v153_android_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn chrome_android_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        chrome_android(),
        chrome_android::v153_android_navigation_template,
        Kind::Navigation,
        ALL,
    )
    .await
}

#[tokio::test]
async fn firefox_navigation_sends_the_captured_page_request() -> TestResult<()> {
    assert_reproduces(
        firefox(),
        firefox::v156_windows_navigation_template,
        Kind::Navigation,
        TCP,
    )
    .await
}

#[tokio::test]
async fn chrome_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        chrome(),
        chromium::v154_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn edge_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        edge(),
        edge::v153_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn brave_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        brave(),
        brave::v154_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn opera_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        opera(),
        opera::v135_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn chrome_android_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        chrome_android(),
        chrome_android::v153_android_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn firefox_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        firefox(),
        firefox::v156_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

/// A negotiated request that ALPN puts on HTTP/2 goes through the pooled
/// negotiated dispatch, which must also send the template's HEADERS priority
/// instead of the connection's navigation priority.
#[tokio::test]
async fn negotiated_http2_request_sends_the_template_priority() -> TestResult<()> {
    let browser = chrome();
    let identity = TestIdentity::generate()?;
    let (client_done, wait_for_client) = oneshot::channel();
    let (url, server) = serve_http2(&identity, wait_for_client).await?;
    let client =
        Client::builder(ClientProfile::new(tls_settings()).with_http2(browser.http2.clone()))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
    let sent = client
        .get_negotiated(&url)?
        .template(&PreparedRequestTemplate::new(
            chromium::v154_windows_fetch_no_store_template(),
        )?)
        .header(RequestHeader::new("referer", url.as_str()))
        .send();
    let response = timeout(TEST_TIMEOUT, sent).await??;
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol);
    assert_eq!(protocol, Some(HttpProtocol::Http2));
    response.into_body().collect().await?;
    let _ = client_done.send(());
    let observed = timeout(TEST_TIMEOUT, server).await???;

    let captured = captured_priority(&browser, Kind::Fetch)?;
    assert!(captured.is_some(), "the capture carries HEADERS priority");
    assert_eq!(observed.priority, captured);
    assert_ne!(
        captured,
        captured_priority(&browser, Kind::Navigation)?,
        "the fetch priority differs from the connection's"
    );
    Ok(())
}

/// The jar's `Cookie` in a templated request, placed by the profile's
/// `CookiePlacement` after template expansion and before client-hint slots
/// are filled.
#[cfg(feature = "cookies")]
mod cookie_placement {
    use phantom::CookieJar;

    use super::*;

    const CHROME_SSE_COOKIE: &str =
        fixture!("sse/chrome/154.0.8037.58/windows-11-26200/set-cookie-then-close.txt");
    const FIREFOX_SSE_COOKIE: &str =
        fixture!("sse/firefox/156.0/windows-11-26200/set-cookie-then-close.txt");
    /// `PROBE_COOKIE` in scripts/capture/sse_reconnect.py.
    const PROBE_COOKIE: &str = "phantom_probe=1";
    /// The `fetch` templates leave `Referer` to the caller; an address-bar
    /// navigation sends none.
    const REFERER: &str = "https://127.0.0.1/run";

    /// Returns the captured EventSource reconnect that carried the cookie.
    fn captured_cookie_request(capture: &str) -> TestResult<Fields> {
        Capture::parse(capture)?
            .http1_requests("sse")?
            .into_iter()
            .find(|fields| {
                fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            })
            .ok_or_else(|| "capture has no reconnect with a Cookie field".into())
    }

    /// Returns the lowercase names before and after the one `Cookie` field,
    /// which must carry `PROBE_COOKIE`.
    fn sides(fields: &Fields) -> TestResult<(Vec<String>, Vec<String>)> {
        let cookies: Vec<_> = fields
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.eq_ignore_ascii_case("cookie"))
            .collect();
        let [(position, (_, value))] = cookies.as_slice() else {
            return Err(format!("expected one Cookie field, found {}", cookies.len()).into());
        };
        if value != PROBE_COOKIE {
            return Err(format!("Cookie was {value:?}").into());
        }
        let lower = |fields: &[(String, String)]| -> Vec<String> {
            fields
                .iter()
                .map(|(name, _)| name.to_ascii_lowercase())
                .collect()
        };
        Ok((lower(&fields[..*position]), lower(&fields[*position + 1..])))
    }

    /// Asserts that every field `observed` shares with `captured` is on the
    /// same side of `Cookie`, and returns the field right after `Cookie`.
    fn assert_cookie_sides(
        observed: &Fields,
        captured: &Fields,
        label: &str,
    ) -> TestResult<Option<String>> {
        let (before, after) = sides(observed)?;
        let (captured_before, captured_after) = sides(captured)?;
        for name in &before {
            assert!(
                !captured_after.contains(name),
                "{label}: {name} follows Cookie in the capture"
            );
        }
        for name in &after {
            assert!(
                !captured_before.contains(name),
                "{label}: {name} precedes Cookie in the capture"
            );
        }
        Ok(after.into_iter().next())
    }

    /// Sends one templated request from a client whose jar holds
    /// `PROBE_COOKIE` for the origin, and returns the fields the origin
    /// received.
    async fn send_with_jar_cookie(
        browser: &Browser,
        template: RequestTemplate,
        placement: CookiePlacement,
        protocol: HttpProtocol,
        caller: Vec<RequestHeader>,
    ) -> TestResult<Fields> {
        let sent = send_with(
            browser,
            template,
            protocol,
            caller,
            placement,
            |builder, url| {
                let jar = CookieJar::default();
                jar.set_cookie(url, &format!("{PROBE_COOKIE}; Path=/"))?;
                Ok(builder.cookie_jar(jar))
            },
        );
        let observed = timeout(TEST_TIMEOUT, sent)
            .await
            .map_err(|_| format!("{protocol:?} request timed out"))??;
        Ok(observed.fields)
    }

    fn referer() -> Vec<RequestHeader> {
        vec![RequestHeader::new("referer", REFERER)]
    }

    /// Firefox sends the jar's `Cookie` after `Referer` and before
    /// `Sec-Fetch-Dest` in the EventSource capture; the preset also puts it
    /// before `Upgrade-Insecure-Requests`, which only a navigation sends.
    #[tokio::test]
    async fn firefox_templates_place_the_jar_cookie_where_firefox_does() -> TestResult<()> {
        let browser = firefox();
        let captured = captured_cookie_request(FIREFOX_SSE_COOKIE)?;
        for (template, caller, next) in [
            (
                firefox::v156_windows_fetch_no_store_template(),
                referer(),
                "sec-fetch-dest",
            ),
            (
                firefox::v156_windows_navigation_template(),
                Vec::new(),
                "upgrade-insecure-requests",
            ),
        ] {
            let http1 = send_with_jar_cookie(
                &browser,
                template.clone(),
                firefox::v156_cookie_placement(),
                HttpProtocol::Http1,
                caller.clone(),
            )
            .await?;
            let after = assert_cookie_sides(&http1, &captured, "Firefox HTTP/1.1")?;
            assert_eq!(after.as_deref(), Some(next), "Firefox HTTP/1.1");

            // No HTTP/2 capture carries a cookie; this neighbour is the
            // preset's, from Firefox source.
            let http2 = send_with_jar_cookie(
                &browser,
                template,
                firefox::v156_cookie_placement(),
                HttpProtocol::Http2,
                caller,
            )
            .await?;
            let (_, after) = sides(&http2)?;
            assert_eq!(
                after.first().map(String::as_str),
                Some(next),
                "Firefox HTTP/2"
            );
        }
        Ok(())
    }

    /// Chrome sends the jar's `Cookie` last on HTTP/1.1, as in the
    /// EventSource capture, and before the final `priority` on HTTP/2.
    #[tokio::test]
    async fn chrome_templates_place_the_jar_cookie_where_chrome_does() -> TestResult<()> {
        let browser = chrome();
        let captured = captured_cookie_request(CHROME_SSE_COOKIE)?;
        let (_, captured_after) = sides(&captured)?;
        assert!(captured_after.is_empty(), "the capture sends Cookie last");
        for (template, caller) in [
            (chromium::v154_windows_navigation_template(), Vec::new()),
            (chromium::v154_windows_fetch_no_store_template(), referer()),
        ] {
            let http1 = send_with_jar_cookie(
                &browser,
                template.clone(),
                chromium::v154_cookie_placement(),
                HttpProtocol::Http1,
                caller.clone(),
            )
            .await?;
            let after = assert_cookie_sides(&http1, &captured, "Chrome HTTP/1.1")?;
            assert_eq!(after, None, "Chrome HTTP/1.1 sends Cookie last");

            // No HTTP/2 capture carries a cookie; this neighbour is the
            // preset's, from Chromium source.
            let http2 = send_with_jar_cookie(
                &browser,
                template,
                chromium::v154_cookie_placement(),
                HttpProtocol::Http2,
                caller,
            )
            .await?;
            let (_, after) = sides(&http2)?;
            assert_eq!(after, ["priority"], "Chrome HTTP/2");
        }
        Ok(())
    }
}

#[tokio::test]
async fn redirect_hop_keeps_the_template_and_drops_caller_hints_cross_origin() -> TestResult<()> {
    timeout(TEST_TIMEOUT, redirect_hop()).await?
}

/// Follows one cross-origin redirect, from one loopback port to another,
/// with the Chrome navigation template and a caller `sec-ch-ua-arch`.
async fn redirect_hop() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_url = format!("https://{}/", first.local_addr()?);
    let location = format!("https://{}/next", second.local_addr()?);
    let (first_acceptor, second_acceptor) =
        (identity.acceptor(H1_ALPN)?, identity.acceptor(H1_ALPN)?);
    let payload = b"template-decoded payload ".repeat(32);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &payload)?;
    let encoded = encoder.finish()?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(first, first_acceptor).await?;
        let first_hop = http1_fields(read_head(&mut stream).await?)?;
        let redirect =
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(redirect.as_bytes()).await?;

        let mut stream = accept_tls(second, second_acceptor).await?;
        let second_hop = http1_fields(read_head(&mut stream).await?)?;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
        response.extend_from_slice(&encoded);
        stream.write_all(&response).await?;
        TestResult::Ok((first_hop, second_hop))
    });

    let profile =
        ClientProfile::new(tls_settings()).with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .build()?;
    let response = client
        .get(HttpProtocol::Http1, &first_url)?
        .template(&PreparedRequestTemplate::new(
            chromium::v154_windows_navigation_template(),
        )?)
        .header(RequestHeader::new("sec-ch-ua-arch", "\"x86\""))
        .content_decoding(ContentDecoding::advertised(1 << 20))
        .send()
        .await?;
    let decoded = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response has no ResponseInfo")?
        .decoded_content_codings()
        .to_vec();
    let body = response.into_body().collect_with_limit(usize::MAX).await?;
    let (first_hop, second_hop) = server.await??;

    // The caller hint joins the block on the first hop.
    let names = |fields: &Fields| {
        fields
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&first_hop)[..5],
        [
            "Connection",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-arch",
            "sec-ch-ua-platform"
        ]
    );
    // The cross-origin hop drops it and is the template's captured page
    // request field for field, including its literal Accept-Encoding.
    assert_eq!(
        second_hop,
        captured(&chrome(), Kind::Navigation, HttpProtocol::Http1)?
    );
    assert!(second_hop.contains(&(
        "Accept-Encoding".to_owned(),
        "gzip, deflate, br, zstd".to_owned()
    )));
    // That template value, not a caller field, advertised gzip, so the
    // final response is decoded.
    assert_eq!(decoded, [ContentCoding::Gzip]);
    assert_eq!(body, payload);
    Ok(())
}

#[tokio::test]
async fn fork_templates_without_a_user_agent_fail_before_any_connection() -> TestResult<()> {
    // Brave's templates also leave `Accept-Language` to the caller, so its
    // requests carry one here and fail only for the missing `User-Agent`.
    for (hints, templates, language) in [
        (
            edge::v153_windows_client_hints(),
            [
                edge::v153_windows_navigation_template(),
                edge::v153_windows_fetch_no_store_template(),
            ],
            None,
        ),
        (
            brave::v154_windows_client_hints(),
            [
                brave::v154_windows_navigation_template(),
                brave::v154_windows_fetch_no_store_template(),
            ],
            Some("en-US,en;q=0.9"),
        ),
        (
            opera::v135_windows_client_hints(),
            [
                opera::v135_windows_navigation_template(),
                opera::v135_windows_fetch_no_store_template(),
            ],
            None,
        ),
    ] {
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chromium::v154_http2())
            .with_client_hints(hints);
        let client = Client::builder(profile).build()?;
        // Nothing listens here; an attempted connection would fail differently.
        let url = "https://127.0.0.1:9/";
        for template in templates {
            let mut builder = client
                .get(HttpProtocol::Http2, url)?
                .template(&PreparedRequestTemplate::new(template)?)
                .header(RequestHeader::new("referer", "https://127.0.0.1:9/"));
            if let Some(language) = language {
                builder = builder.header(RequestHeader::new("accept-language", language));
            }
            let error = builder
                .send()
                .await
                .err()
                .ok_or("brand hints were sent without a User-Agent")?;
            assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
        }
    }
    Ok(())
}

/// Brave's templates leave `Accept-Language` to the caller: Brave draws its
/// `q` value per session, so no literal would match every Brave request.
#[tokio::test]
async fn brave_template_without_an_accept_language_fails_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_client_hints(brave::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    let url = "https://127.0.0.1:9/";
    for template in [
        brave::v154_windows_navigation_template(),
        brave::v154_windows_fetch_no_store_template(),
    ] {
        let error = client
            .get(HttpProtocol::Http2, url)?
            .template(&PreparedRequestTemplate::new(template)?)
            .header(RequestHeader::new("referer", "https://127.0.0.1:9/"))
            .header(RequestHeader::new("user-agent", "Mozilla/5.0"))
            .send()
            .await
            .err()
            .ok_or("a Brave request was sent without Accept-Language")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    }
    Ok(())
}

#[tokio::test]
async fn fetch_template_with_a_requested_hint_fails_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Nothing listens here; an attempted connection would fail differently.
    let url = "https://127.0.0.1:9/";
    let error = client
        .get(HttpProtocol::Http2, url)?
        .template(&PreparedRequestTemplate::new(
            chromium::v154_windows_fetch_no_store_template(),
        )?)
        .header(RequestHeader::new("referer", "https://127.0.0.1:9/"))
        .header(RequestHeader::new("sec-ch-ua-arch", "\"x86\""))
        .send()
        .await
        .err()
        .ok_or("a requested hint was sent at an uncaptured fetch position")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);

    // Automatic hints never go to an `http://` origin, but a caller hint
    // does, so it is refused there too.
    let error = client
        .get(HttpProtocol::Http1, "http://127.0.0.1:9/")?
        .template(&PreparedRequestTemplate::new(
            chromium::v154_windows_fetch_no_store_template(),
        )?)
        .header(RequestHeader::new("referer", "http://127.0.0.1:9/"))
        .header(RequestHeader::new("sec-ch-ua-arch", "\"x86\""))
        .send()
        .await
        .err()
        .ok_or("a requested hint was sent at an uncaptured fetch position over http")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    Ok(())
}

/// Serves HTTP/1.1 requests on one TLS connection, answering each with
/// `reply`, and returns how many request heads arrived before the client
/// closed the connection.
async fn serve_http1_replies(
    identity: &TestIdentity,
    reply: &'static str,
) -> TestResult<(String, tokio::task::JoinHandle<TestResult<usize>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/", listener.local_addr()?);
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let mut requests = 0;
        while read_head(&mut stream).await.is_ok() {
            requests += 1;
            stream.write_all(reply.as_bytes()).await?;
        }
        Ok(requests)
    });
    Ok((url, server))
}

fn chrome_hints_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile =
        ClientProfile::new(tls_settings()).with_client_hints(chromium::v154_windows_client_hints());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// Once an origin asks for a hint the fetch template cannot place, the next
/// fetch to it fails before it is sent.
#[tokio::test]
async fn fetch_template_after_accept_ch_fails_before_the_request_is_sent() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (url, server) = serve_http1_replies(
        &identity,
        "HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\n\r\n",
    )
    .await?;
    let client = chrome_hints_client(&identity)?;
    // One prepared template serves every request.
    let template = PreparedRequestTemplate::new(chromium::v154_windows_fetch_no_store_template())?;
    let fetch = || {
        client.get(HttpProtocol::Http1, &url).map(|request| {
            request
                .template(&template)
                .header(RequestHeader::new("referer", url.as_str()))
        })
    };

    let first = timeout(TEST_TIMEOUT, fetch()?.send()).await??;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    first.into_body().collect().await?;
    let error = timeout(TEST_TIMEOUT, fetch()?.send())
        .await?
        .err()
        .ok_or("a requested hint was sent at an uncaptured fetch position")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);

    drop(client);
    assert_eq!(timeout(TEST_TIMEOUT, server).await???, 1);
    Ok(())
}

/// The retry a `Critical-CH` response asks for would carry the requested
/// hint, so on a fetch template it fails instead of being sent.
#[tokio::test]
async fn fetch_template_critical_ch_retry_fails_before_the_retry_is_sent() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (url, server) = serve_http1_replies(
        &identity,
        "HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\n\
         Critical-CH: Sec-CH-UA-Arch\r\n\r\n",
    )
    .await?;
    let client = chrome_hints_client(&identity)?;

    let error = timeout(
        TEST_TIMEOUT,
        client
            .get(HttpProtocol::Http1, &url)?
            .template(&PreparedRequestTemplate::new(
                chromium::v154_windows_fetch_no_store_template(),
            )?)
            .header(RequestHeader::new("referer", url.as_str()))
            .send(),
    )
    .await?
    .err()
    .ok_or("the Critical-CH retry was sent with a requested hint")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);

    drop(client);
    assert_eq!(timeout(TEST_TIMEOUT, server).await???, 1);
    Ok(())
}

#[tokio::test]
async fn template_without_http3_order_rejects_http3_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings()).with_http3(client_settings());
    let client = Client::builder(profile).build()?;
    let error = client
        .get(HttpProtocol::Http3, "https://127.0.0.1:9/")?
        .template(&PreparedRequestTemplate::new(
            firefox::v156_windows_fetch_no_store_template(),
        )?)
        .send()
        .await
        .err()
        .ok_or("template without an H3 list was sent over H3")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    Ok(())
}

#[tokio::test]
async fn negotiated_template_without_http3_order_is_refused_only_on_quic_routes() -> TestResult<()>
{
    let profile = ClientProfile::new(tls_settings())
        .with_http2(firefox::v156_http2())
        .with_http3(client_settings());
    let client = Client::builder(profile)
        .alt_svc(NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?)
        .build()?;
    let template = PreparedRequestTemplate::new(firefox::v156_windows_navigation_template())?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let url = format!("https://127.0.0.1:{port}/");

    // Direct and SOCKS5 routes can reach an HTTP/3 alternative, so the
    // request is refused before any connection.
    for route in [
        Route::direct(),
        Route::socks5(Socks5Proxy::new(&format!("socks5://127.0.0.1:{port}"))?),
    ] {
        let error = client
            .get_negotiated(&url)?
            .template(&template)
            .route(route)
            .send()
            .await
            .err()
            .ok_or("a route that carries QUIC accepted a template without an H3 list")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    }
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "a refused request opened a connection"
    );

    // A CONNECT-UDP route carries no negotiated request at all, and says so.
    let error = client
        .get_negotiated(&url)?
        .template(&template)
        .route(Route::connect_udp(ConnectUdpProxy::new(&format!(
            "https://127.0.0.1:{port}/udp/{{target_host}}/{{target_port}}/"
        ))?))
        .send()
        .await
        .err()
        .ok_or("a negotiated request was sent over CONNECT-UDP")?;
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);

    // A CONNECT tunnel never carries QUIC, so the request reaches the proxy.
    let proxy = tokio::spawn(async move {
        let (mut tunnel, _) = listener.accept().await?;
        let head = read_head(&mut tunnel).await?;
        tunnel
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
    });
    let sent = client
        .get_negotiated(&url)?
        .template(&template)
        .route(Route::http_proxy(HttpProxy::new(&format!(
            "http://127.0.0.1:{port}"
        ))?))
        .send();
    let error = timeout(TEST_TIMEOUT, sent)
        .await?
        .err()
        .ok_or("the proxy refused the tunnel but the request succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    let head = timeout(TEST_TIMEOUT, proxy).await???;
    assert!(head.starts_with(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n").as_bytes()));
    Ok(())
}
