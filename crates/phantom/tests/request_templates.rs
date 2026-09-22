//! Fixture-backed wire tests of browser request templates.
//!
//! Each test sends a templated request to a loopback origin over HTTP/1.1,
//! HTTP/2, or HTTP/3 and compares the ordered fields the origin received with
//! the same request kind in a retained Chrome 153, Edge 153, or Firefox 156
//! capture, and on HTTP/2 also the HEADERS priority. The captures ran
//! headless, so their `User-Agent` names `HeadlessChrome`; the comparison
//! uses the headful `Chrome` product.

#[path = "request_templates/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "request_templates/wire.rs"]
mod wire;

use std::{
    future::poll_fn,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader,
    profile::{
        ClientHintSettings, ClientProfile, Http2Settings, RequestTemplate, chromium, edge, firefox,
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

const CHROME_H1: &str = fixture!("websocket/chrome/153.0.8010.48/windows-11-26200/h1-accept.txt");
const CHROME_H2: &str = fixture!("websocket/chrome/153.0.8010.48/windows-11-26200/accept.txt");
const CHROME_H3: &str = fixture!("http3/chrome/153.0.8010.48/windows-11-26200/client-startup.txt");
const EDGE_H1: &str = fixture!("websocket/edge/153.0.4234.48/windows-11-26200/h1-accept.txt");
const EDGE_H2: &str = fixture!("websocket/edge/153.0.4234.48/windows-11-26200/accept.txt");
const EDGE_H3: &str = fixture!("http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt");
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
        http2: chromium::v153_http2(),
        hints: Some(chromium::v153_windows_client_hints()),
        http1_capture: CHROME_H1,
        http2_capture: CHROME_H2,
        http3_capture: Some(CHROME_H3),
    }
}

fn edge() -> Browser {
    Browser {
        http2: chromium::v153_http2(),
        hints: Some(edge::v153_windows_client_hints()),
        http1_capture: EDGE_H1,
        http2_capture: EDGE_H2,
        http3_capture: Some(EDGE_H3),
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
/// Caller values come from the capture itself for fields a template leaves
/// to the caller: `Referer` always, and `User-Agent` when the template has
/// no captured value.
async fn send(
    browser: &Browser,
    template: RequestTemplate,
    protocol: HttpProtocol,
    expected: &Fields,
) -> TestResult<Observed> {
    let identity = TestIdentity::generate()?;
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
    let mut profile = ClientProfile::new(tls_settings())
        .with_http2(browser.http2.clone())
        .with_http3(client_settings());
    if let Some(hints) = &browser.hints {
        profile = profile.with_client_hints(hints.clone());
    }
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;

    let (client_done, wait_for_client) = oneshot::channel();
    let (url, server) = match protocol {
        HttpProtocol::Http1 => serve_http1(&identity).await?,
        HttpProtocol::Http2 => serve_http2(&identity, wait_for_client).await?,
        HttpProtocol::Http3 => serve_http3(&identity, wait_for_client)?,
        _ => return Err("no test origin for this protocol".into()),
    };
    let response = client
        .get(protocol, &url)?
        .template(template)
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
        let head = String::from_utf8(read_head(&mut stream).await?)?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let mut fields = Vec::new();
        for line in head.trim_end().split("\r\n").skip(1) {
            let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
            if !name.eq_ignore_ascii_case("host") {
                fields.push((name.to_owned(), value.to_owned()));
            }
        }
        Ok(Observed {
            fields,
            priority: None,
        })
    });
    Ok((url, server))
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
        chromium::v153_windows_navigation_template,
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
        chromium::v153_windows_fetch_no_store_template,
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
async fn firefox_fetch_sends_the_captured_report_request() -> TestResult<()> {
    assert_reproduces(
        firefox(),
        firefox::v156_windows_fetch_no_store_template,
        Kind::Fetch,
        TCP,
    )
    .await
}

#[tokio::test]
async fn contradicting_identity_fails_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v153_http2())
        .with_client_hints(chromium::v153_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Nothing listens here; an attempted connection would fail differently.
    let url = "https://127.0.0.1:9/";

    let firefox_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";
    let error = client
        .get(HttpProtocol::Http2, url)?
        .template(chromium::v153_windows_navigation_template())
        .header(RequestHeader::new("user-agent", firefox_agent))
        .send()
        .await
        .err()
        .ok_or("mismatched User-Agent was sent")?;
    assert_eq!(error.kind(), RequestErrorKind::IdentityMismatch);

    // The profile's own Chrome client hints contradict a Firefox template.
    let error = client
        .get(HttpProtocol::Http2, url)?
        .template(firefox::v156_windows_navigation_template())
        .send()
        .await
        .err()
        .ok_or("mismatched client hints were sent")?;
    assert_eq!(error.kind(), RequestErrorKind::IdentityMismatch);
    Ok(())
}

#[tokio::test]
async fn edge_template_without_a_user_agent_fails_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v153_http2())
        .with_client_hints(edge::v153_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Nothing listens here; an attempted connection would fail differently.
    let url = "https://127.0.0.1:9/";
    for template in [
        edge::v153_windows_navigation_template(),
        edge::v153_windows_fetch_no_store_template(),
    ] {
        let error = client
            .get(HttpProtocol::Http2, url)?
            .template(template)
            .header(RequestHeader::new("referer", "https://127.0.0.1:9/"))
            .send()
            .await
            .err()
            .ok_or("Edge brand hints were sent without a User-Agent")?;
        assert_eq!(error.kind(), RequestErrorKind::IdentityMismatch);
    }
    Ok(())
}

#[tokio::test]
async fn fetch_template_with_a_requested_hint_fails_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v153_http2())
        .with_client_hints(chromium::v153_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Nothing listens here; an attempted connection would fail differently.
    let url = "https://127.0.0.1:9/";
    let error = client
        .get(HttpProtocol::Http2, url)?
        .template(chromium::v153_windows_fetch_no_store_template())
        .header(RequestHeader::new("referer", "https://127.0.0.1:9/"))
        .header(RequestHeader::new("sec-ch-ua-arch", "\"x86\""))
        .send()
        .await
        .err()
        .ok_or("a requested hint was sent at an uncaptured fetch position")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    Ok(())
}

#[tokio::test]
async fn template_without_http3_order_rejects_http3_before_any_connection() -> TestResult<()> {
    let profile = ClientProfile::new(tls_settings()).with_http3(client_settings());
    let client = Client::builder(profile).build()?;
    let error = client
        .get(HttpProtocol::Http3, "https://127.0.0.1:9/")?
        .template(firefox::v156_windows_fetch_no_store_template())
        .send()
        .await
        .err()
        .ok_or("template without an H3 list was sent over H3")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    Ok(())
}
