//! Field order of requests that browsers send to an HTTP proxy, compared
//! with the retained proxy route captures.
//!
//! Each test reads run 0 of
//! `fixtures/proxy/<browser>/<version>/windows-11-26200/<scenario>.txt`,
//! whose three runs agree on every field order, and compares the field
//! names Phantom sends with a built-in profile in the captured order. Values
//! that depend on the capture machine, such as ports and the headless
//! `User-Agent`, are not compared. The captured `fetch()` used the default
//! cache mode, so the no-store template's `Pragma` and `Cache-Control` are
//! removed from Phantom's request before the comparison.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{collections::BTreeMap, future::Future, net::Ipv4Addr, time::Duration};

use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, RequestHeader, Route,
    profile::{
        ClientHintSettings, ClientProfile, ProxyConnectTemplate, RequestTemplate, chromium, edge,
        firefox,
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use tls_support::{TestResult, read_head};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";
const CREDENTIALS: &str = "Basic dXNlcjpzZWNyZXQ=";

macro_rules! proxy_fixture {
    ($browser:literal, $scenario:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/proxy/",
            $browser,
            "/windows-11-26200/",
            $scenario,
            ".txt"
        ))
    };
}

/// One run-0 request of a `phantom-proxy-route-v1` capture.
struct CapturedRequest {
    kind: String,
    status: String,
    request_line: String,
    names: Vec<String>,
}

/// Returns the run-0 HTTP/1.1 requests of a capture that the capture tool
/// kept in full, in arrival order.
fn captured_requests(fixture: &str) -> TestResult<Vec<CapturedRequest>> {
    let values: BTreeMap<&str, &str> = fixture
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let value = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}"))
    };
    if value("format")? != "phantom-proxy-route-v1" {
        return Err("unexpected capture format".into());
    }
    let count: usize = value("run_0_request_count")?.parse()?;
    let mut requests = Vec::new();
    for index in 0..count {
        let prefix = format!("run_0_request_{index}");
        let Some(line) = values.get(format!("{prefix}_line_hex").as_str()) else {
            continue;
        };
        let record = value(&prefix)?;
        let attribute = |name: &str| {
            record
                .split(',')
                .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("capture record omitted {name}"))
        };
        let mut names = Vec::new();
        for field in 0..value(&format!("{prefix}_header_count"))?.parse::<usize>()? {
            let line = decode_hex(value(&format!("{prefix}_header_{field}"))?)?;
            let (name, _) = line.split_once(": ").ok_or("H1 field has no `: `")?;
            names.push(name.to_owned());
        }
        requests.push(CapturedRequest {
            kind: attribute("kind")?,
            status: attribute("status")?,
            request_line: decode_hex(line)?,
            names,
        });
    }
    Ok(requests)
}

/// Returns the names of the first captured request of `kind` with `status`.
fn captured<'a>(
    requests: &'a [CapturedRequest],
    kind: &str,
    status: &str,
) -> TestResult<&'a [String]> {
    requests
        .iter()
        .find(|request| request.kind == kind && request.status == status)
        .map(|request| request.names.as_slice())
        .ok_or_else(|| format!("capture has no {kind} request with status {status}").into())
}

fn decode_hex(value: &str) -> TestResult<String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal value".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}

/// One browser's profile pieces and captures.
struct Browser {
    label: &'static str,
    tls: phantom::profile::TlsSettings,
    hints: Option<ClientHintSettings>,
    navigation: RequestTemplate,
    fetch: RequestTemplate,
    caller: Vec<RequestHeader>,
    connect: ProxyConnectTemplate,
    /// The `User-Agent` the navigation sends.
    user_agent: &'static str,
    /// `http-proxy-auth-hostname` and `http-proxy-auth-loopback`.
    authenticated: [&'static str; 2],
    /// `http-proxy-hostname` and `http-proxy-loopback`.
    anonymous: [&'static str; 2],
}

fn browsers() -> Vec<Browser> {
    vec![
        Browser {
            label: "chrome",
            tls: chromium::v154_tls(),
            hints: Some(chromium::v154_windows_client_hints()),
            navigation: chromium::v154_windows_navigation_template(),
            fetch: chromium::v154_windows_fetch_no_store_template(),
            caller: Vec::new(),
            connect: chromium::v154_proxy_connect(),
            user_agent: CHROME_UA,
            authenticated: [
                proxy_fixture!("chrome/154.0.8037.58", "http-proxy-auth-hostname"),
                proxy_fixture!("chrome/154.0.8037.58", "http-proxy-auth-loopback"),
            ],
            anonymous: [
                proxy_fixture!("chrome/154.0.8037.58", "http-proxy-hostname"),
                proxy_fixture!("chrome/154.0.8037.58", "http-proxy-loopback"),
            ],
        },
        Browser {
            label: "edge",
            tls: edge::v153_tls(),
            hints: Some(edge::v153_windows_client_hints()),
            navigation: edge::v153_windows_navigation_template(),
            fetch: edge::v153_windows_fetch_no_store_template(),
            caller: vec![RequestHeader::new("User-Agent", EDGE_UA)],
            connect: chromium::v154_proxy_connect(),
            user_agent: EDGE_UA,
            authenticated: [
                proxy_fixture!("edge/153.0.4234.48", "http-proxy-auth-hostname"),
                proxy_fixture!("edge/153.0.4234.48", "http-proxy-auth-loopback"),
            ],
            anonymous: [
                proxy_fixture!("edge/153.0.4234.48", "http-proxy-hostname"),
                proxy_fixture!("edge/153.0.4234.48", "http-proxy-loopback"),
            ],
        },
        Browser {
            label: "firefox",
            tls: firefox::v156_tls(),
            hints: None,
            navigation: firefox::v156_windows_navigation_template(),
            fetch: firefox::v156_windows_fetch_no_store_template(),
            caller: Vec::new(),
            connect: firefox::v156_proxy_connect(),
            user_agent: FIREFOX_UA,
            authenticated: [
                proxy_fixture!("firefox/156.0", "http-proxy-auth-hostname"),
                proxy_fixture!("firefox/156.0", "http-proxy-auth-loopback"),
            ],
            anonymous: [
                proxy_fixture!("firefox/156.0", "http-proxy-hostname"),
                proxy_fixture!("firefox/156.0", "http-proxy-loopback"),
            ],
        },
    ]
}

fn profile_client(browser: &Browser, route: Route) -> TestResult<Client> {
    let mut profile =
        ClientProfile::new(browser.tls.clone()).with_proxy_connect(browser.connect.clone());
    if let Some(hints) = browser.hints.clone() {
        profile = profile.with_client_hints(hints);
    }
    Ok(Client::builder(profile).route(route).build()?)
}

/// Returns the field names of a request head, `Host` included.
fn head_names(head: &str) -> TestResult<(String, Vec<String>)> {
    let mut lines = head.trim_end().split("\r\n");
    let request_line = lines.next().ok_or("empty head")?.to_owned();
    let names = lines
        .map(|line| {
            line.split_once(": ")
                .map(|(name, _)| name.to_owned())
                .ok_or("field has no `: `")
        })
        .collect::<Result<_, _>>()?;
    Ok((request_line, names))
}

fn without_no_store(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| !matches!(name.as_str(), "Pragma" | "Cache-Control"))
        .cloned()
        .collect()
}

/// Answers the first forwarded request with a Basic `407` on one proxy
/// connection, then the replay and one more request with `204` on a second.
async fn challenge_then_accept(listener: TcpListener) -> TestResult<Vec<String>> {
    let mut heads = Vec::new();
    let (mut first, _) = listener.accept().await?;
    heads.push(String::from_utf8(read_head(&mut first).await?)?);
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"phantom-capture\"\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
    let (mut second, _) = listener.accept().await?;
    for _ in 0..2 {
        heads.push(String::from_utf8(read_head(&mut second).await?)?);
        second
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
    }
    Ok(heads)
}

/// A navigation challenged by the proxy, its replay, and a `fetch()` that
/// sends the remembered credentials first, forwarded through an HTTP/1.1
/// proxy to a named and to a loopback origin.
#[tokio::test]
async fn forwarded_requests_place_proxy_credentials_as_captured() -> TestResult<()> {
    bounded(async {
        for browser in browsers() {
            for (fixture, origin) in browser
                .authenticated
                .iter()
                .zip(["origin.phantom.test", "127.0.0.1"])
            {
                let label = format!("{} {origin}", browser.label);
                let requests = captured_requests(fixture)?;
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?
                    .with_basic_auth("user", "secret")?;
                let server = tokio::spawn(challenge_then_accept(listener));
                let client = profile_client(&browser, Route::http_proxy(proxy))?;
                for (path, template, referer) in [
                    ("/page", &browser.navigation, None),
                    ("/done", &browser.fetch, Some("http://page.example/")),
                ] {
                    let mut caller = browser.caller.clone();
                    caller.extend(referer.map(|value| RequestHeader::new("Referer", value)));
                    let response = client
                        .get(HttpProtocol::Http1, &format!("http://{origin}:9{path}"))?
                        .template(&PreparedRequestTemplate::new(template.clone())?)
                        .headers(caller)
                        .send()
                        .await?;
                    assert_eq!(response.status(), 204, "{label} {path}");
                    response.into_body().collect().await?;
                }
                let heads = server.await??;
                let [anonymous, replay, remembered] = heads.as_slice() else {
                    return Err(format!("{label}: expected three requests").into());
                };

                for (head, expected, what) in [
                    (anonymous, captured(&requests, "page", "407")?, "challenged"),
                    (replay, captured(&requests, "page", "200")?, "replay"),
                ] {
                    let (request_line, names) = head_names(head)?;
                    assert!(request_line.starts_with("GET http://"), "{label}");
                    assert_eq!(names, expected, "{label} {what}");
                }
                let (_, names) = head_names(remembered)?;
                assert_eq!(
                    without_no_store(&names),
                    captured(&requests, "done", "204")?,
                    "{label} remembered"
                );
                for head in [replay, remembered] {
                    assert!(
                        head.contains(&format!("\r\nProxy-Authorization: {CREDENTIALS}\r\n")),
                        "{label}"
                    );
                }
                assert!(!anonymous.contains("Proxy-Authorization"), "{label}");
                assert!(
                    requests
                        .iter()
                        .any(|request| request.request_line.starts_with("GET http://")),
                    "{label}: the capture forwards in absolute form"
                );
            }
        }
        Ok(())
    })
    .await
}

/// Reads one CONNECT head from each accepted proxy connection, answering
/// the first `challenges` with a Basic `407` and the rest with `200` before
/// closing, so the origin handshake inside the tunnel fails.
async fn record_connects(
    listener: TcpListener,
    challenges: usize,
    count: usize,
) -> TestResult<Vec<String>> {
    let mut heads = Vec::new();
    for index in 0..count {
        let (mut stream, _) = listener.accept().await?;
        heads.push(String::from_utf8(read_head(&mut stream).await?)?);
        let response: &[u8] = if index < challenges {
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"phantom-capture\"\r\nContent-Length: 0\r\n\r\n"
        } else {
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        };
        stream.write_all(response).await?;
    }
    Ok(heads)
}

/// Returns the `User-Agent` value of a head.
fn user_agent(head: &str) -> Option<&str> {
    head.split("\r\n")
        .find_map(|line| line.strip_prefix("User-Agent: "))
}

/// Sends a navigation to an HTTPS origin, whose failure after the tunnel
/// opens does not matter here.
async fn open_tunnel(client: &Client, browser: &Browser, caller: Vec<RequestHeader>) {
    let Ok(builder) = client.get(HttpProtocol::Http1, "https://origin.phantom.test/page") else {
        return;
    };
    let Ok(template) = PreparedRequestTemplate::new(browser.navigation.clone()) else {
        return;
    };
    let _ = builder.template(&template).headers(caller).send().await;
}

/// The profile's CONNECT fields for an HTTPS request through an HTTP/1.1
/// proxy, anonymous, on the replay after a `407`, and with remembered
/// credentials, compared with the captured CONNECT of each browser. The
/// captures tunnel `ws://`; an HTTPS tunnel uses the same request.
#[tokio::test]
async fn connect_requests_send_the_captured_fields() -> TestResult<()> {
    bounded(async {
        for browser in browsers() {
            for (anonymous, authenticated) in browser.anonymous.iter().zip(browser.authenticated) {
                let label = browser.label;
                let expected_anonymous =
                    captured(&captured_requests(anonymous)?, "connect", "200")?.to_vec();
                let expected_authenticated =
                    captured(&captured_requests(authenticated)?, "connect", "200")?.to_vec();

                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
                let server = tokio::spawn(record_connects(listener, 0, 1));
                let client = profile_client(&browser, Route::http_proxy(proxy))?;
                open_tunnel(&client, &browser, browser.caller.clone()).await;
                let heads = server.await??;
                let (request_line, names) = head_names(&heads[0])?;
                assert_eq!(request_line, "CONNECT origin.phantom.test:443 HTTP/1.1");
                assert_eq!(names, expected_anonymous, "{label} anonymous");
                assert_eq!(user_agent(&heads[0]), Some(browser.user_agent), "{label}");

                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?
                    .with_basic_auth("user", "secret")?;
                let server = tokio::spawn(record_connects(listener, 1, 3));
                let client = profile_client(&browser, Route::http_proxy(proxy))?;
                for _ in 0..2 {
                    open_tunnel(&client, &browser, browser.caller.clone()).await;
                }
                let heads = server.await??;
                let (_, challenged) = head_names(&heads[0])?;
                assert_eq!(challenged, expected_anonymous, "{label} challenged");
                for (head, what) in [(&heads[1], "replay"), (&heads[2], "remembered")] {
                    let (_, names) = head_names(head)?;
                    assert_eq!(names, expected_authenticated, "{label} {what}");
                    assert!(
                        head.contains(&format!("\r\nProxy-Authorization: {CREDENTIALS}\r\n")),
                        "{label} {what}"
                    );
                }
            }
        }
        Ok(())
    })
    .await
}

/// CONNECT fields set on the route replace the profile's, and a caller's
/// `User-Agent` replaces the template's in the CONNECT too.
#[tokio::test]
async fn route_connect_fields_win_over_the_profile() -> TestResult<()> {
    bounded(async {
        let browser = browsers().swap_remove(0);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?
            .header(RequestHeader::new("X-Route", "1"));
        let server = tokio::spawn(record_connects(listener, 0, 1));
        let client = profile_client(&browser, Route::http_proxy(proxy))?;
        open_tunnel(&client, &browser, Vec::new()).await;
        let heads = server.await??;
        assert_eq!(head_names(&heads[0])?.1, ["Host", "X-Route"]);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
        let server = tokio::spawn(record_connects(listener, 0, 1));
        let client = profile_client(&browser, Route::http_proxy(proxy))?;
        open_tunnel(
            &client,
            &browser,
            vec![RequestHeader::new("user-agent", "caller")],
        )
        .await;
        let heads = server.await??;
        assert_eq!(user_agent(&heads[0]), Some("caller"));
        Ok(())
    })
    .await
}

/// Without a template slot the generated field follows every other field,
/// the caller's and the cookie jar's included.
#[tokio::test]
async fn forwarded_credentials_without_a_template_follow_every_field() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?
            .with_basic_auth("user", "secret")?;
        let server = tokio::spawn(challenge_then_accept(listener));
        let client = Client::builder(ClientProfile::new(chromium::v154_tls()))
            .route(Route::http_proxy(proxy))
            .build()?;
        for path in ["/page", "/done"] {
            client
                .get(
                    HttpProtocol::Http1,
                    &format!("http://origin.phantom.test{path}"),
                )?
                .header(RequestHeader::new("X-First", "1"))
                .header(RequestHeader::new("X-Second", "2"))
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }
        let heads = server.await??;
        for head in &heads[1..] {
            let (_, names) = head_names(head)?;
            assert_eq!(
                names,
                ["Host", "X-First", "X-Second", "Proxy-Authorization"]
            );
        }
        Ok(())
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "test timed out")?
}
