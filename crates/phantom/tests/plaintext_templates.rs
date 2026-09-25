//! Built-in request templates on plaintext `http://` origins.
//!
//! Browsers treat a loopback origin as potentially trustworthy and a named
//! plaintext origin as not. The expected field lists below are the requests
//! of the proxy route captures of Chrome 154.0.8037.58, Edge 153.0.4234.48,
//! Brave 154.1.96.59, Opera 135.0.5973.92, and Firefox 156.0 on Windows 11
//! build 26200, three agreeing runs each:
//! `fixtures/proxy/<browser>/<version>/windows-11-26200/direct-loopback.txt`
//! for `http://127.0.0.1` and `direct-hostname.txt` for
//! `http://origin.phantom.test`. The captures ran headless, so `User-Agent`
//! is the template's headful value. Their `fetch()` used the default cache
//! mode; the no-store template adds `Pragma` and `Cache-Control` after
//! `Connection` on Chromium and last on Firefox, as its own captures show.
//!
//! The test suite has no resolver override, so the named origin is reached
//! through a loopback HTTP forward proxy, which receives the absolute-form
//! request. The captures show that the field set depends on the origin, not
//! on the route; only Chromium's `Connection` becomes `Proxy-Connection` on
//! that route (`http-proxy-loopback.txt` and `http-proxy-hostname.txt`),
//! which [`forwarded`] applies to the direct lists.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{future::Future, io::Write, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, ContentCoding, ContentDecoding, HttpProtocol, HttpProxy, PreparedRequestTemplate,
    RedirectPolicy, RequestErrorKind, RequestHeader, ResponseInfo, Route,
    profile::{
        ClientHintSettings, ClientProfile, RequestTemplate, brave, chromium, edge, firefox, opera,
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use tls_support::{TestResult, read_head};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";
const OPERA_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 OPR/135.0.0.0";
const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";
const CHROME_BRANDS: &str = r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#;
const EDGE_BRANDS: &str = r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#;
const BRAVE_BRANDS: &str = r#""Chromium";v="154", "Brave";v="154", "Not A(Brand";v="99""#;
const OPERA_BRANDS: &str = r#""Not=A?Brand";v="99", "Opera";v="135", "Chromium";v="151""#;
/// Brave's navigation `Accept`: Chrome's without signed exchanges.
const BRAVE_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8";
/// One of the five `Accept-Language` values Brave draws per session.
const BRAVE_LANGUAGE: &str = "en-US,en;q=0.7";
const CHROMIUM_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const FIREFOX_NAVIGATION_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const LANGUAGE: &str = "en-US,en;q=0.9";
const ALL_CODINGS: &str = "gzip, deflate, br, zstd";
const PLAINTEXT_CODINGS: &str = "gzip, deflate";
const REFERER: &str = "http://page.example/";

type Fields = Vec<(String, String)>;

/// Browsers offer `br` and `zstd` only to a potentially trustworthy origin.
const fn codings(loopback: bool) -> &'static str {
    if loopback {
        ALL_CODINGS
    } else {
        PLAINTEXT_CODINGS
    }
}

fn fields(list: &[(&str, &str)]) -> Fields {
    list.iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// A Chromium-family browser's headers: its `User-Agent`, brand list,
/// navigation `Accept`, `Accept-Language`, and whether it sends `Sec-GPC`.
struct Chromium {
    user_agent: &'static str,
    brands: &'static str,
    navigation_accept: &'static str,
    language: &'static str,
    gpc: bool,
}

impl Chromium {
    fn navigation(&self, loopback: bool) -> Fields {
        let mut list = vec![("Connection", "keep-alive")];
        if loopback {
            list.extend([
                ("sec-ch-ua", self.brands),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Windows\""),
            ]);
        }
        list.extend([
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", self.user_agent),
            ("Accept", self.navigation_accept),
        ]);
        if self.gpc {
            list.push(("Sec-GPC", "1"));
        }
        if loopback {
            list.extend([
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-User", "?1"),
                ("Sec-Fetch-Dest", "document"),
            ]);
        }
        list.extend([
            ("Accept-Encoding", codings(loopback)),
            ("Accept-Language", self.language),
        ]);
        fields(&list)
    }

    fn fetch(&self, loopback: bool) -> Fields {
        let mut list = vec![
            ("Connection", "keep-alive"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-cache"),
        ];
        if loopback {
            list.extend([
                ("sec-ch-ua-platform", "\"Windows\""),
                ("User-Agent", self.user_agent),
                ("sec-ch-ua", self.brands),
                ("sec-ch-ua-mobile", "?0"),
                ("Accept", "*/*"),
            ]);
        } else {
            list.extend([("User-Agent", self.user_agent), ("Accept", "*/*")]);
        }
        if self.gpc {
            list.push(("Sec-GPC", "1"));
        }
        if loopback {
            list.extend([
                ("Sec-Fetch-Site", "same-origin"),
                ("Sec-Fetch-Mode", "cors"),
                ("Sec-Fetch-Dest", "empty"),
            ]);
        }
        list.extend([
            ("Referer", REFERER),
            ("Accept-Encoding", codings(loopback)),
            ("Accept-Language", self.language),
        ]);
        fields(&list)
    }
}

fn firefox_navigation(loopback: bool) -> Fields {
    let mut list = vec![
        ("User-Agent", FIREFOX_UA),
        ("Accept", FIREFOX_NAVIGATION_ACCEPT),
        ("Accept-Language", LANGUAGE),
        ("Accept-Encoding", codings(loopback)),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
    ];
    if loopback {
        list.extend([
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ]);
    }
    list.push(("Priority", "u=0, i"));
    fields(&list)
}

fn firefox_fetch(loopback: bool) -> Fields {
    let mut list = vec![
        ("User-Agent", FIREFOX_UA),
        ("Accept", "*/*"),
        ("Accept-Language", LANGUAGE),
        ("Accept-Encoding", codings(loopback)),
        ("Referer", REFERER),
        ("Connection", "keep-alive"),
    ];
    if loopback {
        list.extend([
            ("Sec-Fetch-Dest", "empty"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Site", "same-origin"),
        ]);
    }
    list.extend([
        ("Priority", "u=4"),
        ("Pragma", "no-cache"),
        ("Cache-Control", "no-cache"),
    ]);
    fields(&list)
}

/// Returns the fields of a direct request as a browser forwards them through
/// an HTTP/1.1 proxy: Chromium sends `Proxy-Connection` where a direct
/// request has `Connection`, and Firefox changes nothing.
fn forwarded(case: &Case, direct: &Fields) -> Fields {
    direct
        .iter()
        .map(|(name, value)| {
            if case.chromium && name == "Connection" {
                ("Proxy-Connection".to_owned(), value.clone())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// One built-in profile, template, caller fields, and the fields a browser
/// sends directly to a loopback and to a named plaintext origin.
struct Case {
    label: &'static str,
    chromium: bool,
    hints: Option<ClientHintSettings>,
    template: RequestTemplate,
    caller: Vec<RequestHeader>,
    loopback: Fields,
    named: Fields,
}

fn cases() -> Vec<Case> {
    let chromium_family = |user_agent, brands| Chromium {
        user_agent,
        brands,
        navigation_accept: CHROMIUM_NAVIGATION_ACCEPT,
        language: LANGUAGE,
        gpc: false,
    };
    let chrome = chromium_family(CHROME_UA, CHROME_BRANDS);
    let edge = chromium_family(EDGE_UA, EDGE_BRANDS);
    let opera = chromium_family(OPERA_UA, OPERA_BRANDS);
    // Brave's `User-Agent` is Chrome's.
    let brave = Chromium {
        user_agent: CHROME_UA,
        brands: BRAVE_BRANDS,
        navigation_accept: BRAVE_NAVIGATION_ACCEPT,
        language: BRAVE_LANGUAGE,
        gpc: true,
    };
    let referer = || RequestHeader::new("referer", REFERER);
    let edge_ua = || RequestHeader::new("user-agent", EDGE_UA);
    let opera_ua = || RequestHeader::new("user-agent", OPERA_UA);
    let brave_caller = || {
        vec![
            RequestHeader::new("user-agent", CHROME_UA),
            RequestHeader::new("accept-language", BRAVE_LANGUAGE),
        ]
    };
    vec![
        Case {
            label: "chrome navigation",
            chromium: true,
            hints: Some(chromium::v154_windows_client_hints()),
            template: chromium::v154_windows_navigation_template(),
            caller: Vec::new(),
            loopback: chrome.navigation(true),
            named: chrome.navigation(false),
        },
        Case {
            label: "chrome fetch",
            chromium: true,
            hints: Some(chromium::v154_windows_client_hints()),
            template: chromium::v154_windows_fetch_no_store_template(),
            caller: vec![referer()],
            loopback: chrome.fetch(true),
            named: chrome.fetch(false),
        },
        Case {
            label: "edge navigation",
            chromium: true,
            hints: Some(edge::v153_windows_client_hints()),
            template: edge::v153_windows_navigation_template(),
            caller: vec![edge_ua()],
            loopback: edge.navigation(true),
            named: edge.navigation(false),
        },
        Case {
            label: "edge fetch",
            chromium: true,
            hints: Some(edge::v153_windows_client_hints()),
            template: edge::v153_windows_fetch_no_store_template(),
            caller: vec![edge_ua(), referer()],
            loopback: edge.fetch(true),
            named: edge.fetch(false),
        },
        Case {
            label: "brave navigation",
            chromium: true,
            hints: Some(brave::v154_windows_client_hints()),
            template: brave::v154_windows_navigation_template(),
            caller: brave_caller(),
            loopback: brave.navigation(true),
            named: brave.navigation(false),
        },
        Case {
            label: "brave fetch",
            chromium: true,
            hints: Some(brave::v154_windows_client_hints()),
            template: brave::v154_windows_fetch_no_store_template(),
            caller: [brave_caller(), vec![referer()]].concat(),
            loopback: brave.fetch(true),
            named: brave.fetch(false),
        },
        Case {
            label: "opera navigation",
            chromium: true,
            hints: Some(opera::v135_windows_client_hints()),
            template: opera::v135_windows_navigation_template(),
            caller: vec![opera_ua()],
            loopback: opera.navigation(true),
            named: opera.navigation(false),
        },
        Case {
            label: "opera fetch",
            chromium: true,
            hints: Some(opera::v135_windows_client_hints()),
            template: opera::v135_windows_fetch_no_store_template(),
            caller: vec![opera_ua(), referer()],
            loopback: opera.fetch(true),
            named: opera.fetch(false),
        },
        Case {
            label: "firefox navigation",
            chromium: false,
            hints: None,
            template: firefox::v156_windows_navigation_template(),
            caller: Vec::new(),
            loopback: firefox_navigation(true),
            named: firefox_navigation(false),
        },
        Case {
            label: "firefox fetch",
            chromium: false,
            hints: None,
            template: firefox::v156_windows_fetch_no_store_template(),
            caller: vec![referer()],
            loopback: firefox_fetch(true),
            named: firefox_fetch(false),
        },
    ]
}

fn client(hints: Option<ClientHintSettings>, route: Option<Route>) -> TestResult<Client> {
    let mut profile = ClientProfile::new(chromium::v154_tls());
    if let Some(hints) = hints {
        profile = profile.with_client_hints(hints);
    }
    let mut builder = Client::builder(profile);
    if let Some(route) = route {
        builder = builder.route(route);
    }
    Ok(builder.build()?)
}

/// Accepts one connection, answers each request head with the matching
/// response, and returns the heads.
async fn serve(listener: TcpListener, responses: Vec<Vec<u8>>) -> TestResult<Vec<String>> {
    let (mut stream, _) = listener.accept().await?;
    let mut heads = Vec::new();
    for response in responses {
        heads.push(String::from_utf8(read_head(&mut stream).await?)?);
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
    Ok(heads)
}

/// Answers each response on its own accepted connection and returns the
/// heads. A redirect to another origin may open a new forwarding connection.
async fn serve_each(listener: TcpListener, responses: Vec<Vec<u8>>) -> TestResult<Vec<String>> {
    let mut heads = Vec::new();
    for response in responses {
        let (mut stream, _) = listener.accept().await?;
        heads.push(String::from_utf8(read_head(&mut stream).await?)?);
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
    Ok(heads)
}

fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// Returns the request line and the fields of a head without `Host`.
fn parse_head(head: &str) -> TestResult<(String, Fields)> {
    let mut lines = head.trim_end().split("\r\n");
    let request_line = lines.next().ok_or("empty head")?.to_owned();
    let mut fields = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(": ").ok_or("field has no `: `")?;
        if !name.eq_ignore_ascii_case("host") {
            fields.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok((request_line, fields))
}

/// Sends `case` to `url` and returns the head the listener received.
async fn send(
    case: &Case,
    url: &str,
    route: Option<Route>,
    listener: TcpListener,
) -> TestResult<String> {
    let server = tokio::spawn(serve(listener, vec![no_content()]));
    let client = client(case.hints.clone(), route)?;
    let response = client
        .get(HttpProtocol::Http1, url)?
        .template(&PreparedRequestTemplate::new(case.template.clone())?)
        .headers(case.caller.clone())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "{}", case.label);
    response.into_body().collect().await?;
    let mut heads = server.await??;
    heads.pop().ok_or_else(|| "no request".into())
}

#[tokio::test]
async fn built_in_templates_send_the_captured_loopback_plaintext_fields() -> TestResult<()> {
    bounded(async {
        for case in cases() {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let url = format!("http://{}/page", listener.local_addr()?);
            let head = send(&case, &url, None, listener).await?;
            let (request_line, fields) = parse_head(&head)?;
            assert_eq!(request_line, "GET /page HTTP/1.1", "{}", case.label);
            assert_eq!(fields, case.loopback, "{}", case.label);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn built_in_templates_send_the_captured_named_plaintext_fields() -> TestResult<()> {
    bounded(async {
        for case in cases() {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
            let head = send(
                &case,
                "http://origin.phantom.test/page",
                Some(Route::http_proxy(proxy)),
                listener,
            )
            .await?;
            let (request_line, fields) = parse_head(&head)?;
            assert_eq!(
                request_line, "GET http://origin.phantom.test/page HTTP/1.1",
                "{}",
                case.label
            );
            assert_eq!(fields, forwarded(&case, &case.named), "{}", case.label);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn built_in_templates_forward_the_captured_loopback_plaintext_fields() -> TestResult<()> {
    bounded(async {
        for case in cases() {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
            let head = send(
                &case,
                "http://127.0.0.1:9/page",
                Some(Route::http_proxy(proxy)),
                listener,
            )
            .await?;
            let (request_line, fields) = parse_head(&head)?;
            assert_eq!(
                request_line, "GET http://127.0.0.1:9/page HTTP/1.1",
                "{}",
                case.label
            );
            assert_eq!(fields, forwarded(&case, &case.loopback), "{}", case.label);
        }
        Ok(())
    })
    .await
}

/// A caller field keeps its value at the template's position on a
/// forwarded request, for either connection field.
#[tokio::test]
async fn caller_connection_fields_override_the_forwarded_template_value() -> TestResult<()> {
    bounded(async {
        for (caller, expected) in [
            (
                RequestHeader::new("proxy-connection", "close"),
                vec![("Proxy-Connection", "close")],
            ),
            (
                RequestHeader::new("connection", "close"),
                vec![("Connection", "close"), ("Proxy-Connection", "keep-alive")],
            ),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
            let case = Case {
                caller: vec![caller],
                ..cases().swap_remove(0)
            };
            let head = send(
                &case,
                "http://origin.phantom.test/page",
                Some(Route::http_proxy(proxy)),
                listener,
            )
            .await?;
            let (_, fields) = parse_head(&head)?;
            let leading: Vec<(&str, &str)> = fields
                .iter()
                .take(expected.len())
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            assert_eq!(leading, expected);
            assert!(
                fields
                    .iter()
                    .skip(expected.len())
                    .all(|(name, _)| !name.eq_ignore_ascii_case("connection")
                        && !name.eq_ignore_ascii_case("proxy-connection"))
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_loopback_plaintext_origin_learns_accept_ch_and_a_named_one_does_not() -> TestResult<()> {
    bounded(async {
        let accept_ch = b"HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec();
        let navigation =
            PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;
        for (url, proxied, learns) in [
            ("http://127.0.0.1/", false, true),
            ("http://origin.phantom.test/", true, false),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let url = if proxied {
                url.to_owned()
            } else {
                format!("http://{address}/")
            };
            let route = proxied
                .then(|| HttpProxy::new(&format!("http://{address}")).map(Route::http_proxy))
                .transpose()?;
            let server = tokio::spawn(serve(listener, vec![accept_ch.clone(), no_content()]));
            let client = client(Some(chromium::v154_windows_client_hints()), route)?;
            for _ in 0..2 {
                client
                    .get(HttpProtocol::Http1, &url)?
                    .template(&navigation)
                    .send()
                    .await?
                    .into_body()
                    .collect()
                    .await?;
            }
            let heads = server.await??;
            let second = heads
                .get(1)
                .ok_or("no second request")?
                .to_ascii_lowercase();
            assert_eq!(second.contains("\r\nsec-ch-ua-arch: "), learns, "{url}");
        }
        Ok(())
    })
    .await
}

fn gzip(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn brotli(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut output = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(data),
        &mut output,
        &brotli::enc::BrotliEncoderParams::default(),
    )?;
    Ok(output)
}

fn coded_response(coding: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// A redirect from a loopback origin to a named one changes the template's
/// `Accept-Encoding`, so the final response is decoded against the codings
/// that hop advertised: `br` is refused there, `gzip` is decoded.
#[tokio::test]
async fn decoding_follows_the_codings_the_final_hop_advertised() -> TestResult<()> {
    bounded(async {
        const BODY: &[u8] = b"plaintext body";
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: http://origin.phantom.test/next\r\n\
Connection: close\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
        let template = PreparedRequestTemplate::new(firefox::v156_windows_navigation_template())?;
        for (coding, body, decodes) in [("br", brotli(BODY)?, false), ("gzip", gzip(BODY)?, true)] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
            let server = tokio::spawn(serve_each(
                listener,
                vec![redirect.clone(), coded_response(coding, &body)],
            ));
            let client = Client::builder(ClientProfile::new(firefox::v156_tls()))
                .route(Route::http_proxy(proxy))
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .build()?;
            let response = client
                .get(HttpProtocol::Http1, "http://127.0.0.1/start")?
                .template(&template)
                .content_decoding(ContentDecoding::advertised(1 << 20))
                .send()
                .await?;
            let decoded = response
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("no response info")?
                .decoded_content_codings()
                .to_vec();
            let collected = response.into_body().collect_with_limit(1 << 20).await;

            let heads = server.await??;
            let (_, first) = parse_head(heads.first().ok_or("no first request")?)?;
            let (_, second) = parse_head(heads.get(1).ok_or("no second request")?)?;
            let encoding = |fields: &Fields| {
                fields
                    .iter()
                    .find(|(name, _)| name == "Accept-Encoding")
                    .map(|(_, value)| value.clone())
            };
            assert_eq!(encoding(&first).as_deref(), Some(ALL_CODINGS));
            assert_eq!(encoding(&second).as_deref(), Some(PLAINTEXT_CODINGS));
            assert!(first.iter().any(|(name, _)| name == "Sec-Fetch-Mode"));
            assert!(
                !second
                    .iter()
                    .any(|(name, _)| name.starts_with("Sec-Fetch-"))
            );

            if decodes {
                assert_eq!(decoded, [ContentCoding::Gzip]);
                assert_eq!(collected?.as_ref(), BODY);
            } else {
                assert!(decoded.is_empty());
                let error = collected.err().ok_or("br body was decoded")?;
                assert_eq!(error.kind(), RequestErrorKind::ContentDecoding);
            }
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
