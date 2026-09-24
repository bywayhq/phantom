//! Differential tests against retained browser EventSource reconnect captures.
//!
//! Each test replays a scenario from `fixtures/sse/` against Phantom over
//! plaintext HTTP/1.1 with the same server stimuli, then compares the reconnect
//! requests, delays, and termination with what Chrome 154 and Firefox 156 did.
//! Delays are measured with a paused clock, so Phantom's values are exact and
//! browser medians may exceed them by at most `TIMER_SLACK`.

#![cfg(feature = "sse")]

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf, time::Duration};

use phantom::{
    Client, HttpProtocol, RequestHeader, SseErrorKind, SseHeader, SseRequestBuilder,
    profile::ClientProfile,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    time::{Instant, timeout},
};

use tls_support::{TestResult, read_head, tls_settings};

/// Largest browser timer overshoot accepted above Phantom's exact delay.
const TIMER_SLACK: Duration = Duration::from_millis(30);
/// Paused-clock window in which no request may follow a terminal response.
const OBSERVATION: Duration = Duration::from_secs(10);
const FAST_RETRY: &str = "retry: 200\n";
/// `PROBE_COOKIE` in scripts/capture/sse_reconnect.py.
const PROBE_COOKIE: &str = "phantom_probe=1";

#[derive(Clone, Copy, Debug)]
enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    const ALL: [Self; 2] = [Self::Chrome, Self::Firefox];

    fn directory(self) -> &'static str {
        match self {
            Self::Chrome => "chrome/154.0.8037.58/windows-11-26200",
            Self::Firefox => "firefox/156.0/windows-11-26200",
        }
    }

    /// Phantom options reproducing the captured scheduling of this browser.
    fn configure(self, builder: SseRequestBuilder) -> SseRequestBuilder {
        match self {
            Self::Chrome => builder,
            Self::Firefox => builder
                .initial_retry(Duration::from_secs(5))
                .min_retry(Duration::from_millis(500)),
        }
    }
}

/// The server's complete reply to one EventSource request.
#[derive(Clone, Copy)]
enum Reply {
    /// `200 text/event-stream` with this body, then connection close.
    Stream(&'static str),
    /// [`Self::Stream`] that also sets `PROBE_COOKIE` with `Path=/`.
    CookieStream(&'static str),
    Status(u16),
    PlainText,
}

impl Reply {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Stream(body) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\nConnection: close\r\n\r\n{body}"
            )
            .into_bytes(),
            Self::CookieStream(body) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\nSet-Cookie: {PROBE_COOKIE}; Path=/\r\n\
                 Connection: close\r\n\r\n{body}"
            )
            .into_bytes(),
            Self::Status(204) => b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec(),
            Self::Status(status) => format!(
                "HTTP/1.1 {status} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            Self::PlainText => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        }
    }
}

// Server stimuli mirror `CATALOG` in scripts/capture/sse_reconnect.py.
fn scenario(name: &str) -> Vec<Reply> {
    use Reply::{CookieStream, PlainText, Status, Stream};
    let fast = |body: &'static str| Stream(leak(format!("{FAST_RETRY}{body}")));
    match name {
        "id-then-close" => vec![fast("id: phantom-1\ndata: a\n\n"), Status(204)],
        "retry-750" => retry_scenario("retry: 750\ndata: a\n\n"),
        "retry-100" => retry_scenario("retry: 100\ndata: a\n\n"),
        "retry-0" => retry_scenario("retry: 0\ndata: a\n\n"),
        "default-delay" => vec![Stream("data: a\n\n"), Stream("data: b\n\n"), Status(204)],
        "retry-persists-across-reconnect" => retry_scenario("retry: 600\ndata: a\n\n"),
        "invalid-retry-ignored" => vec![
            Stream("retry: 600\ndata: a\n\n"),
            Stream("retry: 12x\ndata: b\n\n"),
            Stream("data: c\n\n"),
            Status(204),
        ],
        "empty-id-resets" => vec![
            fast("id: phantom-1\ndata: a\n\n"),
            Stream("id\ndata: b\n\n"),
            Status(204),
        ],
        "non-ascii-id" => vec![fast("id: é-☃\ndata: a\n\n"), Status(204)],
        "reconnect-204" => vec![fast("data: a\n\n"), Status(204)],
        "reconnect-404" => vec![fast("data: a\n\n"), Status(404)],
        "reconnect-500" => vec![fast("data: a\n\n"), Status(500)],
        "reconnect-wrong-content-type" => vec![fast("data: a\n\n"), PlainText],
        "set-cookie-then-close" => vec![
            CookieStream(leak(format!("{FAST_RETRY}data: a\n\n"))),
            Status(204),
        ],
        _ => panic!("scenario {name} has no Phantom replay"),
    }
}

fn retry_scenario(first: &'static str) -> Vec<Reply> {
    vec![
        Reply::Stream(first),
        Reply::Stream("data: b\n\n"),
        Reply::Stream("data: c\n\n"),
        Reply::Status(204),
    ]
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn last_event_id_spelling_value_and_empty_omission_match_both_browsers() -> TestResult<()> {
    for browser in Browser::ALL {
        for (name, expected) in [
            ("id-then-close", vec![None, Some("phantom-1".as_bytes())]),
            ("non-ascii-id", vec![None, Some("é-☃".as_bytes())]),
            (
                "empty-id-resets",
                vec![None, Some("phantom-1".as_bytes()), None],
            ),
        ] {
            let fixture = Fixture::load(browser, name)?;
            for run in 0..fixture.runs()? {
                let captured = fixture.sse_requests(run)?;
                let values = captured
                    .iter()
                    .map(|request| request.header(b"last-event-id"))
                    .collect::<Vec<_>>();
                assert_eq!(values, expected, "{browser:?} {name} run {run}");
                for line in captured.iter().flat_map(|request| &request.lines) {
                    if line.to_ascii_lowercase().starts_with(b"last-event-id:") {
                        assert!(line.starts_with(b"Last-Event-ID: "), "{browser:?} spelling");
                    }
                }
            }

            let phantom = replay(name, |builder| browser.configure(builder)).await?;
            let values = phantom
                .requests
                .iter()
                .map(|request| request.header(b"last-event-id"))
                .collect::<Vec<_>>();
            assert_eq!(values, expected, "Phantom {name} ({browser:?} options)");
            for request in &phantom.requests {
                if let Some(value) = request.header(b"last-event-id") {
                    let mut line = b"Last-Event-ID: ".to_vec();
                    line.extend_from_slice(value);
                    assert!(request.lines.contains(&line), "Phantom spelling differs");
                }
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn last_event_id_placeholder_reproduces_each_browser_field_order() -> TestResult<()> {
    for (browser, expected_index) in [(Browser::Chrome, 9), (Browser::Firefox, 5)] {
        let fixture = Fixture::load(browser, "id-then-close")?;
        let reconnect = fixture
            .sse_requests(0)?
            .into_iter()
            .nth(1)
            .ok_or("fixture lacks the reconnect request")?;
        let index = reconnect
            .position(b"last-event-id")
            .ok_or("reconnect lacks Last-Event-ID")?;
        assert_eq!(index, expected_index, "{browser:?} Last-Event-ID position");
        for run in 1..fixture.runs()? {
            let names = fixture.sse_requests(run)?[1].names();
            assert_eq!(
                names,
                reconnect.names(),
                "{browser:?} run {run} field order"
            );
        }

        let template = reconnect
            .lines
            .iter()
            .filter(|line| !line.to_ascii_lowercase().starts_with(b"host:"))
            .map(|line| {
                let (name, value) = split_field(line)?;
                Ok(if name.eq_ignore_ascii_case("last-event-id") {
                    SseHeader::last_event_id(name)
                } else {
                    SseHeader::field(RequestHeader::new(name, value))
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        let phantom = replay("id-then-close", |builder| {
            browser.configure(builder).headers(template)
        })
        .await?;

        let [initial, resumed] = phantom.requests.as_slice() else {
            return Err("Phantom did not make exactly two requests".into());
        };
        assert_eq!(
            resumed.names(),
            reconnect.names(),
            "{browser:?} reconnect order"
        );
        assert_eq!(
            without_host(&resumed.lines),
            without_host(&reconnect.lines),
            "{browser:?} reconnect fields"
        );
        let captured = fixture.sse_requests(0)?;
        assert_eq!(
            without_host(&initial.lines),
            without_host(&captured[0].lines)
        );
        assert_eq!(initial.header(b"last-event-id"), None);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retry_delays_match_each_browser_with_its_options() -> TestResult<()> {
    for browser in Browser::ALL {
        for name in [
            "retry-750",
            "retry-100",
            "retry-0",
            "default-delay",
            "retry-persists-across-reconnect",
            "invalid-retry-ignored",
            "empty-id-resets",
        ] {
            let fixture = Fixture::load(browser, name)?;
            let phantom = replay(name, |builder| browser.configure(builder)).await?;
            let delays = phantom
                .requests
                .iter()
                .skip(1)
                .map(|request| request.after_stimulus.ok_or("reconnect delay missing"))
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(delays.len(), scenario(name).len() - 1);
            for (index, delay) in delays.iter().enumerate() {
                let median = fixture.median_after_stimulus(index + 1)?;
                assert!(
                    median >= delay.saturating_sub(Duration::from_millis(1))
                        && median <= *delay + TIMER_SLACK,
                    "{browser:?} {name} attempt {}: browser median {median:?}, Phantom {delay:?}",
                    index + 1
                );
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn terminal_reconnect_responses_end_both_browsers_and_phantom() -> TestResult<()> {
    for (name, expected) in [
        ("reconnect-204", None),
        ("reconnect-404", Some(SseErrorKind::UnexpectedStatus)),
        ("reconnect-500", Some(SseErrorKind::UnexpectedStatus)),
        (
            "reconnect-wrong-content-type",
            Some(SseErrorKind::InvalidContentType),
        ),
    ] {
        for browser in Browser::ALL {
            let fixture = Fixture::load(browser, name)?;
            for run in 0..fixture.runs()? {
                let requests = fixture.requests(run)?;
                assert!(
                    requests.iter().all(|request| !request.extra),
                    "{browser:?} {name} run {run} requested after the terminal response"
                );
                assert_eq!(fixture.sse_requests(run)?.len(), 2);
            }

            let phantom = replay(name, |builder| browser.configure(builder)).await?;
            assert_eq!(phantom.requests.len(), 2, "Phantom {name}");
            assert_eq!(phantom.terminal, expected, "Phantom {name}");
            assert!(!phantom.extra_connection, "Phantom {name} reconnected");
        }
    }
    Ok(())
}

/// Replays the stream response's `Set-Cookie` with each browser's
/// `CookiePlacement` preset: the jar's field lands last of Chrome's 16
/// reconnect fields, and between `Referer` and `Sec-Fetch-Dest` among
/// Firefox's 14.
#[cfg(feature = "cookies")]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cookie_placement_presets_reproduce_each_browser_reconnect() -> TestResult<()> {
    use phantom::profile::{chromium, firefox};

    for (browser, placement, expected_index, field_count) in [
        (Browser::Chrome, chromium::v154_cookie_placement(), 15, 16),
        (Browser::Firefox, firefox::v156_cookie_placement(), 7, 14),
    ] {
        let fixture = Fixture::load(browser, "set-cookie-then-close")?;
        let reconnect = fixture
            .sse_requests(0)?
            .into_iter()
            .nth(1)
            .ok_or("fixture lacks the reconnect request")?;
        assert_eq!(
            reconnect.lines.len(),
            field_count,
            "{browser:?} field count"
        );
        assert_eq!(
            reconnect.position(b"cookie"),
            Some(expected_index),
            "{browser:?} Cookie position"
        );
        assert_eq!(reconnect.header(b"cookie"), Some(PROBE_COOKIE.as_bytes()));
        for run in 1..fixture.runs()? {
            assert_eq!(
                fixture.sse_requests(run)?[1].names(),
                reconnect.names(),
                "{browser:?} run {run} field order"
            );
        }

        let template = reconnect
            .lines
            .iter()
            .filter(|line| !field_named(line, b"host") && !field_named(line, b"cookie"))
            .map(|line| {
                let (name, value) = split_field(line)?;
                Ok(SseHeader::field(RequestHeader::new(name, value)))
            })
            .collect::<TestResult<Vec<_>>>()?;
        let profile = ClientProfile::new(tls_settings()).with_cookie_placement(placement);
        let client = Client::builder(profile).cookies().build()?;
        let phantom = replay_with(client, "set-cookie-then-close", |builder| {
            browser.configure(builder).headers(template)
        })
        .await?;

        let [initial, resumed] = phantom.requests.as_slice() else {
            return Err("Phantom did not make exactly two requests".into());
        };
        assert_eq!(initial.header(b"cookie"), None);
        assert_eq!(
            without_host(&resumed.lines),
            without_host(&reconnect.lines),
            "{browser:?} reconnect fields"
        );
    }
    Ok(())
}

/// One recorded Phantom run of a scenario.
struct PhantomRun {
    requests: Vec<Request>,
    /// `None` when the source closed after a 204, else the terminal error.
    terminal: Option<SseErrorKind>,
    extra_connection: bool,
}

async fn replay(
    name: &str,
    configure: impl FnOnce(SseRequestBuilder) -> SseRequestBuilder,
) -> TestResult<PhantomRun> {
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    replay_with(client, name, configure).await
}

async fn replay_with(
    client: Client,
    name: &str,
    configure: impl FnOnce(SseRequestBuilder) -> SseRequestBuilder,
) -> TestResult<PhantomRun> {
    let replies = scenario(name);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        let mut last_stimulus: Option<Instant> = None;
        for reply in replies {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let received = Instant::now();
            let mut request = Request::parse(&head)?;
            request.after_stimulus = last_stimulus.map(|at| received.duration_since(at));
            requests.push(request);
            stream.write_all(&reply.bytes()).await?;
            stream.shutdown().await?;
            drop(stream);
            last_stimulus = Some(Instant::now());
        }
        let extra = timeout(OBSERVATION, listener.accept()).await.is_ok();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((requests, extra))
    });

    let builder = client
        .event_source(HttpProtocol::Http1, &format!("http://{address}/events"))?
        .max_reconnects(8);
    let mut source = configure(builder).connect().await?.into_body();
    let terminal = loop {
        match source.next_event().await {
            Ok(Some(_)) => {}
            Ok(None) => break None,
            Err(error) => break Some(error.kind()),
        }
    };
    let (requests, extra_connection) = server.await??;
    Ok(PhantomRun {
        requests,
        terminal,
        extra_connection,
    })
}

/// One request head, from a fixture or observed from Phantom.
#[derive(Debug)]
struct Request {
    kind: String,
    extra: bool,
    lines: Vec<Vec<u8>>,
    after_stimulus: Option<Duration>,
}

impl Request {
    fn parse(head: &[u8]) -> TestResult<Self> {
        let head = head.strip_suffix(b"\r\n\r\n").ok_or("unterminated head")?;
        let lines = head
            .split(|byte| *byte == b'\n')
            .skip(1)
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec())
            .collect();
        Ok(Self {
            kind: "sse".to_owned(),
            extra: false,
            lines,
            after_stimulus: None,
        })
    }

    fn names(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|line| split_field(line).ok().map(|(name, _)| name.to_owned()))
            .collect()
    }

    fn position(&self, name: &[u8]) -> Option<usize> {
        self.lines.iter().position(|line| field_named(line, name))
    }

    fn header(&self, name: &[u8]) -> Option<&[u8]> {
        self.lines
            .iter()
            .find(|line| field_named(line, name))
            .map(|line| line[name.len() + 1..].trim_ascii())
    }
}

fn field_named(line: &[u8], name: &[u8]) -> bool {
    line.len() > name.len()
        && line[name.len()] == b':'
        && line[..name.len()].eq_ignore_ascii_case(name)
}

fn split_field(line: &[u8]) -> TestResult<(&str, &[u8])> {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("header line lacks a colon")?;
    Ok((
        std::str::from_utf8(&line[..colon])?,
        line[colon + 1..].trim_ascii(),
    ))
}

fn without_host(lines: &[Vec<u8>]) -> Vec<&[u8]> {
    lines
        .iter()
        .filter(|line| !field_named(line, b"host"))
        .map(Vec::as_slice)
        .collect()
}

/// Reader for `format=phantom-sse-reconnect-v1` fixtures.
struct Fixture {
    fields: HashMap<String, String>,
}

impl Fixture {
    fn load(browser: Browser, scenario: &str) -> TestResult<Self> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sse")
            .join(browser.directory())
            .join(format!("{scenario}.txt"));
        let text = std::fs::read_to_string(&path)?;
        let fields = text
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .ok_or_else(|| format!("{}: malformed line {line}", path.display()))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let fixture = Self { fields };
        if fixture.get("format")? != "phantom-sse-reconnect-v1"
            || fixture.get("scenario")? != scenario
        {
            return Err(format!("{} is not the {scenario} fixture", path.display()).into());
        }
        Ok(fixture)
    }

    fn get(&self, key: &str) -> TestResult<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("fixture lacks {key}").into())
    }

    fn runs(&self) -> TestResult<usize> {
        Ok(self.get("repeat_count")?.parse()?)
    }

    fn requests(&self, run: usize) -> TestResult<Vec<Request>> {
        let count: usize = self.get(&format!("run_{run}_request_count"))?.parse()?;
        (0..count)
            .map(|index| {
                let prefix = format!("run_{run}_request_{index}");
                let attributes = self
                    .get(&prefix)?
                    .split(',')
                    .filter_map(|pair| pair.split_once(':'))
                    .collect::<HashMap<_, _>>();
                let headers: usize = self.get(&format!("{prefix}_header_count"))?.parse()?;
                let lines = (0..headers)
                    .map(|header| decode_hex(self.get(&format!("{prefix}_header_{header}"))?))
                    .collect::<TestResult<Vec<_>>>()?;
                Ok(Request {
                    kind: (*attributes.get("kind").ok_or("request lacks kind")?).to_owned(),
                    extra: attributes.get("extra") == Some(&"true"),
                    lines,
                    after_stimulus: None,
                })
            })
            .collect()
    }

    /// Returns the scenario's EventSource requests in attempt order.
    fn sse_requests(&self, run: usize) -> TestResult<Vec<Request>> {
        Ok(self
            .requests(run)?
            .into_iter()
            .filter(|request| request.kind == "sse" && !request.extra)
            .collect())
    }

    fn median_after_stimulus(&self, attempt: usize) -> TestResult<Duration> {
        let summary = self.get(&format!("attempt_{attempt}_after_stimulus_ms"))?;
        let median = summary
            .split(',')
            .find_map(|pair| pair.strip_prefix("median:"))
            .ok_or("attempt summary lacks a median")?;
        Ok(Duration::from_secs_f64(median.parse::<f64>()? / 1000.0))
    }
}

fn decode_hex(text: &str) -> TestResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}
