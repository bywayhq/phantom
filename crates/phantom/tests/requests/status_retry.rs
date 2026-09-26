//! Opt-in retries after caller-listed retryable response statuses.

use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;

use std::{
    collections::VecDeque,
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, ClientBuilder, HttpProtocol, RedirectPolicy, RequestTimeouts, ResponseInfo,
    RetryPolicy, StatusRetry, profile::ClientProfile,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::Instant,
};
use tracing::instrument::WithSubscriber;

use tls_support::{
    H1_ALPN, TestIdentity, accept_tls_stream, client_builder, is_peer_gone, read_head, tls_settings,
};
use tracing_support::OutcomeSubscriber;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// Request heads in arrival order, across every accepted connection.
type Received = Arc<Mutex<Vec<String>>>;

/// Serves scripted HTTP/1.1 responses in order, one per request, on any
/// number of connections. Plaintext when `acceptor` is `None`.
struct ScriptedServer {
    address: SocketAddr,
    received: Received,
    task: JoinHandle<()>,
}

impl ScriptedServer {
    async fn start(responses: &[&str]) -> TestResult<Self> {
        Self::start_with(responses, None).await
    }

    async fn start_with(responses: &[&str], acceptor: Option<SslAcceptor>) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let script = Arc::new(Mutex::new(
            responses
                .iter()
                .map(|response| response.as_bytes().to_vec())
                .collect::<VecDeque<_>>(),
        ));
        let received = Received::default();
        let connection_received = Arc::clone(&received);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let script = Arc::clone(&script);
                let received = Arc::clone(&connection_received);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(mut stream) = accept_tls_stream(tcp, acceptor).await {
                                serve_connection(&mut stream, &script, &received).await;
                            }
                        }
                        None => {
                            let mut stream = tcp;
                            serve_connection(&mut stream, &script, &received).await;
                        }
                    }
                });
            }
        });
        Ok(Self {
            address,
            received,
            task,
        })
    }

    fn url(&self, scheme: &str, path: &str) -> String {
        format!("{scheme}://{}{path}", self.address)
    }

    fn received(&self) -> Vec<String> {
        match self.received.lock() {
            Ok(received) => received.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_connection<S>(
    stream: &mut S,
    script: &Mutex<VecDeque<Vec<u8>>>,
    received: &Mutex<Vec<String>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Ok(head) = read_request(stream).await else {
            return;
        };
        if let Ok(mut received) = received.lock() {
            received.push(head);
        }
        let response = script.lock().ok().and_then(|mut script| script.pop_front());
        let Some(response) = response else {
            return;
        };
        // The client may retire a connection whose body it dropped unread.
        if let Err(error) = stream.write_all(&response).await {
            assert!(
                is_peer_gone(&error),
                "unexpected server write error: {error}"
            );
            return;
        }
        if stream.flush().await.is_err() {
            return;
        }
    }
}

/// Reads one request head and discards its `Content-Length` body.
async fn read_request<S>(stream: &mut S) -> std::io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let head = String::from_utf8_lossy(&read_head(stream).await?).into_owned();
    let length = head
        .to_ascii_lowercase()
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length: ")?.trim().parse().ok())
        .unwrap_or(0_usize);
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await?;
    Ok(head)
}

fn unavailable_with(fields: &str) -> String {
    format!("HTTP/1.1 503 Service Unavailable\r\n{fields}Content-Length: 0\r\n\r\n")
}

fn status_retry(maximum: usize, delay: Duration) -> TestResult<StatusRetry> {
    Ok(StatusRetry::new(
        &[StatusCode::SERVICE_UNAVAILABLE],
        NonZeroUsize::new(maximum).ok_or("maximum must be nonzero")?,
        delay,
    )?)
}

fn plain_builder() -> ClientBuilder {
    Client::builder(ClientProfile::new(tls_settings()))
}

fn retrying_client(status_retry: StatusRetry) -> TestResult<Client> {
    Ok(plain_builder()
        .retry_policy(RetryPolicy::none().with_status_retry(status_retry))
        .build()?)
}

fn request_lines(received: &[String]) -> Vec<&str> {
    received
        .iter()
        .map(|head| head.split("\r\n").next().unwrap_or_default())
        .collect()
}

#[tokio::test]
async fn status_retry_is_disabled_by_default() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
    let client = plain_builder().build()?;

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(request_lines(&server.received()), ["GET / HTTP/1.1"]);
    Ok(())
}

#[tokio::test]
async fn configured_503_is_retried_for_get_and_returns_final_response() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
    let client = retrying_client(status_retry(2, Duration::ZERO)?)?;
    let subscriber = OutcomeSubscriber::default();

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/resource"))?
        .send()
        .with_subscriber(subscriber.dispatch())
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted metadata")?;
    assert_eq!(info.retries_performed(), 0);
    assert_eq!(info.protocol(), HttpProtocol::Http1);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    assert_eq!(
        request_lines(&server.received()),
        ["GET /resource HTTP/1.1", "GET /resource HTTP/1.1"]
    );
    assert_eq!(subscriber.status_retries_for("client.request"), [1]);
    assert!(
        subscriber
            .retries_performed_for("client.request")
            .is_empty()
    );
    assert!(subscriber.retry_reasons_for("client.request").is_empty());
    Ok(())
}

#[tokio::test]
async fn status_retry_repeats_idempotent_owned_body_requests() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
    let client = retrying_client(status_retry(1, Duration::ZERO)?)?;

    let response = client
        .request(
            HttpProtocol::Http1,
            Method::PUT,
            &server.url("http", "/item"),
        )?
        .body(Bytes::from_static(b"payload"))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        request_lines(&server.received()),
        ["PUT /item HTTP/1.1", "PUT /item HTTP/1.1"]
    );
    Ok(())
}

#[tokio::test]
async fn status_retry_skips_non_idempotent_methods() -> TestResult {
    for method in [Method::POST, Method::PATCH] {
        let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
        let client = retrying_client(status_retry(2, Duration::ZERO)?)?;

        let response = client
            .request(
                HttpProtocol::Http1,
                method.clone(),
                &server.url("http", "/submit"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{method}"
        );
        assert_eq!(server.received().len(), 1, "{method} was retried");
    }
    Ok(())
}

#[tokio::test]
async fn status_retry_with_streaming_body_returns_original_response() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
    let client = retrying_client(status_retry(2, Duration::ZERO)?)?;

    let response = client
        .request(
            HttpProtocol::Http1,
            Method::PUT,
            &server.url("http", "/upload"),
        )?
        .streaming_body(Full::new(Bytes::from_static(b"payload")))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(request_lines(&server.received()), ["PUT /upload HTTP/1.1"]);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retry_after_delta_seconds_is_honoured_within_cap() -> TestResult {
    let intermediate = unavailable_with("Retry-After: 30\r\n");
    let server = ScriptedServer::start(&[&intermediate, OK]).await?;
    let client = retrying_client(
        status_retry(1, Duration::from_millis(1))?.honor_retry_after(Duration::from_secs(60)),
    )?;
    let started = Instant::now();

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .await?;

    let waited = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(waited >= Duration::from_secs(30), "waited {waited:?}");
    assert!(waited < Duration::from_secs(31), "waited {waited:?}");
    assert_eq!(server.received().len(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retry_after_http_date_is_honoured_within_cap() -> TestResult {
    let retry_at = SystemTime::now() + Duration::from_secs(30);
    let intermediate = unavailable_with(&format!("Retry-After: {}\r\n", imf_fixdate(retry_at)?));
    let server = ScriptedServer::start(&[&intermediate, OK]).await?;
    let client = retrying_client(
        status_retry(1, Duration::from_millis(1))?.honor_retry_after(Duration::from_secs(60)),
    )?;
    let started = Instant::now();

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .await?;

    // IMF-fixdate truncates to whole seconds, and the wall clock keeps moving.
    let waited = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(waited >= Duration::from_secs(28), "waited {waited:?}");
    assert!(waited <= Duration::from_secs(30), "waited {waited:?}");
    assert_eq!(server.received().len(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retry_after_beyond_cap_returns_response_without_waiting() -> TestResult {
    let intermediate = unavailable_with("Retry-After: 120\r\n");
    let server = ScriptedServer::start(&[&intermediate, OK]).await?;
    let client = retrying_client(
        status_retry(2, Duration::ZERO)?.honor_retry_after(Duration::from_secs(10)),
    )?;
    let subscriber = OutcomeSubscriber::default();
    let started = Instant::now();

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .with_subscriber(subscriber.dispatch())
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "120");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.received().len(), 1);
    assert!(subscriber.status_retries_for("client.request").is_empty());
    Ok(())
}

#[tokio::test]
async fn status_retry_delay_observes_total_deadline() -> TestResult {
    let retry_after = unavailable_with(
        "Retry-After: 30
",
    );
    let cases = [
        (UNAVAILABLE, status_retry(1, Duration::from_secs(30))?),
        (
            retry_after.as_str(),
            status_retry(1, Duration::ZERO)?.honor_retry_after(Duration::from_secs(60)),
        ),
    ];
    for (intermediate, policy) in cases {
        let server = ScriptedServer::start(&[intermediate, OK]).await?;
        let client = retrying_client(policy)?;
        let subscriber = OutcomeSubscriber::default();
        let started = std::time::Instant::now();

        // The delay cannot finish inside the total deadline, so the usable
        // response is returned at once instead of becoming a timeout.
        let response = client
            .get(HttpProtocol::Http1, &server.url("http", "/"))?
            .timeouts(RequestTimeouts::new().total(Duration::from_secs(10)))
            .send()
            .with_subscriber(subscriber.dispatch())
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(server.received().len(), 1, "a retry reached the server");
        assert!(subscriber.status_retries_for("client.request").is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn status_retry_delay_within_total_deadline_still_retries() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, OK]).await?;
    let client = retrying_client(status_retry(1, Duration::from_millis(10))?)?;

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .timeouts(RequestTimeouts::new().total(Duration::from_secs(10)))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.received().len(), 2);
    Ok(())
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn status_retry_learns_cookies_from_intermediate_responses() -> TestResult {
    let intermediate = unavailable_with("Set-Cookie: attempt=first; Path=/\r\n");
    let server = ScriptedServer::start(&[&intermediate, OK]).await?;
    let client = plain_builder()
        .cookies()
        .retry_policy(RetryPolicy::none().with_status_retry(status_retry(1, Duration::ZERO)?))
        .build()?;

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let received = server.received();
    assert_eq!(received.len(), 2);
    assert!(!received[0].contains("\r\nCookie:"));
    assert!(
        received[1].contains("\r\nCookie: attempt=first\r\n"),
        "{}",
        received[1]
    );
    Ok(())
}

#[tokio::test]
async fn status_retry_exhaustion_returns_last_response() -> TestResult {
    let responses = ["one", "two", "three"].map(|attempt| {
        format!("HTTP/1.1 503 Service Unavailable\r\nX-Attempt: {attempt}\r\nContent-Length: 5\r\n\r\nbusy!")
    });
    let server = ScriptedServer::start(&[&responses[0], &responses[1], &responses[2], OK]).await?;
    let client = retrying_client(status_retry(2, Duration::ZERO)?)?;
    let subscriber = OutcomeSubscriber::default();

    let response = client
        .get(HttpProtocol::Http1, &server.url("http", "/"))?
        .send()
        .with_subscriber(subscriber.dispatch())
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["x-attempt"], "three");
    assert_eq!(response.into_body().collect().await?.to_bytes(), "busy!");
    assert_eq!(server.received().len(), 3);
    assert_eq!(subscriber.status_retries_for("client.request"), [1, 2]);
    Ok(())
}

#[tokio::test]
async fn status_retry_budget_is_shared_across_redirect_hops() -> TestResult {
    let identity = TestIdentity::generate()?;
    let redirect = "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
    let server = ScriptedServer::start_with(
        &[UNAVAILABLE, redirect, UNAVAILABLE, OK],
        Some(identity.acceptor(H1_ALPN)?),
    )
    .await?;
    let client = client_builder(&identity, false)
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .retry_policy(RetryPolicy::none().with_status_retry(status_retry(1, Duration::ZERO)?))
        .build()?;

    let response = client
        .get(HttpProtocol::Http1, &server.url("https", "/"))?
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted metadata")?;
    assert_eq!(info.redirects_followed(), 1);
    assert_eq!(info.effective_uri().path(), "/next");
    assert_eq!(
        request_lines(&server.received()),
        ["GET / HTTP/1.1", "GET / HTTP/1.1", "GET /next HTTP/1.1"]
    );
    Ok(())
}

#[tokio::test]
async fn negotiated_status_retry_repeats_on_the_selected_protocol() -> TestResult {
    let identity = TestIdentity::generate()?;
    let server =
        ScriptedServer::start_with(&[UNAVAILABLE, OK], Some(identity.acceptor(H1_ALPN)?)).await?;
    let client = client_builder(&identity, true)
        .retry_policy(RetryPolicy::none().with_status_retry(status_retry(1, Duration::ZERO)?))
        .build()?;

    let response = client
        .get_negotiated(&server.url("https", "/negotiated"))?
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted metadata")?;
    assert_eq!(info.protocol(), HttpProtocol::Http1);
    assert_eq!(
        request_lines(&server.received()),
        ["GET /negotiated HTTP/1.1", "GET /negotiated HTTP/1.1"]
    );
    Ok(())
}

#[test]
fn status_retry_rejects_421_in_configuration() {
    let result = StatusRetry::new(
        &[
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::MISDIRECTED_REQUEST,
        ],
        NonZeroUsize::MIN,
        Duration::ZERO,
    );

    let error = result.err();
    assert_eq!(
        error.and_then(|error| error.status()),
        Some(StatusCode::MISDIRECTED_REQUEST)
    );
    assert!(
        error
            .map(|error| error.to_string())
            .is_some_and(|message| message.contains("421"))
    );
}

/// Formats `time` as an RFC 9110 IMF-fixdate.
fn imf_fixdate(time: SystemTime) -> TestResult<String> {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = i64::try_from(time.duration_since(UNIX_EPOCH)?.as_secs())?;
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    // Civil-from-days in the proleptic Gregorian calendar.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[usize::try_from((days + 4).rem_euclid(7))?],
        MONTHS[usize::try_from(month - 1)?],
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60,
    ))
}
