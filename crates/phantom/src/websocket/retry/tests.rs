use std::{collections::VecDeque, num::NonZeroUsize, time::Duration};

use phantom_net::http1::Http1TlsError;
use tracing::Span;

use super::{WebSocketRetryPolicy, open_with_retries};
use crate::{
    RequestError, TimeoutPhase,
    websocket::{WebSocketError, WebSocketErrorKind},
};

fn refused() -> WebSocketError {
    WebSocketError::request(RequestError::http1_connection_setup(
        Http1TlsError::Connect(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
    ))
}

fn two_retries(delay: Duration) -> WebSocketRetryPolicy {
    WebSocketRetryPolicy::connection_failures(NonZeroUsize::MIN.saturating_add(1), delay)
}

#[test]
fn policy_is_off_by_default() {
    assert_eq!(
        WebSocketRetryPolicy::default(),
        WebSocketRetryPolicy::none()
    );
    assert_eq!(WebSocketRetryPolicy::none().max_connection_failures(), None);
    assert_eq!(WebSocketRetryPolicy::none().delay(), Duration::ZERO);
}

#[tokio::test]
async fn without_a_policy_a_setup_failure_is_returned_after_one_attempt() {
    let mut attempts = 0;
    let result = open_with_retries(WebSocketRetryPolicy::none(), &Span::none(), |_| {
        attempts += 1;
        async { Err::<(), _>(refused()) }
    })
    .await;

    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(WebSocketErrorKind::Connect)
    );
    assert_eq!(attempts, 1);
}

#[tokio::test(start_paused = true)]
async fn setup_failures_are_retried_after_the_delay_until_one_succeeds() {
    let started = tokio::time::Instant::now();
    let mut outcomes = VecDeque::from([Err(refused()), Err(refused()), Ok(7_u8)]);
    let mut numbers = Vec::new();

    let value = open_with_retries(
        two_retries(Duration::from_millis(300)),
        &Span::none(),
        |n| {
            numbers.push(n);
            let outcome = outcomes.pop_front().unwrap_or_else(|| Err(refused()));
            async move { outcome }
        },
    )
    .await;

    assert_eq!(value.ok(), Some(7));
    assert_eq!(numbers, [0, 1, 2]);
    assert_eq!(started.elapsed(), Duration::from_millis(600));
}

#[tokio::test]
async fn an_exhausted_budget_returns_the_last_setup_failure() {
    let mut attempts = 0;
    let result = open_with_retries(two_retries(Duration::ZERO), &Span::none(), |_| {
        attempts += 1;
        async { Err::<(), _>(refused()) }
    })
    .await;

    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(WebSocketErrorKind::Connect)
    );
    assert_eq!(attempts, 3);
}

#[tokio::test]
async fn failures_after_setup_and_timeouts_are_not_retried() {
    let terminal: [fn() -> WebSocketError; 4] = [
        || WebSocketError::invalid_handshake("wrong Sec-WebSocket-Accept"),
        || {
            WebSocketError::request(RequestError::http1_connection_setup(
                Http1TlsError::MissingHttp1Alpn,
            ))
        },
        || {
            WebSocketError::request(RequestError::timeout(
                TimeoutPhase::WebSocketHandshake,
                None,
            ))
        },
        || WebSocketError::request(RequestError::capacity(crate::HttpProtocol::Http2)),
    ];
    for error in terminal {
        let mut attempts = 0;
        let result = open_with_retries(two_retries(Duration::ZERO), &Span::none(), |_| {
            attempts += 1;
            async move { Err::<(), _>(error()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }
}

#[tokio::test]
async fn a_delay_beyond_the_clock_fails_before_the_first_attempt() {
    let mut attempts = 0;
    let result = open_with_retries(two_retries(Duration::MAX), &Span::none(), |_| {
        attempts += 1;
        async { Ok::<_, WebSocketError>(()) }
    })
    .await;

    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(WebSocketErrorKind::InvalidRequest)
    );
    assert_eq!(attempts, 0);
}
