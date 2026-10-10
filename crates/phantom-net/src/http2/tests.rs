use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom_profile::browser::chrome::v154_http2;
use tokio::{io::duplex, time::timeout};

use super::{OriginForm, RequestHeader};
use crate::http2::Http2Body;
use crate::http2::PreparedRequest;
use crate::tracing_test::OutcomeSubscriber;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn bounded_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(cause) => Err(PeerDeadline {
            context: "HTTP/2 peer test exceeded its absolute deadline",
            cause,
        }
        .into()),
    }
}

#[derive(Debug)]
struct PeerDeadline {
    context: &'static str,
    cause: tokio::time::error::Elapsed,
}

impl fmt::Display for PeerDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.cause)
    }
}

impl Error for PeerDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

fn target() -> Result<OriginForm, crate::request::InvalidOriginForm> {
    OriginForm::parse("/resource?item=1")
}

fn headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("accept", "*/*"),
        RequestHeader::new("x-repeat", "alpha"),
        RequestHeader::new("x-middle", "between"),
        RequestHeader::new("x-repeat", "beta"),
        RequestHeader::new("te", "trailers"),
    ]
}

async fn prime_request_trace_callsites() -> TestResult<()> {
    // Parallel no-subscriber tests may register a callsite after a per-test
    // Dispatch is built, so register both request spans before building it.
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let (invalid_client, _invalid_peer) = duplex(128);
    let _ = send_once(invalid_client, {
        let settings = v154_http2();
        let method = http::Method::GET;
        let authority = "user@example.test";
        let target = target()?;
        let headers = vec![];
        let body = None;
        move || PreparedRequest::new(&settings, method, authority, target, headers, body)
    })
    .await;

    let (closed_client, closed_peer) = duplex(128);
    drop(closed_peer);
    let _ = send_once(closed_client, {
        let settings = v154_http2();
        let method = http::Method::GET;
        let authority = "example.test";
        let target = target()?;
        let headers = vec![];
        let body = None;
        move || PreparedRequest::new(&settings, method, authority, target, headers, body)
    })
    .await;
    Ok(())
}

async fn next_nonempty_data(body: &mut Http2Body) -> TestResult<Bytes> {
    loop {
        let frame = body
            .frame()
            .await
            .ok_or("response ended before non-empty DATA")??;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            return Ok(data);
        }
    }
}

async fn reset_observing_server<S>(stream: S) -> TestResult<(::http2::Reason, bool)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"partial"), false)?;

    let reason = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => result?,
        incoming = connection.accept() => {
            return Err(match incoming {
                None => "connection closed without an observable stream reset".into(),
                Some(Ok(_)) => "one-shot client sent an unexpected second request".into(),
                Some(Err(error)) => error.into(),
            });
        }
    };
    drop(send);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok((reason, true))
}

mod adversarial_data_frames;
mod adversarial_header_limits;
mod adversarial_informational;
mod adversarial_malformed;
mod adversarial_wire;
mod connection;
mod continuation_matrix;
mod driver_lifecycle;
mod driver_shutdown;
mod expect_continue;
mod extended_connect;
mod hpack_replay;
mod hpack_transitions;
mod idle_close;
mod idle_ping;
mod ping_peer;
mod preface_ping;
mod request_body_cancellation;
mod request_body_early_response;
mod request_body_error;
mod request_body_flow;
mod request_body_validation;
mod request_trailers;
mod request_validation;
mod request_wire;
mod reset_churn;
mod response_body;
mod shutdown_controls;
mod stream_limit;

// Prepare before raw setup so invalid requests cannot touch the stream or body.
async fn send_once<T, F>(
    stream: T,
    prepare: F,
) -> Result<http::Response<super::Http2Body>, super::Http2Error>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Result<PreparedRequest, super::Http2Error>,
{
    let prepared = prepare()?;
    let connection = super::Http2Connection::connect_with_builder(stream, prepared.client).await?;
    connection
        .send_prepared_request(prepared.request, prepared.body, prepared.trailers)
        .await
}
