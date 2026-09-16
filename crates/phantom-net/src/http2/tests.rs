use std::{
    error::Error,
    future::{Future, poll_fn},
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{DuplexStream, duplex},
    time::timeout,
};

use super::{OriginForm, RequestHeader};
use crate::http2::{Http2Body, send_get};
use crate::tracing_test::OutcomeSubscriber;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn bounded_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/2 peer test exceeded its absolute deadline".into()),
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
    let _ = send_get(
        invalid_client,
        &v152_macos_http2(),
        "user@example.test",
        target()?,
        vec![],
    )
    .await;

    let (closed_client, closed_peer) = duplex(128);
    drop(closed_peer);
    let _ = send_get(
        closed_client,
        &v152_macos_http2(),
        "example.test",
        target()?,
        vec![],
    )
    .await;
    Ok(())
}

async fn next_nonempty_data(body: &mut Http2Body) -> TestResult<Bytes> {
    loop {
        let frame = body
            .frame()
            .await
            .ok_or("response ended before non-empty DATA")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

async fn reset_observing_server(stream: DuplexStream) -> TestResult<(::http2::Reason, bool)> {
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
            if incoming.is_none() {
                return Err("connection closed without an observable stream reset".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    };
    drop(send);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok((reason, true))
}

mod connection;
mod driver_lifecycle;
mod driver_shutdown;
mod request_validation;
mod request_wire;
mod response_body;
