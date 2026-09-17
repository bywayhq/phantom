//! Pull-driven HTTP/2 request-body upload.

use std::{future::poll_fn, pin::Pin, task::Poll};

use ::http2::{Reason, SendStream};
use bytes::Bytes;
use http_body::{Body as _, Frame};

use crate::request::RequestBody;

use super::Http2Error;

const MAX_FLOW_CONTROL_WINDOW: usize = 0x7fff_ffff;

pub(super) async fn send_body(
    stream: &mut SendStream<Bytes>,
    mut body: RequestBody,
) -> Result<(), Http2Error> {
    loop {
        let Some(frame) = next_frame_or_reset(stream, &mut body).await? else {
            return Ok(());
        };
        let Some(frame) = frame else {
            return stream
                .send_data(Bytes::new(), true)
                .map_err(Http2Error::protocol);
        };
        let frame = frame.map_err(Http2Error::RequestBody)?;
        let mut data = frame
            .into_data()
            .map_err(|_| Http2Error::UnsupportedRequestBodyFrame)?;
        let body_ended = body.is_end_stream();

        if data.is_empty() {
            stream
                .send_data(data, body_ended)
                .map_err(Http2Error::protocol)?;
            if body_ended {
                return Ok(());
            }
            continue;
        }

        while !data.is_empty() {
            stream.reserve_capacity(data.len().min(MAX_FLOW_CONTROL_WINDOW));
            let Some(capacity) = next_capacity_or_reset(stream).await? else {
                return Ok(());
            };
            if capacity == 0 {
                return Err(Http2Error::RequestBodyClosed);
            }
            let chunk_len = capacity.min(data.len());
            let end_of_stream = body_ended && chunk_len == data.len();
            stream
                .send_data(data.split_to(chunk_len), end_of_stream)
                .map_err(Http2Error::protocol)?;
            if end_of_stream {
                return Ok(());
            }
        }
    }
}

async fn next_frame_or_reset(
    stream: &mut SendStream<Bytes>,
    body: &mut RequestBody,
) -> Result<Option<Option<Result<Frame<Bytes>, crate::request::RequestBodyError>>>, Http2Error> {
    poll_fn(|context| {
        if let Poll::Ready(reset) = poll_reset(stream, context) {
            return Poll::Ready(reset.map(|()| None));
        }
        Pin::new(&mut *body)
            .poll_frame(context)
            .map(|frame| Ok(Some(frame)))
    })
    .await
}

async fn next_capacity_or_reset(
    stream: &mut SendStream<Bytes>,
) -> Result<Option<usize>, Http2Error> {
    poll_fn(|context| {
        if let Poll::Ready(reset) = poll_reset(stream, context) {
            return Poll::Ready(reset.map(|()| None));
        }
        match stream.poll_capacity(context) {
            Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(Some(capacity))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(Http2Error::protocol(error))),
            Poll::Ready(None) => Poll::Ready(Err(Http2Error::RequestBodyClosed)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

fn poll_reset(
    stream: &mut SendStream<Bytes>,
    context: &mut std::task::Context<'_>,
) -> Poll<Result<(), Http2Error>> {
    match stream.poll_reset(context) {
        Poll::Ready(Ok(reason)) if reason == Reason::NO_ERROR => Poll::Ready(Ok(())),
        Poll::Ready(Ok(reason)) => Poll::Ready(Err(Http2Error::stream_reset(reason))),
        Poll::Ready(Err(error)) => Poll::Ready(Err(Http2Error::protocol(error))),
        Poll::Pending => Poll::Pending,
    }
}
