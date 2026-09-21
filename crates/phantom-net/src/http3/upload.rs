//! Request content upload for ordinary HTTP/3 requests.

use std::{
    future::{Future, pending, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use h3::error::{Code, StreamError};
use http_body_util::BodyExt as _;

use super::{Http3Error, Http3ErrorKind, RequestSendStream, request::PreparedTrailers};
use crate::request::RequestBody;

const REQUEST_BODY_CHUNK_BYTES: usize = 64 * 1024;

pub(super) enum UploadError {
    Body(Http3Error),
    Stream(StreamError),
}

/// Send side of one ordinary request stream.
pub(super) enum RequestSend {
    /// The request has no content, or the stream was finished before handoff.
    Stream(Box<RequestSendStream>),
    /// Request content is still being written.
    Upload(Upload),
    /// The upload finished or was reset.
    Done,
}

impl RequestSend {
    pub(super) fn stream(send: RequestSendStream) -> Self {
        Self::Stream(Box::new(send))
    }

    pub(super) fn start_upload(
        &mut self,
        body: Option<RequestBody>,
        trailers: Option<PreparedTrailers>,
    ) {
        if let Self::Stream(send) = std::mem::replace(self, Self::Done) {
            *self = Self::Upload(Upload::start(*send, body, trailers));
        }
    }

    /// Resolves when an in-flight upload ends; pending otherwise.
    ///
    /// Dropping the returned future leaves the upload in place.
    pub(super) async fn uploaded(&mut self) -> Result<(), UploadError> {
        let Self::Upload(upload) = self else {
            return pending().await;
        };
        let result = poll_fn(|context| upload.poll(context)).await;
        *self = Self::Done;
        result
    }

    pub(super) fn reset(&mut self, code: Code) {
        match std::mem::replace(self, Self::Done) {
            Self::Stream(mut send) => {
                send.stop_stream(code);
                *self = Self::Stream(send);
            }
            Self::Upload(upload) => upload.abort(code),
            Self::Done => {}
        }
    }
}

/// An in-flight request upload that owns its send stream.
///
/// Dropping an unfinished upload resets the stream. Quinn finishes a dropped
/// send stream implicitly, which would present a truncated body as complete.
pub(super) struct Upload {
    future: Pin<Box<dyn Future<Output = Result<(), UploadError>> + Send>>,
    reset_code: Arc<AtomicU64>,
}

impl Upload {
    fn start(
        send: RequestSendStream,
        body: Option<RequestBody>,
        trailers: Option<PreparedTrailers>,
    ) -> Self {
        let reset_code = Arc::new(AtomicU64::new(Code::H3_REQUEST_CANCELLED.value()));
        let mut guard = ResetOnDrop {
            send,
            armed: true,
            reset_code: Arc::clone(&reset_code),
        };
        let future = Box::pin(async move {
            let result = send_body(&mut guard.send, body, trailers).await;
            if result.is_ok() {
                guard.disarm();
            }
            result
        });
        Self { future, reset_code }
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), UploadError>> {
        self.future.as_mut().poll(context)
    }

    fn abort(self, code: Code) {
        self.reset_code.store(code.value(), Ordering::Release);
    }
}

struct ResetOnDrop {
    send: RequestSendStream,
    armed: bool,
    reset_code: Arc<AtomicU64>,
}

impl ResetOnDrop {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let code = Code::from(self.reset_code.load(Ordering::Acquire));
            self.send.stop_stream(code);
        }
    }
}

async fn send_body(
    send: &mut RequestSendStream,
    body: Option<RequestBody>,
    trailers: Option<PreparedTrailers>,
) -> Result<(), UploadError> {
    if let Some(mut body) = body {
        while let Some(frame) = body.frame().await {
            let frame = frame
                .map_err(Http3Error::request_body)
                .map_err(UploadError::Body)?;
            let mut data = match frame.into_data() {
                Ok(data) => data,
                Err(frame) => {
                    frame.into_trailers().map_err(|_| {
                        UploadError::Body(Http3Error::without_source(
                            Http3ErrorKind::Request,
                            "HTTP/3 request body produced an unsupported frame",
                        ))
                    })?;
                    let ordered = body.take_ordered_trailers().ok_or_else(|| {
                        UploadError::Body(Http3Error::without_source(
                            Http3ErrorKind::Request,
                            "HTTP/3 request body omitted its ordered trailer values",
                        ))
                    })?;
                    let trailers = PreparedTrailers::new(ordered)
                        .map_err(UploadError::Body)?
                        .ok_or_else(|| {
                            UploadError::Body(Http3Error::without_source(
                                Http3ErrorKind::Request,
                                "HTTP/3 request body produced an empty trailer block",
                            ))
                        })?;
                    let (fields, ordered) = trailers.into_parts();
                    send.send_ordered_trailers(fields, ordered)
                        .await
                        .map_err(UploadError::Stream)?;
                    return send.finish().await.map_err(UploadError::Stream);
                }
            };
            if data.is_empty() {
                send.send_data(data).await.map_err(UploadError::Stream)?;
            } else {
                while !data.is_empty() {
                    let chunk_len = data.len().min(REQUEST_BODY_CHUNK_BYTES);
                    send.send_data(data.split_to(chunk_len))
                        .await
                        .map_err(UploadError::Stream)?;
                }
            }
        }
    }
    if let Some(trailers) = trailers {
        let (fields, ordered) = trailers.into_parts();
        send.send_ordered_trailers(fields, ordered)
            .await
            .map_err(UploadError::Stream)?;
    }
    send.finish().await.map_err(UploadError::Stream)
}
