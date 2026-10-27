//! Response projection and exclusive body-read ownership.

use super::{MAX_METADATA, UploadPermit};
use crate::{
    client::Header,
    error::Failure,
    policy::{RedirectHistory, coding_name},
    upload::Upload,
};
use http_body::Body;
use http_body_util::BodyExt;
use phantom::{Bytes, ResponseBody};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

pub(super) enum Stream {
    Body { body: ResponseBody, pending: Bytes },
    Events(Box<phantom::SseStream>),
}
pub(super) struct BodyOwner {
    pub(super) client: u64,
    pub(super) stream: Mutex<Option<Stream>>,
    pub(super) closed: AtomicBool,
    pub(super) busy: AtomicBool,
    pub(super) changed: Notify,
    pub(super) _upload: Option<UploadPermit>,
    pub(super) stream_upload: Option<std::sync::Arc<Upload>>,
}
impl BodyOwner {
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

pub(super) struct ReadLease {
    pub(super) owner: std::sync::Arc<BodyOwner>,
    pub(super) stream: Option<Stream>,
    pub(super) restored: bool,
}
impl Drop for ReadLease {
    fn drop(&mut self) {
        if !self.restored {
            self.owner.close();
        }
        self.owner.busy.store(false, Ordering::SeqCst);
    }
}
impl ReadLease {
    pub(super) async fn read(mut self, maximum: usize) -> Result<ReadResult, Failure> {
        self.stream = self
            .owner
            .stream
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take();
        let Some(stream) = self.stream.as_mut() else {
            return Ok(ReadResult::End(phantom::ResponseTrailers::Unavailable));
        };
        let changed = self.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.owner.closed.load(Ordering::SeqCst) {
            return Err(Failure::new("body_closed"));
        }
        let Stream::Body { body, pending } = stream else {
            return Err(Failure::new("body_type"));
        };
        let next = async {
            while pending.is_empty() {
                let Some(frame) = body.frame().await else {
                    return Ok::<Option<Bytes>, Failure>(None);
                };
                if let Ok(data) = frame
                    .map_err(|error| {
                        crate::multipart::request_failure(&error)
                            .unwrap_or_else(|| Failure::from(error))
                    })?
                    .into_data()
                {
                    *pending = data;
                }
            }
            Ok(Some(pending.split_to(maximum.min(pending.len()))))
        };
        let bytes = tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("body_closed")),
            result = next => result.map_err(|error| match &self.owner.stream_upload {
                Some(upload) => upload.failure(error),
                None => error,
            })?,
        };
        if bytes.is_some() {
            let mut slot = self
                .owner
                .stream
                .lock()
                .map_err(|_| Failure::new("internal"))?;
            if !self.owner.closed.load(Ordering::SeqCst) {
                *slot = self.stream.take();
                self.restored = true;
            }
        }
        match bytes {
            Some(bytes) => Ok(ReadResult::Data(bytes)),
            None => {
                let Some(Stream::Body { body, .. }) = self.stream.take() else {
                    return Err(Failure::new("internal"));
                };
                Ok(ReadResult::End(body.into_trailers()))
            }
        }
    }
}

pub(super) struct Head {
    pub(super) status: u16,
    pub(super) protocol: &'static str,
    pub(super) effective_url: String,
    pub(super) redirects_followed: usize,
    pub(super) connection_setup_retries: usize,
    pub(super) decoded_content_codings: Vec<&'static str>,
    pub(super) redirect_history: Option<RedirectHistory>,
    pub(super) headers: Vec<Header>,
    pub(super) body: std::sync::Arc<BodyOwner>,
}

pub(super) fn response_head(
    response: http::Response<ResponseBody>,
    client: u64,
    upload: UploadPermit,
    stream_upload: Option<std::sync::Arc<Upload>>,
    events: Option<super::sse::Limits>,
) -> Result<Head, Failure> {
    let info = response
        .extensions()
        .get::<phantom::ResponseInfo>()
        .ok_or_else(|| Failure::new("response_info_unavailable"))?;
    let effective_url = info.effective_uri().to_string();
    let redirects_followed = info.redirects_followed();
    let connection_setup_retries = info.retries_performed();
    let decoded_content_codings = info
        .decoded_content_codings()
        .iter()
        .copied()
        .map(coding_name)
        .collect();
    let redirect_history = response
        .extensions()
        .get::<phantom::RedirectHistory>()
        .map(|history| RedirectHistory::capture(history, MAX_METADATA))
        .transpose()?;
    let fields = response
        .extensions()
        .get::<phantom::OrderedResponseHeaders>()
        .ok_or_else(|| Failure::new("ordered_headers_unavailable"))?;
    let size = fields.iter().try_fold(0usize, |size, field| {
        size.checked_add(field.name().len())?
            .checked_add(field.value().len())
    });
    if fields.iter().count() > 256 || size.is_none_or(|size| size > 32 * 1024) {
        return Err(Failure::new("response_headers_limit"));
    }
    let headers = fields
        .iter()
        .map(|field| Header {
            name: field.name().to_owned(),
            value: field.value().to_vec(),
            sensitive: field.is_sensitive(),
        })
        .collect();
    let protocol = match response.version() {
        http::Version::HTTP_11 => "h1",
        http::Version::HTTP_2 => "h2",
        http::Version::HTTP_3 => "h3",
        _ => "unknown",
    };
    let status = response.status().as_u16();
    if response.body().is_end_stream()
        && let Some(upload) = &stream_upload
    {
        upload.close();
    }
    let stream = match events {
        Some(limits) => Stream::Events(Box::new(
            phantom::SseStream::from_response_with_limits(response, limits.core()?)
                .map_err(|error| super::sse::failure(&error))?
                .into_body(),
        )),
        None => Stream::Body {
            body: response.into_body(),
            pending: Bytes::new(),
        },
    };
    let owner = std::sync::Arc::new(BodyOwner {
        client,
        stream: Mutex::new(Some(stream)),
        closed: AtomicBool::new(false),
        busy: AtomicBool::new(false),
        changed: Notify::new(),
        _upload: Some(upload),
        stream_upload,
    });
    Ok(Head {
        status,
        protocol,
        effective_url,
        redirects_followed,
        connection_setup_retries,
        decoded_content_codings,
        redirect_history,
        headers,
        body: owner,
    })
}
pub(super) enum ReadResult {
    Data(Bytes),
    End(phantom::ResponseTrailers),
}
