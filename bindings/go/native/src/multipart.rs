//! One request-owned multipart encoder, with demand for only its current reader.

use std::{
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use http_body::{Body, Frame};
use phantom::{
    Bytes, MultipartStreamError, PreparedBodyError, PreparedBodyErrorKind, StreamingMultipartBody,
    StreamingMultipartPart,
};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::{
    error::Failure,
    upload::{Upload, UploadBody},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Span {
    offset: usize,
    length: usize,
}
impl Span {
    fn bytes<'a>(&self, input: &'a [u8]) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(self.length)
            .ok_or_else(|| Failure::new("invalid_multipart"))?;
        input
            .get(self.offset..end)
            .ok_or_else(|| Failure::new("invalid_multipart"))
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Data {
    Reader {},
    Text { data: Span },
    Bytes { data: Span },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    name: String,
    source: Data,
    filename: Option<String>,
    content_type: Option<String>,
}

#[derive(Default)]
struct Demand {
    active: Option<usize>,
    pending: Option<usize>,
}
struct Readers {
    sources: Vec<Option<Arc<Upload>>>,
    demand: Mutex<Demand>,
    changed: Notify,
    owner: Mutex<Weak<Upload>>,
}

pub(super) struct Multipart {
    body: Mutex<Option<StreamingMultipartBody>>,
    readers: Arc<Readers>,
}
impl Multipart {
    pub(super) fn new(
        client: u64,
        boundary: &str,
        parts: Vec<Part>,
        input: &[u8],
        maximum: usize,
    ) -> Result<Self, Failure> {
        if parts.len() > 1024 {
            return Err(Failure::new("multipart_too_many_parts"));
        }
        // Validate all spans and core metadata/framing before copying any
        // buffered contents or allocating reader channels.
        let mut metadata = Vec::with_capacity(parts.len());
        for part in &parts {
            let field = match &part.source {
                Data::Text { data } => {
                    std::str::from_utf8(data.bytes(input)?)
                        .map_err(|_| Failure::new("invalid_multipart"))?;
                    StreamingMultipartPart::text(&part.name, "", maximum)
                }
                Data::Bytes { data } => {
                    data.bytes(input)?;
                    StreamingMultipartPart::bytes(&part.name, Bytes::new())
                }
                Data::Reader {} => StreamingMultipartPart::bytes(&part.name, Bytes::new()),
            }
            .map_err(failure)?;
            metadata.push(with_metadata(part, field)?);
        }
        StreamingMultipartBody::new(boundary, metadata, maximum).map_err(failure)?;
        let sources = parts
            .iter()
            .map(|part| matches!(part.source, Data::Reader {}).then(|| Upload::new(client, None)))
            .collect();
        let readers = Arc::new(Readers {
            sources,
            demand: Mutex::new(Demand::default()),
            changed: Notify::new(),
            owner: Mutex::new(Weak::new()),
        });
        let mut fields = Vec::with_capacity(parts.len());
        for (index, part) in parts.iter().enumerate() {
            let field = match &part.source {
                Data::Reader {} => {
                    let source = readers.sources[index]
                        .as_ref()
                        .ok_or_else(|| Failure::new("internal"))?;
                    StreamingMultipartPart::stream(
                        &part.name,
                        Reader {
                            readers: Arc::clone(&readers),
                            index,
                            body: source.body()?,
                            started: false,
                        },
                    )
                }
                Data::Text { data } => StreamingMultipartPart::text(
                    &part.name,
                    std::str::from_utf8(data.bytes(input)?)
                        .map_err(|_| Failure::new("invalid_multipart"))?,
                    maximum,
                ),
                Data::Bytes { data } => StreamingMultipartPart::bytes(
                    &part.name,
                    Bytes::copy_from_slice(data.bytes(input)?),
                ),
            }
            .map_err(failure)?;
            fields.push(with_metadata(part, field)?);
        }
        let body = StreamingMultipartBody::new(boundary, fields, maximum).map_err(failure)?;
        Ok(Self {
            body: Mutex::new(Some(body)),
            readers,
        })
    }

    pub(super) fn take_body(&self, owner: &Arc<Upload>) -> Result<StreamingMultipartBody, Failure> {
        *self
            .readers
            .owner
            .lock()
            .map_err(|_| Failure::new("internal"))? = Arc::downgrade(owner);
        let body = self
            .body
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take()
            .ok_or_else(|| Failure::new("upload_used"))?;
        Ok(body)
    }
    pub(super) fn close(&self) {
        for source in self.readers.sources.iter().flatten() {
            source.close();
        }
    }
    pub(super) fn active(&self) -> Result<Arc<Upload>, Failure> {
        let index = self
            .readers
            .demand
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .active
            .ok_or_else(|| Failure::new("multipart_not_demanded"))?;
        self.readers.sources[index]
            .as_ref()
            .cloned()
            .ok_or_else(|| Failure::new("internal"))
    }
    pub(super) async fn next(&self) -> Result<usize, Failure> {
        loop {
            let changed = self.readers.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(index) = self
                .readers
                .demand
                .lock()
                .map_err(|_| Failure::new("internal"))?
                .pending
                .take()
            {
                return Ok(index);
            }
            changed.await;
        }
    }
}

fn with_metadata(
    part: &Part,
    mut field: StreamingMultipartPart,
) -> Result<StreamingMultipartPart, Failure> {
    if let Some(filename) = &part.filename {
        field = field.with_filename(filename).map_err(failure)?;
    }
    if let Some(content_type) = &part.content_type {
        field = field.with_content_type(content_type).map_err(failure)?;
    }
    Ok(field)
}

struct Reader {
    readers: Arc<Readers>,
    index: usize,
    body: UploadBody,
    started: bool,
}
impl Drop for Reader {
    fn drop(&mut self) {
        // Core removes completed parts normally. Dropping any unfinished part
        // abandons the entire request, including its unpolled readers.
        if !self.body.is_end_stream()
            && let Ok(owner) = self.readers.owner.lock()
            && let Some(owner) = owner.upgrade()
        {
            owner.close();
        }
    }
}
impl Body for Reader {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if !self.started {
            let Ok(mut demand) = self.readers.demand.lock() else {
                return Poll::Ready(Some(Err(std::io::Error::other("multipart unavailable"))));
            };
            demand.active = Some(self.index);
            demand.pending = Some(self.index);
            drop(demand);
            self.readers.changed.notify_waiters();
            self.started = true;
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }
}

pub(super) fn content_type(boundary: &str) -> Result<String, Failure> {
    StreamingMultipartBody::new(boundary, [], usize::MAX)
        .map(|body| body.content_type().to_owned())
        .map_err(failure)
}
fn failure(error: PreparedBodyError) -> Failure {
    failure_kind(error.kind())
}
pub(super) fn request_failure(error: &phantom::RequestError) -> Option<Failure> {
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        if let Some(MultipartStreamError::Framing(error)) =
            error.downcast_ref::<MultipartStreamError>()
        {
            return Some(failure_kind(error.kind()));
        }
        source = error.source();
    }
    None
}
fn failure_kind(kind: PreparedBodyErrorKind) -> Failure {
    Failure::new(match kind {
        PreparedBodyErrorKind::TooLarge => "multipart_too_large",
        PreparedBodyErrorKind::Allocation => "multipart_allocation",
        PreparedBodyErrorKind::InvalidName => "multipart_invalid_name",
        PreparedBodyErrorKind::InvalidFilename => "multipart_invalid_filename",
        PreparedBodyErrorKind::InvalidContentType => "multipart_invalid_content_type",
        PreparedBodyErrorKind::InvalidBoundary => "multipart_invalid_boundary",
        PreparedBodyErrorKind::BoundaryCollision => "multipart_boundary_collision",
        PreparedBodyErrorKind::TooManyParts => "multipart_too_many_parts",
        _ => "multipart",
    })
}

#[cfg(test)]
mod tests;
