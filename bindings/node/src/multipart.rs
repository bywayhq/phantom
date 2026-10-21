//! One core multipart encoder and one demand channel for its active JS source.

use crate::{
    error::failure,
    upload::{Upload, UploadBody},
};
use bytes::Bytes;
use http_body::{Body, Frame};
use napi::Result;
use phantom::{StreamingMultipartBody, StreamingMultipartPart};
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError, Weak},
    task::{Context, Poll},
};
use tokio::sync::Notify;

pub(crate) enum Data {
    Text(String),
    Bytes(Vec<u8>),
    Stream,
    File { path: String, maximum: u64 },
}
pub(crate) struct Part {
    pub(crate) name: String,
    pub(crate) data: Data,
    pub(crate) filename: Option<String>,
    pub(crate) content_type: Option<String>,
}
#[derive(Default)]
struct Demand {
    active: Option<usize>,
    pending: Option<usize>,
}
struct Sources {
    children: Vec<Option<Arc<Upload>>>,
    demand: Mutex<Demand>,
    changed: Notify,
    owner: Mutex<Weak<Upload>>,
}
pub(crate) struct Multipart {
    body: Mutex<Option<StreamingMultipartBody>>,
    sources: Arc<Sources>,
}
impl fmt::Debug for Multipart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Multipart { inputs redacted }")
    }
}
impl Multipart {
    pub(crate) fn new(boundary: &str, parts: Vec<Part>, maximum: usize) -> Result<Arc<Self>> {
        let sources = Arc::new(Sources {
            children: parts
                .iter()
                .map(|p| matches!(p.data, Data::Stream).then(|| Upload::new(None)))
                .collect(),
            demand: Mutex::new(Demand::default()),
            changed: Notify::new(),
            owner: Mutex::new(Weak::new()),
        });
        let mut fields = Vec::with_capacity(parts.len());
        for (index, part) in parts.into_iter().enumerate() {
            let field = match part.data {
                Data::Text(value) => StreamingMultipartPart::text(&part.name, &value, maximum),
                Data::Bytes(value) => StreamingMultipartPart::bytes(&part.name, Bytes::from(value)),
                Data::Stream => {
                    let child = sources.children[index]
                        .as_ref()
                        .ok_or_else(|| failure("Internal", "multipart source unavailable"))?;
                    StreamingMultipartPart::stream(
                        &part.name,
                        SourceBody {
                            sources: Arc::clone(&sources),
                            index,
                            body: child.body()?,
                            started: false,
                            complete: false,
                        },
                    )
                }
                Data::File { path, maximum } => {
                    StreamingMultipartPart::stream(&part.name, LazyFile::new(path, maximum))
                }
            }
            .map_err(crate::prepared_body::core_error)?;
            let field = if let Some(filename) = part.filename {
                field
                    .with_filename(filename)
                    .map_err(crate::prepared_body::core_error)?
            } else {
                field
            };
            let field = if let Some(content_type) = part.content_type {
                field
                    .with_content_type(content_type)
                    .map_err(crate::prepared_body::core_error)?
            } else {
                field
            };
            fields.push(field);
        }
        let body = StreamingMultipartBody::new(boundary, fields, maximum)
            .map_err(crate::prepared_body::core_error)?;
        Ok(Arc::new(Self {
            body: Mutex::new(Some(body)),
            sources,
        }))
    }
    pub(crate) fn take_body(&self, owner: &Arc<Upload>) -> Result<StreamingMultipartBody> {
        *self
            .sources
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(owner);
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| failure("InvalidOperation", "multipart belongs to one request"))
    }
    pub(crate) fn active(&self) -> Result<Arc<Upload>> {
        let index = self
            .sources
            .demand
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
            .ok_or_else(|| failure("InvalidUpload", "multipart source not demanded"))?;
        self.sources.children[index]
            .as_ref()
            .cloned()
            .ok_or_else(|| failure("Internal", "multipart source unavailable"))
    }
    pub(crate) async fn next(&self) -> u32 {
        loop {
            let changed = self.sources.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(index) = self
                .sources
                .demand
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pending
                .take()
            {
                return index as u32;
            }
            changed.await;
        }
    }
    pub(crate) fn stop(&self) {
        for child in self.sources.children.iter().flatten() {
            child.stop();
        }
    }
    pub(crate) fn fail(&self) {
        for child in self.sources.children.iter().flatten() {
            child.fail();
        }
    }
}
struct SourceBody {
    sources: Arc<Sources>,
    index: usize,
    body: UploadBody,
    started: bool,
    complete: bool,
}
impl Body for SourceBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if !self.started {
            let mut demand = self
                .sources
                .demand
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            demand.active = Some(self.index);
            demand.pending = Some(self.index);
            drop(demand);
            self.sources.changed.notify_waiters();
            self.started = true;
        }
        let result = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(result, Poll::Ready(None)) {
            self.complete = true;
        }
        result
    }
}
impl Drop for SourceBody {
    fn drop(&mut self) {
        if !self.complete
            && let Some(owner) = self
                .sources
                .owner
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .upgrade()
        {
            owner.stop();
        }
    }
}

// Open only on the core encoder's first poll, inside the exchange deadline.
type OpeningFile = Pin<Box<dyn Future<Output = io::Result<crate::request::FileBody>> + Send>>;
struct LazyFile {
    opening: Option<OpeningFile>,
    file: Option<crate::request::FileBody>,
}
impl LazyFile {
    fn new(path: String, maximum: u64) -> Self {
        Self {
            opening: Some(Box::pin(async move {
                let file = tokio::fs::File::open(path)
                    .await
                    .map_err(|_| io::Error::other("multipart file open failed"))?;
                let metadata = file
                    .metadata()
                    .await
                    .map_err(|_| io::Error::other("multipart file metadata failed"))?;
                if !metadata.is_file() || metadata.len() > maximum {
                    return Err(io::Error::other("multipart file exceeds maximumBytes"));
                }
                Ok(crate::request::FileBody::new(file, metadata.len()))
            })),
            file: None,
        }
    }
}
impl Body for LazyFile {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if let Some(opening) = &mut self.opening {
            match opening.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.opening = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Ok(file)) => {
                    self.opening = None;
                    self.file = Some(file);
                }
            }
        }
        match &mut self.file {
            Some(file) => Pin::new(file).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }
}

pub(crate) fn request_error(error: &phantom::RequestError) -> Option<napi::Error> {
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        if let Some(phantom::MultipartStreamError::Framing(error)) =
            error.downcast_ref::<phantom::MultipartStreamError>()
        {
            return Some(crate::prepared_body::core_kind(error.kind()));
        }
        source = error.source();
    }
    None
}

#[cfg(test)]
mod tests;
