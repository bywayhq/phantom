//! Core multipart framing with one demanded Python source and lazy native files.

use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use http_body::{Body, Frame};
use phantom::{
    Bytes, PreparedBodyError, PreparedBodyErrorKind, StreamingMultipartBody, StreamingMultipartPart,
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyInt, PyList, PyString},
};
use tokio::sync::Notify;

use crate::{
    error,
    upload::{FileBody, NativeUpload, Producer, ProducerBody},
};

#[derive(Default)]
struct Demand {
    active: Option<usize>,
    pending: Option<usize>,
    closed: bool,
}
struct Sources {
    slots: Vec<Option<Arc<Producer>>>,
    demand: Mutex<Demand>,
    changed: Notify,
}
impl Sources {
    fn close(&self) {
        if let Ok(mut state) = self.demand.lock() {
            state.closed = true;
            state.pending = None;
        }
        for source in self.slots.iter().flatten() {
            source.close();
        }
        self.changed.notify_waiters();
    }
    async fn wait(&self, terminal: bool) -> PyResult<Option<usize>> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .demand
                    .lock()
                    .map_err(|_| error::input("upload_state"))?;
                if state.closed {
                    return Ok(None);
                }
                if !terminal && let Some(index) = state.pending.take() {
                    return Ok(Some(index));
                }
            }
            changed.await;
        }
    }
    fn active(&self) -> PyResult<Arc<Producer>> {
        let state = self
            .demand
            .lock()
            .map_err(|_| error::input("upload_state"))?;
        if state.closed {
            return Err(error::input("upload_closed"));
        }
        state
            .active
            .and_then(|index| self.slots[index].clone())
            .ok_or_else(|| error::input("upload_without_credit"))
    }
}

pub(super) struct Multipart {
    body: Mutex<Option<StreamingMultipartBody>>,
    sources: Arc<Sources>,
}
impl Multipart {
    pub(super) fn take_body(&self) -> PyResult<StreamingMultipartBody> {
        self.body
            .lock()
            .map_err(|_| error::input("upload_state"))?
            .take()
            .ok_or_else(|| error::input("upload_used"))
    }
    pub(super) fn close(&self) {
        self.sources.close();
        // An unsubmitted body can own lazy readers too. Drop outside the lock.
        let body = self.body.lock().ok().and_then(|mut body| body.take());
        drop(body);
    }
}

#[pyclass(frozen)]
pub(super) struct NativeStreamingMultipart {
    pub(super) inner: Arc<Multipart>,
    content_type: String,
}

type Fields<'py> = (
    u8,
    Bound<'py, PyString>,
    Bound<'py, PyAny>,
    Option<Bound<'py, PyString>>,
    Option<Bound<'py, PyString>>,
);

fn prepared(error: PreparedBodyError) -> PyErr {
    prepared_kind(error.kind())
}

fn prepared_kind(kind: PreparedBodyErrorKind) -> PyErr {
    error::NativeError::new_err((
        "prepared_body",
        match kind {
            PreparedBodyErrorKind::TooLarge => "too_large",
            PreparedBodyErrorKind::Allocation => "allocation",
            PreparedBodyErrorKind::InvalidName => "invalid_name",
            PreparedBodyErrorKind::InvalidFilename => "invalid_filename",
            PreparedBodyErrorKind::InvalidContentType => "invalid_content_type",
            PreparedBodyErrorKind::InvalidBoundary => "invalid_boundary",
            PreparedBodyErrorKind::BoundaryCollision => "boundary_collision",
            PreparedBodyErrorKind::TooManyParts => "too_many_parts",
            _ => "unknown",
        },
        None::<String>,
        None::<String>,
    ))
}

pub(super) fn request_error(failure: phantom::RequestError) -> PyErr {
    use std::error::Error;
    let mut source = failure.source();
    while let Some(current) = source {
        if let Some(phantom::MultipartStreamError::Framing(error)) =
            current.downcast_ref::<phantom::MultipartStreamError>()
        {
            return prepared_kind(error.kind());
        }
        source = current.source();
    }
    error::request(failure)
}
fn copy_bytes(input: &[u8]) -> PyResult<Bytes> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| prepared_kind(PreparedBodyErrorKind::Allocation))?;
    output.extend_from_slice(input);
    Ok(output.into())
}

fn metadata(
    mut field: StreamingMultipartPart,
    filename: &Option<Bound<'_, PyString>>,
    content_type: &Option<Bound<'_, PyString>>,
) -> PyResult<StreamingMultipartPart> {
    if let Some(filename) = filename {
        field = field
            .with_filename(
                filename
                    .to_str()
                    .map_err(|_| error::input("invalid_multipart"))?,
            )
            .map_err(prepared)?;
    }
    if let Some(content_type) = content_type {
        field = field
            .with_content_type(
                content_type
                    .to_str()
                    .map_err(|_| error::input("invalid_multipart"))?,
            )
            .map_err(prepared)?;
    }
    Ok(field)
}

#[pymethods]
impl NativeStreamingMultipart {
    #[staticmethod]
    fn content_type_for(boundary: &Bound<'_, PyString>) -> PyResult<String> {
        if boundary.len()? > 70 {
            return Err(error::input("invalid_boundary"));
        }
        StreamingMultipartBody::new(
            boundary
                .to_str()
                .map_err(|_| error::input("invalid_boundary"))?,
            [],
            usize::MAX,
        )
        .map(|body| body.content_type().to_owned())
        .map_err(prepared)
    }
    #[new]
    fn new(
        py: Python<'_>,
        boundary: &Bound<'_, PyString>,
        parts: &Bound<'_, PyList>,
        maximum_bytes: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let maximum = maximum_bytes
            .cast_exact::<PyInt>()
            .map_err(|_| error::input("invalid_maximum_bytes"))?
            .extract::<usize>()
            .map_err(|_| error::input("invalid_maximum_bytes"))?;
        if parts.len() > 1024 || boundary.len()? > 70 {
            return Err(error::input("invalid_multipart"));
        }
        let boundary = boundary
            .to_str()
            .map_err(|_| error::input("invalid_boundary"))?;
        // Bound metadata and static payloads before allocating native copies.
        let fields = parts
            .iter()
            .map(|part| {
                part.extract::<Fields<'_>>()
                    .map_err(|_| error::input("invalid_multipart"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let mut payload = 0_usize;
        let mut validated = Vec::with_capacity(fields.len());
        for (kind, name, value, filename, content_type) in &fields {
            if [Some(name), filename.as_ref(), content_type.as_ref()]
                .into_iter()
                .flatten()
                .map(|v| v.len())
                .collect::<PyResult<Vec<_>>>()?
                .into_iter()
                .any(|length| length > 4096)
            {
                return Err(error::input("invalid_multipart"));
            }
            let name = name
                .to_str()
                .map_err(|_| error::input("invalid_multipart"))?;
            let field = match kind {
                0 => {
                    let value = value
                        .cast::<PyString>()
                        .map_err(|_| error::input("invalid_multipart"))?;
                    if value.len()? > maximum {
                        return Err(error::input("multipart_too_large"));
                    }
                    payload = payload
                        .checked_add(
                            value
                                .to_str()
                                .map_err(|_| error::input("invalid_multipart"))?
                                .len(),
                        )
                        .filter(|n| *n <= maximum)
                        .ok_or_else(|| error::input("multipart_too_large"))?;
                    StreamingMultipartPart::text(name, "", maximum)
                }
                1 => {
                    let bytes = value
                        .cast::<PyBytes>()
                        .map_err(|_| error::input("invalid_multipart"))?;
                    payload = payload
                        .checked_add(bytes.as_bytes().len())
                        .filter(|n| *n <= maximum)
                        .ok_or_else(|| error::input("multipart_too_large"))?;
                    StreamingMultipartPart::bytes(name, Bytes::new())
                }
                2 => StreamingMultipartPart::bytes(name, Bytes::new()),
                3 => {
                    let path = value
                        .cast::<PyString>()
                        .map_err(|_| error::input("invalid_multipart"))?;
                    if path.len()? > 32768 {
                        return Err(error::input("invalid_upload_path"));
                    }
                    path.to_str()
                        .map_err(|_| error::input("invalid_upload_path"))?;
                    StreamingMultipartPart::bytes(name, Bytes::new())
                }
                _ => return Err(error::input("invalid_multipart")),
            }
            .map_err(prepared)?;
            validated.push(metadata(field, filename, content_type)?);
        }
        py.detach(|| StreamingMultipartBody::new(boundary, validated, maximum))
            .map_err(prepared)?;
        let sources = Arc::new(Sources {
            slots: fields
                .iter()
                .map(|(kind, ..)| (*kind == 2).then(|| Producer::new(None)))
                .collect(),
            demand: Mutex::new(Demand::default()),
            changed: Notify::new(),
        });
        let mut encoded = Vec::with_capacity(fields.len());
        for (index, (kind, name, value, filename, content_type)) in fields.iter().enumerate() {
            let name = name
                .to_str()
                .map_err(|_| error::input("invalid_multipart"))?;
            let field = match kind {
                0 => {
                    let text = value
                        .cast::<PyString>()?
                        .to_str()
                        .map_err(|_| error::input("invalid_multipart"))?;
                    py.detach(|| StreamingMultipartPart::text(name, text, maximum))
                }
                1 => StreamingMultipartPart::bytes(
                    name,
                    copy_bytes(value.cast::<PyBytes>()?.as_bytes())?,
                ),
                3 => {
                    let path = PathBuf::from(
                        value
                            .cast::<PyString>()?
                            .to_str()
                            .map_err(|_| error::input("invalid_upload_path"))?,
                    );
                    StreamingMultipartPart::stream(
                        name,
                        LazyFile {
                            path: Some(path),
                            opening: None,
                            body: None,
                            sources: Arc::clone(&sources),
                            done: false,
                        },
                    )
                }
                2 => {
                    let producer = sources.slots[index]
                        .as_ref()
                        .ok_or_else(|| error::input("invalid_multipart"))?;
                    StreamingMultipartPart::stream(
                        name,
                        Reader {
                            sources: Arc::clone(&sources),
                            index,
                            body: producer.body()?,
                            started: false,
                        },
                    )
                }
                _ => return Err(error::input("invalid_multipart")),
            }
            .map_err(prepared)?;
            encoded.push(metadata(field, filename, content_type)?);
        }
        let body = py
            .detach(|| StreamingMultipartBody::new(boundary, encoded, maximum))
            .map_err(prepared)?;
        let content_type = body.content_type().to_owned();
        Ok(Self {
            inner: Arc::new(Multipart {
                body: Mutex::new(Some(body)),
                sources,
            }),
            content_type,
        })
    }
    #[getter]
    fn content_type(&self) -> &str {
        &self.content_type
    }
    fn next_part<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let sources = Arc::clone(&self.inner.sources);
        pyo3_async_runtimes::tokio::future_into_py(py, async move { sources.wait(false).await })
    }
    fn terminal<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let sources = Arc::clone(&self.inner.sources);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            sources.wait(true).await.map(|_| ())
        })
    }
    fn credit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = self.inner.sources.active()?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move { owner.wait(false).await })
    }
    fn write(&self, bytes: &Bound<'_, PyBytes>, offset: usize, length: usize) -> PyResult<()> {
        NativeUpload {
            inner: self.inner.sources.active()?,
        }
        .write(bytes, offset, length)
    }
    fn finish(&self) -> PyResult<()> {
        NativeUpload {
            inner: self.inner.sources.active()?,
        }
        .finish()
    }
    fn fail(&self) -> PyResult<()> {
        NativeUpload {
            inner: self.inner.sources.active()?,
        }
        .fail()
    }
    fn abort(&self) {
        self.inner.close();
    }
}

struct Reader {
    sources: Arc<Sources>,
    index: usize,
    body: ProducerBody,
    started: bool,
}
impl Drop for Reader {
    fn drop(&mut self) {
        if !self.body.is_end_stream() {
            self.sources.close();
        }
    }
}
impl Body for Reader {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if !self.started {
            let Ok(mut state) = self.sources.demand.lock() else {
                return Poll::Ready(Some(Err(io::Error::other("multipart unavailable"))));
            };
            if state.closed {
                return Poll::Ready(Some(Err(io::Error::other("multipart closed"))));
            }
            state.active = Some(self.index);
            state.pending = Some(self.index);
            drop(state);
            self.sources.changed.notify_waiters();
            self.started = true;
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }
}

type Opening = Pin<Box<dyn Future<Output = io::Result<FileBody>> + Send>>;
struct LazyFile {
    path: Option<PathBuf>,
    opening: Option<Opening>,
    body: Option<FileBody>,
    sources: Arc<Sources>,
    done: bool,
}
impl Drop for LazyFile {
    fn drop(&mut self) {
        if !self.done {
            self.sources.close();
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
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(path) = self.path.take() {
            self.opening = Some(Box::pin(FileBody::open(path)));
        }
        if let Some(opening) = &mut self.opening {
            match opening.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.done = true;
                    self.opening = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Ok(body)) => {
                    self.body = Some(body);
                    self.opening = None;
                }
            }
        }
        let Some(body) = &mut self.body else {
            return Poll::Ready(None);
        };
        let frame = Pin::new(body).poll_frame(cx);
        if matches!(&frame, Poll::Ready(None | Some(Err(_)))) {
            self.done = true;
            self.body = None;
        }
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    #[test]
    fn child_eof_keeps_next_source_idle_and_unfinished_drop_closes_root() -> PyResult<()> {
        Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(error::io)?;
        runtime.block_on(async {
            let first = Producer::new(None);
            let second = Producer::new(None);
            let sources = Arc::new(Sources {
                slots: vec![Some(Arc::clone(&first)), Some(Arc::clone(&second))],
                demand: Mutex::new(Demand::default()),
                changed: Notify::new(),
            });
            let mut first_body = Reader {
                sources: Arc::clone(&sources),
                index: 0,
                body: first.body()?,
                started: false,
            };
            let mut second_body = Reader {
                sources: Arc::clone(&sources),
                index: 1,
                body: second.body()?,
                started: false,
            };
            let mut cx = Context::from_waker(Waker::noop());
            assert!(Pin::new(&mut first_body).poll_frame(&mut cx).is_pending());
            assert_eq!(sources.wait(false).await?, Some(0));
            assert!(first.wait(false).await?);
            NativeUpload { inner: first }.finish()?;
            assert!(matches!(
                Pin::new(&mut first_body).poll_frame(&mut cx),
                Poll::Ready(None)
            ));
            drop(first_body);
            assert!(sources.active().is_ok());
            assert!(
                !sources
                    .demand
                    .lock()
                    .map_err(|_| error::input("upload_state"))?
                    .closed
            );
            // Merely constructing the next reader did not publish its demand.
            assert!(
                sources
                    .demand
                    .lock()
                    .map_err(|_| error::input("upload_state"))?
                    .pending
                    .is_none()
            );
            assert!(Pin::new(&mut second_body).poll_frame(&mut cx).is_pending());
            assert_eq!(sources.wait(false).await?, Some(1));
            drop(second_body);
            assert_eq!(sources.wait(false).await?, None);
            assert!(!second.wait(false).await?);
            assert!(sources.active().is_err());
            Ok(())
        })
    }
}
