use crate::error;
use http_body_util::BodyExt;
use phantom::{Bytes, ResponseBody};
use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

struct Stream {
    body: ResponseBody,
    pending: Bytes,
}
struct BodyOwner {
    stream: Mutex<Option<Stream>>,
    busy: AtomicBool,
    closed: AtomicBool,
    changed: Notify,
}

struct ReadLease {
    owner: Arc<BodyOwner>,
    stream: Option<Stream>,
    finished: bool,
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        if !self.finished {
            self.owner.closed.store(true, Ordering::SeqCst);
        }
        self.owner.busy.store(false, Ordering::SeqCst);
    }
}

impl ReadLease {
    fn acquire(owner: &Arc<BodyOwner>) -> PyResult<Self> {
        owner
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| error::input("concurrent_body_read"))?;
        let mut lease = Self {
            owner: Arc::clone(owner),
            stream: None,
            finished: false,
        };
        lease.stream = owner
            .stream
            .lock()
            .map_err(|_| error::input("body_state"))?
            .take();
        Ok(lease)
    }

    fn restore(mut self) -> PyResult<()> {
        let mut slot = self
            .owner
            .stream
            .lock()
            .map_err(|_| error::input("body_state"))?;
        if !self.owner.closed.load(Ordering::SeqCst) {
            *slot = self.stream.take();
        }
        self.finished = true;
        Ok(())
    }
}

fn append_body(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> PyResult<()> {
    if bytes.len() > maximum.saturating_sub(output.len()) {
        return Err(error::NativeError::new_err((
            "request",
            "response_body_limit",
            None::<String>,
            None::<String>,
        )));
    }
    let length = output.len() + bytes.len();
    if length > output.capacity() {
        // Grow with observed data, without reserving the caller's entire bound.
        let capacity = length.max(output.capacity().saturating_mul(2)).min(maximum);
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(|_| PyMemoryError::new_err("response body allocation failed"))?;
    }
    output.extend_from_slice(bytes);
    Ok(())
}

#[pyclass]
pub(super) struct NativeResponse {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    protocol: String,
    headers: Vec<(String, Vec<u8>)>,
    owner: Arc<BodyOwner>,
}

impl NativeResponse {
    pub(super) fn new(response: phantom::Response<ResponseBody>) -> PyResult<Self> {
        let status = response.status().as_u16();
        let protocol = match response.version() {
            http::Version::HTTP_11 => "h1",
            http::Version::HTTP_2 => "h2",
            http::Version::HTTP_3 => "h3",
            _ => "unknown",
        }
        .to_owned();
        let headers = response
            .extensions()
            .get::<phantom::OrderedResponseHeaders>()
            .map(|fields| {
                fields
                    .iter()
                    .map(|field| (field.name().to_owned(), field.value().to_vec()))
                    .collect()
            })
            .ok_or_else(|| error::input("ordered_headers_unavailable"))?;
        Ok(Self {
            status,
            protocol,
            headers,
            owner: Arc::new(BodyOwner {
                stream: Mutex::new(Some(Stream {
                    body: response.into_body(),
                    pending: Bytes::new(),
                })),
                busy: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                changed: Notify::new(),
            }),
        })
    }
}

#[pymethods]
impl NativeResponse {
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(String, Bound<'py, PyBytes>)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.clone(), PyBytes::new(py, value)))
            .collect()
    }

    fn close(&self) -> PyResult<()> {
        self.owner.closed.store(true, Ordering::SeqCst);
        self.owner
            .stream
            .lock()
            .map_err(|_| error::input("body_state"))?
            .take();
        self.owner.changed.notify_waiters();
        Ok(())
    }

    fn read_chunk<'py>(&self, py: Python<'py>, maximum: usize) -> PyResult<Bound<'py, PyAny>> {
        if maximum == 0 || maximum > 1024 * 1024 {
            return Err(error::input("chunk_size"));
        }
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut lease = ReadLease::acquire(&owner)?;
            let Some(stream) = lease.stream.as_mut() else {
                return Ok(None::<Py<PyBytes>>);
            };
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if owner.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let next = async {
                while stream.pending.is_empty() {
                    let Some(frame) = stream.body.frame().await else {
                        return Ok::<Option<Bytes>, PyErr>(None);
                    };
                    if let Ok(data) = frame.map_err(error::request)?.into_data() {
                        stream.pending = data;
                    }
                }
                let length = maximum.min(stream.pending.len());
                Ok(Some(stream.pending.split_to(length)))
            };
            let bytes: Option<Bytes> = tokio::select! {
                biased;
                () = &mut changed => return Err(error::input("body_closed")),
                result = next => result?,
            };
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            lease.restore()?;
            Python::attach(|py| Ok(Some(PyBytes::new(py, &bytes).unbind())))
        })
    }

    fn read<'py>(&self, py: Python<'py>, maximum: usize) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut lease = ReadLease::acquire(&owner)?;
            let Some(stream) = lease.stream.as_mut() else {
                return Ok(Vec::<u8>::new());
            };
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if owner.closed.load(Ordering::SeqCst) {
                return Ok(Vec::new());
            }
            let collect = async {
                let mut output = Vec::new();
                append_body(&mut output, &stream.pending, maximum)?;
                stream.pending = Bytes::new();
                while let Some(frame) = stream.body.frame().await {
                    if let Ok(data) = frame.map_err(error::request)?.into_data() {
                        append_body(&mut output, &data, maximum)?;
                    }
                }
                Ok(output)
            };
            tokio::select! {
                biased;
                () = &mut changed => Err(error::input("body_closed")),
                result = collect => result,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::append_body;

    #[test]
    fn collection_allocates_from_received_bytes_and_accepts_exact_bound() -> pyo3::PyResult<()> {
        let mut output = Vec::new();
        append_body(&mut output, b"", usize::MAX)?;
        assert_eq!(output.capacity(), 0);
        append_body(&mut output, b"hello", 5)?;
        append_body(&mut output, b"", 5)?;
        assert_eq!(output, b"hello");
        Ok(())
    }

    #[test]
    fn overflow_preserves_collected_prefix_without_appending() -> pyo3::PyResult<()> {
        let mut output = Vec::new();
        append_body(&mut output, b"he", 4)?;
        assert!(append_body(&mut output, b"llo", 4).is_err());
        assert_eq!(output, b"he");
        assert!(append_body(&mut Vec::new(), b"a", 0).is_err());
        Ok(())
    }
}
