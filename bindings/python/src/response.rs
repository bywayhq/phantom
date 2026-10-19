use crate::error;
use http_body_util::BodyExt;
use phantom::{Bytes, ResponseBody};
use pyo3::{prelude::*, types::PyBytes};
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
            if owner
                .busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err(error::input("concurrent_body_read"));
            }
            let mut lease = ReadLease {
                owner: Arc::clone(&owner),
                stream: None,
                finished: false,
            };
            lease.stream = owner
                .stream
                .lock()
                .map_err(|_| error::input("body_state"))?
                .take();
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
}
