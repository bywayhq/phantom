use crate::{error, upload::UploadOwner};
use http_body_util::BodyExt;
use phantom::{Bytes, ResponseBody, ResponseTrailers};
use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tokio::sync::Notify;

const OPEN: u8 = 0;
const CLOSED: u8 = 1;
const EXPIRED: u8 = 2;

struct Stream {
    body: ResponseBody,
    pending: Bytes,
}
struct BodyOwner {
    stream: Mutex<Option<Stream>>,
    trailers: Mutex<ResponseTrailers>,
    busy: AtomicBool,
    state: AtomicU8,
    changed: Notify,
    upload: Mutex<Option<UploadOwner>>,
    watchdog: Mutex<Option<tokio::task::AbortHandle>>,
    protocol: String,
}

impl BodyOwner {
    fn close(&self, expired: bool) {
        self.finish(expired, ResponseTrailers::Unavailable);
    }

    fn finish(&self, expired: bool, trailers: ResponseTrailers) -> bool {
        let mut retained = self.trailers.lock().unwrap_or_else(PoisonError::into_inner);
        if self
            .state
            .compare_exchange(
                OPEN,
                if expired { EXPIRED } else { CLOSED },
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return false;
        }
        *retained = trailers;
        drop(retained);
        if let Ok(mut stream) = self.stream.lock() {
            stream.take();
        }
        if let Ok(mut upload) = self.upload.lock()
            && let Some(upload) = upload.take()
        {
            upload.close();
        }
        self.changed.notify_waiters();
        if let Ok(mut task) = self.watchdog.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
        true
    }
    fn closed_error(&self) -> PyErr {
        if self.state.load(Ordering::SeqCst) == EXPIRED {
            error::total_timeout(Some(&self.protocol))
        } else {
            error::input("body_closed")
        }
    }
}
impl Drop for BodyOwner {
    fn drop(&mut self) {
        self.close(false);
        if let Ok(mut task) = self.watchdog.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

struct ReadLease {
    owner: Arc<BodyOwner>,
    stream: Option<Stream>,
    finished: bool,
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        if !self.finished {
            self.owner.close(false);
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

    fn complete(mut self) -> PyResult<()> {
        let stream = self
            .stream
            .take()
            .ok_or_else(|| error::input("body_state"))?;
        if !self.owner.finish(false, stream.body.into_trailers()) {
            return Err(self.owner.closed_error());
        }
        self.finished = true;
        Ok(())
    }

    fn restore(mut self) -> PyResult<()> {
        let mut slot = self
            .owner
            .stream
            .lock()
            .map_err(|_| error::input("body_state"))?;
        if self.owner.state.load(Ordering::SeqCst) == OPEN {
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

fn response_info(extensions: &http::Extensions) -> PyResult<&phantom::ResponseInfo> {
    extensions.get::<phantom::ResponseInfo>().ok_or_else(|| {
        error::NativeError::new_err((
            "response",
            "response_info_unavailable",
            None::<String>,
            None::<String>,
        ))
    })
}

type TrailerFields<'py> = (String, Option<Vec<(String, Bound<'py, PyBytes>, bool)>>);

type RedirectHopFields = (String, String, String, String, u16);
type RedirectHistoryFields = (Vec<RedirectHopFields>, usize);

#[pyclass]
pub(super) struct NativeResponse {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    redirects_followed: usize,
    #[pyo3(get)]
    connection_setup_retries: usize,
    #[pyo3(get)]
    decoded_content_codings: Vec<String>,
    #[pyo3(get)]
    redirect_history: Option<RedirectHistoryFields>,
    headers: Vec<(String, Vec<u8>, bool)>,
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
                    .map(|field| {
                        (
                            field.name().to_owned(),
                            field.value().to_vec(),
                            field.is_sensitive(),
                        )
                    })
                    .collect()
            })
            .ok_or_else(|| error::input("ordered_headers_unavailable"))?;
        let info = response_info(response.extensions())?;
        let url = info.effective_uri().to_string();
        let redirects_followed = info.redirects_followed();
        let connection_setup_retries = info.retries_performed();
        let redirect_history =
            response
                .extensions()
                .get::<phantom::RedirectHistory>()
                .map(|history| {
                    (
                        history
                            .entries()
                            .iter()
                            .map(|hop| {
                                (
                                    hop.from_uri().to_string(),
                                    hop.to_uri().to_string(),
                                    hop.method().to_string(),
                                    hop.next_method().to_string(),
                                    hop.status().as_u16(),
                                )
                            })
                            .collect(),
                        history.omitted_hops(),
                    )
                });
        let decoded_content_codings = info
            .decoded_content_codings()
            .iter()
            .map(|coding| {
                match coding {
                    phantom::ContentCoding::Gzip => "gzip",
                    phantom::ContentCoding::Deflate => "deflate",
                    phantom::ContentCoding::Brotli => "br",
                    phantom::ContentCoding::Zstd => "zstd",
                    _ => "unknown",
                }
                .to_owned()
            })
            .collect();
        Ok(Self {
            status,
            protocol: protocol.clone(),
            url,
            redirects_followed,
            connection_setup_retries,
            decoded_content_codings,
            redirect_history,
            headers,
            owner: Arc::new(BodyOwner {
                stream: Mutex::new(Some(Stream {
                    body: response.into_body(),
                    pending: Bytes::new(),
                })),
                trailers: Mutex::new(ResponseTrailers::Pending),
                busy: AtomicBool::new(false),
                state: AtomicU8::new(OPEN),
                changed: Notify::new(),
                upload: Mutex::new(None),
                watchdog: Mutex::new(None),
                protocol: protocol.clone(),
            }),
        })
    }
    pub(super) fn watch_upload(
        &self,
        upload: Option<UploadOwner>,
        deadline: Option<tokio::time::Instant>,
    ) -> PyResult<()> {
        *self
            .owner
            .upload
            .lock()
            .map_err(|_| error::input("body_state"))? = upload;
        if let Some(deadline) = deadline {
            let owner = Arc::downgrade(&self.owner);
            let task = tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                if let Some(owner) = owner.upgrade()
                    && owner.state.load(Ordering::SeqCst) == OPEN
                {
                    owner.close(true);
                }
            });
            *self
                .owner
                .watchdog
                .lock()
                .map_err(|_| error::input("body_state"))? = Some(task.abort_handle());
        }
        Ok(())
    }
}

#[pymethods]
impl NativeResponse {
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(String, Bound<'py, PyBytes>, bool)> {
        self.headers
            .iter()
            .map(|(name, value, sensitive)| (name.clone(), PyBytes::new(py, value), *sensitive))
            .collect()
    }

    #[getter]
    fn trailers<'py>(&self, py: Python<'py>) -> PyResult<TrailerFields<'py>> {
        let retained = self
            .owner
            .trailers
            .lock()
            .map_err(|_| error::input("body_state"))?;
        let (state, headers) = match &*retained {
            ResponseTrailers::Pending => ("pending", None),
            ResponseTrailers::Unavailable => ("unavailable", None),
            ResponseTrailers::Complete(fields) => (
                "complete",
                Some(
                    fields
                        .iter()
                        .map(|field| {
                            (
                                field.name().to_owned(),
                                PyBytes::new(py, field.value()),
                                field.is_sensitive(),
                            )
                        })
                        .collect(),
                ),
            ),
            _ => return Err(error::input("unsupported_response_trailers")),
        };
        Ok((state.to_owned(), headers))
    }

    fn close(&self) -> PyResult<()> {
        self.owner.close(false);
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
                if owner.state.load(Ordering::SeqCst) == EXPIRED {
                    return Err(owner.closed_error());
                }
                return Ok(None::<Py<PyBytes>>);
            };
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if owner.state.load(Ordering::SeqCst) != OPEN {
                return Err(owner.closed_error());
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
                () = &mut changed => return Err(owner.closed_error()),
                result = next => result?,
            };
            let Some(bytes) = bytes else {
                lease.complete()?;
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
                if owner.state.load(Ordering::SeqCst) == EXPIRED {
                    return Err(owner.closed_error());
                }
                return Ok(Vec::<u8>::new());
            };
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if owner.state.load(Ordering::SeqCst) != OPEN {
                return Err(owner.closed_error());
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
            let output = tokio::select! {
                biased;
                () = &mut changed => Err(owner.closed_error()),
                result = collect => result,
            }?;
            lease.complete()?;
            Ok(output)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeResponse, append_body, response_info};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        num::NonZeroUsize,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn first_terminal_outcome_wins_over_late_deadline_or_close() {
        for (expired, expected) in [(false, super::CLOSED), (true, super::EXPIRED)] {
            let owner = super::BodyOwner {
                stream: std::sync::Mutex::new(None),
                trailers: std::sync::Mutex::new(phantom::ResponseTrailers::Pending),
                busy: std::sync::atomic::AtomicBool::new(false),
                state: std::sync::atomic::AtomicU8::new(super::OPEN),
                changed: tokio::sync::Notify::new(),
                upload: std::sync::Mutex::new(None),
                watchdog: std::sync::Mutex::new(None),
                protocol: "h2".to_owned(),
            };
            owner.close(expired);
            owner.close(!expired);
            assert_eq!(
                owner.state.load(std::sync::atomic::Ordering::SeqCst),
                expected
            );
        }
    }

    #[test]
    fn missing_response_info_is_a_typed_error() -> pyo3::PyResult<()> {
        pyo3::Python::initialize();
        let result = response_info(&http::Extensions::new()).map(|_| ());
        assert!(result.is_err());
        pyo3::Python::attach(|py| {
            use pyo3::prelude::*;
            let error = result
                .err()
                .ok_or_else(|| crate::error::input("test_error"))?;
            assert!(error.is_instance_of::<crate::error::NativeError>(py));
            let arguments: (String, String, Option<String>, Option<String>) =
                error.value(py).getattr("args")?.extract()?;
            assert_eq!(arguments.0, "response");
            assert_eq!(arguments.1, "response_info_unavailable");
            assert_eq!((arguments.2, arguments.3), (None, None));
            Ok(())
        })
    }

    #[test]
    fn actual_followed_redirect_metadata_reaches_native_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let peer = thread::spawn(move || -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(5);
            for path in ["/start", "/finish?encoded=%2F"] {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Err(std::io::ErrorKind::TimedOut.into());
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                    let mut byte = [0];
                    stream.read_exact(&mut byte)?;
                    head.push(byte[0]);
                }
                assert!(head.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
                stream.write_all(if path == "/start" {
                    b"HTTP/1.1 302 Found\r\nLocation: /finish?encoded=%2F\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                })?;
            }
            Ok(())
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let outcome = runtime.block_on(async {
            let client = phantom::Client::builder(phantom_profile::browser::chrome::v154_windows())
                .route(phantom::Route::direct())
                .redirect_policy(phantom::RedirectPolicy::limited(NonZeroUsize::MIN))
                .build()?;
            let request = client.get(phantom::HttpProtocol::Http1, &format!("{origin}/start"))?;
            let response = tokio::time::timeout(Duration::from_secs(5), request.send()).await??;
            NativeResponse::new(response)
                .map_err(Into::<Box<dyn std::error::Error + Send + Sync>>::into)
        });
        peer.join().map_err(|_| "HTTP/1 peer panicked")??;
        let response = outcome?;
        assert_eq!(response.url, format!("{origin}/finish?encoded=%2F"));
        assert_eq!(response.redirects_followed, 1);
        assert_eq!(response.connection_setup_retries, 0);
        Ok(())
    }

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
