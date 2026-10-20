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
            protocol,
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
    use super::{NativeResponse, append_body, response_info};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        num::NonZeroUsize,
        thread,
        time::{Duration, Instant},
    };

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
