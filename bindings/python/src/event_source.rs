//! Pull-driven reconnecting sources retain admission between HTTP attempts.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use phantom::{Client, HttpProtocol, SseError, SseErrorKind, SseEventSource, SseHeader, SseLimits};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyFloat, PyInt, PyList},
};
use tokio::sync::Notify;

use crate::{
    configuration, error, header_hook,
    lifecycle::{Admission, Lifecycle, Registration},
    request_fields, response,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Terminal {
    Open,
    Closed,
    Aborted,
}

struct State {
    source: Option<SseEventSource>,
    admission: Option<Admission>,
    registration: Option<Registration>,
    leased: bool,
    terminal: Terminal,
    last_event_id: String,
    retry_ms: u128,
    reconnects: usize,
}

pub(super) struct Owner {
    state: Mutex<State>,
    changed: Notify,
    hooks: Option<Arc<header_hook::Owner>>,
}

impl Owner {
    pub(super) fn abort(&self) {
        self.finish(Terminal::Aborted);
    }

    fn close(&self) {
        self.finish(Terminal::Closed);
    }

    fn finish(&self, terminal: Terminal) {
        let (source, idle) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.terminal != Terminal::Open {
                return;
            }
            state.terminal = terminal;
            if state.leased {
                (None, false)
            } else {
                // Retain custody while dropping the idle source outside the lock.
                state.leased = true;
                (state.source.take(), true)
            }
        };
        drop(source);
        if idle {
            self.release_terminal();
        }
        if let Some(hooks) = &self.hooks {
            hooks.close();
        }
        self.changed.notify_waiters();
    }

    /// Releases closed-source custody after its actual destructor has returned.
    fn release_terminal(&self) {
        let (admission, registration) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            (state.admission.take(), state.registration.take())
        };
        drop(registration);
        drop(admission);
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .leased = false;
    }

    async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .terminal
                != Terminal::Open
            {
                return;
            }
            changed.await;
        }
    }

    async fn drained(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let drained = {
                let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.admission.is_none() && !state.leased
            };
            if drained {
                return;
            }
            changed.await;
        }
    }

    async fn idle(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .leased
            {
                return;
            }
            changed.await;
        }
    }

    fn closed_error(&self) -> PyErr {
        if self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal
            == Terminal::Aborted
        {
            error::NativeError::new_err((
                "request",
                "client_closed",
                None::<String>,
                None::<String>,
            ))
        } else {
            error::NativeError::new_err(("sse", "closed", None::<String>, None::<String>))
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}

/// A cancelled poll restores the core source, including its reconnect future.
struct Lease {
    owner: Arc<Owner>,
    source: Option<SseEventSource>,
}

impl Lease {
    fn take(owner: &Arc<Owner>) -> PyResult<Self> {
        let mut state = owner.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.leased {
            return Err(error::input("concurrent_event_read"));
        }
        state.leased = true;
        Ok(Self {
            owner: Arc::clone(owner),
            source: state.source.take(),
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let (source, terminal) = {
            let mut state = self
                .owner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(source) = &self.source {
                state.last_event_id = source.last_event_id().to_owned();
                state.retry_ms = source.retry_delay().as_millis();
                state.reconnects = source.reconnects();
                if source.is_closed() && state.terminal == Terminal::Open {
                    state.terminal = Terminal::Closed;
                }
            }
            if state.terminal != Terminal::Open {
                (self.source.take(), true)
            } else {
                state.source = self.source.take();
                state.leased = false;
                (None, false)
            }
        };
        drop(source);
        if terminal {
            self.owner.release_terminal();
        }
        if terminal && let Some(hooks) = &self.owner.hooks {
            hooks.close();
        }
        self.owner.changed.notify_waiters();
    }
}

#[pyclass]
pub(super) struct NativeEventSource {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    protocol: String,
    #[pyo3(get)]
    url: String,
    headers: Vec<(String, Vec<u8>, bool)>,
    owner: Arc<Owner>,
}

#[pymethods]
impl NativeEventSource {
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(String, Bound<'py, PyBytes>, bool)> {
        self.headers
            .iter()
            .map(|(name, value, sensitive)| (name.clone(), PyBytes::new(py, value), *sensitive))
            .collect()
    }

    #[getter]
    fn last_event_id(&self) -> String {
        self.owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_event_id
            .clone()
    }

    #[getter]
    fn retry_ms(&self) -> u128 {
        self.owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retry_ms
    }

    #[getter]
    fn reconnects(&self) -> usize {
        self.owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconnects
    }

    #[getter]
    fn is_closed(&self) -> bool {
        self.owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal
            != Terminal::Open
    }

    fn next_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        let mut lease = Lease::take(&owner)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let Some(source) = lease.source.as_mut() else {
                if owner
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .terminal
                    == Terminal::Aborted
                {
                    return Err(owner.closed_error());
                }
                return Ok(None::<(String, String, String)>);
            };
            let result = tokio::select! {
                biased;
                () = owner.closed() => return Err(owner.closed_error()),
                result = source.next_event() => result,
            };
            result
                .map(|event| event.map(phantom::SseEvent::into_parts))
                .map_err(failure)
        })
    }

    fn close(&self) {
        self.owner.close();
    }

    fn wait_idle<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            owner.idle().await;
            Ok(())
        })
    }

    fn wait_closed<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Bound<'py, PyAny>> {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or_else(|| error::input("invalid_timeout"))?;
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::timeout_at(deadline, owner.drained())
                .await
                .map_err(|_| error::input("shutdown_timeout"))
        })
    }
}

fn duration(value: &Bound<'_, PyAny>) -> PyResult<Duration> {
    if value.cast_exact::<PyInt>().is_err() && value.cast_exact::<PyFloat>().is_err() {
        return Err(error::input("invalid_sse_duration"));
    }
    Duration::try_from_secs_f64(
        value
            .extract::<f64>()
            .map_err(|_| error::input("invalid_sse_duration"))?,
    )
    .map_err(|_| error::input("invalid_sse_duration"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn connect<'py>(
    py: Python<'py>,
    client: &Client,
    lifecycle: &Arc<Lifecycle>,
    url: &str,
    protocol: &str,
    headers: Option<&Bound<'_, PyList>>,
    last_event_id_slot: Option<usize>,
    maximum_line_bytes: usize,
    maximum_event_bytes: usize,
    idle_timeout: Option<&Bound<'_, PyAny>>,
    initial_retry: &Bound<'_, PyAny>,
    min_retry: Option<&Bound<'_, PyAny>>,
    max_reconnects: &Bound<'_, PyAny>,
    timeouts: Option<configuration::TimeoutFields>,
    inherit_proxy: bool,
    proxy: Option<&str>,
    proxy_username: Option<&str>,
    proxy_password: Option<&str>,
    header_hooks: Option<PyRef<'_, header_hook::NativeHeaderHooks>>,
) -> PyResult<Bound<'py, PyAny>> {
    let protocol = match protocol {
        "h1" => HttpProtocol::Http1,
        "h2" => HttpProtocol::Http2,
        "h3" => HttpProtocol::Http3,
        _ => return Err(error::input("invalid_protocol")),
    };
    let maximum = max_reconnects
        .cast_exact::<PyInt>()
        .map_err(|_| error::input("invalid_sse_reconnects"))?
        .extract::<usize>()
        .map_err(|_| error::input("invalid_sse_reconnects"))?;
    let mut request = client
        .event_source(protocol, url)
        .map_err(error::request)?
        .limits(SseLimits::new(maximum_line_bytes, maximum_event_bytes))
        .max_reconnects(maximum)
        .initial_retry(duration(initial_retry)?);
    if let Some(timeout) = idle_timeout {
        request = request.idle_timeout(duration(timeout)?);
    }
    if let Some(minimum) = min_retry {
        request = request.min_retry(duration(minimum)?);
    }
    if let Some(headers) = headers {
        let (headers, _) = request_fields::headers(headers, None)?;
        if last_event_id_slot.is_some_and(|index| index >= headers.len()) {
            return Err(error::input("invalid_sse_header_slot"));
        }
        if let Some(index) = last_event_id_slot {
            let header = headers
                .get(index)
                .ok_or_else(|| error::input("invalid_sse_header_slot"))?;
            if !header.value().is_empty() || header.is_sensitive() {
                return Err(error::input("invalid_sse_header_slot"));
            }
        }
        request = request.headers(
            headers
                .into_iter()
                .enumerate()
                .map(|(index, header)| {
                    if last_event_id_slot == Some(index) {
                        SseHeader::last_event_id(header.name())
                    } else {
                        SseHeader::field(header)
                    }
                })
                .collect(),
        );
    } else if last_event_id_slot.is_some() {
        return Err(error::input("invalid_sse_header_slot"));
    }
    if let Some(timeouts) = timeouts {
        if timeouts.iter().any(|(name, _)| name == "read_idle") {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "EventSource uses idle_timeout instead of timeouts.read_idle",
            ));
        }
        request = request.request_timeouts(configuration::request_timeouts(None, Some(timeouts))?);
    }
    if !inherit_proxy {
        request = request.route(configuration::route(proxy, proxy_username, proxy_password)?);
    } else if proxy.is_some() || proxy_username.is_some() || proxy_password.is_some() {
        return Err(error::input("invalid_sse_proxy"));
    }
    let mut hook_guard = header_hook::Guard(None);
    if let Some(hooks) = header_hooks {
        if !hooks.owner.is_source() || hooks.redirects {
            return Err(error::input("invalid_sse_header_hooks"));
        }
        for index in 0..hooks.count {
            let owner = Arc::clone(&hooks.owner);
            request = request.async_header_hook(move |context| {
                let owner = Arc::clone(&owner);
                Box::pin(async move { owner.run(index, context, (0, 0)).await })
            });
        }
        if hooks.logical != 0 {
            request = request.async_request_hooks(header_hook::LogicalHooks {
                owner: Arc::clone(&hooks.owner),
                phases: hooks.logical,
            });
        }
        hook_guard.0 = Some(Arc::clone(&hooks.owner));
    }
    let admission = lifecycle.admit("request")?;
    let lifecycle = Arc::clone(lifecycle);
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let mut hook_guard = hook_guard;
        let response = tokio::select! {
            biased;
            () = admission.aborted() => return Err(error::NativeError::new_err(("request", "client_closed", None::<String>, None::<String>))),
            result = request.connect() => result.map_err(failure)?,
        };
        let status = response.status().as_u16();
        let protocol = response::response_protocol(response.version()).to_owned();
        let headers = response::response_headers(response.extensions())?;
        let url = response::response_info(response.extensions())?
            .effective_uri()
            .to_string();
        let source = response.into_body();
        let closed = source.is_closed();
        let owner = Arc::new(Owner {
            state: Mutex::new(State {
                last_event_id: source.last_event_id().to_owned(),
                retry_ms: source.retry_delay().as_millis(),
                reconnects: source.reconnects(),
                source: (!closed).then_some(source),
                admission: (!closed).then_some(admission),
                registration: None,
                leased: false,
                terminal: if closed {
                    Terminal::Closed
                } else {
                    Terminal::Open
                },
            }),
            changed: Notify::new(),
            hooks: hook_guard.0.take(),
        });
        if closed && let Some(hooks) = &owner.hooks {
            hooks.close();
        }
        let registration = lifecycle.event_source(Arc::downgrade(&owner));
        {
            let mut state = owner.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.terminal == Terminal::Open {
                state.registration = Some(registration);
            }
        }
        Ok(NativeEventSource {
            status,
            protocol,
            url,
            headers,
            owner,
        })
    })
}

fn failure(failure: SseError) -> PyErr {
    let kind = match failure.kind() {
        SseErrorKind::Request => "request",
        SseErrorKind::InvalidRequestHeader => "invalid_request_header",
        SseErrorKind::InvalidReconnectDelay => "invalid_reconnect_delay",
        SseErrorKind::InvalidIdleTimeout => "invalid_idle_timeout",
        SseErrorKind::UnexpectedStatus => "unexpected_status",
        SseErrorKind::InvalidContentType => "invalid_content_type",
        SseErrorKind::UnsupportedContentEncoding => "unsupported_content_encoding",
        SseErrorKind::LineTooLong => "line_too_long",
        SseErrorKind::EventTooLarge => "event_too_large",
        SseErrorKind::Body => "body",
        SseErrorKind::IdleTimeout => "idle_timeout",
        SseErrorKind::ReconnectLimit => "reconnect_limit",
        _ => "unknown",
    };
    let result = error::NativeError::new_err(("sse", kind, None::<String>, None::<String>));
    if let Some(source) = std::error::Error::source(&failure)
        .and_then(|source| source.downcast_ref::<phantom::RequestError>())
    {
        let original = error::request_ref(source);
        if let Err(error) =
            Python::attach(|py| result.value(py).setattr("original", original.value(py)))
        {
            return error;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        future::{Future, poll_fn},
        pin::pin,
        sync::{
            Arc, Condvar, Mutex, PoisonError,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        task::Poll,
        thread,
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{Lease, Owner, State, Terminal};
    use crate::lifecycle::Lifecycle;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Default)]
    struct DropGate {
        armed: AtomicBool,
        released: Mutex<bool>,
        changed: Condvar,
    }

    impl DropGate {
        fn release(&self) {
            *self.released.lock().unwrap_or_else(PoisonError::into_inner) = true;
            self.changed.notify_all();
        }
    }

    struct ReleaseOnDrop(Arc<DropGate>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    struct SourceDrop {
        gate: Arc<DropGate>,
        entered: mpsc::Sender<()>,
    }

    impl Drop for SourceDrop {
        fn drop(&mut self) {
            if !self.gate.armed.load(Ordering::Acquire) {
                return;
            }
            // The receiver may have gone away after a failed test assertion.
            let _ = self.entered.send(());
            let mut released = self
                .gate
                .released
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            while !*released {
                released = self
                    .gate
                    .changed
                    .wait(released)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }

    async fn source_owner(probe: SourceDrop, lifecycle: &Arc<Lifecycle>) -> TestResult<Arc<Owner>> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}/events", listener.local_addr()?);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                head.push(stream.read_u8().await?);
            }
            assert!(head.starts_with(b"GET /events HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndata:x\n\n").await?;
            stream.shutdown().await
        });
        let client = phantom::Client::builder(phantom_profile::browser::chrome::v154_windows())
            .route(phantom::Route::direct())
            .build()?;
        let opening = client
            .event_source(phantom::HttpProtocol::Http1, &url)?
            .header_hook(move |_| {
                let _probe = &probe;
                Ok(())
            })
            .connect();
        let response = tokio::time::timeout(Duration::from_secs(5), opening).await??;
        tokio::time::timeout(Duration::from_secs(5), peer).await???;
        let source = response.into_body();
        let owner = Arc::new(Owner {
            state: Mutex::new(State {
                last_event_id: source.last_event_id().to_owned(),
                retry_ms: source.retry_delay().as_millis(),
                reconnects: source.reconnects(),
                source: Some(source),
                admission: Some(lifecycle.admit("request")?),
                registration: None,
                leased: false,
                terminal: Terminal::Open,
            }),
            changed: tokio::sync::Notify::new(),
            hooks: None,
        });
        owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .registration = Some(lifecycle.event_source(Arc::downgrade(&owner)));
        Ok(owner)
    }

    async fn assert_pending(future: impl Future) {
        let mut future = pin!(future);
        assert!(poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
    }

    fn cleanup_waits_for_source_drop(leased: bool) -> TestResult {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let gate = Arc::new(DropGate::default());
            let _release = ReleaseOnDrop(Arc::clone(&gate));
            let (entered, started) = mpsc::channel();
            let lifecycle = Arc::new(Lifecycle::default());
            let owner = source_owner(
                SourceDrop {
                    gate: Arc::clone(&gate),
                    entered,
                },
                &lifecycle,
            )
            .await?;
            gate.armed.store(true, Ordering::Release);
            let worker = if leased {
                let lease = Lease::take(&owner)?;
                owner.close();
                thread::spawn(move || drop(lease))
            } else {
                let owner = Arc::clone(&owner);
                thread::spawn(move || owner.close())
            };
            started.recv_timeout(Duration::from_secs(5))?;
            assert!(
                owner.state.try_lock().is_ok(),
                "source destructor holds owner lock"
            );
            assert_pending(owner.idle()).await;
            assert_pending(owner.drained()).await;
            assert_pending(lifecycle.drained()).await;
            owner.close();
            assert!(Lease::take(&owner).is_err());
            assert_pending(owner.idle()).await;
            gate.release();
            worker
                .join()
                .map_err(|_| std::io::Error::other("source cleanup thread panicked"))?;
            tokio::time::timeout(Duration::from_secs(1), owner.idle()).await?;
            tokio::time::timeout(Duration::from_secs(1), owner.drained()).await?;
            tokio::time::timeout(Duration::from_secs(1), lifecycle.drained()).await?;
            Ok(())
        })
    }

    #[test]
    fn idle_close_waits_for_actual_source_destruction_outside_owner_lock() -> TestResult {
        cleanup_waits_for_source_drop(false)
    }

    #[test]
    fn closed_read_lease_waits_for_actual_source_destruction_outside_owner_lock() -> TestResult {
        cleanup_waits_for_source_drop(true)
    }
}
