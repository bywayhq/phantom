//! Owned WebSocket halves with one in-flight operation in each direction.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use phantom::{
    Bytes, HttpProtocol, WebSocket, WebSocketCloseFrame, WebSocketError, WebSocketLimits,
    WebSocketMessage, WebSocketRetryPolicy,
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyInt, PyList},
};
use tokio::sync::Notify;

use crate::{
    error,
    lifecycle::{Admission, Lifecycle, Registration},
    request_fields, runtime,
};

type Writer = SplitSink<WebSocket, WebSocketMessage>;
type Reader = SplitStream<WebSocket>;
type NativeMessage = (&'static str, Py<PyAny>, Option<u16>);

fn failure(kind: &str) -> PyErr {
    error::NativeError::new_err(("websocket", kind.to_owned(), None::<String>, None::<String>))
}

fn websocket_error(error: WebSocketError) -> PyErr {
    error_details(&error)
}

fn error_details(error: &WebSocketError) -> PyErr {
    use phantom::WebSocketErrorKind as Kind;
    let kind = match error.kind() {
        Kind::ServerPinPolicy => "server_pin_policy",
        Kind::SessionTickets => "session_tickets",
        Kind::InvalidUri => "invalid_uri",
        Kind::UnsupportedScheme => "unsupported_scheme",
        Kind::InvalidAuthority => "invalid_authority",
        Kind::InvalidRequest => "invalid_request",
        Kind::ProtocolUnavailable => "protocol_unavailable",
        Kind::UnsupportedRoute => "unsupported_route",
        Kind::RuntimeUnavailable => "runtime_unavailable",
        Kind::Connect => "connect",
        Kind::Proxy => "proxy",
        Kind::Tls => "tls",
        Kind::Http1 => "http1",
        Kind::Http2 => "http2",
        Kind::Http3 => "http3",
        Kind::Random => "random",
        Kind::Timeout => "timeout",
        Kind::HandshakeRejected => "handshake_rejected",
        Kind::InvalidHandshake => "invalid_handshake",
        Kind::Capacity => "capacity",
        Kind::ClientClosed => "client_closed",
        Kind::AttemptBudgetExhausted => "attempt_budget_exhausted",
        Kind::Protocol => "protocol",
        Kind::InvalidUtf8 => "invalid_utf8",
        Kind::Io => "io",
        Kind::AbnormalClosure => "abnormal_closure",
        Kind::Closed => "closed",
        Kind::DestinationDenied => "destination_denied",
        _ => "unknown",
    };
    let phase = error.timeout_phase().map(error::timeout_phase);
    error::NativeError::new_err(("websocket", kind, None::<String>, phase))
}

fn handshake_error(error: WebSocketError, url: String, lifecycle: &Arc<Lifecycle>) -> PyErr {
    let failure = error_details(&error);
    let Some(response) = error.into_response() else {
        return failure;
    };
    let retained =
        crate::response::NativeResponse::websocket_rejection(response, url).and_then(|response| {
            response.track(lifecycle);
            Python::attach(|py| {
                failure
                    .value(py)
                    .setattr("response", Py::new(py, response)?)
            })
        });
    match retained {
        Ok(()) => failure,
        Err(error) => error,
    }
}

pub(super) struct Owner {
    writer: Mutex<Option<Writer>>,
    reader: Mutex<Option<Reader>>,
    closed: AtomicBool,
    changed: Notify,
    registration: Mutex<Option<Registration>>,
}

impl Owner {
    pub(super) fn abort(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.changed.notify_waiters();
    }

    async fn closed(&self) {
        let notified = self.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.closed.load(Ordering::SeqCst) {
            notified.await;
        }
    }
}

/// Cancellation drops the leased half and wakes any operation on its sibling.
struct Lease<T> {
    owner: Arc<Owner>,
    stream: Option<T>,
    restored: bool,
}

impl<T> Lease<T> {
    fn take(owner: &Arc<Owner>, slot: &Mutex<Option<T>>, busy: &str) -> PyResult<Self> {
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if owner.closed.load(Ordering::SeqCst) {
            return Err(failure("closed"));
        }
        let stream = slot.take().ok_or_else(|| failure(busy))?;
        Ok(Self {
            owner: Arc::clone(owner),
            stream: Some(stream),
            restored: false,
        })
    }

    fn restore(mut self, slot: &Mutex<Option<T>>) -> PyResult<()> {
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if self.owner.closed.load(Ordering::SeqCst) {
            return Err(failure("closed"));
        }
        *slot = self.stream.take();
        self.restored = true;
        Ok(())
    }
}

impl<T> Drop for Lease<T> {
    fn drop(&mut self) {
        if !self.restored {
            self.owner.abort();
        }
    }
}

#[pyclass]
pub(super) struct NativeWebSocket {
    owner: Arc<Owner>,
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    protocol: &'static str,
    #[pyo3(get)]
    selected_protocol: Option<String>,
    headers: Vec<(String, Vec<u8>, bool)>,
    maximum: usize,
}

impl NativeWebSocket {
    fn new(socket: WebSocket) -> PyResult<Self> {
        let response = socket.handshake_response();
        let status = response.status().as_u16();
        let protocol = match response.version() {
            http::Version::HTTP_11 => "h1",
            http::Version::HTTP_2 => "h2",
            http::Version::HTTP_3 => "h3",
            _ => "unknown",
        };
        let headers = response
            .extensions()
            .get::<phantom::OrderedResponseHeaders>()
            .map(|headers| {
                headers
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
        let selected_protocol = socket.selected_protocol().map(str::to_owned);
        let maximum = socket.limits().max_message_size().get();
        let (writer, reader) = socket.split();
        Ok(Self {
            owner: Arc::new(Owner {
                writer: Mutex::new(Some(writer)),
                reader: Mutex::new(Some(reader)),
                closed: AtomicBool::new(false),
                changed: Notify::new(),
                registration: Mutex::new(None),
            }),
            status,
            protocol,
            selected_protocol,
            headers,
            maximum,
        })
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        message: WebSocketMessage,
    ) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        let mut lease = Lease::take(&owner, &owner.writer, "concurrent_send")?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let stream = lease.stream.as_mut().ok_or_else(|| failure("closed"))?;
            tokio::select! {
                biased;
                () = owner.closed() => return Err(failure("closed")),
                result = stream.send(message) => result.map_err(websocket_error)?,
            }
            lease.restore(&owner.writer)
        })
    }
}

#[pymethods]
impl NativeWebSocket {
    #[getter]
    fn is_closed(&self) -> bool {
        self.owner.closed.load(Ordering::SeqCst)
    }

    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> Vec<(String, Bound<'py, PyBytes>, bool)> {
        self.headers
            .iter()
            .map(|(name, value, sensitive)| (name.clone(), PyBytes::new(py, value), *sensitive))
            .collect()
    }

    fn abort(&self) {
        self.owner.abort();
    }

    fn send<'py>(&self, py: Python<'py>, data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let message = if let Ok(data) = data.cast::<PyBytes>() {
            if data.as_bytes().len() > self.maximum {
                return Err(failure("capacity"));
            }
            WebSocketMessage::Binary(Bytes::copy_from_slice(data.as_bytes()))
        } else if let Ok(data) = data.cast::<pyo3::types::PyString>() {
            if data.len()? > self.maximum {
                return Err(failure("capacity"));
            }
            let data = data.to_str()?;
            if data.len() > self.maximum {
                return Err(failure("capacity"));
            }
            WebSocketMessage::Text(data.to_owned())
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "WebSocket data must be str or bytes",
            ));
        };
        self.write(py, message)
    }

    fn ping<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if data.as_bytes().len() > 125 {
            return Err(failure("capacity"));
        }
        self.write(
            py,
            WebSocketMessage::Ping(Bytes::copy_from_slice(data.as_bytes())),
        )
    }

    fn pong<'py>(
        &self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if data.as_bytes().len() > 125 {
            return Err(failure("capacity"));
        }
        self.write(
            py,
            WebSocketMessage::Pong(Bytes::copy_from_slice(data.as_bytes())),
        )
    }

    #[pyo3(signature = (code, reason))]
    fn close<'py>(
        &self,
        py: Python<'py>,
        code: Option<u16>,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        if reason.len() > 123 {
            return Err(failure("capacity"));
        }
        let frame = match code {
            Some(code) => Some(WebSocketCloseFrame::new(code, reason).map_err(websocket_error)?),
            None if reason.is_empty() => None,
            None => return Err(error::input("websocket_close_reason_requires_code")),
        };
        self.write(py, WebSocketMessage::Close(frame))
    }

    fn receive<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        let mut lease = Lease::take(&owner, &owner.reader, "concurrent_receive")?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let stream = lease.stream.as_mut().ok_or_else(|| failure("closed"))?;
            let message = tokio::select! {
                biased;
                () = owner.closed() => return Err(failure("closed")),
                result = stream.next() => result.ok_or_else(|| failure("closed"))?.map_err(websocket_error)?,
            };
            let terminal = matches!(message, WebSocketMessage::Close(_));
            let output = Python::attach(|py| -> PyResult<NativeMessage> {
                Ok(match message {
                    WebSocketMessage::Text(text) => {
                        ("text", text.into_pyobject(py)?.unbind().into_any(), None)
                    }
                    WebSocketMessage::Binary(data) => {
                        ("binary", PyBytes::new(py, &data).unbind().into_any(), None)
                    }
                    WebSocketMessage::Ping(data) => {
                        ("ping", PyBytes::new(py, &data).unbind().into_any(), None)
                    }
                    WebSocketMessage::Pong(data) => {
                        ("pong", PyBytes::new(py, &data).unbind().into_any(), None)
                    }
                    WebSocketMessage::Close(frame) => match frame {
                        Some(frame) => (
                            "close",
                            frame.reason().into_pyobject(py)?.unbind().into_any(),
                            Some(frame.code()),
                        ),
                        None => ("close", py.None(), None),
                    },
                    _ => return Err(failure("unknown_message")),
                })
            })?;
            if terminal {
                owner.abort();
            } else {
                lease.restore(&owner.reader)?;
            }
            Ok(output)
        })
    }
}

impl Drop for NativeWebSocket {
    fn drop(&mut self) {
        self.owner.abort();
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn connect<'py>(
    client: &phantom::Client,
    admission: Admission,
    py: Python<'py>,
    url: &str,
    protocol: &str,
    headers: &Bound<'py, PyList>,
    maximum_frame_bytes: &Bound<'py, PyAny>,
    maximum_message_bytes: &Bound<'py, PyAny>,
    maximum_fragments: &Bound<'py, PyAny>,
    inherit_handshake_timeout: bool,
    handshake_timeout_ms: Option<&Bound<'py, PyAny>>,
    maximum_connection_failures: Option<&Bound<'py, PyAny>>,
    retry_delay_ms: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if url.len() > 65536 {
        return Err(error::input("url_limit"));
    }
    let positive = |value: &Bound<'_, PyAny>| -> PyResult<NonZeroUsize> {
        value
            .cast_exact::<PyInt>()
            .ok()
            .and_then(|value| value.extract::<usize>().ok())
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| error::input("invalid_websocket_limit"))
    };
    let limits = WebSocketLimits::new(
        positive(maximum_frame_bytes)?,
        positive(maximum_message_bytes)?,
    )
    .map_err(websocket_error)?
    .with_max_message_fragments(positive(maximum_fragments)?);
    let mut request = match protocol {
        "profile" => client.websocket_with_profile_policy(url),
        "h1" => client.websocket(url),
        "h2" => client.websocket_with_protocol(HttpProtocol::Http2, url),
        "h3" => client.websocket_with_protocol(HttpProtocol::Http3, url),
        _ => return Err(error::input("invalid_websocket_protocol")),
    }
    .map_err(websocket_error)?
    .limits(limits);
    for header in request_fields::headers(headers, None)?.0 {
        request = request.header(header);
    }
    let unsigned = |value: &Bound<'_, PyAny>| -> PyResult<u64> {
        value
            .cast_exact::<PyInt>()
            .ok()
            .and_then(|value| value.extract::<u64>().ok())
            .ok_or_else(|| error::input("invalid_websocket_duration"))
    };
    if !inherit_handshake_timeout {
        request = request.handshake_timeout(
            handshake_timeout_ms
                .map(|value| {
                    unsigned(value).and_then(|value| {
                        if value == 0 {
                            Err(error::input("invalid_websocket_timeout"))
                        } else {
                            Ok(Duration::from_millis(value))
                        }
                    })
                })
                .transpose()?,
        );
    }
    let delay = Duration::from_millis(unsigned(retry_delay_ms)?);
    if let Some(maximum) = maximum_connection_failures {
        request = request.retry_policy(WebSocketRetryPolicy::connection_failures(
            positive(maximum)?,
            delay,
        ));
    }
    let url = url.to_owned();
    runtime::initialize()?;
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let opening = async {
            let socket = request
                .connect()
                .await
                .map_err(|error| handshake_error(error, url, admission.lifecycle()))
                .and_then(NativeWebSocket::new)?;
            let registration = admission.lifecycle().socket(Arc::downgrade(&socket.owner));
            let mut retained = socket
                .owner
                .registration
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !socket.owner.closed.load(Ordering::SeqCst) {
                *retained = Some(registration);
            }
            drop(retained);
            Ok(socket)
        };
        tokio::select! {
            biased;
            () = admission.aborted() => Err(failure("client_closed")),
            result = opening => result,
        }
    })
}
