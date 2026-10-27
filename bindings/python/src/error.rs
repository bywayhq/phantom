use phantom::{RequestError, RequestErrorKind};
use pyo3::{PyErr, create_exception, exceptions::PyException};

create_exception!(_native, NativeError, PyException);

pub(super) fn certificate(kind: &'static str) -> PyErr {
    NativeError::new_err(("client_certificate", kind, None::<String>, None::<String>))
}

pub(super) fn input(kind: &'static str) -> PyErr {
    NativeError::new_err(("input", kind, None::<String>, None::<String>))
}

pub(super) fn io(_: std::io::Error) -> PyErr {
    NativeError::new_err(("io", "file_io", None::<String>, None::<String>))
}

pub(super) fn request(error: RequestError) -> PyErr {
    let kind = match error.kind() {
        RequestErrorKind::Timeout => "timeout",
        RequestErrorKind::AttemptBudgetExhausted => "attempt_budget_exhausted",
        RequestErrorKind::ClientClosed => "client_closed",
        RequestErrorKind::ResponseBodyLimit => "response_body_limit",
        RequestErrorKind::RequestBody => "request_body",
        RequestErrorKind::InvalidUri => "invalid_uri",
        RequestErrorKind::UnsupportedScheme => "unsupported_scheme",
        RequestErrorKind::InvalidAuthority => "invalid_authority",
        RequestErrorKind::InvalidHeader => "invalid_header",
        RequestErrorKind::RequestTemplate => "request_template",
        RequestErrorKind::ProtocolUnavailable => "protocol_unavailable",
        RequestErrorKind::UnsupportedRoute => "unsupported_route",
        RequestErrorKind::InvalidTarget => "invalid_target",
        RequestErrorKind::Redirect => "redirect",
        RequestErrorKind::Resolve => "resolve",
        RequestErrorKind::Connect => "connect",
        RequestErrorKind::DestinationDenied => "destination_denied",
        RequestErrorKind::Proxy => "proxy",
        RequestErrorKind::RuntimeUnavailable => "runtime_unavailable",
        RequestErrorKind::Capacity => "capacity",
        RequestErrorKind::InvalidTimeout => "invalid_timeout",
        RequestErrorKind::Tls => "tls",
        RequestErrorKind::Http1 => "http1",
        RequestErrorKind::Http2 => "http2",
        RequestErrorKind::Http3 => "http3",
        RequestErrorKind::ServerPinPolicy => "server_pin_policy",
        RequestErrorKind::SessionTickets => "session_tickets",
        RequestErrorKind::HeaderHook => "header_hook",
        RequestErrorKind::Transfer => "transfer",
        RequestErrorKind::ContentDecoding => "content_decoding",
        _ => "unknown",
    };
    let protocol = error.protocol().map(super::client::protocol_name);
    let phase = error.timeout_phase().map(timeout_phase);
    NativeError::new_err(("request", kind, protocol, phase))
}

pub(super) fn timeout_phase(phase: phantom::TimeoutPhase) -> &'static str {
    match phase {
        phantom::TimeoutPhase::PoolAdmission => "pool_admission",
        phantom::TimeoutPhase::Connect => "connect",
        phantom::TimeoutPhase::ResponseHead => "response_head",
        phantom::TimeoutPhase::ReadIdle => "read_idle",
        phantom::TimeoutPhase::Total => "total",
        phantom::TimeoutPhase::WebSocketHandshake => "websocket_handshake",
        _ => "unknown",
    }
}

/// Preparation and unread streaming responses share the original total clock.
pub(super) fn total_timeout(protocol: Option<&str>) -> PyErr {
    NativeError::new_err((
        "request",
        "timeout",
        protocol.map(str::to_owned),
        Some("total"),
    ))
}
