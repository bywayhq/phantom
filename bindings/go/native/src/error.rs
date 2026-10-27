use phantom::{RequestError, RequestErrorKind};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Failure {
    pub(super) kind: &'static str,
    pub(super) protocol: Option<&'static str>,
    pub(super) timeout_phase: Option<&'static str>,
}

impl Failure {
    pub(super) const fn new(kind: &'static str) -> Self {
        Self {
            kind,
            protocol: None,
            timeout_phase: None,
        }
    }
}

impl From<phantom::BuildError> for Failure {
    fn from(error: phantom::BuildError) -> Self {
        if let Some(cause) = std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<phantom::ClientCertificateError>())
        {
            return crate::client_certificate::failure(cause);
        }
        Self::new(match error.kind() {
            phantom::BuildErrorKind::InvalidBaseUrl => "invalid_base_url",
            phantom::BuildErrorKind::TrustStore => "invalid_trust_store",
            _ => "invalid_client_configuration",
        })
    }
}

impl From<RequestError> for Failure {
    fn from(error: RequestError) -> Self {
        Self::from(&error)
    }
}

impl From<&RequestError> for Failure {
    fn from(error: &RequestError) -> Self {
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
        Self {
            kind,
            protocol: error.protocol().map(super::client::protocol_name),
            timeout_phase: error.timeout_phase().map(|phase| match phase {
                phantom::TimeoutPhase::PoolAdmission => "pool_admission",
                phantom::TimeoutPhase::Connect => "connect",
                phantom::TimeoutPhase::ResponseHead => "response_head",
                phantom::TimeoutPhase::ReadIdle => "read_idle",
                phantom::TimeoutPhase::Total => "total",
                _ => "unknown",
            }),
        }
    }
}
