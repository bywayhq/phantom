//! Redacted failures for the JavaScript adapter.

use napi::{Error, Status};

pub(crate) fn failure(code: &str, message: &str) -> Error {
    // The JS facade turns this private transport prefix into PhantomError.code.
    Error::new(Status::GenericFailure, format!("PHANTOM:{code}:{message}"))
}

pub(crate) fn request(error: phantom::RequestError) -> Error {
    let protocol = match error.protocol() {
        Some(phantom::HttpProtocol::Http1) => "http1",
        Some(phantom::HttpProtocol::Http2) => "http2",
        Some(phantom::HttpProtocol::Http3) => "http3",
        _ => "",
    };
    let phase = match error.timeout_phase() {
        Some(phantom::TimeoutPhase::PoolAdmission) => "poolAdmission",
        Some(phantom::TimeoutPhase::Connect) => "connect",
        Some(phantom::TimeoutPhase::ResponseHead) => "responseHead",
        Some(phantom::TimeoutPhase::ReadIdle) => "readIdle",
        Some(phantom::TimeoutPhase::Total) => "total",
        Some(phantom::TimeoutPhase::WebSocketHandshake) => "webSocketHandshake",
        _ => "",
    };
    Error::new(
        Status::GenericFailure,
        format!(
            "PHANTOM_REQUEST:{:?}:{protocol}:{phase}:{error}",
            error.kind()
        ),
    )
}

pub(crate) fn total_timeout() -> Error {
    Error::new(
        Status::GenericFailure,
        "PHANTOM_REQUEST:Timeout::total:request deadline expired",
    )
}
