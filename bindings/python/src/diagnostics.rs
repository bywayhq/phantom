//! A single attachment owns a live core observer independently of the response.

use crate::error;
use phantom::{
    ConnectionEndpointScope, RequestConnection, RequestDiagnostics, RequestTimelineOutcome,
    RequestTiming, RequestTimingOutcome, RequestTimingPhase, TlsConnectionState,
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyInt},
};
use std::{num::NonZeroUsize, sync::Mutex};

type TlsInfo = (
    bool,
    Option<u16>,
    Option<u16>,
    Option<Py<PyBytes>>,
    bool,
    Option<Vec<Py<PyBytes>>>,
);
type TlsState = (&'static str, Option<TlsInfo>);
type Connection = (
    bool,
    &'static str,
    Option<String>,
    Option<String>,
    TlsState,
    TlsState,
);
type Event = (
    usize,
    usize,
    Option<usize>,
    Option<&'static str>,
    &'static str,
    u128,
    Option<u128>,
    &'static str,
    Option<Connection>,
);
type Timeline = (&'static str, Option<u128>, Vec<Event>, usize, usize);

fn unsupported() -> PyErr {
    error::input("unsupported_diagnostics_value")
}

fn tls(py: Python<'_>, state: &TlsConnectionState) -> PyResult<TlsState> {
    Ok(match state {
        TlsConnectionState::NotUsed => ("not_used", None),
        TlsConnectionState::Unavailable => ("unavailable", None),
        TlsConnectionState::Pending => ("pending", None),
        TlsConnectionState::Established(info) => (
            "established",
            Some((
                info.peer_verified,
                info.version.map(|value| value.protocol_id()),
                info.cipher_suite.map(|value| value.iana_id()),
                info.alpn
                    .as_ref()
                    .map(|value| PyBytes::new(py, value).unbind()),
                info.session_resumed,
                info.peer_certificates.as_ref().map(|chain| {
                    chain
                        .iter()
                        .map(|der| PyBytes::new(py, der).unbind())
                        .collect()
                }),
            )),
        ),
        _ => return Err(unsupported()),
    })
}

fn connection(py: Python<'_>, value: &RequestConnection) -> PyResult<Connection> {
    let scope = match value.endpoint_scope {
        ConnectionEndpointScope::Unavailable => "unavailable",
        ConnectionEndpointScope::TcpSocket => "tcp_socket",
        ConnectionEndpointScope::QuicEndpoint => "quic_endpoint",
        _ => return Err(unsupported()),
    };
    Ok((
        value.reused,
        scope,
        value.local_address.map(|address| address.to_string()),
        value.peer_address.map(|address| address.to_string()),
        tls(py, &value.origin_tls)?,
        tls(py, &value.proxy_tls)?,
    ))
}

fn event(py: Python<'_>, value: RequestTiming) -> PyResult<Event> {
    let phase = match value.phase {
        RequestTimingPhase::AttemptAdmission => "attempt_admission",
        RequestTimingPhase::PoolAdmission => "pool_admission",
        RequestTimingPhase::ConnectionAcquisition => "connection_acquisition",
        RequestTimingPhase::ConnectionUse => "connection_use",
        RequestTimingPhase::ResolutionWait => "resolution_wait",
        RequestTimingPhase::TcpConnect => "tcp_connect",
        RequestTimingPhase::TlsHandshake => "tls_handshake",
        RequestTimingPhase::QuicHandshake => "quic_handshake",
        RequestTimingPhase::SendResponseHead => "send_response_head",
        RequestTimingPhase::ResponseBody => "response_body",
        _ => return Err(unsupported()),
    };
    let outcome = match value.outcome {
        RequestTimingOutcome::Pending => "pending",
        RequestTimingOutcome::Completed => "completed",
        RequestTimingOutcome::Failed => "failed",
        RequestTimingOutcome::Interrupted => "interrupted",
        RequestTimingOutcome::Abandoned => "abandoned",
        RequestTimingOutcome::Cached => "cached",
        RequestTimingOutcome::EarlyData => "early_data",
        _ => return Err(unsupported()),
    };
    let protocol = value
        .protocol
        .map(|version| match version {
            http::Version::HTTP_09 => Ok("h0.9"),
            http::Version::HTTP_10 => Ok("h1.0"),
            http::Version::HTTP_11 => Ok("h1"),
            http::Version::HTTP_2 => Ok("h2"),
            http::Version::HTTP_3 => Ok("h3"),
            _ => Err(unsupported()),
        })
        .transpose()?;
    Ok((
        value.id,
        value.hop,
        value.admission,
        protocol,
        phase,
        value.started.as_nanos(),
        value.finished.map(|duration| duration.as_nanos()),
        outcome,
        value
            .connection
            .as_ref()
            .map(|value| connection(py, value))
            .transpose()?,
    ))
}

#[pyclass(frozen)]
pub(super) struct NativeRequestDiagnostics {
    maximum_events: NonZeroUsize,
    observer: Mutex<Option<RequestDiagnostics>>,
}

impl NativeRequestDiagnostics {
    pub(super) fn attach(&self, request: &mut phantom::RequestBuilder) -> PyResult<()> {
        let mut observer = self
            .observer
            .lock()
            .map_err(|_| error::input("diagnostics_state"))?;
        if observer.is_some() {
            return Err(error::input("diagnostics_already_attached"));
        }
        *observer = Some(request.diagnostics(self.maximum_events));
        Ok(())
    }
}

#[pymethods]
impl NativeRequestDiagnostics {
    #[new]
    fn new(maximum_events: &Bound<'_, PyAny>) -> PyResult<Self> {
        let capacity = maximum_events
            .cast_exact::<PyInt>()
            .map_err(|_| error::input("invalid_diagnostics_capacity"))?
            .extract::<usize>()
            .map_err(|_| error::input("invalid_diagnostics_capacity"))?;
        Ok(Self {
            maximum_events: NonZeroUsize::new(capacity)
                .ok_or_else(|| error::input("invalid_diagnostics_capacity"))?,
            observer: Mutex::new(None),
        })
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Option<Timeline>> {
        let observer = self
            .observer
            .lock()
            .map_err(|_| error::input("diagnostics_state"))?
            .clone();
        let Some(observer) = observer else {
            return Ok(None);
        };
        let snapshot = observer.snapshot();
        let outcome = match snapshot.outcome {
            RequestTimelineOutcome::NotStarted => "not_started",
            RequestTimelineOutcome::Pending => "pending",
            RequestTimelineOutcome::ResponseHead => "response_head",
            RequestTimelineOutcome::Failed => "failed",
            RequestTimelineOutcome::Cancelled => "cancelled",
            _ => return Err(unsupported()),
        };
        Ok(Some((
            outcome,
            snapshot.send_elapsed.map(|duration| duration.as_nanos()),
            snapshot
                .events
                .into_iter()
                .map(|value| event(py, value))
                .collect::<PyResult<_>>()?,
            snapshot.dropped_events,
            snapshot.admitted_attempts,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unattached_snapshot_differs_from_unpolled_core_observer() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let observer = NativeRequestDiagnostics {
                maximum_events: NonZeroUsize::MIN,
                observer: Mutex::new(None),
            };
            assert!(observer.snapshot(py)?.is_none());
            *observer
                .observer
                .lock()
                .map_err(|_| error::input("test_diagnostics_state"))? =
                Some(RequestDiagnostics::new(NonZeroUsize::MIN));
            let snapshot = observer
                .snapshot(py)?
                .ok_or_else(|| error::input("test_missing_snapshot"))?;
            assert_eq!(snapshot.0, "not_started");
            assert!(snapshot.1.is_none());
            assert!(snapshot.2.is_empty());
            assert_eq!((snapshot.3, snapshot.4), (0, 0));
            Ok(())
        })
    }

    #[test]
    fn event_offsets_keep_more_than_u64_nanoseconds_and_absent_fields() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let duration = Duration::new(u64::MAX, 999_999_999);
            let value = event(
                py,
                RequestTiming {
                    id: 3,
                    hop: 2,
                    admission: None,
                    protocol: Some(http::Version::HTTP_3),
                    phase: RequestTimingPhase::QuicHandshake,
                    started: duration,
                    finished: None,
                    outcome: RequestTimingOutcome::Pending,
                    connection: None,
                },
            )?;
            assert_eq!(value.3, Some("h3"));
            assert_eq!(value.4, "quic_handshake");
            assert_eq!(value.5, duration.as_nanos());
            assert!(value.5 > u128::from(u64::MAX));
            assert!(value.2.is_none() && value.6.is_none() && value.8.is_none());
            for (state, expected) in [
                (TlsConnectionState::NotUsed, "not_used"),
                (TlsConnectionState::Unavailable, "unavailable"),
                (TlsConnectionState::Pending, "pending"),
            ] {
                let mapped = tls(py, &state)?;
                assert_eq!(mapped.0, expected);
                assert!(mapped.1.is_none());
            }
            Ok(())
        })
    }
}
