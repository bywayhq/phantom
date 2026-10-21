//! Owned single-request observations; no JavaScript references or callbacks.

use std::{
    num::NonZeroUsize,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use napi::{Result, bindgen_prelude::BigInt};
use phantom::{
    ConnectionEndpointScope, RequestBuilder, RequestDiagnostics, RequestTimelineOutcome,
    RequestTimingOutcome, RequestTimingPhase, TlsConnectionState,
};

use crate::{
    error::failure,
    ffi::{
        DiagnosticConnectionInfo, DiagnosticEventInfo, DiagnosticTimelineInfo, DiagnosticTlsInfo,
        DiagnosticTlsState,
    },
};

const MAXIMUM_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Diagnostics {
    capacity: NonZeroUsize,
    observer: Mutex<Option<RequestDiagnostics>>,
}

impl Diagnostics {
    pub(crate) fn new(maximum: BigInt) -> Result<Self> {
        let capacity = crate::ffi::positive_count(maximum).map_err(|_| {
            failure(
                "InvalidArgument",
                "maximumEvents must be a positive integer fitting usize",
            )
        })?;
        Ok(Self {
            capacity,
            observer: Mutex::new(None),
        })
    }

    pub(crate) fn attach(&self, builder: &mut RequestBuilder) -> Result<()> {
        let mut observer = self.observer.lock().unwrap_or_else(PoisonError::into_inner);
        if observer.is_some() {
            return Err(failure(
                "DiagnosticsAlreadyUsed",
                "diagnostics belong to one request",
            ));
        }
        *observer = Some(builder.diagnostics(self.capacity));
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<Option<DiagnosticTimelineInfo>> {
        let observer = self
            .observer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        observer
            .map(|observer| project(observer.snapshot()))
            .transpose()
    }
}

fn unsupported() -> napi::Error {
    failure(
        "UnsupportedDiagnosticsValue",
        "core diagnostics value is unsupported",
    )
}

fn integer(value: u128) -> BigInt {
    BigInt {
        sign_bit: false,
        words: vec![value as u64, (value >> 64) as u64],
    }
}

fn duration(value: Duration) -> BigInt {
    integer(value.as_nanos())
}

struct Budget(usize);
impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.0 = self
            .0
            .checked_sub(bytes)
            .ok_or_else(|| failure("DiagnosticsLimit", "diagnostics snapshot exceeds 16 MiB"))?;
        Ok(())
    }

    fn reserve<T>(&mut self, count: usize) -> Result<Vec<T>> {
        self.charge(
            count.checked_mul(std::mem::size_of::<T>()).ok_or_else(|| {
                failure("DiagnosticsLimit", "diagnostics snapshot exceeds 16 MiB")
            })?,
        )?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| failure("Allocation", "could not allocate diagnostics snapshot"))?;
        Ok(result)
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<napi::bindgen_prelude::Buffer> {
        let mut result = self.reserve(bytes.len())?;
        result.extend_from_slice(bytes);
        Ok(result.into())
    }

    fn text(&mut self, text: &str) -> Result<String> {
        self.charge(text.len())?;
        let mut result = String::new();
        result
            .try_reserve_exact(text.len())
            .map_err(|_| failure("Allocation", "could not allocate diagnostics snapshot"))?;
        result.push_str(text);
        Ok(result)
    }
}

fn tls(state: &TlsConnectionState, budget: &mut Budget) -> Result<DiagnosticTlsState> {
    let (state, info) = match state {
        TlsConnectionState::NotUsed => ("not_used", None),
        TlsConnectionState::Unavailable => ("unavailable", None),
        TlsConnectionState::Pending => ("pending", None),
        TlsConnectionState::Established(info) => {
            let alpn = info
                .alpn
                .as_deref()
                .map(|bytes| budget.bytes(bytes))
                .transpose()?;
            let peer_certificates_der = info
                .peer_certificates
                .as_ref()
                .map(|certificates| {
                    let mut result = budget.reserve(certificates.len())?;
                    for certificate in certificates.iter() {
                        result.push(budget.bytes(certificate)?);
                    }
                    Ok::<_, napi::Error>(result)
                })
                .transpose()?;
            (
                "established",
                Some(DiagnosticTlsInfo {
                    peer_verified: info.peer_verified,
                    version_id: info.version.map(|value| u32::from(value.protocol_id())),
                    cipher_suite_id: info.cipher_suite.map(|value| u32::from(value.iana_id())),
                    alpn,
                    session_resumed: info.session_resumed,
                    peer_certificates_der,
                }),
            )
        }
        _ => return Err(unsupported()),
    };
    Ok(DiagnosticTlsState {
        state: budget.text(state)?,
        info,
    })
}

fn connection(
    value: &phantom::RequestConnection,
    budget: &mut Budget,
) -> Result<DiagnosticConnectionInfo> {
    budget.charge(std::mem::size_of::<DiagnosticConnectionInfo>())?;
    let scope = match value.endpoint_scope {
        ConnectionEndpointScope::Unavailable => "unavailable",
        ConnectionEndpointScope::TcpSocket => "tcp_socket",
        ConnectionEndpointScope::QuicEndpoint => "quic_endpoint",
        _ => return Err(unsupported()),
    };
    Ok(DiagnosticConnectionInfo {
        reused: value.reused,
        endpoint_scope: budget.text(scope)?,
        local_address: value
            .local_address
            .map(|address| budget.text(&address.to_string()))
            .transpose()?,
        peer_address: value
            .peer_address
            .map(|address| budget.text(&address.to_string()))
            .transpose()?,
        origin_tls: tls(&value.origin_tls, budget)?,
        proxy_tls: tls(&value.proxy_tls, budget)?,
    })
}

fn phase(value: RequestTimingPhase) -> Result<&'static str> {
    Ok(match value {
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
    })
}

fn outcome(value: RequestTimingOutcome) -> Result<&'static str> {
    Ok(match value {
        RequestTimingOutcome::Pending => "pending",
        RequestTimingOutcome::Completed => "completed",
        RequestTimingOutcome::Failed => "failed",
        RequestTimingOutcome::Interrupted => "interrupted",
        RequestTimingOutcome::Abandoned => "abandoned",
        RequestTimingOutcome::Cached => "cached",
        RequestTimingOutcome::EarlyData => "early_data",
        _ => return Err(unsupported()),
    })
}

fn project(value: phantom::RequestTimeline) -> Result<DiagnosticTimelineInfo> {
    let outcome_name = match value.outcome {
        RequestTimelineOutcome::NotStarted => "not_started",
        RequestTimelineOutcome::Pending => "pending",
        RequestTimelineOutcome::ResponseHead => "response_head",
        RequestTimelineOutcome::Failed => "failed",
        RequestTimelineOutcome::Cancelled => "cancelled",
        _ => return Err(unsupported()),
    };
    let mut budget = Budget(MAXIMUM_SNAPSHOT_BYTES);
    let mut events = budget.reserve(value.events.len())?;
    for event in value.events {
        let protocol = event
            .protocol
            .map(|version| match version {
                http::Version::HTTP_10 | http::Version::HTTP_11 => Ok("h1"),
                http::Version::HTTP_2 => Ok("h2"),
                http::Version::HTTP_3 => Ok("h3"),
                _ => Err(unsupported()),
            })
            .transpose()?;
        events.push(DiagnosticEventInfo {
            id: integer(event.id as u128),
            hop: integer(event.hop as u128),
            admission: event.admission.map(|value| integer(value as u128)),
            protocol: protocol.map(|value| budget.text(value)).transpose()?,
            phase: budget.text(phase(event.phase)?)?,
            started_ns: duration(event.started),
            finished_ns: event.finished.map(duration),
            outcome: budget.text(outcome(event.outcome)?)?,
            connection: event
                .connection
                .as_deref()
                .map(|value| connection(value, &mut budget))
                .transpose()?,
        });
    }
    Ok(DiagnosticTimelineInfo {
        outcome: budget.text(outcome_name)?,
        send_elapsed_ns: value.send_elapsed.map(duration),
        events,
        dropped_events: integer(value.dropped_events as u128),
        admitted_attempts: integer(value.admitted_attempts as u128),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_preserves_high_word_and_absence() -> Result<()> {
        let duration = duration(Duration::new(u64::MAX, 999_999_999));
        assert_eq!(
            duration.words,
            vec![
                (Duration::MAX.as_nanos() & u128::from(u64::MAX)) as u64,
                (Duration::MAX.as_nanos() >> 64) as u64
            ]
        );
        let owner = Diagnostics::new(integer(1))?;
        assert!(owner.snapshot()?.is_none());
        let core = RequestDiagnostics::new(NonZeroUsize::MIN);
        let snapshot = project(core.snapshot())?;
        assert_eq!(snapshot.outcome, "not_started");
        assert!(snapshot.send_elapsed_ns.is_none());
        assert!(snapshot.events.is_empty());
        Ok(())
    }

    #[test]
    fn snapshot_limits_fail_before_copy_and_keep_tls_absence() -> Result<()> {
        let mut budget = Budget(1);
        assert!(budget.bytes(&[1, 2]).is_err());
        let state = tls(&TlsConnectionState::Unavailable, &mut Budget(64))?;
        assert_eq!(state.state, "unavailable");
        assert!(state.info.is_none());
        Ok(())
    }

    #[test]
    fn attachment_is_single_use_and_unknown_protocol_is_not_guessed() -> Result<()> {
        let owner = Diagnostics::new(integer(1))?;
        let client = phantom::Client::builder(phantom_profile::browser::chrome::v154_windows())
            .build()
            .map_err(|_| failure("Test", "could not build test client"))?;
        let mut first = client
            .get(phantom::HttpProtocol::Http1, "http://127.0.0.1/")
            .map_err(|_| failure("Test", "could not build test request"))?;
        owner.attach(&mut first)?;
        assert_eq!(
            owner.snapshot()?.map(|value| value.outcome).as_deref(),
            Some("not_started")
        );
        assert!(owner.attach(&mut first).is_err());
        let event = phantom::RequestTiming {
            id: 0,
            hop: 0,
            admission: None,
            protocol: Some(http::Version::HTTP_09),
            phase: RequestTimingPhase::SendResponseHead,
            started: Duration::ZERO,
            finished: None,
            outcome: RequestTimingOutcome::Pending,
            connection: None,
        };
        let snapshot = phantom::RequestTimeline {
            outcome: RequestTimelineOutcome::Pending,
            send_elapsed: Some(Duration::ZERO),
            events: vec![event],
            dropped_events: 0,
            admitted_attempts: 0,
        };
        let error = project(snapshot).err().ok_or_else(unsupported)?;
        assert!(
            error
                .reason
                .starts_with("PHANTOM:UnsupportedDiagnosticsValue:")
        );
        Ok(())
    }
}
