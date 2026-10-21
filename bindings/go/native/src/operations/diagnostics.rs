//! Caller-owned request observations, independent of request/body ownership.

use std::{
    io::{self, Write},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use phantom::{
    ConnectionEndpointScope, RequestBuilder, RequestConnection, RequestDiagnostics,
    RequestTimelineOutcome, RequestTiming, RequestTimingOutcome, RequestTimingPhase,
    TlsConnectionState,
};
use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::MAX_METADATA;
use crate::error::Failure;

pub(super) struct Owner {
    maximum: NonZeroUsize,
    observer: Mutex<Option<RequestDiagnostics>>,
}

impl Owner {
    pub(super) fn new(maximum: usize) -> Result<Self, Failure> {
        Ok(Self {
            maximum: NonZeroUsize::new(maximum)
                .ok_or_else(|| Failure::new("invalid_diagnostics_capacity"))?,
            observer: Mutex::new(None),
        })
    }

    pub(super) fn attach(&self, request: &mut RequestBuilder) -> Result<(), Failure> {
        let mut slot = self.observer.lock().map_err(|_| Failure::new("internal"))?;
        if slot.is_some() {
            return Err(Failure::new("diagnostics_already_attached"));
        }
        *slot = Some(request.diagnostics(self.maximum));
        Ok(())
    }

    pub(super) fn reply(&self) -> Result<Vec<u8>, Failure> {
        let observer = self
            .observer
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .clone();
        let timeline = observer.as_ref().map(RequestDiagnostics::snapshot);
        let value = timeline.as_ref().map(Timeline::new).transpose()?;
        let mut output = BoundedWriter(Vec::new());
        let reply = SnapshotReply { value, error: None };
        serde_json::to_writer(&mut output, &reply).map_err(|error| {
            Failure::new(
                if error.io_error_kind() == Some(io::ErrorKind::OutOfMemory) {
                    "diagnostics_allocation"
                } else {
                    "metadata_limit"
                },
            )
        })?;
        Ok(output.0)
    }
}

#[derive(Serialize)]
struct SnapshotReply<'a> {
    value: Option<Timeline<'a>>,
    error: Option<Failure>,
}

#[derive(Serialize)]
struct Elapsed {
    seconds: u64,
    nanoseconds: u32,
}

impl From<Duration> for Elapsed {
    fn from(value: Duration) -> Self {
        Self {
            seconds: value.as_secs(),
            nanoseconds: value.subsec_nanos(),
        }
    }
}

#[derive(Serialize)]
struct Timeline<'a> {
    outcome: &'static str,
    send_elapsed: Option<Elapsed>,
    events: Vec<Event<'a>>,
    dropped_events: usize,
    admitted_attempts: usize,
}

impl<'a> Timeline<'a> {
    fn new(value: &'a phantom::RequestTimeline) -> Result<Self, Failure> {
        Ok(Self {
            outcome: match value.outcome {
                RequestTimelineOutcome::NotStarted => "not_started",
                RequestTimelineOutcome::Pending => "pending",
                RequestTimelineOutcome::ResponseHead => "response_head",
                RequestTimelineOutcome::Failed => "failed",
                RequestTimelineOutcome::Cancelled => "cancelled",
                _ => return Err(unsupported()),
            },
            send_elapsed: value.send_elapsed.map(Elapsed::from),
            events: value
                .events
                .iter()
                .map(Event::new)
                .collect::<Result<_, _>>()?,
            dropped_events: value.dropped_events,
            admitted_attempts: value.admitted_attempts,
        })
    }
}

#[derive(Serialize)]
struct Event<'a> {
    id: usize,
    hop: usize,
    admission: Option<usize>,
    protocol: Option<&'static str>,
    phase: &'static str,
    started: Elapsed,
    finished: Option<Elapsed>,
    outcome: &'static str,
    connection: Option<Connection<'a>>,
}

impl<'a> Event<'a> {
    fn new(value: &'a RequestTiming) -> Result<Self, Failure> {
        Ok(Self {
            id: value.id,
            hop: value.hop,
            admission: value.admission,
            protocol: value
                .protocol
                .map(|version| match version {
                    http::Version::HTTP_10 | http::Version::HTTP_11 => Ok("h1"),
                    http::Version::HTTP_2 => Ok("h2"),
                    http::Version::HTTP_3 => Ok("h3"),
                    _ => Err(unsupported()),
                })
                .transpose()?,
            phase: phase(value.phase)?,
            started: value.started.into(),
            finished: value.finished.map(Elapsed::from),
            outcome: match value.outcome {
                RequestTimingOutcome::Pending => "pending",
                RequestTimingOutcome::Completed => "completed",
                RequestTimingOutcome::Failed => "failed",
                RequestTimingOutcome::Interrupted => "interrupted",
                RequestTimingOutcome::Abandoned => "abandoned",
                RequestTimingOutcome::Cached => "cached",
                RequestTimingOutcome::EarlyData => "early_data",
                _ => return Err(unsupported()),
            },
            connection: value
                .connection
                .as_deref()
                .map(Connection::new)
                .transpose()?,
        })
    }
}

fn phase(value: RequestTimingPhase) -> Result<&'static str, Failure> {
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

#[derive(Serialize)]
struct Connection<'a> {
    reused: bool,
    endpoint_scope: &'static str,
    local_address: Option<std::net::SocketAddr>,
    peer_address: Option<std::net::SocketAddr>,
    origin_tls: Tls<'a>,
    proxy_tls: Tls<'a>,
}

impl<'a> Connection<'a> {
    fn new(value: &'a RequestConnection) -> Result<Self, Failure> {
        Ok(Self {
            reused: value.reused,
            endpoint_scope: match value.endpoint_scope {
                ConnectionEndpointScope::Unavailable => "unavailable",
                ConnectionEndpointScope::TcpSocket => "tcp_socket",
                ConnectionEndpointScope::QuicEndpoint => "quic_endpoint",
                _ => return Err(unsupported()),
            },
            local_address: value.local_address,
            peer_address: value.peer_address,
            origin_tls: Tls::new(&value.origin_tls)?,
            proxy_tls: Tls::new(&value.proxy_tls)?,
        })
    }
}

#[derive(Serialize)]
struct Tls<'a> {
    state: &'static str,
    info: Option<TlsInfo<'a>>,
}

impl<'a> Tls<'a> {
    fn new(value: &'a TlsConnectionState) -> Result<Self, Failure> {
        let state = match value {
            TlsConnectionState::NotUsed => "not_used",
            TlsConnectionState::Unavailable => "unavailable",
            TlsConnectionState::Pending => "pending",
            TlsConnectionState::Established(_) => "established",
            _ => return Err(unsupported()),
        };
        let info = match value {
            TlsConnectionState::Established(info) => Some(TlsInfo {
                peer_verified: info.peer_verified,
                version_id: info.version.map(|value| value.protocol_id()),
                cipher_suite_id: info.cipher_suite.map(|value| value.iana_id()),
                alpn: info.alpn.as_deref(),
                session_resumed: info.session_resumed,
                peer_certificates_der: info.peer_certificates.as_deref().map(Certificates),
            }),
            _ => None,
        };
        Ok(Self { state, info })
    }
}

#[derive(Serialize)]
struct TlsInfo<'a> {
    peer_verified: bool,
    version_id: Option<u16>,
    cipher_suite_id: Option<u16>,
    alpn: Option<&'a [u8]>,
    session_resumed: bool,
    peer_certificates_der: Option<Certificates<'a>>,
}

struct Certificates<'a>(&'a [Arc<[u8]>]);

impl Serialize for Certificates<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for certificate in self.0 {
            sequence.serialize_element(certificate.as_ref())?;
        }
        sequence.end()
    }
}

fn unsupported() -> Failure {
    Failure::new("unsupported_diagnostics_value")
}

struct BoundedWriter(Vec<u8>);

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > MAX_METADATA.saturating_sub(self.0.len()) {
            return Err(io::Error::other("diagnostics metadata limit"));
        }
        let length = self.0.len() + input.len();
        if length > self.0.capacity() {
            let capacity = length
                .max(self.0.capacity().saturating_mul(2))
                .min(MAX_METADATA);
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattached_and_unpolled_observers_remain_distinct() -> Result<(), Failure> {
        assert!(Owner::new(0).is_err());
        let owner = Owner::new(1)?;
        let unattached: serde_json::Value =
            serde_json::from_slice(&owner.reply()?).map_err(|_| Failure::new("test_reply"))?;
        assert!(unattached["value"].is_null());
        *owner
            .observer
            .lock()
            .map_err(|_| Failure::new("test_lock"))? =
            Some(RequestDiagnostics::new(NonZeroUsize::MIN));
        let attached: serde_json::Value =
            serde_json::from_slice(&owner.reply()?).map_err(|_| Failure::new("test_reply"))?;
        assert_eq!(attached["value"]["outcome"], "not_started");
        assert!(attached["value"]["send_elapsed"].is_null());
        assert_eq!(attached["value"]["events"], serde_json::json!([]));
        Ok(())
    }

    #[test]
    fn full_duration_and_tls_absence_are_projected_without_defaults() -> Result<(), Failure> {
        let elapsed = Elapsed::from(Duration::MAX);
        assert_eq!(elapsed.seconds, u64::MAX);
        assert_eq!(elapsed.nanoseconds, 999_999_999);
        for (state, name) in [
            (TlsConnectionState::NotUsed, "not_used"),
            (TlsConnectionState::Unavailable, "unavailable"),
            (TlsConnectionState::Pending, "pending"),
        ] {
            let state = Tls::new(&state)?;
            assert_eq!(state.state, name);
            assert!(state.info.is_none());
        }
        Ok(())
    }

    #[test]
    fn oversized_certificate_metadata_stops_encoding_without_copying_der()
    -> Result<(), Box<dyn std::error::Error>> {
        let chain: Arc<[Arc<[u8]>]> = Arc::from([Arc::from(vec![255; MAX_METADATA])]);
        let info = TlsInfo {
            peer_verified: true,
            version_id: None,
            cipher_suite_id: None,
            alpn: None,
            session_resumed: false,
            peer_certificates_der: Some(Certificates(&chain)),
        };
        let mut writer = BoundedWriter(Vec::new());
        assert!(serde_json::to_writer(&mut writer, &info).is_err());
        assert!(writer.0.len() <= MAX_METADATA);
        assert_eq!(chain[0].len(), MAX_METADATA);
        let mut next = BoundedWriter(Vec::new());
        serde_json::to_writer(&mut next, &Elapsed::from(Duration::ZERO))?;
        assert_eq!(next.0, br#"{"seconds":0,"nanoseconds":0}"#);
        Ok(())
    }
}
