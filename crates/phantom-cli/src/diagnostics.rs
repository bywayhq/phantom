use std::path::PathBuf;

use phantom::{
    ConnectionEndpointScope, RequestConnection, RequestDiagnostics, RequestTimelineOutcome,
    RequestTimingOutcome, RequestTimingPhase, TlsConnectionState,
};
use serde_json::{Value, json};

use crate::{CliError, Result, profiles};

fn phase(value: RequestTimingPhase) -> &'static str {
    match value {
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
        _ => "unknown",
    }
}

fn outcome(value: RequestTimingOutcome) -> &'static str {
    match value {
        RequestTimingOutcome::Pending => "pending",
        RequestTimingOutcome::Completed => "completed",
        RequestTimingOutcome::Failed => "failed",
        RequestTimingOutcome::Interrupted => "interrupted",
        RequestTimingOutcome::Abandoned => "abandoned",
        RequestTimingOutcome::Cached => "cached",
        RequestTimingOutcome::EarlyData => "early_data",
        _ => "unknown",
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn tls(state: &TlsConnectionState) -> Value {
    match state {
        TlsConnectionState::NotUsed => json!({"state": "not_used"}),
        TlsConnectionState::Unavailable => json!({"state": "unavailable"}),
        TlsConnectionState::Pending => json!({"state": "pending"}),
        TlsConnectionState::Established(info) => json!({
            "state": "established", "peer_verified": info.peer_verified,
            "version_id": info.version.map(|version| version.protocol_id()),
            "cipher_suite_id": info.cipher_suite.map(|suite| suite.iana_id()),
            "alpn_hex": info.alpn.as_ref().map(|alpn| hex(alpn)),
            "session_resumed": info.session_resumed,
            "peer_certificates_der_hex": info.peer_certificates.as_ref()
                .map(|chain| chain.iter().map(|certificate| hex(certificate)).collect::<Vec<_>>()),
        }),
        _ => json!({"state": "unknown"}),
    }
}

fn connection(connection: &RequestConnection) -> Value {
    json!({
        "reused": connection.reused,
        "endpoint_scope": match connection.endpoint_scope {
            ConnectionEndpointScope::Unavailable => "unavailable",
            ConnectionEndpointScope::TcpSocket => "tcp_socket",
            ConnectionEndpointScope::QuicEndpoint => "quic_endpoint",
            _ => "unknown",
        },
        "local_address": connection.local_address.map(|address| address.to_string()),
        "peer_address": connection.peer_address.map(|address| address.to_string()),
        "origin_tls": tls(&connection.origin_tls), "proxy_tls": tls(&connection.proxy_tls),
    })
}

pub(super) fn document(diagnostics: &RequestDiagnostics) -> Value {
    let timeline = diagnostics.snapshot();
    let outcome = match timeline.outcome {
        RequestTimelineOutcome::NotStarted => "not_started",
        RequestTimelineOutcome::Pending => "pending",
        RequestTimelineOutcome::ResponseHead => "response_head",
        RequestTimelineOutcome::Failed => "failed",
        RequestTimelineOutcome::Cancelled => "cancelled",
        _ => "unknown",
    };
    let events: Vec<_> = timeline
        .events
        .iter()
        .map(|event| {
            json!({
                "id": event.id, "hop": event.hop, "admission": event.admission,
                "protocol": event.protocol.map(|protocol| match protocol {
                    http::Version::HTTP_11 => "h1", http::Version::HTTP_2 => "h2",
                    http::Version::HTTP_3 => "h3", _ => "unknown",
                }),
                "phase": phase(event.phase), "outcome": self::outcome(event.outcome),
                "started_seconds": event.started.as_secs_f64(),
                "finished_seconds": event.finished.map(|duration| duration.as_secs_f64()),
                "connection": event.connection.as_deref().map(connection),
            })
        })
        .collect();
    json!({
        "format": "phantom.request-diagnostics", "version": 1,
        "outcome": outcome, "send_elapsed_seconds": timeline.send_elapsed.map(|duration| duration.as_secs_f64()),
        "admitted_attempts": timeline.admitted_attempts, "dropped_events": timeline.dropped_events,
        "events": events,
    })
}

pub(super) async fn write(path: &PathBuf, diagnostics: &RequestDiagnostics) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&document(diagnostics)).map_err(CliError::operation)?;
    profiles::write_output(Some(path), &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unstarted_request_has_null_elapsed_and_no_invented_phases() {
        let handle = RequestDiagnostics::new(std::num::NonZeroUsize::MIN);
        let result = document(&handle);
        assert_eq!(result["outcome"], "not_started");
        assert!(result["send_elapsed_seconds"].is_null());
        assert_eq!(result["events"], json!([]));
    }
}
