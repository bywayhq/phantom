//! Live request diagnostics and owned timeline projections.

use std::{fmt, sync::Arc};

use napi::{
    Result,
    bindgen_prelude::{BigInt, Buffer},
};
use napi_derive::napi;

/// One coherent timeline; response_head says nothing about body completion.
#[derive(Debug)]
#[napi(object)]
pub struct DiagnosticTimelineInfo {
    /// Actual core send state.
    pub outcome: String,
    /// Exact elapsed send time; absent before polling.
    pub send_elapsed_ns: Option<BigInt>,
    /// Retained observations in start order.
    pub events: Vec<DiagnosticEventInfo>,
    /// Observations omitted at the configured capacity.
    pub dropped_events: BigInt,
    /// Origin admissions, including observations omitted at capacity.
    pub admitted_attempts: BigInt,
}

/// One observed phase; overlapping phases must not be added together.
#[derive(Debug)]
#[napi(object)]
pub struct DiagnosticEventInfo {
    /// Original observation sequence number.
    pub id: BigInt,
    /// Zero-based redirect hop.
    pub hop: BigInt,
    /// One-based origin admission, when attributable.
    pub admission: Option<BigInt>,
    /// Known protocol family, absent when unobserved.
    pub protocol: Option<String>,
    /// Actual operation observed by the core.
    pub phase: String,
    /// Exact offset from first send poll.
    pub started_ns: BigInt,
    /// Exact finishing offset; absent while pending.
    pub finished_ns: Option<BigInt>,
    /// Actual phase outcome.
    pub outcome: String,
    /// Connection-use facts, absent for other phases.
    pub connection: Option<DiagnosticConnectionInfo>,
}

/// Connection-use facts, independent of TLS session resumption.
#[napi(object)]
pub struct DiagnosticConnectionInfo {
    /// A previous HTTP request was dispatched on this connection.
    pub reused: bool,
    /// What the endpoint addresses describe.
    pub endpoint_scope: String,
    /// Actual local endpoint, when exposed.
    pub local_address: Option<String>,
    /// Actual transport peer, which may be a proxy.
    pub peer_address: Option<String>,
    /// Origin TLS facts at connection use.
    pub origin_tls: DiagnosticTlsState,
    /// Outer proxy TLS facts at connection use.
    pub proxy_tls: DiagnosticTlsState,
}
impl fmt::Debug for DiagnosticConnectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticConnectionInfo")
            .finish_non_exhaustive()
    }
}

/// Explicit TLS state; info exists only for established TLS.
#[derive(Debug)]
#[napi(object)]
pub struct DiagnosticTlsState {
    /// not_used, unavailable, pending or established.
    pub state: String,
    /// Actual established handshake information.
    pub info: Option<DiagnosticTlsInfo>,
}

/// Negotiated facts and available leaf-first DER, not a constructed trust chain.
#[napi(object)]
pub struct DiagnosticTlsInfo {
    /// Core server-name and chain verification result.
    pub peer_verified: bool,
    /// Negotiated TLS protocol identifier, when mapped.
    pub version_id: Option<u32>,
    /// Negotiated cipher IANA identifier, when mapped.
    pub cipher_suite_id: Option<u32>,
    /// Selected ALPN bytes; absent differs from empty.
    pub alpn: Option<Buffer>,
    /// TLS session resumption, separate from HTTP connection reuse.
    pub session_resumed: bool,
    /// Available backend certificates, absent when unavailable.
    pub peer_certificates_der: Option<Vec<Buffer>>,
}
impl fmt::Debug for DiagnosticTlsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticTlsInfo").finish_non_exhaustive()
    }
}

/// Single-use native owner, retained independently of client and response.
#[derive(Debug)]
#[napi]
pub struct NativeRequestDiagnostics {
    pub(super) state: Arc<crate::request_diagnostics::Diagnostics>,
}

#[napi]
impl NativeRequestDiagnostics {
    /// Retains at most this positive exact count of observations.
    #[napi(constructor)]
    pub fn new(maximum_events: BigInt) -> Result<Self> {
        Ok(Self {
            state: Arc::new(crate::request_diagnostics::Diagnostics::new(
                maximum_events,
            )?),
        })
    }

    /// Copies the live timeline; absent before actual core attachment.
    #[napi]
    pub fn snapshot(&self) -> Result<Option<DiagnosticTimelineInfo>> {
        self.state.snapshot()
    }
}
