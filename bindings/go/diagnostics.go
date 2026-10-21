package phantom

import (
	"encoding/json"
	"net/netip"
	"runtime"
	"sync/atomic"
)

// DiagnosticDuration is an exact nonnegative monotonic offset or elapsed time.
// Nanoseconds is less than one billion. The pair preserves durations that do
// not fit time.Duration; it is not a wall-clock timestamp.
type DiagnosticDuration struct {
	Seconds     uint64 `json:"seconds"`
	Nanoseconds uint32 `json:"nanoseconds"`
}

// TimelineOutcome describes the send future independently of its response body.
type TimelineOutcome string

const (
	TimelineNotStarted   TimelineOutcome = "not_started"
	TimelinePending      TimelineOutcome = "pending"
	TimelineResponseHead TimelineOutcome = "response_head"
	TimelineFailed       TimelineOutcome = "failed"
	TimelineCancelled    TimelineOutcome = "cancelled"
)

// TimingPhase names an operation observed by the core, not an inferred duration.
type TimingPhase string

const (
	TimingAttemptAdmission      TimingPhase = "attempt_admission"
	TimingPoolAdmission         TimingPhase = "pool_admission"
	TimingConnectionAcquisition TimingPhase = "connection_acquisition"
	TimingConnectionUse         TimingPhase = "connection_use"
	TimingResolutionWait        TimingPhase = "resolution_wait"
	TimingTCPConnect            TimingPhase = "tcp_connect"
	TimingTLSHandshake          TimingPhase = "tls_handshake"
	TimingQUICHandshake         TimingPhase = "quic_handshake"
	TimingSendResponseHead      TimingPhase = "send_response_head"
	TimingResponseBody          TimingPhase = "response_body"
)

// TimingOutcome names how an observed operation ended, or whether it is pending.
type TimingOutcome string

const (
	TimingPending     TimingOutcome = "pending"
	TimingCompleted   TimingOutcome = "completed"
	TimingFailed      TimingOutcome = "failed"
	TimingInterrupted TimingOutcome = "interrupted"
	TimingAbandoned   TimingOutcome = "abandoned"
	TimingCached      TimingOutcome = "cached"
	TimingEarlyData   TimingOutcome = "early_data"
)

// EndpointScope identifies what a connection's socket addresses describe.
type EndpointScope string

const (
	EndpointUnavailable  EndpointScope = "unavailable"
	EndpointTCPSocket    EndpointScope = "tcp_socket"
	EndpointQUICEndpoint EndpointScope = "quic_endpoint"
)

// TLSState distinguishes absent, opaque, in-progress and completed TLS layers.
type TLSState string

const (
	TLSNotUsed     TLSState = "not_used"
	TLSUnavailable TLSState = "unavailable"
	TLSPending     TLSState = "pending"
	TLSEstablished TLSState = "established"
)

func (d *DiagnosticDuration) UnmarshalJSON(input []byte) error {
	var wire struct {
		Seconds     *uint64 `json:"seconds"`
		Nanoseconds *uint32 `json:"nanoseconds"`
	}
	if json.Unmarshal(input, &wire) != nil || wire.Seconds == nil || wire.Nanoseconds == nil || *wire.Nanoseconds >= 1_000_000_000 {
		return &Error{Kind: "native_abi"}
	}
	d.Seconds, d.Nanoseconds = *wire.Seconds, *wire.Nanoseconds
	return nil
}

// RequestTimeline is a coherent copy of retained core observations. Outcome is
// not_started, pending, response_head, failed or cancelled and describes send
// only. Response-head completion does not imply response-body completion.
type RequestTimeline struct {
	Outcome          TimelineOutcome     `json:"outcome"`
	SendElapsed      *DiagnosticDuration `json:"send_elapsed"`
	Events           []RequestTiming     `json:"events"`
	DroppedEvents    uint64              `json:"dropped_events"`
	AdmittedAttempts uint64              `json:"admitted_attempts"`
}

// RequestTiming records one observed phase, in start order. Intervals can
// overlap and must not be added together. Missing phases are unobserved, not
// zero-duration operations. IDs include omitted events; admission starts at one.
// Phase is attempt_admission, pool_admission, connection_acquisition,
// connection_use, resolution_wait, tcp_connect, tls_handshake, quic_handshake,
// send_response_head or response_body. Outcome is pending, completed, failed,
// interrupted, abandoned, cached or early_data. Protocol is nil, h1, h2 or h3.
type RequestTiming struct {
	ID         uint64              `json:"id"`
	Hop        uint64              `json:"hop"`
	Admission  *uint64             `json:"admission"`
	Protocol   *string             `json:"protocol"`
	Phase      TimingPhase         `json:"phase"`
	Started    DiagnosticDuration  `json:"started"`
	Finished   *DiagnosticDuration `json:"finished"`
	Outcome    TimingOutcome       `json:"outcome"`
	Connection *RequestConnection  `json:"connection"`
}

// RequestConnection describes the connection selected by an origin attempt.
// Reused means earlier HTTP dispatch, independently of TLS session resumption.
// EndpointScope is unavailable, tcp_socket or quic_endpoint. A peer can be a
// proxy; QUIC local addresses can contain an unspecified IP.
type RequestConnection struct {
	Reused        bool               `json:"reused"`
	EndpointScope EndpointScope      `json:"endpoint_scope"`
	LocalAddress  *netip.AddrPort    `json:"local_address"`
	PeerAddress   *netip.AddrPort    `json:"peer_address"`
	OriginTLS     TLSConnectionState `json:"origin_tls"`
	ProxyTLS      TLSConnectionState `json:"proxy_tls"`
}

// TLSConnectionState distinguishes not_used, unavailable, pending and
// established. Only established carries Info. Pending can occur with early data.
type TLSConnectionState struct {
	State TLSState           `json:"state"`
	Info  *TLSConnectionInfo `json:"info"`
}

// TLSConnectionInfo contains completed-handshake facts. Certificates are the
// available leaf-first DER chain, not a constructed trust chain. Nil means the
// backend supplied none or DER encoding failed. VersionID and CipherSuiteID are
// IANA identifiers; nil means unavailable. ALPN is the negotiated raw bytes.
type TLSConnectionInfo struct {
	PeerVerified        bool     `json:"peer_verified"`
	VersionID           *uint16  `json:"version_id"`
	CipherSuiteID       *uint16  `json:"cipher_suite_id"`
	ALPN                []byte   `json:"alpn"`
	SessionResumed      bool     `json:"session_resumed"`
	PeerCertificatesDER [][]byte `json:"peer_certificates_der"`
}

// RequestDiagnostics retains live observations independently of the response.
// Attach it to exactly one Request. It is safe for concurrent snapshots and
// must not be copied after first use. Close it when observations are no longer needed.
type RequestDiagnostics struct{ id atomic.Uint64 }

// NewRequestDiagnostics retains up to maximumEvents, which must be positive.
// Excess events are counted, not retained. No background polling task is started.
func NewRequestDiagnostics(maximumEvents uint64) (*RequestDiagnostics, error) {
	if maximumEvents == 0 {
		return nil, &Error{Kind: "invalid_diagnostics_capacity"}
	}
	value, err := dispatch(map[string]any{"kind": "new_diagnostics", "maximum": maximumEvents}, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil || result.ID == 0 {
		return nil, &Error{Kind: "native_abi"}
	}
	owner := &RequestDiagnostics{}
	owner.id.Store(result.ID)
	runtime.SetFinalizer(owner, func(diagnostics *RequestDiagnostics) {
		// Finalizers cannot report release errors; callers observe them through Close.
		_ = diagnostics.Close()
	})
	return owner, nil
}

// Snapshot returns nil before a core request has attached this observer.
// Failed and cancelled sends remain observable. Body completion is a separate
// response_body event and includes caller delays, decoding and trailers.
// A metadata_limit error leaves the observer usable and publishes no partial
// snapshot; all event and certificate bytes must fit the 256 KiB reply bound.
func (d *RequestDiagnostics) Snapshot() (*RequestTimeline, error) {
	if d == nil || d.id.Load() == 0 {
		return nil, &Error{Kind: "invalid_handle"}
	}
	value, err := dispatch(map[string]any{"kind": "diagnostics_snapshot", "diagnostics": d.id.Load()}, nil)
	runtime.KeepAlive(d)
	if err != nil {
		return nil, err
	}
	return decodeRequestTimeline(value)
}

func decodeRequestTimeline(value json.RawMessage) (*RequestTimeline, error) {
	if string(value) == "null" {
		return nil, nil
	}
	var wire struct {
		Outcome          TimelineOutcome     `json:"outcome"`
		SendElapsed      *DiagnosticDuration `json:"send_elapsed"`
		Events           []RequestTiming     `json:"events"`
		DroppedEvents    *uint64             `json:"dropped_events"`
		AdmittedAttempts *uint64             `json:"admitted_attempts"`
	}
	if json.Unmarshal(value, &wire) != nil || wire.Events == nil || wire.DroppedEvents == nil || wire.AdmittedAttempts == nil {
		return nil, &Error{Kind: "native_abi"}
	}
	switch wire.Outcome {
	case "not_started", "pending", "response_head", "failed", "cancelled":
	default:
		return nil, &Error{Kind: "native_abi"}
	}
	return &RequestTimeline{
		Outcome: wire.Outcome, SendElapsed: wire.SendElapsed, Events: wire.Events,
		DroppedEvents: *wire.DroppedEvents, AdmittedAttempts: *wire.AdmittedAttempts,
	}, nil
}

// Close releases foreign access without cancelling the observed request. A
// snapshot racing Close can finish if native lookup already retained its owner.
// Closing or a failed request never makes this single-use handle reusable.
func (d *RequestDiagnostics) Close() error {
	if d == nil {
		return nil
	}
	id := d.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(d, nil)
	return control("release_diagnostics", "diagnostics", id)
}
