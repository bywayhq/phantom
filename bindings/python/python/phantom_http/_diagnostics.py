"""Live snapshots of one core request observer; polling starts no work."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Literal

from . import _native
from ._errors import _call


@dataclass(frozen=True)
class TlsConnectionInfo:
    peer_verified: bool
    version_id: int | None
    cipher_suite_id: int | None
    alpn: bytes | None = field(repr=False)
    session_resumed: bool
    peer_certificates_der: tuple[bytes, ...] | None = field(repr=False)


@dataclass(frozen=True)
class TlsConnectionState:
    state: Literal["not_used", "unavailable", "pending", "established"]
    info: TlsConnectionInfo | None


@dataclass(frozen=True)
class RequestConnection:
    reused: bool
    endpoint_scope: Literal["unavailable", "tcp_socket", "quic_endpoint"]
    local_address: str | None
    peer_address: str | None
    origin_tls: TlsConnectionState
    proxy_tls: TlsConnectionState


@dataclass(frozen=True)
class RequestTiming:
    id: int
    hop: int
    admission: int | None
    protocol: Literal["h0.9", "h1.0", "h1", "h2", "h3"] | None
    phase: Literal[
        "attempt_admission",
        "pool_admission",
        "connection_acquisition",
        "connection_use",
        "resolution_wait",
        "tcp_connect",
        "tls_handshake",
        "quic_handshake",
        "send_response_head",
        "response_body",
    ]
    started_ns: int
    finished_ns: int | None
    outcome: Literal[
        "pending",
        "completed",
        "failed",
        "interrupted",
        "abandoned",
        "cached",
        "early_data",
    ]
    connection: RequestConnection | None


@dataclass(frozen=True)
class RequestTimeline:
    """Events are in start order; overlapping intervals must not be summed."""

    outcome: Literal["not_started", "pending", "response_head", "failed", "cancelled"]
    send_elapsed_ns: int | None
    events: tuple[RequestTiming, ...]
    dropped_events: int
    admitted_attempts: int


def _tls(value: _native._DiagnosticTls) -> TlsConnectionState:
    state, info = value
    if info is None:
        return TlsConnectionState(state, None)
    verified, version, cipher, alpn, resumed, certificates = info
    return TlsConnectionState(
        state,
        TlsConnectionInfo(
            verified,
            version,
            cipher,
            alpn,
            resumed,
            None if certificates is None else tuple(certificates),
        ),
    )


def _connection(value: _native._DiagnosticConnection) -> RequestConnection:
    reused, scope, local, peer, origin, proxy = value
    return RequestConnection(reused, scope, local, peer, _tls(origin), _tls(proxy))


def _event(value: _native._DiagnosticEvent) -> RequestTiming:
    (
        identifier,
        hop,
        admission,
        protocol,
        phase,
        started,
        finished,
        outcome,
        connection,
    ) = value
    return RequestTiming(
        identifier,
        hop,
        admission,
        protocol,
        phase,
        started,
        finished,
        outcome,
        None if connection is None else _connection(connection),
    )


@dataclass(frozen=True, init=False, eq=False)
class RequestDiagnostics:
    """Attach once; retain observations after request failure or body closure."""

    maximum_events: int
    _native: _native.NativeRequestDiagnostics = field(repr=False, compare=False)

    def __init__(self, maximum_events: int = 128) -> None:
        if type(maximum_events) is not int:
            raise TypeError("maximum_events must be an integer")
        if not 0 < maximum_events <= 2 * sys.maxsize + 1:
            raise ValueError("maximum_events must be positive and fit usize")
        object.__setattr__(self, "maximum_events", maximum_events)
        object.__setattr__(
            self, "_native", _call(_native.NativeRequestDiagnostics, maximum_events)
        )

    def snapshot(self) -> RequestTimeline | None:
        """None means unattached. Missing timings are unobserved, never zero."""
        value = _call(self._native.snapshot)
        if value is None:
            return None
        outcome, elapsed, events, dropped, admissions = value
        return RequestTimeline(
            outcome, elapsed, tuple(map(_event, events)), dropped, admissions
        )
