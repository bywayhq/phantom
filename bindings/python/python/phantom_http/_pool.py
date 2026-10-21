"""Operational pool limits passed directly to the core client."""

import math
import sys
from dataclasses import dataclass
from typing import TypeAlias

_PoolFields: TypeAlias = tuple[int | float | None, ...]


@dataclass(frozen=True, kw_only=True)
class PoolOptions:
    """Override pool limits; None preserves each core default.

    Counts are positive integers. Active and pending limits apply per pool key
    (origin and route), across its connections. Retention counts pool entries,
    not sockets. HTTP/3 permits at most eight connections per transport location.
    negotiated_setup_wait_limit is finite nonnegative seconds, including zero.
    These settings do not change profile wire settings or binding admission.
    """

    max_retained_http1_connections: int | None = None
    max_concurrent_http1_requests_per_origin: int | None = None
    max_pending_http1_requests_per_origin: int | None = None
    max_retained_http2_connections: int | None = None
    max_concurrent_http2_requests_per_origin: int | None = None
    max_pending_http2_requests_per_origin: int | None = None
    max_http2_connections_per_origin: int | None = None
    max_retained_http3_connections: int | None = None
    max_concurrent_http3_requests_per_origin: int | None = None
    max_pending_http3_requests_per_origin: int | None = None
    max_http3_connections_per_origin: int | None = None
    negotiated_setup_wait_limit: float | None = None

    def __post_init__(self) -> None:
        self._native_fields()

    def _native_fields(self) -> _PoolFields:
        values: list[int | float | None] = []
        for name, value in (
            ("max_retained_http1_connections", self.max_retained_http1_connections),
            (
                "max_concurrent_http1_requests_per_origin",
                self.max_concurrent_http1_requests_per_origin,
            ),
            (
                "max_pending_http1_requests_per_origin",
                self.max_pending_http1_requests_per_origin,
            ),
            ("max_retained_http2_connections", self.max_retained_http2_connections),
            (
                "max_concurrent_http2_requests_per_origin",
                self.max_concurrent_http2_requests_per_origin,
            ),
            (
                "max_pending_http2_requests_per_origin",
                self.max_pending_http2_requests_per_origin,
            ),
            ("max_http2_connections_per_origin", self.max_http2_connections_per_origin),
            ("max_retained_http3_connections", self.max_retained_http3_connections),
            (
                "max_concurrent_http3_requests_per_origin",
                self.max_concurrent_http3_requests_per_origin,
            ),
            (
                "max_pending_http3_requests_per_origin",
                self.max_pending_http3_requests_per_origin,
            ),
            ("max_http3_connections_per_origin", self.max_http3_connections_per_origin),
            ("negotiated_setup_wait_limit", self.negotiated_setup_wait_limit),
        ):
            if value is not None:
                if name == "negotiated_setup_wait_limit":
                    if type(value) not in (int, float):
                        raise TypeError(f"{name} must be seconds as int or float")
                    try:
                        value = float(value)
                    except OverflowError:
                        raise ValueError(
                            f"{name} must be finite and nonnegative"
                        ) from None
                    if not math.isfinite(value) or value < 0:
                        raise ValueError(f"{name} must be finite and nonnegative")
                else:
                    if type(value) is not int:
                        raise TypeError(f"{name} must be a positive int")
                    if not 1 <= value <= sys.maxsize * 2 + 1:
                        raise ValueError(f"{name} must fit a positive native usize")
            values.append(value)
        return tuple(values)
