"""Explicit encrypted DNS endpoints, constructed by the native client."""

from dataclasses import dataclass, field
from typing import ClassVar, Literal

from ._configuration import INHERIT, _Inherit, _seconds


def _integer(value: int, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its supported range")


def _validate(
    identity: str,
    bootstrap: tuple[str, ...],
    timeout: float,
    max_concurrent: int,
    families: str,
    roots: tuple[bytes, ...],
    padding_block: int | None | _Inherit,
) -> None:
    if type(bootstrap) is not tuple or type(roots) is not tuple:
        raise TypeError("DNS bootstrap and roots must be tuples")
    if not bootstrap or len(bootstrap) + len(roots) > 1024:
        raise ValueError("DNS requires bootstrap addresses within 1024 entries")
    remaining = 65536
    for value in (identity, *bootstrap):
        if type(value) is not str:
            raise TypeError("DNS identity and bootstrap addresses must be strings")
        if len(value) > remaining:
            raise ValueError("DNS settings exceed 65536 bytes")
        try:
            remaining -= len(value.encode("utf-8"))
        except UnicodeError:
            raise ValueError("DNS settings require valid UTF-8") from None
        if remaining < 0:
            raise ValueError("DNS settings exceed 65536 bytes")
    for root in roots:
        if type(root) is not bytes:
            raise TypeError("DNS roots must contain DER bytes")
        remaining -= len(root)
        if remaining < 0:
            raise ValueError("DNS settings exceed 65536 bytes")
    if type(timeout) not in (int, float):
        raise TypeError("DNS timeout must be seconds as int or float")
    if _seconds(timeout) == 0:
        raise ValueError("DNS timeout must be positive seconds")
    _integer(max_concurrent, "max_concurrent", 1, 2**64 - 1)
    if type(families) is not str or families not in ("dual", "ipv4"):
        raise ValueError("DNS families must be dual or ipv4")
    if padding_block is not INHERIT and padding_block is not None:
        _integer(padding_block, "padding_block", 1, 65535)


@dataclass(frozen=True, kw_only=True)
class DnsOverHttps:
    """Direct verified HTTP/2 DNS using explicit bootstrap IPs and lookup bounds.

    Roots add DER trust anchors for this endpoint. Timeout is positive seconds;
    max_concurrent bounds whole lookups, including both address families.
    INHERIT padding retains the wire preset, None disables it, and an integer
    sets a block size in bytes. The chromium154 preset enables its DNS headers
    and 128-byte padding; explicit query_id and padding replace those values.
    """

    _kind: ClassVar[str] = "https"
    endpoint: str = field(repr=False)
    bootstrap: tuple[str, ...] = field(repr=False)
    timeout: float
    max_concurrent: int
    method: Literal["post", "get"] = "post"
    families: Literal["dual", "ipv4"] = "dual"
    roots: tuple[bytes, ...] = field(default=(), repr=False)
    wire: Literal["standard", "chromium154"] = "standard"
    query_id: int = 0
    padding_block: int | None | _Inherit = INHERIT

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        _validate(
            self.endpoint,
            self.bootstrap,
            self.timeout,
            self.max_concurrent,
            self.families,
            self.roots,
            self.padding_block,
        )
        if type(self.method) is not str or self.method not in ("post", "get"):
            raise ValueError("DNS-over-HTTPS method must be post or get")
        if type(self.wire) is not str or self.wire not in ("standard", "chromium154"):
            raise ValueError("DNS-over-HTTPS wire must be standard or chromium154")
        _integer(self.query_id, "query_id", 0, 65535)


@dataclass(frozen=True, kw_only=True)
class DnsOverTls:
    """Direct verified TLS DNS with an explicit identity and IP:port bootstrap.

    Use brackets around IPv6 socket addresses. Roots add DER trust anchors;
    timeout is positive seconds and max_concurrent is in 1..32767. Dual queries
    return IPv6 first. INHERIT and None both omit padding for this transport.
    """

    _kind: ClassVar[str] = "tls"
    server_name: str = field(repr=False)
    bootstrap: tuple[str, ...] = field(repr=False)
    timeout: float
    max_concurrent: int
    families: Literal["dual", "ipv4"] = "dual"
    roots: tuple[bytes, ...] = field(default=(), repr=False)
    padding_block: int | None | _Inherit = INHERIT

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        _validate(
            self.server_name,
            self.bootstrap,
            self.timeout,
            self.max_concurrent,
            self.families,
            self.roots,
            self.padding_block,
        )
        _integer(self.max_concurrent, "max_concurrent", 1, 32767)
