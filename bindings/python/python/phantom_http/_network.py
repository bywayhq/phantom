"""Bounded network settings passed directly to the core client."""

import sys
from dataclasses import dataclass, field

from ._configuration import INHERIT, _Inherit
from ._dns import DnsOverHttps, DnsOverTls


def _text_size(value: str, remaining: int, name: str) -> int:
    if type(value) is not str:
        raise TypeError(f"{name} must be str")
    if len(value) > remaining:
        raise ValueError("network exceeds 65536 UTF-8 bytes")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    if size > remaining:
        raise ValueError("network exceeds 65536 UTF-8 bytes")
    return remaining - size


@dataclass(frozen=True)
class HostOverride:
    """Resolve a logical host to ordered IP addresses; an empty tuple blocks it."""

    host: str = field(repr=False)
    addresses: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if type(self.addresses) is not tuple:
            raise TypeError("addresses must be a tuple")
        if len(self.addresses) + 1 > 1024:
            raise ValueError("network exceeds 1024 entries")
        remaining = _text_size(self.host, 65536, "host")
        for address in self.addresses:
            remaining = _text_size(address, remaining, "addresses")


@dataclass(frozen=True, kw_only=True)
class NetworkOptions:
    """Override DNS answers and bind sources, without changing logical hosts.

    Entries share a 1024 count and 65536 UTF-8 byte bound. The last override
    for a normalized host, and the last source address per family, win.
    unix_socket connects direct H1/H2 through a fixed Unix pathname, retaining
    URL authority and TLS verification. TCP recipes, proxies, H3, source/DNS
    overrides and encrypted session checkpoints are unavailable with it.
    Paths are used verbatim; the library does not create or remove them.
    public_only admits public IPs for new direct connections. It excludes
    special-purpose ranges and cannot enforce proxy egress or revoke live pools.
    dns selects a separate direct encrypted resolver. Its endpoint settings have
    their own 1024-entry/64-KiB bound. dns_cache=None disables address caching;
    INHERIT keeps the profile policy.
    max_alt_svc_origins enables direct-route Alt-Svc discovery with this capacity.
    """

    host_overrides: tuple[HostOverride, ...] = field(default=(), repr=False)
    local_addresses: tuple[str, ...] = field(default=(), repr=False)
    interface: str | None = field(default=None, repr=False)
    unix_socket: str | None = field(default=None, repr=False)
    public_only: bool = False
    dns: DnsOverHttps | DnsOverTls | None = field(default=None, repr=False)
    dns_cache: _Inherit | None = INHERIT
    max_alt_svc_origins: int | None = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.max_alt_svc_origins is not None and (
            type(self.max_alt_svc_origins) is not int
            or not 0 < self.max_alt_svc_origins <= sys.maxsize
        ):
            raise ValueError("max_alt_svc_origins must be a positive platform integer")
        if self.dns_cache is not INHERIT and self.dns_cache is not None:
            raise TypeError("dns_cache must be INHERIT or None")
        if self.dns is not None:
            if type(self.dns) not in (DnsOverHttps, DnsOverTls):
                raise TypeError("dns must be DnsOverHttps or DnsOverTls")
            self.dns._validate()
        if type(self.public_only) is not bool:
            raise TypeError("public_only must be boolean")
        if type(self.host_overrides) is not tuple:
            raise TypeError("host_overrides must be a tuple")
        if type(self.local_addresses) is not tuple:
            raise TypeError("local_addresses must be a tuple")
        count = len(self.host_overrides) + len(self.local_addresses)
        if count > 1024:
            raise ValueError("network exceeds 1024 entries")
        remaining = 65536
        for override in self.host_overrides:
            if type(override) is not HostOverride:
                raise TypeError("host_overrides must contain HostOverride")
            if type(override.addresses) is not tuple:
                raise TypeError("addresses must be a tuple")
            count += len(override.addresses)
            if count > 1024:
                raise ValueError("network exceeds 1024 entries")
            remaining = _text_size(override.host, remaining, "host")
            for address in override.addresses:
                remaining = _text_size(address, remaining, "addresses")
        for address in self.local_addresses:
            remaining = _text_size(address, remaining, "local_addresses")
        if self.interface is not None:
            remaining = _text_size(self.interface, remaining, "interface")
        if self.unix_socket is not None:
            _text_size(self.unix_socket, remaining, "unix_socket")
            if not self.unix_socket or "\x00" in self.unix_socket:
                raise ValueError("unix_socket must be a nonempty pathname without NUL")
