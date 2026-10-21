"""Bounded network settings passed directly to the core client."""

from dataclasses import dataclass, field
from typing import TypeAlias

_NetworkDefaults: TypeAlias = tuple[
    tuple[tuple[str, tuple[str, ...]], ...], tuple[str, ...], str | None
]
_NetworkFields: TypeAlias = (
    _NetworkDefaults
    | tuple[tuple[tuple[str, tuple[str, ...]], ...], tuple[str, ...], str | None, str]
)


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
    """

    host_overrides: tuple[HostOverride, ...] = field(default=(), repr=False)
    local_addresses: tuple[str, ...] = field(default=(), repr=False)
    interface: str | None = field(default=None, repr=False)
    unix_socket: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._native_fields()

    def _native_fields(self) -> _NetworkFields:
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
        fields: _NetworkDefaults = (
            tuple((item.host, item.addresses) for item in self.host_overrides),
            self.local_addresses,
            self.interface,
        )
        if self.unix_socket is not None:
            return (*fields, self.unix_socket)
        return fields
