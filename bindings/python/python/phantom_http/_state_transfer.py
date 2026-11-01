"""Typed, editable state transfers using the core checkpoint admission bounds."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal, TypeAlias, TypeVar

from ._errors import SessionTicketError

_MAX_TEXT = 32 * 1024 * 1024
_Scheme: TypeAlias = Literal["http", "https"]
_SameSite: TypeAlias = Literal["strict", "lax", "none"]
_CookieFields: TypeAlias = tuple[
    _Scheme,
    str,
    str,
    str,
    bool,
    str,
    bool,
    bool,
    _SameSite | None,
    str | None,
    int | None,
]
_AltSvcFields: TypeAlias = tuple[str, str, int, int]


def _expiry(value: int | None) -> None:
    if value is not None and (
        type(value) is not int or not -(2**127) <= value < 2**127
    ):
        raise ValueError("expires_at_ns must be integer Unix nanoseconds")


@dataclass(frozen=True, kw_only=True)
class CookieSnapshotEntry:
    """One cookie; expires_at_ns is absolute Unix nanoseconds, None for a session.

    Import validates cookie rules and attributes atomically. Values are credentials.
    """

    source_scheme: Literal["http", "https"]
    name: str = field(repr=False)
    value: str = field(repr=False)
    domain: str = field(repr=False)
    path: str = field(default="/", repr=False)
    host_only: bool = True
    secure: bool = False
    http_only: bool = False
    same_site: Literal["strict", "lax", "none"] | None = None
    partition_key: str | None = field(default=None, repr=False)
    expires_at_ns: int | None = None

    def __post_init__(self) -> None:
        if self.source_scheme not in ("http", "https"):
            raise ValueError("source_scheme must be http or https")
        if self.same_site not in (None, "strict", "lax", "none"):
            raise ValueError("same_site must be strict, lax, none or None")
        if any(
            type(v) is not bool for v in (self.host_only, self.secure, self.http_only)
        ):
            raise TypeError("cookie flags must be bool")
        _expiry(self.expires_at_ns)

    def _fields(self) -> _CookieFields:
        return (
            self.source_scheme,
            self.name,
            self.value,
            self.domain,
            self.host_only,
            self.path,
            self.secure,
            self.http_only,
            self.same_site,
            self.partition_key,
            self.expires_at_ns,
        )

    def _text(self) -> tuple[str, ...]:
        return (
            self.source_scheme,
            self.name,
            self.value,
            self.domain,
            self.path,
            self.same_site or "",
            self.partition_key or "",
        )


@dataclass(frozen=True, kw_only=True)
class AltSvcSnapshotEntry:
    """One direct-route alternative; expires_at_ns is absolute Unix nanoseconds."""

    origin: str = field(repr=False)
    alternative_host: str = field(repr=False)
    alternative_port: int
    expires_at_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.alternative_port) is not int
            or not 0 <= self.alternative_port <= 65535
        ):
            raise ValueError("alternative_port must fit an unsigned 16-bit integer")
        if self.expires_at_ns is None:
            raise TypeError("expires_at_ns is required")
        _expiry(self.expires_at_ns)

    def _fields(self) -> _AltSvcFields:
        return (
            self.origin,
            self.alternative_host,
            self.alternative_port,
            self.expires_at_ns,
        )

    def _text(self) -> tuple[str, ...]:
        return self.origin, self.alternative_host


_Entry = TypeVar("_Entry", CookieSnapshotEntry, AltSvcSnapshotEntry)


def _bounded(
    entries: Iterable[_Entry], kind: type[_Entry], maximum: int
) -> tuple[_Entry, ...]:
    result: list[_Entry] = []
    remaining = _MAX_TEXT
    for entry in entries:
        if len(result) == maximum:
            raise ValueError(f"snapshot exceeds {maximum} entries")
        if type(entry) is not kind:
            raise TypeError(f"snapshot entries must be {kind.__name__}")
        for text in entry._text():
            if type(text) is not str:
                raise TypeError("snapshot text fields must be str")
            if len(text) > remaining:
                raise ValueError("snapshot text exceeds 32 MiB")
            try:
                remaining -= len(text.encode("utf-8"))
            except UnicodeError:
                raise ValueError("snapshot text must be valid UTF-8") from None
            if remaining < 0:
                raise ValueError("snapshot text exceeds 32 MiB")
        result.append(entry)
    return tuple(result)


@dataclass(frozen=True, init=False)
class CookieSnapshot:
    """Cookies ordered oldest first; admits 16,384 entries and 32 MiB of text."""

    entries: tuple[CookieSnapshotEntry, ...] = field(repr=False)

    def __init__(self, entries: Iterable[CookieSnapshotEntry] = ()) -> None:
        object.__setattr__(
            self, "entries", _bounded(entries, CookieSnapshotEntry, 16384)
        )

    def _fields(self) -> list[_CookieFields]:
        return [
            entry._fields()
            for entry in _bounded(self.entries, CookieSnapshotEntry, 16384)
        ]

    @classmethod
    def _from_fields(cls, entries: list[_CookieFields]) -> CookieSnapshot:
        return cls(
            CookieSnapshotEntry(
                source_scheme=scheme,
                name=name,
                value=value,
                domain=domain,
                host_only=host_only,
                path=path,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                partition_key=partition_key,
                expires_at_ns=expiry,
            )
            for scheme, name, value, domain, host_only, path, secure, http_only, same_site, partition_key, expiry in entries
        )


@dataclass(frozen=True, init=False)
class AltSvcSnapshot:
    """Direct alternatives in LRU order; admits 32,768 entries and 32 MiB of text."""

    entries: tuple[AltSvcSnapshotEntry, ...] = field(repr=False)

    def __init__(self, entries: Iterable[AltSvcSnapshotEntry] = ()) -> None:
        object.__setattr__(
            self, "entries", _bounded(entries, AltSvcSnapshotEntry, 32768)
        )

    def _fields(self) -> list[_AltSvcFields]:
        return [
            entry._fields()
            for entry in _bounded(self.entries, AltSvcSnapshotEntry, 32768)
        ]

    @classmethod
    def _from_fields(cls, entries: list[_AltSvcFields]) -> AltSvcSnapshot:
        return cls(
            AltSvcSnapshotEntry(
                origin=origin,
                alternative_host=host,
                alternative_port=port,
                expires_at_ns=expiry,
            )
            for origin, host, port, expiry in entries
        )


def _ticket_key(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("ticket key must be bytes")
    if len(value) != 32:
        raise SessionTicketError("session_tickets", "invalid_key_length")
    return value


def _ticket_bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encrypted tickets must be bytes")
    if len(value) > 16 * 1024 * 1024:
        raise SessionTicketError("session_tickets", "too_large")
    return value
