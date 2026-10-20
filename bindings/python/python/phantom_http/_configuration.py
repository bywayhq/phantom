"""Immutable settings mapped directly to the native client."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias


class _Inherit(Enum):
    VALUE = "inherit"


INHERIT = _Inherit.VALUE
_TimeoutValue: TypeAlias = float | None | _Inherit
_TimeoutFields: TypeAlias = list[tuple[str, float | None]]


def _seconds(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timeout durations must be seconds as int or float")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError("timeout durations must be finite and nonnegative") from None
    if not math.isfinite(result) or result < 0:
        raise ValueError("timeout durations must be finite and nonnegative")
    return result


@dataclass(frozen=True, kw_only=True)
class Timeouts:
    """Client phase limits in seconds. None disables a limit; zero is finite."""

    pool_admission: float | None = None
    connect: float | None = None
    response_head: float | None = None
    read_idle: float | None = None
    total: float | None = None

    def __post_init__(self) -> None:
        self._native_fields()

    def _native_fields(self) -> _TimeoutFields:
        return [
            (name, None if value is None else _seconds(value))
            for name, value in (
                ("pool_admission", self.pool_admission),
                ("connect", self.connect),
                ("response_head", self.response_head),
                ("read_idle", self.read_idle),
                ("total", self.total),
            )
        ]


@dataclass(frozen=True, kw_only=True)
class TimeoutOverrides:
    """Per-request limits: INHERIT, disabled None, or finite seconds incl. zero."""

    pool_admission: _TimeoutValue = INHERIT
    connect: _TimeoutValue = INHERIT
    response_head: _TimeoutValue = INHERIT
    read_idle: _TimeoutValue = INHERIT
    total: _TimeoutValue = INHERIT

    def __post_init__(self) -> None:
        self._native_fields()

    def _native_fields(self) -> _TimeoutFields:
        return [
            (name, None if value is None else _seconds(value))
            for name, value in (
                ("pool_admission", self.pool_admission),
                ("connect", self.connect),
                ("response_head", self.response_head),
                ("read_idle", self.read_idle),
                ("total", self.total),
            )
            if not isinstance(value, _Inherit)
        ]


@dataclass(frozen=True)
class Proxy:
    """An explicit proxy URI and optional separately supplied credentials."""

    url: str = field(repr=False)
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.url, str):
            raise TypeError("proxy URL must be a string")
        if (self.username is None) != (self.password is None):
            raise ValueError("proxy username and password must be supplied together")
        if self.username is not None and (
            not isinstance(self.username, str) or not isinstance(self.password, str)
        ):
            raise TypeError("proxy credentials must be strings")


@dataclass(frozen=True, kw_only=True)
class Trust:
    """Additional DER origin/proxy roots; certificate verification stays enabled."""

    roots: tuple[bytes, ...] = field(default=(), repr=False)
    proxy_roots: tuple[bytes, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        for name, values in (("roots", self.roots), ("proxy_roots", self.proxy_roots)):
            if not isinstance(values, tuple) or any(
                not isinstance(value, bytes) for value in values
            ):
                raise TypeError(f"{name} must be a tuple of DER bytes")


@dataclass(frozen=True, kw_only=True)
class SessionSharing:
    """Live state selected for sharing between independent client pools."""

    cookies: bool = False
    dns: bool = False
    client_hints: bool = False
    discovery: bool = False
    tickets: bool = False

    def __post_init__(self) -> None:
        for value in (
            self.cookies,
            self.dns,
            self.client_hints,
            self.discovery,
            self.tickets,
        ):
            if not isinstance(value, bool):
                raise TypeError("session sharing selections must be bool")


@dataclass(frozen=True)
class ContentDecoding:
    """Decode only caller-advertised codings, with an inclusive stream limit."""

    maximum_decoded_bytes: int | None = None

    def __post_init__(self) -> None:
        value = self.maximum_decoded_bytes
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError("maximum_decoded_bytes must be an integer")
            if not 0 <= value <= 2**64 - 1:
                raise ValueError(
                    "maximum_decoded_bytes must fit an unsigned 64-bit integer"
                )

    @classmethod
    def none(cls) -> ContentDecoding:
        return cls()

    @classmethod
    def advertised(cls, maximum_decoded_bytes: int) -> ContentDecoding:
        if isinstance(maximum_decoded_bytes, bool) or not isinstance(
            maximum_decoded_bytes, int
        ):
            raise TypeError("maximum_decoded_bytes must be an integer")
        return cls(maximum_decoded_bytes)


@dataclass(frozen=True)
class Header:
    """An ordered caller header, optionally never-indexed by HTTP/2 and HTTP/3."""

    name: str
    value: str | bytes = field(repr=False)
    sensitive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError("header names must be strings")
        if not isinstance(self.value, (str, bytes)):
            raise TypeError("header values must be str or bytes")
        if not isinstance(self.sensitive, bool):
            raise TypeError("header sensitivity must be a bool")
