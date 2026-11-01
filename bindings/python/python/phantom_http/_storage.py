"""Caller-owned storage of encrypted checkpoints with one operation deadline."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import Protocol, TypeVar

from ._errors import Error, SessionSnapshotError, TimeoutError
from ._session import _checkpoint_bytes

_T = TypeVar("_T")
_MAX_SNAPSHOT = 32 * 1024 * 1024


def _key(value: bytes) -> bytes:
    value = _checkpoint_bytes(value)
    if len(value) != 32:
        raise SessionSnapshotError("session_snapshot", "invalid_key_length")
    return value


class SessionStore(Protocol):
    """Synchronous backend; bound reads to 32 MiB before collecting bytes.

    Return None only for absence. The backend owns admission, write ordering
    and durability. Blocking calls cannot be interrupted by Phantom.
    """

    def load(self, name: str) -> bytes | None: ...

    def save(self, name: str, snapshot: bytes) -> None: ...


class AsyncSessionStore(Protocol):
    """Async backend; release operation resources on task cancellation.

    Bound reads to 32 MiB before collection; None means absence, not failure.
    Methods must yield promptly. The backend owns admission and durability.
    """

    async def load(self, name: str) -> bytes | None: ...

    async def save(self, name: str, snapshot: bytes) -> None: ...


class SessionStorageError(Error):
    """Redacted storage failure; original retains a backend exception."""

    def __init__(self, kind: str, original: Exception | None = None) -> None:
        super().__init__("session_storage", kind)
        self.original = original


def _deadline(name: str, timeout: float) -> float:
    if type(name) is not str:
        raise TypeError("session name must be str")
    if not name or len(name) > 256:
        raise SessionStorageError("invalid_name")
    try:
        valid = 0 < len(name.encode("utf-8")) <= 256
    except UnicodeError:
        valid = False
    if not valid or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name):
        raise SessionStorageError("invalid_name")
    if type(timeout) not in (int, float):
        raise ValueError("timeout must be finite positive seconds")
    try:
        seconds = float(timeout)
    except OverflowError:
        raise ValueError("timeout exceeds the supported clock range") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("timeout must be finite positive seconds")
    deadline = monotonic() + seconds
    if not math.isfinite(deadline):
        raise ValueError("timeout exceeds the supported clock range")
    _check(deadline)
    return deadline


def _check(deadline: float) -> None:
    if monotonic() >= deadline:
        raise TimeoutError("session_storage", "deadline") from None


def _loaded(snapshot: bytes | None) -> bytes | None:
    if snapshot is not None:
        if type(snapshot) is not bytes:
            raise SessionStorageError("invalid_snapshot")
        if len(snapshot) > _MAX_SNAPSHOT:
            raise SessionStorageError("too_large")
    return snapshot


async def _wait(operation: Awaitable[_T], deadline: float) -> _T:
    try:
        result = await asyncio.wait_for(operation, _remaining(deadline))
    except asyncio.TimeoutError:
        raise TimeoutError("session_storage", "deadline") from None
    except Exception:
        _check(deadline)
        raise
    _check(deadline)
    return result


def _remaining(deadline: float) -> float:
    return max(0, deadline - monotonic())


async def _backend(operation: Callable[[], Awaitable[_T]]) -> _T:
    try:
        return await operation()
    except Exception as error:
        raise SessionStorageError("backend", error) from None
