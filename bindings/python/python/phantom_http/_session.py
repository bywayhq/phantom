"""Shared cookie/attempt owners and encrypted-checkpoint input projection."""

from __future__ import annotations

from collections.abc import (
    Iterable,
)

from . import _native
from ._configuration import (
    Proxy,
    SessionSharing,
)
from ._errors import _call

_NO_SHARED_STATE = SessionSharing()


def _receiving_routes(
    routes: Iterable[str | Proxy | None],
) -> list[tuple[str | None, str | None, str | None]]:
    result: list[tuple[str | None, str | None, str | None]] = []
    for route in routes:
        if isinstance(route, str):
            route = Proxy(route)
        if route is not None and not isinstance(route, Proxy):
            raise TypeError("receiving routes must be URI strings, Proxy or None")
        result.append(
            (None, None, None)
            if route is None
            else (route.url, route.username, route.password)
        )
    return result


def _checkpoint_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("checkpoint and key must be bytes")
    return value


class AttemptBudget:
    """One allowance shared across requests and clients, including resends."""

    def __init__(self, maximum: int) -> None:
        self._native = _native.AttemptBudget(maximum)

    @property
    def remaining(self) -> int:
        return self._native.remaining

    def try_admit(self) -> None:
        """Charge an attempt outside Phantom; requests are charged already."""
        _call(self._native.try_admit)


class Cookies:
    """The client's shared, bounded cookie jar."""

    def __init__(self, native: _native.NativeCookies) -> None:
        self._native = native

    def set(self, url: str, set_cookie: str) -> None:
        _call(self._native.set, url, set_cookie)

    def for_url(self, url: str) -> str | None:
        return _call(self._native.for_url, url)

    def clear(self) -> None:
        _call(self._native.clear)

    def __len__(self) -> int:
        return len(self._native)
