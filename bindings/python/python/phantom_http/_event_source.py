"""Pull-driven event sources with bounded reconnection."""

from __future__ import annotations

import asyncio
import math
import sys
from collections.abc import Generator, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypedDict, cast

from . import _native
from ._configuration import INHERIT, Header, Proxy, TimeoutOverrides, _Inherit
from ._errors import _call, _error, _primary_error
from ._request import _request_fields
from ._sse import _DEFAULT_SSE_LIMITS, Event, SseLimits

if TYPE_CHECKING:
    from ._response import ResponseHeaders
    from ._sync import Client

_SseProtocol = Literal["h1", "h2", "h3"]


@dataclass(frozen=True)
class LastEventId:
    """Place the managed event ID here; use lowercase on HTTP/2 and HTTP/3."""

    name: str


_SourceHeaders = Iterable[Header | tuple[str, str | bytes] | LastEventId]


class _EventSourceOptions(TypedDict, total=False):
    headers: _SourceHeaders | None
    limits: SseLimits
    idle_timeout: float | None
    initial_retry: float
    min_retry: float | None
    max_reconnects: int
    timeouts: TimeoutOverrides | None
    proxy: str | Proxy | None | _Inherit


class _NativeOptions(TypedDict):
    headers: list[tuple[str, bytes, bool]] | None
    last_event_id_slot: int | None
    maximum_line_bytes: int
    maximum_event_bytes: int
    idle_timeout: float | None
    initial_retry: float
    min_retry: float | None
    max_reconnects: int
    timeouts: list[tuple[str, float | None]] | None
    inherit_proxy: bool
    proxy: str | None
    proxy_username: str | None
    proxy_password: str | None


def _duration(value: float, name: str) -> float:
    if type(value) not in (int, float):
        raise TypeError(f"{name} must be finite nonnegative seconds")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be finite nonnegative seconds") from None
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be finite nonnegative seconds")
    return result


class AsyncEventSource:
    """Read events with bounded reconnects; close when you stop iterating."""

    def __init__(self, native: _native.NativeEventSource) -> None:
        from ._response import ResponseHeader, ResponseHeaders

        self._native = native
        self._finished = False
        self.status = native.status
        self.protocol = native.protocol
        self.url = native.url
        self.headers = ResponseHeaders(
            ResponseHeader(*field) for field in native.headers
        )

    @property
    def status_code(self) -> int:
        """Initial response status; the other head fields are initial snapshots too."""
        return self.status

    @property
    def last_event_id(self) -> str:
        return _call(lambda: self._native.last_event_id)

    @property
    def retry_ms(self) -> int:
        """Effective reconnect delay in milliseconds, including a caller minimum."""
        return _call(lambda: self._native.retry_ms)

    @property
    def reconnects(self) -> int:
        return _call(lambda: self._native.reconnects)

    @property
    def closed(self) -> bool:
        return _call(lambda: self._native.is_closed)

    def __aiter__(self) -> AsyncEventSource:
        return self

    async def __anext__(self) -> Event:
        if self._finished:
            raise StopAsyncIteration
        try:
            fields = await self._native.next_event()
        except asyncio.CancelledError as error:
            try:
                # Python cancellation schedules native cancellation asynchronously.
                await asyncio.wait_for(self._native.wait_idle(), 5)
            except BaseException as cleanup:
                raise _primary_error(error, cleanup=cleanup) from None
            raise
        except _native.NativeError as error:
            failure = _error(error)
            if failure.kind != "concurrent_event_read":
                self._finished = True
            raise failure from None
        # Cancelled reads preserve the native source and any pending reconnect.
        if fields is None:
            self._finished = True
            raise StopAsyncIteration
        return Event(*fields)

    def close(self) -> None:
        """Stop reads and reconnects; this operation is idempotent."""
        _call(self._native.close)
        self._finished = True

    async def aclose(self, *, timeout_ms: int = 5000) -> None:
        """Stop and wait for an in-flight read to release its native ownership."""
        from ._client import _shutdown_timeout

        _shutdown_timeout(timeout_ms)
        self.close()
        try:
            await self._native.wait_closed(timeout_ms)
        except _native.NativeError as error:
            raise _error(error) from None

    async def __aenter__(self) -> AsyncEventSource:
        return self

    async def __aexit__(
        self, _: object, error: BaseException | None, __: object
    ) -> None:
        try:
            await self.aclose()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise


class EventSource:
    """Synchronous event iterator on its creating client's loop and thread."""

    def __init__(self, client: Client, source: AsyncEventSource) -> None:
        self._client = client
        self._source = source

    @property
    def status(self) -> int:
        return self._source.status

    @property
    def status_code(self) -> int:
        return self._source.status_code

    @property
    def protocol(self) -> str:
        return self._source.protocol

    @property
    def url(self) -> str:
        return self._source.url

    @property
    def headers(self) -> ResponseHeaders:
        return self._source.headers

    @property
    def last_event_id(self) -> str:
        return self._source.last_event_id

    @property
    def retry_ms(self) -> int:
        return self._source.retry_ms

    @property
    def reconnects(self) -> int:
        return self._source.reconnects

    @property
    def closed(self) -> bool:
        return self._source.closed

    def __iter__(self) -> EventSource:
        return self

    def __next__(self) -> Event:
        try:
            return self._client._run(self._source.__anext__)
        except StopAsyncIteration:
            raise StopIteration from None

    def close(self, *, timeout_ms: int = 5000) -> None:
        from ._client import _shutdown_timeout

        self._client._check_thread_loop()
        _shutdown_timeout(timeout_ms)
        if self._client._loop.is_closed() and self.closed:
            return
        self._client._run(lambda: self._source.aclose(timeout_ms=timeout_ms))

    def __enter__(self) -> EventSource:
        return self

    def __exit__(self, _: object, error: BaseException | None, __: object) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise


class _EventSourceConnect:
    def __init__(
        self,
        native: _native.NativeClient,
        url: str,
        protocol: _SseProtocol,
        *,
        headers: _SourceHeaders | None = None,
        limits: SseLimits = _DEFAULT_SSE_LIMITS,
        idle_timeout: float | None = None,
        initial_retry: float = 3.0,
        min_retry: float | None = None,
        max_reconnects: int = 3,
        timeouts: TimeoutOverrides | None = None,
        proxy: str | Proxy | None | _Inherit = INHERIT,
    ) -> None:
        if not isinstance(url, str):
            raise TypeError("EventSource url must be str")
        if len(url) > 65536 or len(url.encode()) > 65536:
            raise ValueError("EventSource url exceeds 65536 bytes")
        if protocol not in ("h1", "h2", "h3"):
            raise ValueError("EventSource protocol must be h1, h2 or h3")
        if not isinstance(limits, SseLimits):
            raise TypeError("limits must be SseLimits")
        limits.__post_init__()
        if (
            type(max_reconnects) is not int
            or not 0 <= max_reconnects <= 2 * sys.maxsize + 1
        ):
            raise ValueError(
                "max_reconnects must be a nonnegative platform-sized integer"
            )
        if timeouts is not None and not isinstance(timeouts, TimeoutOverrides):
            raise TypeError("timeouts must be TimeoutOverrides or None")
        if timeouts is not None and not isinstance(timeouts.read_idle, _Inherit):
            raise ValueError(
                "EventSource uses idle_timeout instead of timeouts.read_idle"
            )
        if (
            not isinstance(proxy, _Inherit)
            and proxy is not None
            and not isinstance(proxy, (str, Proxy))
        ):
            raise TypeError("proxy must be str, Proxy, None or INHERIT")
        selected_proxy = Proxy(proxy) if isinstance(proxy, str) else proxy
        slot: int | None = None

        def fields(
            source: _SourceHeaders,
        ) -> Generator[Header | tuple[str, str | bytes], None, None]:
            nonlocal slot
            for index, field in enumerate(source):
                if isinstance(field, LastEventId):
                    if slot is not None:
                        raise ValueError("headers can contain only one LastEventId")
                    slot = index
                    yield (field.name, b"")
                else:
                    yield field

        ordered = None if headers is None else _request_fields(fields(headers), ())[0]
        self._options: _NativeOptions = {
            "headers": ordered,
            "last_event_id_slot": slot,
            "maximum_line_bytes": limits.max_line_bytes,
            "maximum_event_bytes": limits.max_event_bytes,
            "idle_timeout": None
            if idle_timeout is None
            else _duration(idle_timeout, "idle_timeout"),
            "initial_retry": _duration(initial_retry, "initial_retry"),
            "min_retry": None
            if min_retry is None
            else _duration(min_retry, "min_retry"),
            "max_reconnects": max_reconnects,
            "timeouts": None if timeouts is None else timeouts._native_fields(),
            "inherit_proxy": isinstance(proxy, _Inherit),
            "proxy": selected_proxy.url if isinstance(selected_proxy, Proxy) else None,
            "proxy_username": selected_proxy.username
            if isinstance(selected_proxy, Proxy)
            else None,
            "proxy_password": selected_proxy.password
            if isinstance(selected_proxy, Proxy)
            else None,
        }
        self._native = native
        self._url = url
        self._protocol = protocol
        self._used = False
        self._source: AsyncEventSource | None = None

    async def _connect(self) -> AsyncEventSource:
        if self._used:
            raise RuntimeError("an EventSource opening can only be awaited once")
        self._used = True
        try:
            self._source = AsyncEventSource(
                await self._native.event_source(
                    self._url, self._protocol, **self._options
                )
            )
        except _native.NativeError as error:
            raise _error(error) from None
        return self._source

    def __await__(self) -> Generator[object, None, AsyncEventSource]:
        return cast(
            Generator[object, None, AsyncEventSource], self._connect().__await__()
        )

    async def __aenter__(self) -> AsyncEventSource:
        return await self

    async def __aexit__(
        self, kind: object, error: BaseException | None, traceback: object
    ) -> None:
        if self._source is not None:
            await self._source.__aexit__(kind, error, traceback)
