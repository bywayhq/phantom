"""Pull-based WebSockets on the client's native transport and profile."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypeAlias, cast

from . import _native
from ._configuration import INHERIT, _Inherit
from ._errors import Error, TimeoutError, _error, _primary_error
from ._request import _Headers, _request_fields
from ._response import AsyncResponse, ResponseHeader, ResponseHeaders

if TYPE_CHECKING:
    from ._sync import Response

_WebSocketProtocol: TypeAlias = Literal["profile", "h1", "h2", "h3"]


@dataclass(frozen=True)
class WebSocketLimits:
    """Positive frame/message byte limits and data-frame count per message."""

    maximum_frame_bytes: int = 16 * 1024 * 1024
    maximum_message_bytes: int = 64 * 1024 * 1024
    maximum_fragments: int = 131072

    def __post_init__(self) -> None:
        for value in (
            self.maximum_frame_bytes,
            self.maximum_message_bytes,
            self.maximum_fragments,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("WebSocket limits must be positive integers")
        if self.maximum_frame_bytes > self.maximum_message_bytes:
            raise ValueError("frame limit must not exceed message limit")


_DEFAULT_WEBSOCKET_LIMITS = WebSocketLimits()


@dataclass(frozen=True, kw_only=True)
class WebSocketRetry:
    """Retry setup failures before the opening reaches the origin; delay is milliseconds."""

    maximum: int
    delay_ms: int = 0

    def __post_init__(self) -> None:
        if type(self.maximum) is not int or not 1 <= self.maximum <= 2**32 - 1:
            raise ValueError("WebSocket retry maximum must be a positive u32 integer")
        if type(self.delay_ms) is not int or not 0 <= self.delay_ms <= 2**64 - 1:
            raise ValueError("WebSocket retry delay_ms must be a u64 integer")


@dataclass(frozen=True)
class WebSocketPing:
    """Received Ping; the native engine has already flushed its Pong reply."""

    data: bytes = field(repr=False)


@dataclass(frozen=True)
class WebSocketPong:
    """Received Pong control message."""

    data: bytes = field(repr=False)


@dataclass(frozen=True)
class WebSocketClose:
    """Received Close; no status code means the peer sent an empty Close frame."""

    code: int | None
    reason: str = field(default="", repr=False)


WebSocketMessage: TypeAlias = (
    str | bytes | WebSocketPing | WebSocketPong | WebSocketClose
)


class WebSocketError(Error):
    """A redacted WebSocket handshake, framing or transport failure."""

    def __init__(
        self,
        category: str,
        kind: str,
        protocol: str | None = None,
        timeout_phase: str | None = None,
    ) -> None:
        super().__init__(category, kind, protocol, timeout_phase)
        self.response: AsyncResponse | Response | None = None


class WebSocketClosed(WebSocketError):
    """recv reached Close; code/reason describe the peer's optional close frame."""

    def __init__(self, frame: WebSocketClose | None = None) -> None:
        super().__init__("websocket", "closed")
        self.code = frame.code if frame is not None else None
        self.reason = frame.reason if frame is not None else ""


def _failure(error: _native.NativeError) -> Error:
    mapped = _error(error)
    if mapped.category != "websocket":
        return mapped
    if mapped.kind == "closed":
        return WebSocketClosed()
    if type(mapped) is not Error:
        return mapped
    failure = WebSocketError(
        mapped.category, mapped.kind, mapped.protocol, mapped.timeout_phase
    )
    response = cast("_native.NativeResponse | None", getattr(error, "response", None))
    if response is not None:
        failure.response = AsyncResponse(response)
    return failure


def _close_frame(code: int | None, reason: str) -> None:
    if code is not None and (type(code) is not int or not 0 <= code <= 65535):
        raise ValueError("WebSocket close code must be a u16 integer or None")
    if not isinstance(reason, str):
        raise TypeError("WebSocket close reason must be str")
    if code is None and reason:
        raise ValueError("WebSocket close reason requires a code")
    if len(reason) > 123 or len(reason.encode()) > 123:
        raise ValueError("WebSocket close reason exceeds 123 UTF-8 bytes")


class AsyncWebSocket:
    """One reader and one writer may run together; cancellation aborts this socket."""

    def __init__(self, native: _native.NativeWebSocket) -> None:
        self._native = native
        self._loop = asyncio.get_running_loop()
        self.status = native.status
        self.protocol = native.protocol
        self.selected_protocol = native.selected_protocol
        self.headers = ResponseHeaders(
            ResponseHeader(name, value, sensitive)
            for name, value, sensitive in native.headers
        )
        self._close_frame: WebSocketClose | None = None
        self._receiving = False
        self._receive_idle = asyncio.Event()
        self._receive_idle.set()

    @property
    def is_closed(self) -> bool:
        return self._native.is_closed

    def _check_loop(self) -> None:
        if asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("WebSockets belong to their opening event loop")

    async def send(self, data: str | bytes) -> None:
        """Flush one complete text or binary message within the configured limit."""
        self._check_loop()
        try:
            await self._native.send(data)
        except asyncio.CancelledError:
            self.abort()
            raise
        except _native.NativeError as error:
            raise _failure(error) from None

    async def receive(self) -> WebSocketMessage:
        """Pull one data/control message; a peer Close is returned exactly once."""
        self._check_loop()
        if self.is_closed:
            raise WebSocketClosed(self._close_frame)
        if self._receiving:
            raise WebSocketError("websocket", "concurrent_receive", self.protocol)
        self._receiving = True
        self._receive_idle.clear()
        try:
            try:
                kind, data, code = await self._native.receive()
            except asyncio.CancelledError:
                self.abort()
                raise
            except _native.NativeError as error:
                raise _failure(error) from None
            if kind == "text":
                return cast(str, data)
            if kind == "binary":
                return cast(bytes, data)
            if kind == "ping":
                return WebSocketPing(cast(bytes, data))
            if kind == "pong":
                return WebSocketPong(cast(bytes, data))
            self._close_frame = WebSocketClose(code, cast(str | None, data) or "")
            return self._close_frame
        finally:
            self._receiving = False
            self._receive_idle.set()

    async def recv(self) -> str | bytes:
        """Pull the next data message, skipping Ping/Pong; Close raises WebSocketClosed."""
        while True:
            message = await self.receive()
            if isinstance(message, (str, bytes)):
                return message
            if isinstance(message, WebSocketClose):
                raise WebSocketClosed(message)

    async def ping(self, data: bytes = b"") -> None:
        """Flush a Ping with at most 125 payload bytes; does not await a Pong."""
        self._check_loop()
        try:
            await self._native.ping(data)
        except asyncio.CancelledError:
            self.abort()
            raise
        except _native.NativeError as error:
            raise _failure(error) from None

    async def pong(self, data: bytes = b"") -> None:
        """Flush an unsolicited Pong with at most 125 payload bytes."""
        self._check_loop()
        try:
            await self._native.pong(data)
        except asyncio.CancelledError:
            self.abort()
            raise
        except _native.NativeError as error:
            raise _failure(error) from None

    async def send_close(self, code: int | None = 1000, reason: str = "") -> None:
        """Flush Close without waiting for the peer; None sends an empty frame."""
        self._check_loop()
        _close_frame(code, reason)
        try:
            await self._native.close(code, reason)
        except asyncio.CancelledError:
            self.abort()
            raise
        except _native.NativeError as error:
            raise _failure(error) from None

    async def aclose(
        self, code: int | None = 1000, reason: str = "", *, timeout_ms: int = 5000
    ) -> None:
        """Flush Close, await the peer reply, then release; timeout bounds both phases."""
        self._check_loop()
        if self.is_closed:
            return
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise ValueError("close timeout_ms must be a positive integer")

        _close_frame(code, reason)
        try:
            closing = self._native.close(code, reason)
        except _native.NativeError as error:
            raise _failure(error) from None

        async def handshake() -> None:
            try:
                await closing
            except _native.NativeError as error:
                raise _failure(error) from None
            while not self.is_closed:
                # An existing receive owns the stream until its next event or close.
                await self._receive_idle.wait()
                if self._receiving:
                    continue
                if not self.is_closed:
                    await self.receive()

        try:
            await asyncio.wait_for(handshake(), timeout_ms / 1000)
        except asyncio.TimeoutError:
            raise TimeoutError(
                "websocket", "timeout", self.protocol, "websocket_close"
            ) from None
        finally:
            self.abort()

    def abort(self) -> None:
        """Release this socket immediately and wake its pending operations."""
        self._native.abort()

    def __aiter__(self) -> AsyncWebSocket:
        return self

    async def __anext__(self) -> str | bytes:
        try:
            return await self.recv()
        except WebSocketClosed as error:
            if error.code in (None, 1000, 1001):
                raise StopAsyncIteration from None
            raise

    async def __aenter__(self) -> AsyncWebSocket:
        self._check_loop()
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


class _WebSocketConnect:
    def __init__(
        self,
        native: _native.NativeClient,
        url: str,
        protocol: _WebSocketProtocol,
        headers: _Headers,
        limits: WebSocketLimits,
        handshake_timeout_ms: int | None | _Inherit,
        retry: WebSocketRetry | None,
    ) -> None:
        if not isinstance(url, str):
            raise TypeError("WebSocket url must be str")
        if len(url) > 65536 or len(url.encode()) > 65536:
            raise ValueError("WebSocket url exceeds 65536 bytes")
        if protocol not in ("profile", "h1", "h2", "h3"):
            raise ValueError("WebSocket protocol must be profile, h1, h2 or h3")
        if not isinstance(limits, WebSocketLimits):
            raise TypeError("limits must be WebSocketLimits")
        if (
            handshake_timeout_ms is not INHERIT
            and handshake_timeout_ms is not None
            and (
                type(handshake_timeout_ms) is not int
                or not 0 < handshake_timeout_ms <= 2**64 - 1
            )
        ):
            raise ValueError(
                "handshake_timeout_ms must be a positive u64 integer, None or INHERIT"
            )
        if retry is not None and not isinstance(retry, WebSocketRetry):
            raise TypeError("retry must be WebSocketRetry or None")
        self._native = native
        self._arguments = (
            url,
            protocol,
            _request_fields(headers, ())[0],
            limits.maximum_frame_bytes,
            limits.maximum_message_bytes,
            limits.maximum_fragments,
            handshake_timeout_ms is INHERIT,
            handshake_timeout_ms if isinstance(handshake_timeout_ms, int) else None,
            retry.maximum if retry is not None else None,
            retry.delay_ms if retry is not None else 0,
        )
        self._used = False
        self._socket: AsyncWebSocket | None = None

    async def _connect(self) -> AsyncWebSocket:
        if self._used:
            raise RuntimeError("a WebSocket opening can only be awaited once")
        self._used = True
        try:
            self._socket = AsyncWebSocket(
                await self._native.websocket(*self._arguments)
            )
        except _native.NativeError as error:
            raise _failure(error) from None
        return self._socket

    def __await__(self) -> Generator[object, None, AsyncWebSocket]:
        return cast(
            Generator[object, None, AsyncWebSocket], self._connect().__await__()
        )

    async def __aenter__(self) -> AsyncWebSocket:
        return await self

    async def __aexit__(
        self, kind: object, error: BaseException | None, traceback: object
    ) -> None:
        if self._socket is not None:
            await self._socket.__aexit__(kind, error, traceback)
