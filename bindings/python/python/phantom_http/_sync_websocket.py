"""Synchronous WebSockets use the owning client's existing wait bridge."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._errors import _primary_error
from ._websocket import (
    AsyncWebSocket,
    WebSocketClosed,
    WebSocketMessage,
)

if TYPE_CHECKING:
    from ._sync import Client


class WebSocket:
    """A synchronous socket bound to its client's creating thread."""

    def __init__(self, client: Client, socket: AsyncWebSocket) -> None:
        self._client = client
        self._socket = socket
        self.status = socket.status
        self.protocol = socket.protocol
        self.selected_protocol = socket.selected_protocol
        self.headers = socket.headers

    @property
    def is_closed(self) -> bool:
        return self._socket.is_closed

    def send(self, data: str | bytes) -> None:
        """Flush one complete text or binary message."""
        self._client._run(lambda: self._socket.send(data))

    def recv(self) -> str | bytes:
        """Read the next data message; a peer Close raises WebSocketClosed."""
        return self._client._run(lambda: self._socket.recv())

    def receive(self) -> WebSocketMessage:
        """Read one data or control message."""
        return self._client._run(lambda: self._socket.receive())

    def ping(self, data: bytes = b"") -> None:
        self._client._run(lambda: self._socket.ping(data))

    def pong(self, data: bytes = b"") -> None:
        self._client._run(lambda: self._socket.pong(data))

    def close(
        self, code: int = 1000, reason: str = "", *, timeout_ms: int = 5000
    ) -> None:
        """Flush Close and release the socket without waiting for the peer."""
        self._client._run(
            lambda: self._socket.aclose(code, reason, timeout_ms=timeout_ms)
        )

    def abort(self) -> None:
        self._client._check_thread_loop()
        self._socket.abort()

    def __iter__(self) -> WebSocket:
        return self

    def __next__(self) -> str | bytes:
        try:
            return self.recv()
        except WebSocketClosed as error:
            if error.code in (None, 1000, 1001):
                raise StopIteration from None
            raise

    def __enter__(self) -> WebSocket:
        return self

    def __exit__(self, _: object, error: BaseException | None, __: object) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise
