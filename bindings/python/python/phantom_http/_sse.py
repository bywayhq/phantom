"""Pull-driven events from one HTTP response."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import _native
from ._errors import _call, _primary_error

if TYPE_CHECKING:
    from ._response import AsyncResponse
    from ._sync import Client, Response


@dataclass(frozen=True)
class SseLimits:
    """Encoded bytes per line and event block, excluding line endings."""

    max_line_bytes: int = 64 * 1024
    max_event_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        import sys

        for name in ("max_line_bytes", "max_event_bytes"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 2 * sys.maxsize + 1:
                raise ValueError(f"{name} must be a nonnegative platform-sized integer")


_DEFAULT_SSE_LIMITS = SseLimits()


@dataclass(frozen=True)
class Event:
    """Dispatched data, event type (default message), and persistent event ID."""

    data: str = field(repr=False)
    event: str
    id: str = field(repr=False)


class AsyncEventStream:
    """Async iterator over one response. Close it when you stop reading."""

    def __init__(
        self, response: AsyncResponse, native: _native.NativeEventStream
    ) -> None:
        self.response = response
        self._native = native
        self._finished = False

    @property
    def last_event_id(self) -> str:
        return _call(lambda: self._native.last_event_id)

    @property
    def retry_ms(self) -> int | None:
        """Last valid retry field in milliseconds, or None; no reconnect occurs."""
        return _call(lambda: self._native.retry_ms)

    def __aiter__(self) -> AsyncEventStream:
        return self

    async def __anext__(self) -> Event:
        if self._finished:
            raise StopAsyncIteration
        try:
            fields = await self._native.next_event()
            self.response._check_upload()
        except BaseException as error:
            # A rejected concurrent read does not own the pending reader.
            from ._errors import Error, _error

            primary = _error(error) if isinstance(error, _native.NativeError) else error
            if isinstance(primary, Error) and primary.kind == "concurrent_body_read":
                raise primary from None
            self._finished = True
            raise await self.response._close_after_error(error) from None
        if fields is None:
            self._finished = True
            await self.response.aclose()
            raise StopAsyncIteration
        return Event(*fields)

    def close(self) -> None:
        self.response.close()
        self._finished = True

    async def aclose(self, *, timeout_ms: int = 5000) -> None:
        await self.response.aclose(timeout_ms=timeout_ms)
        self._finished = True

    async def __aenter__(self) -> AsyncEventStream:
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


class EventStream:
    """Synchronous iterator over one response, owned by its creating client."""

    def __init__(self, client: Client, stream: AsyncEventStream) -> None:
        self._client = client
        self._stream = stream

    @property
    def response(self) -> Response:
        """The response head and retained trailers for this event stream."""
        from ._sync import Response

        return Response(self._client, self._stream.response)

    @property
    def last_event_id(self) -> str:
        return self._stream.last_event_id

    @property
    def retry_ms(self) -> int | None:
        return self._stream.retry_ms

    def __iter__(self) -> EventStream:
        return self

    def __next__(self) -> Event:
        try:
            return self._client._run(self._stream.__anext__)
        except StopAsyncIteration:
            raise StopIteration from None

    def close(self) -> None:
        self.response.close()
        self._stream._finished = True

    def __enter__(self) -> EventStream:
        return self

    def __exit__(self, _: object, error: BaseException | None, __: object) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise
