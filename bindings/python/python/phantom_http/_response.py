"""Response metadata, body readers and terminal cleanup."""

from __future__ import annotations

import asyncio
import codecs
import json as _json
import sys
from collections.abc import (
    AsyncGenerator,
)
from dataclasses import dataclass
from dataclasses import field as _field
from typing import (
    Literal,
    TypeVar,
    cast,
    overload,
)

from . import _native, _upload
from ._errors import (
    DecodeError,
    Error,
    TimeoutError,
    _call,
    _primary_error,
    _upload_error,
)
from ._sse import _DEFAULT_SSE_LIMITS, AsyncEventStream, SseLimits


@dataclass(frozen=True)
class RedirectHop:
    """One followed redirect; URL fields are omitted from repr."""

    from_url: str = _field(repr=False)
    to_url: str = _field(repr=False)
    method: str
    next_method: str
    status: int


@dataclass(frozen=True)
class RedirectHistory:
    """First retained hops and the count of later omitted redirects."""

    entries: tuple[RedirectHop, ...]
    omitted_hops: int


@dataclass(frozen=True)
class ResponseHeader:
    """One ordered received field with an owned byte value."""

    name: str
    value: bytes = _field(repr=False)
    # False also covers protocols whose decoder omits sensitivity markers.
    sensitive: bool


_Default = TypeVar("_Default")


class ResponseHeaders(tuple[ResponseHeader, ...]):
    """Ordered raw fields with case-insensitive lookups; duplicates stay separate."""

    @overload
    def get(self, name: str) -> bytes | None: ...

    @overload
    def get(self, name: str, default: _Default) -> bytes | _Default: ...

    def get(
        self, name: str, default: _Default | None = None
    ) -> bytes | _Default | None:
        """Return the first matching raw value, or default when absent."""
        if not isinstance(name, str):
            raise TypeError("header name must be str")
        key = name.lower()
        return next(
            (field.value for field in self if field.name.lower() == key), default
        )

    def get_list(self, name: str) -> list[bytes]:
        """Return all matching raw values in received order, without joining them."""
        if not isinstance(name, str):
            raise TypeError("header name must be str")
        key = name.lower()
        return [field.value for field in self if field.name.lower() == key]


@dataclass(frozen=True)
class ResponseTrailers:
    """Non-draining snapshot; only complete has fields, possibly an empty tuple."""

    state: Literal["pending", "unavailable", "complete"]
    headers: tuple[ResponseHeader, ...] | None


class AsyncResponse:
    """An owned response body. Close it when you stop reading."""

    def __init__(
        self, native: _native.NativeResponse, upload: _upload.Upload | None = None
    ) -> None:
        self._native = native
        self._upload = upload
        self.status = native.status
        self.protocol = native.protocol
        self.headers = ResponseHeaders(
            ResponseHeader(*field) for field in native.headers
        )

    @property
    def url(self) -> str:
        """The effective URL reported by the HTTP client."""
        return self._native.url

    @property
    def redirects_followed(self) -> int:
        return self._native.redirects_followed

    @property
    def connection_setup_retries(self) -> int:
        """Caller-enabled connection-setup retries, excluding protocol replays."""
        return self._native.connection_setup_retries

    @property
    def redirect_history(self) -> RedirectHistory | None:
        retained = self._native.redirect_history
        if retained is None:
            return None
        entries, omitted = retained
        return RedirectHistory(tuple(RedirectHop(*hop) for hop in entries), omitted)

    @property
    def decoded_content_codings(self) -> tuple[str, ...]:
        """Recorded application order; this does not imply body completion."""
        return tuple(self._native.decoded_content_codings)

    @property
    def trailers(self) -> ResponseTrailers:
        """Retained fields after validated EOF, without reading the body."""
        state, headers = _call(lambda: self._native.trailers)
        if state not in ("pending", "unavailable", "complete"):
            raise Error("response", "unsupported_response_trailers")
        return ResponseTrailers(
            cast(Literal["pending", "unavailable", "complete"], state),
            None
            if headers is None
            else tuple(ResponseHeader(*field) for field in headers),
        )

    @property
    def status_code(self) -> int:
        return self.status

    def raise_for_status(self) -> None:
        """Raise for HTTP 4xx/5xx without consuming or closing the body."""
        from ._sync import HTTPStatusError

        if 400 <= self.status < 600:
            raise HTTPStatusError(self)

    def close(self) -> None:
        if self._upload is not None:
            self._upload.check_loop()
        _call(self._native.close)
        if self._upload is not None:
            self._upload.close()

    def events(self, *, limits: SseLimits = _DEFAULT_SSE_LIMITS) -> AsyncEventStream:
        """Consume an unread 200 text/event-stream response without reconnecting.

        Invalid metadata leaves the body readable. A previous byte read or event
        conversion is rejected without disturbing its current reader.
        """
        if not isinstance(limits, SseLimits):
            raise TypeError("limits must be SseLimits")
        native = _call(
            self._native.events, limits.max_line_bytes, limits.max_event_bytes
        )
        return AsyncEventStream(self, native)

    async def aclose(self, *, timeout_ms: int = 5000) -> None:
        """Abort the body and settle cooperative producer cleanup."""
        if self._upload is not None:
            self._upload.check_wait()
        self.close()
        if self._upload is not None:
            if not await self._upload.wait(timeout_ms):
                raise TimeoutError("request", "shutdown_timeout", self.protocol)
            self._check_upload()

    def _check_upload(self) -> None:
        if self._upload is not None and (
            self._upload.error is not None or self._upload.cleanup_error is not None
        ):
            raise _upload_error(self._upload) from None

    async def _close_after_error(self, error: BaseException) -> BaseException:
        primary = _primary_error(error)
        if (
            isinstance(primary, Error)
            and primary.category == "input"
            and primary.kind in ("concurrent_body_read", "body_consumed")
        ):
            # The rejected call never acquired the other read's body lease.
            return primary
        try:
            await self.aclose()
        except BaseException as cleanup:
            return _primary_error(error, self._upload, cleanup)
        return _primary_error(error, self._upload)

    async def read_chunk(self, maximum: int = 65536) -> bytes | None:
        """Read at most maximum bytes (1 through 1 MiB), or None at EOF."""
        try:
            chunk = await self._native.read_chunk(maximum)
            if chunk is None:
                await self.aclose()
            self._check_upload()
            return chunk
        except asyncio.CancelledError as error:
            try:
                self.close()
            except BaseException as cleanup:
                raise _primary_error(error, self._upload, cleanup) from None
            raise _primary_error(error, self._upload) from None
        except BaseException as error:
            raise await self._close_after_error(error) from None

    async def iter_bytes(self, chunk_size: int = 65536) -> AsyncGenerator[bytes, None]:
        try:
            while (chunk := await self.read_chunk(chunk_size)) is not None:
                yield chunk
        except BaseException as error:
            raise await self._close_after_error(error) from None
        else:
            await self.aclose()

    async def read(self, *, max_bytes: int) -> bytes:
        """Collect up to max_bytes; close on completion or a body failure."""
        if not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a nonnegative integer")
        try:
            body = await self._native.read(min(max_bytes, sys.maxsize))
        except BaseException as error:
            raise await self._close_after_error(error) from None
        await self.aclose()
        return body

    async def text(
        self, *, max_bytes: int, encoding: str = "utf-8", errors: str = "strict"
    ) -> str:
        """Collect and decode remaining bytes with an explicit input limit."""
        try:
            codecs.lookup(encoding)
            codecs.lookup_error(errors)
        except LookupError:
            raise DecodeError("response", "encoding", self.protocol) from None
        body = await self.read(max_bytes=max_bytes)
        try:
            return body.decode(encoding, errors)
        except (UnicodeError, LookupError):
            raise DecodeError("response", "text_decode", self.protocol) from None

    async def json(self, *, max_bytes: int) -> object:
        """Collect and parse remaining bytes using Python's JSON decoder."""
        body = await self.read(max_bytes=max_bytes)
        try:
            return cast(object, _json.loads(body))
        except (ValueError, RecursionError):
            raise DecodeError("response", "json_decode", self.protocol) from None

    async def __aenter__(self) -> AsyncResponse:
        return self

    async def __aexit__(
        self, _: object, error: BaseException | None, __: object
    ) -> None:
        if error is not None:
            raise await self._close_after_error(error) from None
        await self.aclose()
