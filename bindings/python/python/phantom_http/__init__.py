"""HTTP requests with explicit browser profiles and protocols."""

from __future__ import annotations

import asyncio
import contextlib
import sys
import threading
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator, Iterable
from os import PathLike
from typing import Literal, ParamSpec, TypeAlias, TypeVar, cast

from . import _native

_Protocol: TypeAlias = Literal["h1", "h2", "h3", "negotiated"]
_Context: TypeAlias = Literal["navigation", "fetch"]
_Headers: TypeAlias = Iterable[tuple[str, str | bytes]]
_UploadPath: TypeAlias = str | PathLike[str]
_P = ParamSpec("_P")
_T = TypeVar("_T")


class Error(Exception):
    """A redacted failure with stable kind, protocol and timeout_phase fields."""

    def __init__(
        self,
        category: str,
        kind: str,
        protocol: str | None = None,
        timeout_phase: str | None = None,
    ) -> None:
        super().__init__(f"{category}: {kind}")
        self.category = category
        self.kind = kind
        self.protocol = protocol
        self.timeout_phase = timeout_phase


class TimeoutError(Error):
    """A request or graceful shutdown reached its deadline."""


class AttemptBudgetExhausted(Error):
    """The shared origin HTTP attempt allowance is exhausted."""


class ClientClosed(Error):
    """The client has stopped admitting requests."""


class BodyLimitExceeded(Error):
    """Body collection exceeded the caller's bound."""


def _error(error: _native.NativeError) -> Error:
    category, kind, protocol, phase = cast(
        tuple[str, str, str | None, str | None], error.args
    )
    cls = {
        "timeout": TimeoutError,
        "shutdown_timeout": TimeoutError,
        "attempt_budget_exhausted": AttemptBudgetExhausted,
        "client_closed": ClientClosed,
        "response_body_limit": BodyLimitExceeded,
    }.get(kind, Error)
    return cls(category, kind, protocol, phase)


def _call(function: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
    try:
        return function(*args, **kwargs)
    except _native.NativeError as error:
        raise _error(error) from None


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


class AsyncResponse:
    """An owned response body. Close it when you stop reading."""

    def __init__(self, native: _native.NativeResponse) -> None:
        self._native = native
        self.status = native.status
        self.protocol = native.protocol
        self.headers = native.headers

    def close(self) -> None:
        _call(self._native.close)

    async def read_chunk(self, maximum: int = 65536) -> bytes | None:
        """Read at most maximum bytes (1 through 1 MiB), or None at EOF."""
        try:
            return await self._native.read_chunk(maximum)
        except asyncio.CancelledError:
            self.close()
            raise
        except _native.NativeError as error:
            raise _error(error) from None

    async def iter_bytes(self, chunk_size: int = 65536) -> AsyncGenerator[bytes, None]:
        try:
            while (chunk := await self.read_chunk(chunk_size)) is not None:
                yield chunk
        finally:
            self.close()

    async def read(self, *, max_bytes: int) -> bytes:
        """Collect up to max_bytes. The body closes on failure or completion."""
        if not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a nonnegative integer")
        try:
            return await self._native.read(min(max_bytes, sys.maxsize))
        except _native.NativeError as error:
            raise _error(error) from None
        finally:
            self.close()

    async def __aenter__(self) -> AsyncResponse:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class AsyncClient:
    """Reuse connections and cookies across requests."""

    def __init__(
        self,
        *,
        profile: str,
        protocol: _Protocol,
        context: _Context | None = None,
        proxy: str | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
    ) -> None:
        self._native = _call(
            _native.NativeClient, profile, protocol, context, proxy, cookies, timeout_ms
        )
        self.cookies = Cookies(self._native.cookies)

    @property
    def is_closed(self) -> bool:
        return self._native.is_closed

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: _Headers = (),
        body: bytes | None = None,
        upload: _UploadPath | None = None,
        budget: AttemptBudget | None = None,
        timeout_ms: int | None = None,
    ) -> AsyncResponse:
        """Return the response head without collecting its body."""
        ordered = []
        for name, value in headers:
            if isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except UnicodeEncodeError:
                    raise ValueError(
                        "header text must fit Latin-1; supply bytes explicitly"
                    ) from None
            if not isinstance(value, bytes):
                raise TypeError("header values must be str or bytes")
            ordered.append((name, value))
        try:
            native = await self._native.request(
                method,
                url,
                ordered,
                body,
                upload,
                None if budget is None else budget._native,
                timeout_ms,
            )
            return AsyncResponse(native)
        except _native.NativeError as error:
            raise _error(error) from None

    async def close(self, *, timeout_ms: int = 5000) -> None:
        """Close admission and wait for active owners within this bound."""
        try:
            await self._native.shutdown(timeout_ms)
        except _native.NativeError as error:
            raise _error(error) from None

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()


class Response:
    """Synchronous access to an asynchronous response."""

    def __init__(self, client: Client, response: AsyncResponse) -> None:
        self._client = client
        self._response = response
        self.status = response.status
        self.protocol = response.protocol
        self.headers = response.headers

    def read(self, *, max_bytes: int) -> bytes:
        return self._client._run(lambda: self._response.read(max_bytes=max_bytes))

    def iter_bytes(self, chunk_size: int = 65536) -> Generator[bytes, None, None]:
        try:
            while (
                chunk := self._client._run(
                    lambda: self._response.read_chunk(chunk_size)
                )
            ) is not None:
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        self._response.close()

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class Client:
    """A same-thread sync wrapper above AsyncClient, with one reusable loop."""

    def __init__(
        self,
        *,
        profile: str,
        protocol: _Protocol,
        context: _Context | None = None,
        proxy: str | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
    ) -> None:
        self._thread = threading.get_ident()
        self._check_thread_loop()
        self._async = AsyncClient(
            profile=profile,
            protocol=protocol,
            context=context,
            proxy=proxy,
            cookies=cookies,
            timeout_ms=timeout_ms,
        )
        self._loop = asyncio.new_event_loop()
        self.cookies = self._async.cookies

    def _check_thread_loop(self) -> None:
        if self._thread != threading.get_ident():
            raise RuntimeError("synchronous clients belong to their creating thread")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError("use AsyncClient inside a running event loop")

    def _run(self, make_coroutine: Callable[[], Coroutine[object, object, _T]]) -> _T:
        self._check_thread_loop()
        if self._loop.is_closed():
            raise ClientClosed("request", "client_closed")
        task = self._loop.create_task(make_coroutine())
        try:
            return self._loop.run_until_complete(task)
        except KeyboardInterrupt:
            task.cancel()
            # A racing completion must not replace the original interruption.
            with contextlib.suppress(BaseException):
                self._loop.run_until_complete(task)
            raise

    @property
    def is_closed(self) -> bool:
        return self._async.is_closed

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: _Headers = (),
        body: bytes | None = None,
        upload: _UploadPath | None = None,
        budget: AttemptBudget | None = None,
        timeout_ms: int | None = None,
    ) -> Response:
        return Response(
            self,
            self._run(
                lambda: self._async.request(
                    method,
                    url,
                    headers=headers,
                    body=body,
                    upload=upload,
                    budget=budget,
                    timeout_ms=timeout_ms,
                )
            ),
        )

    def close(self, *, timeout_ms: int = 5000) -> None:
        self._check_thread_loop()
        if self._loop.is_closed():
            return
        try:
            self._run(lambda: self._async.close(timeout_ms=timeout_ms))
        finally:
            self._loop.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
