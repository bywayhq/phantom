"""HTTP requests with explicit browser profiles and protocols."""

import asyncio
import contextlib
import threading

from . import _native


class Error(Exception):
    """A redacted failure with stable kind, protocol and timeout_phase fields."""

    def __init__(self, category, kind, protocol=None, timeout_phase=None):
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


def _error(error):
    category, kind, protocol, phase = error.args
    cls = {
        "timeout": TimeoutError,
        "shutdown_timeout": TimeoutError,
        "attempt_budget_exhausted": AttemptBudgetExhausted,
        "client_closed": ClientClosed,
        "response_body_limit": BodyLimitExceeded,
    }.get(kind, Error)
    return cls(category, kind, protocol, phase)


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _native.NativeError as error:
        raise _error(error) from None


class AttemptBudget:
    """One allowance shared across requests and clients, including resends."""

    def __init__(self, maximum):
        self._native = _native.AttemptBudget(maximum)

    @property
    def remaining(self):
        return self._native.remaining

    def try_admit(self):
        """Charge an attempt outside Phantom; requests are charged already."""
        _call(self._native.try_admit)


class Cookies:
    """The client's shared, bounded cookie jar."""

    def __init__(self, native):
        self._native = native

    def set(self, url, set_cookie):
        _call(self._native.set, url, set_cookie)

    def for_url(self, url):
        return _call(self._native.for_url, url)

    def clear(self):
        _call(self._native.clear)

    def __len__(self):
        return len(self._native)


class AsyncResponse:
    """An owned response body. Close it when you stop reading."""

    def __init__(self, native):
        self._native = native
        self.status = native.status
        self.protocol = native.protocol
        self.headers = native.headers

    def close(self):
        _call(self._native.close)

    async def read_chunk(self, maximum=65536):
        """Read at most maximum bytes (1 through 1 MiB), or None at EOF."""
        try:
            return await self._native.read_chunk(maximum)
        except asyncio.CancelledError:
            self.close()
            raise
        except _native.NativeError as error:
            raise _error(error) from None

    async def iter_bytes(self, chunk_size=65536):
        try:
            while (chunk := await self.read_chunk(chunk_size)) is not None:
                yield chunk
        finally:
            self.close()

    async def read(self, *, max_bytes):
        """Collect up to max_bytes. The body closes on failure or completion."""
        if not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a nonnegative integer")
        result = bytearray()
        try:
            while (
                chunk := await self.read_chunk(min(65536, max_bytes - len(result) + 1))
            ) is not None:
                if len(result) + len(chunk) > max_bytes:
                    raise BodyLimitExceeded("request", "response_body_limit")
                result.extend(chunk)
            return bytes(result)
        finally:
            self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self.close()


class AsyncClient:
    """Reuse connections and cookies across requests."""

    def __init__(
        self,
        *,
        profile,
        protocol,
        context=None,
        proxy=None,
        cookies=True,
        timeout_ms=None,
    ):
        self._native = _call(
            _native.NativeClient, profile, protocol, context, proxy, cookies, timeout_ms
        )
        self.cookies = Cookies(self._native.cookies)

    @property
    def is_closed(self):
        return self._native.is_closed

    async def request(
        self,
        method,
        url,
        *,
        headers=(),
        body=None,
        upload=None,
        budget=None,
        timeout_ms=None,
    ):
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

    async def close(self, *, timeout_ms=5000):
        """Close admission and wait for active owners within this bound."""
        try:
            await self._native.shutdown(timeout_ms)
        except _native.NativeError as error:
            raise _error(error) from None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()


class Response:
    """Synchronous access to an asynchronous response."""

    def __init__(self, client, response):
        self._client = client
        self._response = response
        self.status = response.status
        self.protocol = response.protocol
        self.headers = response.headers

    def read(self, *, max_bytes):
        return self._client._run(lambda: self._response.read(max_bytes=max_bytes))

    def iter_bytes(self, chunk_size=65536):
        try:
            while (
                chunk := self._client._run(
                    lambda: self._response.read_chunk(chunk_size)
                )
            ) is not None:
                yield chunk
        finally:
            self.close()

    def close(self):
        self._response.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Client:
    """A same-thread sync wrapper above AsyncClient, with one reusable loop."""

    def __init__(self, **options):
        self._thread = threading.get_ident()
        self._check_thread_loop()
        self._async = AsyncClient(**options)
        self._loop = asyncio.new_event_loop()
        self.cookies = self._async.cookies

    def _check_thread_loop(self):
        if self._thread != threading.get_ident():
            raise RuntimeError("synchronous clients belong to their creating thread")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError("use AsyncClient inside a running event loop")

    def _run(self, make_coroutine):
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
    def is_closed(self):
        return self._async.is_closed

    def request(self, method, url, **options):
        return Response(
            self, self._run(lambda: self._async.request(method, url, **options))
        )

    def close(self, *, timeout_ms=5000):
        self._check_thread_loop()
        if self._loop.is_closed():
            return
        try:
            self._run(lambda: self._async.close(timeout_ms=timeout_ms))
        finally:
            self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
