"""HTTP requests with explicit browser profiles and protocols."""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import json as _json
import sys
import threading
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator, Iterable
from dataclasses import dataclass
from dataclasses import field as _field
from os import PathLike
from typing import Literal, ParamSpec, TypeAlias, TypeVar, cast

from . import _native
from ._configuration import INHERIT as INHERIT
from ._configuration import ConnectionRetry as ConnectionRetry
from ._configuration import ContentDecoding as ContentDecoding
from ._configuration import Header as Header
from ._configuration import Proxy as Proxy
from ._configuration import RedirectPolicy as RedirectPolicy
from ._configuration import RetryPolicy as RetryPolicy
from ._configuration import SessionSharing as SessionSharing
from ._configuration import StatusRetry as StatusRetry
from ._configuration import TimeoutOverrides as TimeoutOverrides
from ._configuration import Timeouts as Timeouts
from ._configuration import Trust as Trust
from ._configuration import _redirect_count
from ._native import NativeProfile as _NativeProfile

_Protocol: TypeAlias = Literal["h1", "h2", "h3", "negotiated"]
_CatalogContext: TypeAlias = Literal["navigation", "fetch"]
_Context: TypeAlias = Literal["navigation", "fetch", "profile", "raw"]
_Headers: TypeAlias = Iterable[Header | tuple[str, str | bytes]]
_UploadPath: TypeAlias = str | PathLike[str]
_P = ParamSpec("_P")
_T = TypeVar("_T")
_NO_SHARED_STATE = SessionSharing()


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


class ProfileError(Error):
    """A profile document failed strict validation at a canonical field."""

    def __init__(self, kind: str, field: str) -> None:
        super().__init__("profile", kind)
        self.field = field
        self.args = (f"profile: {kind} at {field}",)


class DecodeError(Error):
    """Text or JSON decoding failed without including response content."""


class HTTPStatusError(Error):
    """An explicit status check failed; the response remains readable."""

    def __init__(self, response: Response | AsyncResponse) -> None:
        super().__init__("response", "http_status", response.protocol)
        self.response = response
        self.status_code = response.status_code
        self.args = (f"response: HTTP status {self.status_code}",)


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


def _profile_call(
    function: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
) -> _T:
    try:
        return _call(function, *args, **kwargs)
    except _native.NativeProfileError as error:
        kind, field = cast(tuple[str, str], error.args)
        raise ProfileError(kind, field) from None


@dataclass(frozen=True, slots=True, init=False)
class Profile:
    """Immutable native settings; imports do not retain catalog identity."""

    _native: _NativeProfile = _field(repr=False)

    def __init__(self) -> None:
        raise TypeError("use Profile.from_catalog or Profile.import_json")

    @classmethod
    def _wrap(cls, native: _NativeProfile) -> Profile:
        profile = object.__new__(cls)
        object.__setattr__(profile, "_native", native)
        return profile

    @classmethod
    def from_catalog(
        cls, exact_id: str, *, context: _CatalogContext | None = None
    ) -> Profile:
        return cls._wrap(
            _profile_call(_native.NativeProfile.from_catalog, exact_id, context)
        )

    @classmethod
    def import_json(cls, document: bytes) -> Profile:
        if not isinstance(document, bytes):
            raise TypeError("profile documents must be bytes")
        return cls._wrap(_profile_call(_native.NativeProfile.import_json, document))

    def export_json(self) -> bytes:
        return _profile_call(self._native.export_json)

    def describe(self) -> dict[str, object]:
        """Return a fresh editable document, including literal header values."""
        return cast(dict[str, object], _json.loads(self.export_json()))

    @property
    def catalog_id(self) -> str | None:
        return self._native.catalog_id


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


class AsyncResponse:
    """An owned response body. Close it when you stop reading."""

    def __init__(self, native: _native.NativeResponse) -> None:
        self._native = native
        self.status = native.status
        self.protocol = native.protocol
        self.headers = native.headers

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
    def status_code(self) -> int:
        return self.status

    def raise_for_status(self) -> None:
        """Raise for HTTP 4xx/5xx without consuming or closing the body."""
        if 400 <= self.status < 600:
            raise HTTPStatusError(self)

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

    async def __aexit__(self, *_: object) -> None:
        self.close()


class AsyncClient:
    """Reuse connections and cookies across requests."""

    def __init__(
        self,
        *,
        profile: str | Profile,
        protocol: _Protocol,
        context: _Context | None = None,
        proxy: str | Proxy | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
        base_url: str | None = None,
        trust: Trust | None = None,
        timeouts: Timeouts | None = None,
        redirect_policy: RedirectPolicy | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        if retry_policy is not None and not isinstance(retry_policy, RetryPolicy):
            raise TypeError("retry_policy must be RetryPolicy")
        if redirect_policy is not None and not isinstance(
            redirect_policy, RedirectPolicy
        ):
            raise TypeError("redirect_policy must be RedirectPolicy")
        if not isinstance(profile, (str, Profile)):
            raise TypeError("profile must be an exact catalog ID or Profile")
        if timeouts is not None and not isinstance(timeouts, Timeouts):
            raise TypeError("timeouts must be Timeouts")
        if timeout_ms is not None and timeouts is not None:
            raise ValueError("pass timeout_ms or timeouts, not both")
        if trust is not None and not isinstance(trust, Trust):
            raise TypeError("trust must be Trust")
        if proxy is not None and not isinstance(proxy, (str, Proxy)):
            raise TypeError("proxy must be a URI string or Proxy")
        if isinstance(proxy, str):
            proxy = Proxy(proxy)
        route = proxy
        roots = Trust() if trust is None else trust
        self._native = _call(
            _native.NativeClient,
            profile._native if isinstance(profile, Profile) else profile,
            protocol,
            context,
            None if route is None else route.url,
            cookies,
            timeout_ms,
            base_url,
            list(roots.roots),
            list(roots.proxy_roots),
            None if route is None else route.username,
            None if route is None else route.password,
            None if timeouts is None else timeouts._native_fields(),
            None if redirect_policy is None else redirect_policy.maximum_hops,
            None if retry_policy is None else retry_policy._native_fields(),
        )
        self.cookies = Cookies(self._native.cookies)

    @property
    def is_closed(self) -> bool:
        return self._native.is_closed

    @classmethod
    def _from_native(cls, native: _native.NativeClient) -> AsyncClient:
        client = object.__new__(cls)
        client._native = native
        client.cookies = Cookies(native.cookies)
        return client

    def fork(self, *, sharing: SessionSharing = _NO_SHARED_STATE) -> AsyncClient:
        """Create open independent pools, sharing only selected live state."""
        if not isinstance(sharing, SessionSharing):
            raise TypeError("sharing must be SessionSharing")
        return AsyncClient._from_native(
            _call(
                self._native.fork,
                sharing.cookies,
                sharing.dns,
                sharing.client_hints,
                sharing.discovery,
                sharing.tickets,
            )
        )

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
        timeouts: TimeoutOverrides | None = None,
        content_decoding: ContentDecoding | None = None,
        redirect_policy: RedirectPolicy | None = None,
        redirect_history_limit: int | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> AsyncResponse:
        """Return the response head without collecting its body."""
        if timeouts is not None and not isinstance(timeouts, TimeoutOverrides):
            raise TypeError("request timeouts must be TimeoutOverrides")
        if timeout_ms is not None and timeouts is not None:
            raise ValueError("pass timeout_ms or timeouts, not both")
        if content_decoding is not None and not isinstance(
            content_decoding, ContentDecoding
        ):
            raise TypeError("content_decoding must be ContentDecoding")
        if retry_policy is not None and not isinstance(retry_policy, RetryPolicy):
            raise TypeError("retry_policy must be RetryPolicy")
        if redirect_policy is not None and not isinstance(
            redirect_policy, RedirectPolicy
        ):
            raise TypeError("redirect_policy must be RedirectPolicy")
        if redirect_history_limit is not None:
            _redirect_count(redirect_history_limit, positive=True)
        ordered = []
        for field in headers:
            if isinstance(field, Header):
                name, value, sensitive = field.name, field.value, field.sensitive
            else:
                name, value = field
                sensitive = False
            if isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except UnicodeEncodeError:
                    raise ValueError(
                        "header text must fit Latin-1; supply bytes explicitly"
                    ) from None
            if not isinstance(value, bytes):
                raise TypeError("header values must be str or bytes")
            ordered.append((name, value, sensitive))
        try:
            native = await self._native.request(
                method,
                url,
                ordered,
                body,
                upload,
                None if budget is None else budget._native,
                timeout_ms,
                None if timeouts is None else timeouts._native_fields(),
                None
                if content_decoding is None
                else content_decoding.maximum_decoded_bytes,
                None if redirect_policy is None else redirect_policy.maximum_hops,
                redirect_history_limit,
                None if retry_policy is None else retry_policy._native_fields(),
            )
            return AsyncResponse(native)
        except _native.NativeError as error:
            raise _error(error) from None

    async def close_idle_connections(self) -> None:
        """Release idle connections, retaining active bodies and session state."""
        try:
            await self._native.close_idle_connections()
        except _native.NativeError as error:
            raise _error(error) from None

    async def refresh_connections(self) -> None:
        """Retire current pools; active owners finish and tickets remain available."""
        try:
            await self._native.refresh_connections()
        except _native.NativeError as error:
            raise _error(error) from None

    def clear_session_tickets(self) -> int:
        return _call(self._native.clear_session_tickets)

    def clear_dns_cache(self) -> None:
        _call(self._native.clear_dns_cache)

    def clear_client_hints(self) -> None:
        _call(self._native.clear_client_hints)

    def clear_alt_svc(self) -> None:
        _call(self._native.clear_alt_svc)

    def clear_alt_svc_racing_history(self) -> None:
        _call(self._native.clear_alt_svc_racing_history)

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

    @property
    def url(self) -> str:
        return self._response.url

    @property
    def redirects_followed(self) -> int:
        return self._response.redirects_followed

    @property
    def connection_setup_retries(self) -> int:
        return self._response.connection_setup_retries

    @property
    def redirect_history(self) -> RedirectHistory | None:
        return self._response.redirect_history

    @property
    def decoded_content_codings(self) -> tuple[str, ...]:
        return self._response.decoded_content_codings

    @property
    def status_code(self) -> int:
        return self.status

    def raise_for_status(self) -> None:
        """Raise for HTTP 4xx/5xx without consuming or closing the body."""
        if 400 <= self.status < 600:
            raise HTTPStatusError(self)

    def read(self, *, max_bytes: int) -> bytes:
        return self._client._run(lambda: self._response.read(max_bytes=max_bytes))

    def text(
        self, *, max_bytes: int, encoding: str = "utf-8", errors: str = "strict"
    ) -> str:
        return self._client._run(
            lambda: self._response.text(
                max_bytes=max_bytes, encoding=encoding, errors=errors
            )
        )

    def json(self, *, max_bytes: int) -> object:
        return self._client._run(lambda: self._response.json(max_bytes=max_bytes))

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
        profile: str | Profile,
        protocol: _Protocol,
        context: _Context | None = None,
        proxy: str | Proxy | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
        base_url: str | None = None,
        trust: Trust | None = None,
        timeouts: Timeouts | None = None,
        redirect_policy: RedirectPolicy | None = None,
        retry_policy: RetryPolicy | None = None,
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
            base_url=base_url,
            trust=trust,
            timeouts=timeouts,
            redirect_policy=redirect_policy,
            retry_policy=retry_policy,
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

    def fork(self, *, sharing: SessionSharing = _NO_SHARED_STATE) -> Client:
        """Create a fork with its own synchronous loop and shutdown lifecycle."""
        self._check_thread_loop()
        client = object.__new__(Client)
        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        try:
            client._async = self._async.fork(sharing=sharing)
            client.cookies = client._async.cookies
        except BaseException:
            client._loop.close()
            raise
        return client

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
        timeouts: TimeoutOverrides | None = None,
        content_decoding: ContentDecoding | None = None,
        redirect_policy: RedirectPolicy | None = None,
        redirect_history_limit: int | None = None,
        retry_policy: RetryPolicy | None = None,
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
                    timeouts=timeouts,
                    content_decoding=content_decoding,
                    redirect_policy=redirect_policy,
                    redirect_history_limit=redirect_history_limit,
                    retry_policy=retry_policy,
                )
            ),
        )

    def close_idle_connections(self) -> None:
        self._run(lambda: self._async.close_idle_connections())

    def refresh_connections(self) -> None:
        self._run(lambda: self._async.refresh_connections())

    def clear_session_tickets(self) -> int:
        self._check_thread_loop()
        return self._async.clear_session_tickets()

    def clear_dns_cache(self) -> None:
        self._check_thread_loop()
        self._async.clear_dns_cache()

    def clear_client_hints(self) -> None:
        self._check_thread_loop()
        self._async.clear_client_hints()

    def clear_alt_svc(self) -> None:
        self._check_thread_loop()
        self._async.clear_alt_svc()

    def clear_alt_svc_racing_history(self) -> None:
        self._check_thread_loop()
        self._async.clear_alt_svc_racing_history()

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
