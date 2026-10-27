"""Synchronous client/response adapters bound to one private event loop."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import (
    Callable,
    Coroutine,
    Generator,
    Iterable,
    Iterator,
)

from typing_extensions import Unpack

from . import _upload
from ._bodies import PreparedBody, StreamingMultipartBody
from ._certificates import ClientCertificate
from ._client import AsyncClient
from ._configuration import (
    ContentDecoding,
    Proxy,
    RedirectPolicy,
    RetryPolicy,
    SessionSharing,
    TimeoutOverrides,
    Timeouts,
    Trust,
)
from ._convenience import (
    _DEFAULT_BODY_LIMIT,
    _JSON_UNSET,
    _Form,
    _Params,
    _SyncRequestOptions,
)
from ._diagnostics import (
    RequestDiagnostics,
)
from ._errors import (
    _T,
    ClientClosed,
    Error,
    _call,
    _primary_error,
)
from ._network import NetworkOptions
from ._pool import PoolOptions
from ._profile import Profile
from ._request import _Context, _Headers, _Protocol, _RequestContext, _UploadPath
from ._response import AsyncResponse, RedirectHistory, ResponseTrailers
from ._session import (
    _NO_SHARED_STATE,
    AttemptBudget,
    _checkpoint_bytes,
    _receiving_routes,
)
from ._sync_websocket import WebSocket
from ._transfer import TransferControl
from ._websocket import (
    _DEFAULT_WEBSOCKET_LIMITS,
    AsyncWebSocket,
    WebSocketError,
    WebSocketLimits,
    _WebSocketProtocol,
)


class HTTPStatusError(Error):
    """An explicit status check failed; the response remains readable."""

    def __init__(self, response: Response | AsyncResponse) -> None:
        super().__init__("response", "http_status", response.protocol)
        self.response = response
        self.status_code = response.status_code
        self.args = (f"response: HTTP status {self.status_code}",)


class Response:
    """Synchronous response with an owned body."""

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
    def trailers(self) -> ResponseTrailers:
        return self._response.trailers

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
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                raise _primary_error(error, cleanup=cleanup) from None
            raise
        else:
            self.close()

    def close(self) -> None:
        self._client._check_thread_loop()
        # Native abort remains usable after a successful client shutdown.
        _call(self._response._native.close)
        if not self._client._loop.is_closed():
            self._client._run(lambda: self._response.aclose())

    def __enter__(self) -> Response:
        return self

    def __exit__(self, _: object, error: BaseException | None, __: object) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise


class Client:
    """Synchronous client. Use from its creating thread outside a running event loop."""

    def __init__(
        self,
        *,
        profile: str | Profile,
        protocol: _Protocol = "negotiated",
        context: _Context | None = None,
        proxy: str | Proxy | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
        base_url: str | None = None,
        trust: Trust | None = None,
        timeouts: Timeouts | None = None,
        redirect_policy: RedirectPolicy | None = None,
        retry_policy: RetryPolicy | None = None,
        client_certificate: ClientCertificate | None = None,
        client_certificates_for: tuple[tuple[str, ClientCertificate], ...] = (),
        network: NetworkOptions | None = None,
        pool: PoolOptions | None = None,
    ) -> None:
        # Keep the public constructor seam used by applications and test doubles.
        from . import AsyncClient

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
            client_certificate=client_certificate,
            client_certificates_for=client_certificates_for,
            network=network,
            pool=pool,
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

    def websocket(
        self,
        url: str,
        *,
        protocol: _WebSocketProtocol = "h1",
        headers: _Headers = (),
        limits: WebSocketLimits = _DEFAULT_WEBSOCKET_LIMITS,
        handshake_timeout_ms: int | None = None,
    ) -> WebSocket:
        """Open a socket on this client's profile, route and synchronous loop."""

        async def connect() -> AsyncWebSocket:
            return await self._async.websocket(
                url,
                protocol=protocol,
                headers=headers,
                limits=limits,
                handshake_timeout_ms=handshake_timeout_ms,
            )

        try:
            return WebSocket(self, self._run(connect))
        except WebSocketError as error:
            if isinstance(error.response, AsyncResponse):
                error.response = Response(self, error.response)
            raise

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

    def export_session(self, key: bytes) -> bytes:
        """Export supported state without changing this client or its pools."""
        self._check_thread_loop()
        return _call(self._async._native.export_session, _checkpoint_bytes(key))

    def restore_session(
        self,
        snapshot: bytes,
        key: bytes,
        *,
        receiving_routes: Iterable[str | Proxy | None] = (),
    ) -> Client:
        """Restore a checkpoint into a new client with its own synchronous loop."""
        self._check_thread_loop()
        native = _call(
            self._async._native.restore_session,
            _checkpoint_bytes(snapshot),
            _checkpoint_bytes(key),
            _receiving_routes(receiving_routes),
        )
        client = object.__new__(Client)
        client._thread = threading.get_ident()
        client._loop = asyncio.new_event_loop()
        try:
            client._async = AsyncClient._from_native(native)
            client.cookies = client._async.cookies
        except BaseException:
            client._loop.close()
            raise
        return client

    def get(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send GET and return the response head."""
        return self.request("GET", url, **options)

    def head(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send HEAD and return the response head."""
        return self.request("HEAD", url, **options)

    def post(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send POST and return the response head."""
        return self.request("POST", url, **options)

    def put(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send PUT and return the response head."""
        return self.request("PUT", url, **options)

    def patch(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send PATCH and return the response head."""
        return self.request("PATCH", url, **options)

    def delete(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send DELETE and return the response head."""
        return self.request("DELETE", url, **options)

    def options(self, url: str, **options: Unpack[_SyncRequestOptions]) -> Response:
        """Send OPTIONS and return the response head."""
        return self.request("OPTIONS", url, **options)

    @contextlib.contextmanager
    def stream(
        self, method: str, url: str, **options: Unpack[_SyncRequestOptions]
    ) -> Iterator[Response]:
        """Open a response and close it when the context exits."""
        with self.request(method, url, **options) as response:
            yield response

    def request(
        self,
        method: str,
        url: str,
        *,
        context: _RequestContext | None = None,
        params: _Params | None = None,
        json: object = _JSON_UNSET,
        form: _Form | None = None,
        maximum_body_bytes: int = _DEFAULT_BODY_LIMIT,
        headers: _Headers = (),
        trailers: _Headers = (),
        expect_continue_ms: int | None = None,
        body: bytes
        | PreparedBody
        | StreamingMultipartBody
        | Iterable[bytes]
        | None = None,
        body_length: int | None = None,
        upload: _UploadPath | None = None,
        budget: AttemptBudget | None = None,
        timeout_ms: int | None = None,
        timeouts: TimeoutOverrides | None = None,
        content_decoding: ContentDecoding | None = None,
        redirect_policy: RedirectPolicy | None = None,
        redirect_history_limit: int | None = None,
        retry_policy: RetryPolicy | None = None,
        transfer_control: TransferControl | None = None,
        diagnostics: RequestDiagnostics | None = None,
    ) -> Response:
        """Send a request with the same options as AsyncClient.request."""
        if body is not None and not isinstance(
            body, (bytes, PreparedBody, StreamingMultipartBody, Iterable)
        ):
            raise TypeError(
                "Client body must be bytes, PreparedBody or Iterable[bytes]"
            )
        source = (
            _upload.SyncSource(body)
            if body is not None
            and not isinstance(body, (bytes, PreparedBody, StreamingMultipartBody))
            else body
        )
        if isinstance(source, StreamingMultipartBody):
            return Response(
                self,
                self._run(
                    lambda: self._async._request(
                        method,
                        url,
                        context=context,
                        params=params,
                        json=json,
                        form=form,
                        maximum_body_bytes=maximum_body_bytes,
                        headers=headers,
                        trailers=trailers,
                        expect_continue_ms=expect_continue_ms,
                        body=source,
                        body_length=body_length,
                        upload=upload,
                        budget=budget,
                        timeout_ms=timeout_ms,
                        timeouts=timeouts,
                        content_decoding=content_decoding,
                        redirect_policy=redirect_policy,
                        redirect_history_limit=redirect_history_limit,
                        retry_policy=retry_policy,
                        transfer_control=transfer_control,
                        diagnostics=diagnostics,
                        _synchronous=True,
                    )
                ),
            )
        return Response(
            self,
            self._run(
                lambda: self._async.request(
                    method,
                    url,
                    context=context,
                    params=params,
                    json=json,
                    form=form,
                    maximum_body_bytes=maximum_body_bytes,
                    headers=headers,
                    trailers=trailers,
                    expect_continue_ms=expect_continue_ms,
                    body=source,
                    body_length=body_length,
                    upload=upload,
                    budget=budget,
                    timeout_ms=timeout_ms,
                    timeouts=timeouts,
                    content_decoding=content_decoding,
                    redirect_policy=redirect_policy,
                    redirect_history_limit=redirect_history_limit,
                    retry_policy=retry_policy,
                    transfer_control=transfer_control,
                    diagnostics=diagnostics,
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
            # A noncooperative iterator finalizer remains owned by this loop.
            # A later close can resume it instead of destroying pending tasks.
            if not any(not upload.settled.done() for upload in self._async._uploads):
                self._loop.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, _: object, error: BaseException | None, __: object) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise
