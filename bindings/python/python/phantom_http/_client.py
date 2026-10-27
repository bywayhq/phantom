"""Reusable async client configuration, requests and shutdown."""

from __future__ import annotations

import asyncio
from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Iterable,
)
from contextlib import asynccontextmanager
from typing import (
    TypedDict,
    cast,
)

from typing_extensions import Unpack

from . import _multipart, _native, _upload
from ._bodies import PreparedBody, StreamingMultipartBody
from ._certificates import ClientCertificate
from ._configuration import (
    ContentDecoding,
    Proxy,
    RedirectPolicy,
    RetryPolicy,
    SessionSharing,
    TimeoutOverrides,
    Timeouts,
    Trust,
    _redirect_count,
)
from ._convenience import (
    _DEFAULT_BODY_LIMIT,
    _JSON_UNSET,
    _AsyncRequestOptions,
    _Form,
    _Params,
    _prepare_request,
)
from ._diagnostics import (
    RequestDiagnostics,
)
from ._errors import (
    Error,
    TimeoutError,
    _call,
    _error,
    _primary_error,
    _upload_error,
)
from ._network import NetworkOptions, _NetworkFields
from ._pool import PoolOptions, _PoolFields
from ._profile import Profile
from ._request import (
    _Context,
    _Headers,
    _Protocol,
    _request_fields,
    _RequestContext,
    _UploadPath,
)
from ._response import AsyncResponse
from ._session import (
    _NO_SHARED_STATE,
    AttemptBudget,
    Cookies,
    _checkpoint_bytes,
    _receiving_routes,
)
from ._transfer import TransferControl


class _RequestFields(TypedDict, total=False):
    context: _RequestContext
    redirect_credential_headers: tuple[str, ...]
    diagnostics: _native.NativeRequestDiagnostics


class _ClientFields(TypedDict, total=False):
    redirect_credential_headers: tuple[str, ...]
    network: _NetworkFields
    pool: _PoolFields
    server_spki_pins: tuple[bytes, ...]
    proxy_server_spki_pins: tuple[bytes, ...]
    client_certificate: _native.NativeClientCertificate
    client_certificates_for: tuple[tuple[str, _native.NativeClientCertificate], ...]


def _certificates(
    default: ClientCertificate | None,
    origins: tuple[tuple[str, ClientCertificate], ...],
) -> _ClientFields:
    if default is not None and not isinstance(default, ClientCertificate):
        raise TypeError("client_certificate must be ClientCertificate")
    if not isinstance(origins, tuple):
        raise TypeError("client_certificates_for must be an ordered tuple of pairs")
    if len(origins) > 256:
        raise Error("input", "too_many_client_certificate_origins")
    total = 0
    for pair in origins:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], ClientCertificate)
        ):
            raise TypeError(
                "client_certificates_for requires (origin, certificate) pairs"
            )
        if len(pair[0]) > 65536:
            raise Error("input", "client_certificate_origins_too_large")
        try:
            size = len(pair[0].encode("utf-8"))
        except UnicodeError:
            raise Error("input", "invalid_client_certificates_for") from None
        total += size
        if size > 65536 or total > 16 * 1024 * 1024:
            raise Error("input", "client_certificate_origins_too_large")
    result: _ClientFields = {}
    if default is not None:
        result["client_certificate"] = default._native
    if origins:
        result["client_certificates_for"] = tuple(
            (origin, certificate._native) for origin, certificate in origins
        )
    return result


class AsyncClient:
    """Reuse connections and cookies across requests."""

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
        if pool is not None and type(pool) is not PoolOptions:
            raise TypeError("pool must be PoolOptions")
        pool_fields = None if pool is None else pool._native_fields()
        if network is not None and type(network) is not NetworkOptions:
            raise TypeError("network must be NetworkOptions")
        network_fields = None if network is None else network._native_fields()
        client_fields = _certificates(client_certificate, client_certificates_for)
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
        if roots.server_spki_pins is not None:
            client_fields["server_spki_pins"] = roots.server_spki_pins
        if roots.proxy_server_spki_pins is not None:
            client_fields["proxy_server_spki_pins"] = roots.proxy_server_spki_pins
        if pool_fields is not None:
            client_fields["pool"] = pool_fields
        if network_fields is not None:
            client_fields["network"] = network_fields
        if redirect_policy is not None and redirect_policy.credential_headers:
            client_fields["redirect_credential_headers"] = (
                redirect_policy.credential_headers
            )
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
            retry_policy,
            **client_fields,
        )
        self.cookies = Cookies(self._native.cookies)
        self._uploads: set[_upload.Upload] = set()

    @property
    def is_closed(self) -> bool:
        return self._native.is_closed

    @classmethod
    def _from_native(cls, native: _native.NativeClient) -> AsyncClient:
        client = object.__new__(cls)
        client._native = native
        client.cookies = Cookies(native.cookies)
        client._uploads = set()
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

    async def export_session(self, key: bytes) -> bytes:
        """Export encrypted state; already-running native CPU work cannot be cancelled."""
        return await asyncio.to_thread(
            _call, self._native.export_session, _checkpoint_bytes(key)
        )

    async def restore_session(
        self,
        snapshot: bytes,
        key: bytes,
        *,
        receiving_routes: Iterable[str | Proxy | None] = (),
    ) -> AsyncClient:
        """Restore into independent pools using this client's compatible settings."""
        native = await asyncio.to_thread(
            _call,
            self._native.restore_session,
            _checkpoint_bytes(snapshot),
            _checkpoint_bytes(key),
            _receiving_routes(receiving_routes),
        )
        return AsyncClient._from_native(native)

    async def get(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send GET and return the response head."""
        return await self.request("GET", url, **options)

    async def head(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send HEAD and return the response head."""
        return await self.request("HEAD", url, **options)

    async def post(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send POST and return the response head."""
        return await self.request("POST", url, **options)

    async def put(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send PUT and return the response head."""
        return await self.request("PUT", url, **options)

    async def patch(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send PATCH and return the response head."""
        return await self.request("PATCH", url, **options)

    async def delete(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send DELETE and return the response head."""
        return await self.request("DELETE", url, **options)

    async def options(
        self, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncResponse:
        """Send OPTIONS and return the response head."""
        return await self.request("OPTIONS", url, **options)

    @asynccontextmanager
    async def stream(
        self, method: str, url: str, **options: Unpack[_AsyncRequestOptions]
    ) -> AsyncIterator[AsyncResponse]:
        """Open a response and close it when the context exits."""
        async with await self.request(method, url, **options) as response:
            yield response

    async def request(
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
        | AsyncIterable[bytes]
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
    ) -> AsyncResponse:
        """Return the response head; close or read the owned body afterwards.

        params appends ordered query fields. Choose one of json, form, body or
        upload. maximum_body_bytes bounds encoded JSON and form bodies.
        context overrides the client default for this request; "raw" omits it.
        """
        return await self._request(
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
            body=body,
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

    async def _request(
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
        | AsyncIterable[bytes]
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
        _synchronous: bool = False,
    ) -> AsyncResponse:
        """Return the response head without collecting its body.

        Producer body_length checks demanded frames and EOF. An unread source
        suffix is not pulled after the transport finishes or abandons the body.
        """
        multipart = body if isinstance(body, StreamingMultipartBody) else None
        pump: _upload.Upload | None = None
        if multipart is not None:
            multipart_pump = multipart._claim(not _synchronous)
            pump = multipart_pump
            self._uploads.add(multipart_pump)
            pump.settled.add_done_callback(
                lambda _: self._uploads.discard(multipart_pump)
            )
        try:
            url, headers, body = _prepare_request(
                url, headers, body, upload, params, json, form, maximum_body_bytes
            )
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
            if transfer_control is not None and not isinstance(
                transfer_control, TransferControl
            ):
                raise TypeError("transfer_control must be TransferControl")
            if diagnostics is not None and not isinstance(
                diagnostics, RequestDiagnostics
            ):
                raise TypeError("diagnostics must be RequestDiagnostics")
            if redirect_policy is not None and not isinstance(
                redirect_policy, RedirectPolicy
            ):
                raise TypeError("redirect_policy must be RedirectPolicy")
            if redirect_history_limit is not None:
                _redirect_count(redirect_history_limit, positive=True)
            for active in self._uploads:
                active.check_loop()
            prepared = body if isinstance(body, PreparedBody) else None
            producer = body is not None and not isinstance(
                body, (bytes, PreparedBody, StreamingMultipartBody)
            )
            if body is not None and upload is not None:
                raise ValueError("pass body or upload, not both")
            if producer and not isinstance(body, AsyncIterable):
                raise TypeError(
                    "AsyncClient body must be bytes, PreparedBody or AsyncIterable[bytes]"
                )
            if multipart is not None and body_length is not None:
                raise ValueError("body_length is not available for streaming multipart")
            if prepared is not None and body_length is not None:
                if type(body_length) is not int or body_length != prepared.length:
                    raise ValueError(
                        "body_length must equal the prepared encoded length"
                    )
            else:
                _upload.length(body_length, producer)
            ordered, ordered_trailers = _request_fields(headers, trailers)
            if expect_continue_ms is not None:
                if type(expect_continue_ms) is not int:
                    raise TypeError("expect_continue_ms must be an integer")
                if not 0 <= expect_continue_ms <= 2**64 - 1:
                    raise ValueError(
                        "expect_continue_ms must fit an unsigned 64-bit integer"
                    )
            if multipart is not None:
                multipart._prepare(cast(_multipart.Upload, pump))
            else:
                pump = (
                    _upload.Upload(cast(AsyncIterable[bytes], body), body_length)
                    if producer
                    else None
                )
                if pump is not None:
                    self._uploads.add(pump)
                    pump.settled.add_done_callback(
                        lambda _: self._uploads.discard(pump)
                    )
            diagnostic_fields: _RequestFields = {}
            if context is not None:
                diagnostic_fields["context"] = context
            if diagnostics is not None:
                diagnostic_fields["diagnostics"] = diagnostics._native
            if redirect_policy is not None and redirect_policy.credential_headers:
                diagnostic_fields["redirect_credential_headers"] = (
                    redirect_policy.credential_headers
                )
            arguments = (
                method,
                url,
                ordered,
                None
                if producer or prepared is not None or multipart is not None
                else cast(bytes | None, body),
                upload,
                None if budget is None else budget._native,
                timeout_ms,
                None if timeouts is None else timeouts._native_fields(),
                None
                if content_decoding is None
                else content_decoding.maximum_decoded_bytes,
                None if redirect_policy is None else redirect_policy.maximum_hops,
                redirect_history_limit,
                retry_policy,
            )
            if multipart is not None:
                operation = self._native.request(
                    *arguments,
                    **diagnostic_fields,
                    multipart=cast(_multipart.Upload, pump).native,
                    transfer_control=None
                    if transfer_control is None
                    else transfer_control._native,
                    trailers=ordered_trailers,
                    expect_continue_ms=expect_continue_ms,
                )
            elif prepared is not None:
                operation = self._native.request(
                    *arguments,
                    **diagnostic_fields,
                    prepared_body=prepared._native,
                    body_length=body_length,
                    transfer_control=None
                    if transfer_control is None
                    else transfer_control._native,
                    trailers=ordered_trailers,
                    expect_continue_ms=expect_continue_ms,
                )
            elif ordered_trailers or expect_continue_ms is not None:
                operation = self._native.request(
                    *arguments,
                    **diagnostic_fields,
                    producer=None
                    if pump is None
                    else cast("_native.NativeUpload", pump.native),
                    transfer_control=None
                    if transfer_control is None
                    else transfer_control._native,
                    trailers=ordered_trailers,
                    expect_continue_ms=expect_continue_ms,
                )
            elif transfer_control is not None:
                operation = self._native.request(
                    *arguments,
                    **diagnostic_fields,
                    producer=None
                    if pump is None
                    else cast("_native.NativeUpload", pump.native),
                    transfer_control=transfer_control._native,
                )
            else:
                operation = (
                    self._native.request(*arguments, **diagnostic_fields)
                    if pump is None
                    else self._native.request(
                        *arguments,
                        producer=cast("_native.NativeUpload", pump.native),
                        **diagnostic_fields,
                    )
                )
            native = await operation
            return AsyncResponse(native, pump)
        except BaseException as error:
            if pump is not None:
                try:
                    pump.close()
                    if not await pump.wait():
                        raise TimeoutError("request", "shutdown_timeout")
                except BaseException as cleanup:
                    raise _primary_error(error, pump, cleanup) from None
            raise _primary_error(error, pump) from None

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
        started = asyncio.get_running_loop().time()
        pumps = tuple(self._uploads)
        for pump in pumps:
            pump.check_wait()
        for pump in pumps:
            pump.close()
        try:
            await self._native.shutdown(timeout_ms)
        except _native.NativeError as error:
            raise _error(error) from None
        if pumps:
            remaining = max(
                0.0, timeout_ms / 1000 - (asyncio.get_running_loop().time() - started)
            )
            _, pending = await asyncio.wait(
                {pump.settled for pump in pumps}, timeout=remaining
            )
            if pending:
                raise TimeoutError("request", "shutdown_timeout")
            for pump in pumps:
                if pump.error is not None or pump.cleanup_error is not None:
                    raise _upload_error(pump) from None

    async def aclose(self, *, timeout_ms: int = 5000) -> None:
        """Close admission and settle active work within timeout_ms."""
        await self.close(timeout_ms=timeout_ms)

    async def __aenter__(self) -> AsyncClient:
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
