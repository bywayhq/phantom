"""HTTP requests with explicit browser profiles and protocols."""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import json as _json
import sys
import threading
from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    Callable,
    Coroutine,
    Generator,
    Iterable,
)
from dataclasses import dataclass
from dataclasses import field as _field
from os import PathLike
from typing import (
    TYPE_CHECKING,
    Literal,
    ParamSpec,
    TypeAlias,
    TypedDict,
    TypeVar,
    cast,
)

from . import _native, _upload
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
from ._diagnostics import RequestConnection as RequestConnection
from ._diagnostics import RequestDiagnostics as RequestDiagnostics
from ._diagnostics import RequestTimeline as RequestTimeline
from ._diagnostics import RequestTiming as RequestTiming
from ._diagnostics import TlsConnectionInfo as TlsConnectionInfo
from ._diagnostics import TlsConnectionState as TlsConnectionState
from ._native import NativeProfile as _NativeProfile
from ._transfer import TransferControl as TransferControl
from ._transfer import TransferLimits as TransferLimits
from ._transfer import TransferSnapshot as TransferSnapshot

if TYPE_CHECKING:
    from ._native import NativeClientCertificate as _NativeClientCertificate
    from ._native import NativePreparedBody as _NativePreparedBody

_Protocol: TypeAlias = Literal["h1", "h2", "h3", "negotiated"]
_CatalogContext: TypeAlias = Literal["navigation", "fetch"]
_Context: TypeAlias = Literal["navigation", "fetch", "profile", "raw"]
_Headers: TypeAlias = Iterable[Header | tuple[str, str | bytes]]
_UploadPath: TypeAlias = str | PathLike[str]
_P = ParamSpec("_P")
_T = TypeVar("_T")
_NO_SHARED_STATE = SessionSharing()


class _DiagnosticsFields(TypedDict, total=False):
    diagnostics: _native.NativeRequestDiagnostics


class _CertificateFields(TypedDict, total=False):
    client_certificate: _native.NativeClientCertificate
    client_certificates_for: tuple[tuple[str, _native.NativeClientCertificate], ...]


class Error(Exception):
    """A redacted failure; upload causes require explicit attribute inspection."""

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
        self.original: BaseException | None = None
        self.cleanup_error: BaseException | None = None


class TimeoutError(Error):
    """A request or graceful shutdown reached its deadline."""


class AttemptBudgetExhausted(Error):
    """The shared origin HTTP attempt allowance is exhausted."""


class ClientClosed(Error):
    """The client has stopped admitting requests."""


class BodyLimitExceeded(Error):
    """Body collection exceeded the caller's bound."""


class PreparedBodyError(Error):
    """Core preparation failed; kind omits field values and body contents."""


def _request_fields(
    headers: _Headers, trailers: _Headers
) -> tuple[list[tuple[str, bytes, bool]], list[tuple[str, bytes, bool]]]:
    remaining = 65536
    count = 0
    result: list[list[tuple[str, bytes, bool]]] = []
    for fields in (headers, trailers):
        ordered = []
        for field in fields:
            count += 1
            if count > 256:
                raise ValueError("headers and trailers exceed 256 fields")
            if isinstance(field, Header):
                name, value, sensitive = field.name, field.value, field.sensitive
            else:
                name, value = field
                sensitive = False
            if not isinstance(name, str):
                raise TypeError("header and trailer names must be str")
            if not isinstance(value, (str, bytes)):
                raise TypeError("header and trailer values must be str or bytes")
            if len(name) + len(value) > remaining:
                raise ValueError("headers and trailers exceed 65536 bytes")
            remaining -= len(name.encode("utf-8")) + len(value)
            if remaining < 0:
                raise ValueError("headers and trailers exceed 65536 bytes")
            if isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except UnicodeEncodeError:
                    raise ValueError(
                        "header text must fit Latin-1; supply bytes explicitly"
                    ) from None
            ordered.append((name, value, sensitive))
        result.append(ordered)
    return result[0], result[1]


class UploadError(Error):
    """Producer or cleanup failure; original exceptions require explicit inspection."""

    def __init__(
        self, original: BaseException | None, cleanup_error: BaseException | None
    ) -> None:
        super().__init__("request", "request_body")
        self.original = original
        self.cleanup_error = cleanup_error


def _upload_error(upload: _upload.Upload) -> BaseException:
    if isinstance(
        upload.error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
    ):
        return upload.error
    return UploadError(upload.error, upload.cleanup_error)


def _primary_error(
    error: BaseException,
    upload: _upload.Upload | None = None,
    cleanup: BaseException | None = None,
) -> BaseException:
    primary: BaseException = (
        _error(error) if isinstance(error, _native.NativeError) else error
    )
    if not isinstance(primary, Error):
        # Caller exceptions may define read-only or throwing metadata properties.
        # Cleanup must not replace those exceptions while trying to annotate them.
        return primary
    details = cast(dict[str, object], primary.__dict__)
    if upload is not None:
        # A producer failure explains RequestBody, but cannot replace a distinct
        # transport failure, timeout, cancellation or exhausted attempt budget.
        if (
            isinstance(error, _native.NativeError)
            and isinstance(primary, Error)
            and primary.kind == "request_body"
            and upload.error is not None
        ):
            failure = _upload_error(upload)
            if not isinstance(failure, Error):
                return failure
            failure.protocol = primary.protocol
            failure.timeout_phase = primary.timeout_phase
            primary = failure
            details = cast(dict[str, object], primary.__dict__)
        if upload.error is not None and upload.error is not primary:
            details["original"] = upload.error
        if upload.cleanup_error is not None:
            details["cleanup_error"] = upload.cleanup_error
    if isinstance(cleanup, UploadError):
        if details.get("original") is None:
            details["original"] = cleanup.original
        cleanup = cleanup.cleanup_error
    if cleanup is not None and details.get("cleanup_error") is None:
        details["cleanup_error"] = cleanup
    return primary


class ProfileError(Error):
    """A profile document failed strict validation at a canonical field."""

    def __init__(self, kind: str, field: str) -> None:
        super().__init__("profile", kind)
        self.field = field
        self.args = (f"profile: {kind} at {field}",)


class SessionSnapshotError(Error):
    """An encrypted checkpoint failed validation without exposing its contents."""


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
    if category == "session_snapshot":
        return SessionSnapshotError(category, kind, protocol, phase)
    if category == "prepared_body":
        return PreparedBodyError(category, kind, protocol, phase)
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


@dataclass(frozen=True, slots=True, repr=False)
class MultipartPart:
    """One ordered text/byte field; files and producers are not read implicitly."""

    name: str
    value: str | bytes
    filename: str | None = None
    content_type: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("name", self.name),
            ("filename", self.filename),
            ("content_type", self.content_type),
        ):
            if value is None and name != "name":
                continue
            if not isinstance(value, str):
                raise TypeError(f"{name} must be str")
            if len(value) > 4096:
                raise PreparedBodyError("prepared_body", "too_large")
        if not isinstance(self.value, (str, bytes)):
            raise TypeError("multipart value must be str or bytes")

    def __repr__(self) -> str:
        return "MultipartPart(<redacted>)"


def _encoded_maximum(value: int) -> None:
    if type(value) is not int:
        raise TypeError("maximum_bytes must be an integer")
    if not 0 <= value <= sys.maxsize * 2 + 1:
        raise ValueError("maximum_bytes must fit an unsigned native integer")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class PreparedBody:
    """Immutable native-owned encoded body, reusable across clients and attempts."""

    _native: _NativePreparedBody

    def __init__(self) -> None:
        raise TypeError("use PreparedBody.form or PreparedBody.multipart")

    @classmethod
    def _wrap(cls, native: _NativePreparedBody) -> PreparedBody:
        body = object.__new__(cls)
        object.__setattr__(body, "_native", native)
        return body

    @classmethod
    def form(
        cls, pairs: Iterable[tuple[str, str]], *, maximum_bytes: int
    ) -> PreparedBody:
        """Encode ordered duplicate UTF-8 pairs with an explicit encoded-byte cap."""
        _encoded_maximum(maximum_bytes)
        ordered: list[tuple[str, str]] = []
        for pair in pairs:
            if len(ordered) >= maximum_bytes:
                raise PreparedBodyError("prepared_body", "too_large")
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError("form pairs must be (str, str) tuples")
            name, value = pair
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("form pairs must contain str")
            ordered.append((name, value))
        return cls._wrap(_call(_native.NativePreparedBody.form, ordered, maximum_bytes))

    @classmethod
    def multipart(
        cls, parts: Iterable[MultipartPart], *, boundary: str, maximum_bytes: int
    ) -> PreparedBody:
        """Encode ordered fields; text normalizes CRLF, bytes remain byte-exact."""
        _encoded_maximum(maximum_bytes)
        if not isinstance(boundary, str):
            raise TypeError("boundary must be str")
        if len(boundary) > 70:
            raise PreparedBodyError("prepared_body", "invalid_boundary")
        ordered: list[tuple[str, str | bytes, str | None, str | None]] = []
        for part in parts:
            if len(ordered) == 1024:
                raise PreparedBodyError("prepared_body", "too_many_parts")
            if not isinstance(part, MultipartPart):
                raise TypeError("multipart parts must be MultipartPart")
            ordered.append((part.name, part.value, part.filename, part.content_type))
        return cls._wrap(
            _call(
                _native.NativePreparedBody.multipart, boundary, ordered, maximum_bytes
            )
        )

    @property
    def content_type(self) -> str:
        return self._native.content_type

    @property
    def length(self) -> int:
        return self._native.length

    def to_bytes(self) -> bytes:
        """Return an explicit copy of the encoded payload."""
        return self._native.to_bytes()

    def __repr__(self) -> str:
        return f"PreparedBody(length={self.length})"


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class ClientCertificate:
    """Parsed leaf-first chain and matching unencrypted key; no implicit file IO.

    Inputs total at most 16 MiB; DER chains contain one through 256 certificates.
    Parsing releases the GIL. The owner has no private-key export operation.
    Client origin mappings accept at most 256 ordered pairs, with 64 KiB per
    origin and 16 MiB aggregate UTF-8 origin bytes. The last core-normalized
    origin match wins; unmapped origins use the optional default certificate.
    """

    _native: _NativeClientCertificate = _field(repr=False)

    def __init__(self) -> None:
        raise TypeError("use ClientCertificate.from_pem or ClientCertificate.from_der")

    @classmethod
    def _wrap(cls, native: _NativeClientCertificate) -> ClientCertificate:
        certificate = object.__new__(cls)
        object.__setattr__(certificate, "_native", native)
        return certificate

    @classmethod
    def from_pem(
        cls, certificate_chain: bytes, private_key: bytes
    ) -> ClientCertificate:
        cls._check_bytes((certificate_chain,), private_key)
        return cls._wrap(
            _call(
                _native.NativeClientCertificate.from_pem, certificate_chain, private_key
            )
        )

    @classmethod
    def from_der(
        cls, certificate_chain: tuple[bytes, ...], private_key: bytes
    ) -> ClientCertificate:
        if not isinstance(certificate_chain, tuple):
            raise TypeError("certificate_chain must be a tuple of DER bytes")
        if not 1 <= len(certificate_chain) <= 256:
            raise Error("client_certificate", "invalid_chain_count")
        cls._check_bytes(certificate_chain, private_key)
        return cls._wrap(
            _call(
                _native.NativeClientCertificate.from_der, certificate_chain, private_key
            )
        )

    @staticmethod
    def _check_bytes(chain: tuple[bytes, ...], key: bytes) -> None:
        if not isinstance(key, bytes) or any(
            not isinstance(item, bytes) for item in chain
        ):
            raise TypeError("certificate chain and private key must be bytes")
        if len(key) + sum(map(len, chain)) > 16 * 1024 * 1024:
            raise Error("client_certificate", "too_large")

    def __repr__(self) -> str:
        return "ClientCertificate()"


def _certificates(
    default: ClientCertificate | None,
    origins: tuple[tuple[str, ClientCertificate], ...],
) -> _CertificateFields:
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
    result: _CertificateFields = {}
    if default is not None:
        result["client_certificate"] = default._native
    if origins:
        result["client_certificates_for"] = tuple(
            (origin, certificate._native) for origin, certificate in origins
        )
    return result


def _receiving_routes(
    routes: Iterable[str | Proxy | None],
) -> list[tuple[str | None, str | None, str | None]]:
    result: list[tuple[str | None, str | None, str | None]] = []
    for route in routes:
        if isinstance(route, str):
            route = Proxy(route)
        if route is not None and not isinstance(route, Proxy):
            raise TypeError("receiving routes must be URI strings, Proxy or None")
        result.append(
            (None, None, None)
            if route is None
            else (route.url, route.username, route.password)
        )
    return result


def _checkpoint_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("checkpoint and key must be bytes")
    return value


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

    @classmethod
    def import_ja3(cls, description: str, *, base: Profile) -> ImportedProfile:
        """Import raw JA3 using the base for its missing settings."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(_native.NativeProfile.import_ja3, description, base._native)
        )

    @classmethod
    def import_client_hello(cls, handshake: bytes, *, base: Profile) -> ImportedProfile:
        """Import a TCP handshake including its four-byte header, without a TLS record."""
        _import_input(handshake, bytes, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_client_hello, handshake, base._native
            )
        )

    @classmethod
    def import_akamai(cls, description: str, *, base: Profile) -> ImportedProfile:
        """Import ordered HTTP/2 settings, window update and pseudo-header order."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_akamai, description, base._native
            )
        )

    @classmethod
    def import_ja4(
        cls,
        description: str,
        *,
        format: Literal["sorted", "original"],
        base: Profile,
    ) -> ImportedProfile:
        """Import raw JA4; sorted input retains the explicit base's ordering."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_ja4, description, format, base._native
            )
        )

    @classmethod
    def import_quic_transport(
        cls, parameters: bytes, *, base: Profile
    ) -> ImportedProfile:
        """Import extension 57 payload bytes; connection IDs are generated afresh."""
        _import_input(parameters, bytes, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_quic_transport, parameters, base._native
            )
        )

    def export_json(self) -> bytes:
        return _profile_call(self._native.export_json)

    def describe(self) -> dict[str, object]:
        """Return a fresh editable document, including literal header values."""
        return cast(dict[str, object], _json.loads(self.export_json()))

    @property
    def catalog_id(self) -> str | None:
        return self._native.catalog_id


@dataclass(frozen=True, slots=True)
class ImportedProfile:
    """Custom profile and canonical paths supplied by input or retained from its base."""

    profile: Profile
    observed_fields: tuple[str, ...]
    supplemented_fields: tuple[str, ...]


def _import_input(
    value: object, expected: type[str] | type[bytes], base: Profile
) -> None:
    if not isinstance(base, Profile):
        raise TypeError("base must be a Profile")
    if not isinstance(value, expected):
        raise TypeError(
            "description must be str" if expected is str else "input must be bytes"
        )


def _imported(result: tuple[_NativeProfile, list[str], list[str]]) -> ImportedProfile:
    profile, observed, supplemented = result
    return ImportedProfile(Profile._wrap(profile), tuple(observed), tuple(supplemented))


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

    def __init__(
        self, native: _native.NativeResponse, upload: _upload.Upload | None = None
    ) -> None:
        self._native = native
        self._upload = upload
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
        if self._upload is not None:
            self._upload.check_loop()
        _call(self._native.close)
        if self._upload is not None:
            self._upload.close()

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
            and primary.kind == "concurrent_body_read"
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
        client_certificate: ClientCertificate | None = None,
        client_certificates_for: tuple[tuple[str, ClientCertificate], ...] = (),
    ) -> None:
        certificates = _certificates(client_certificate, client_certificates_for)
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
            **(
                {"server_spki_pins": roots.server_spki_pins}
                if roots.server_spki_pins is not None
                else {}
            ),
            **(
                {"proxy_server_spki_pins": roots.proxy_server_spki_pins}
                if roots.proxy_server_spki_pins is not None
                else {}
            ),
            **certificates,
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

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: _Headers = (),
        trailers: _Headers = (),
        expect_continue_ms: int | None = None,
        body: bytes | PreparedBody | AsyncIterable[bytes] | None = None,
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
        """Return the response head without collecting its body.

        Producer body_length checks demanded frames and EOF. An unread source
        suffix is not pulled after the transport finishes or abandons the body.
        """
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
        if diagnostics is not None and not isinstance(diagnostics, RequestDiagnostics):
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
        producer = body is not None and not isinstance(body, (bytes, PreparedBody))
        if body is not None and upload is not None:
            raise ValueError("pass body or upload, not both")
        if producer and not isinstance(body, AsyncIterable):
            raise TypeError(
                "AsyncClient body must be bytes, PreparedBody or AsyncIterable[bytes]"
            )
        if prepared is not None and body_length is not None:
            if type(body_length) is not int or body_length != prepared.length:
                raise ValueError("body_length must equal the prepared encoded length")
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
        pump = (
            _upload.Upload(cast(AsyncIterable[bytes], body), body_length)
            if producer
            else None
        )
        if pump is not None:
            self._uploads.add(pump)
            pump.settled.add_done_callback(lambda _: self._uploads.discard(pump))
        diagnostic_fields: _DiagnosticsFields = {}
        if diagnostics is not None:
            diagnostic_fields["diagnostics"] = diagnostics._native
        try:
            arguments = (
                method,
                url,
                ordered,
                None if producer or prepared is not None else cast(bytes | None, body),
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
            if prepared is not None:
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
                    producer=None if pump is None else pump.native,
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
                    producer=None if pump is None else pump.native,
                    transfer_control=transfer_control._native,
                )
            else:
                operation = (
                    self._native.request(*arguments, **diagnostic_fields)
                    if pump is None
                    else self._native.request(
                        *arguments, producer=pump.native, **diagnostic_fields
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

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(
        self, _: object, error: BaseException | None, __: object
    ) -> None:
        try:
            await self.close()
        except BaseException as cleanup:
            if error is not None:
                raise _primary_error(error, cleanup=cleanup) from None
            raise


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
        client_certificate: ClientCertificate | None = None,
        client_certificates_for: tuple[tuple[str, ClientCertificate], ...] = (),
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
            client_certificate=client_certificate,
            client_certificates_for=client_certificates_for,
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

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: _Headers = (),
        trailers: _Headers = (),
        expect_continue_ms: int | None = None,
        body: bytes | PreparedBody | Iterable[bytes] | None = None,
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
        if body is not None and not isinstance(body, (bytes, PreparedBody, Iterable)):
            raise TypeError(
                "Client body must be bytes, PreparedBody or Iterable[bytes]"
            )
        source = (
            _upload.SyncSource(body)
            if body is not None and not isinstance(body, (bytes, PreparedBody))
            else body
        )
        return Response(
            self,
            self._run(
                lambda: self._async.request(
                    method,
                    url,
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
