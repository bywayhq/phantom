"""Redacted public errors and native/producer failure precedence."""

from __future__ import annotations

import asyncio
from collections.abc import (
    Callable,
)
from typing import (
    ParamSpec,
    TypeVar,
    cast,
)

from . import _native, _upload

_P = ParamSpec("_P")
_T = TypeVar("_T")


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


class SseError(Error):
    """SSE response validation or decoding exceeded its configured contract."""


def _error(error: _native.NativeError) -> Error:
    category, kind, protocol, phase = cast(
        tuple[str, str, str | None, str | None], error.args
    )
    if category == "session_snapshot":
        return SessionSnapshotError(category, kind, protocol, phase)
    if category == "prepared_body":
        return PreparedBodyError(category, kind, protocol, phase)
    if category == "sse":
        failure = SseError(category, kind, protocol, phase)
        original = cast(object, getattr(error, "original", None))
        if isinstance(original, _native.NativeError):
            failure.original = _error(original)
        return failure
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
