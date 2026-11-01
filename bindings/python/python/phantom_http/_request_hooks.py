"""Metadata-only observers for a logical HTTP request."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TypeAlias, TypeVar

from . import _native
from ._errors import Error, _error
from ._response import ResponseHeader, ResponseHeaders


@dataclass(frozen=True)
class RequestHookContext:
    """The original method and resolved URL, before redirects or retries."""

    method: str
    url: str = field(repr=False)


@dataclass(frozen=True)
class ResponseHookContext:
    """Final decoded response metadata, without access to its unread body.

    headers preserves duplicate values, but does not represent wire order.
    retries_performed counts connection-setup retries, as on Response.
    """

    request: RequestHookContext
    status: int
    protocol: str
    headers: ResponseHeaders = field(repr=False)
    url: str = field(repr=False)
    redirects_followed: int
    retries_performed: int
    decoded_content_codings: tuple[str, ...]


@dataclass(frozen=True)
class RequestErrorHookContext:
    """The original terminal error; inspect error.original for a Python cause."""

    request: RequestHookContext
    error: Error = field(repr=False)


@dataclass(frozen=True)
class RequestHooks:
    """Synchronous logical observers for Client or AsyncClient.

    Client observers run before request observers, once per phase across
    redirects and retries. A response observer sees the unread final head.
    Later body failures do not call on_error. Observers cannot change headers
    or bodies. Use header_hooks to edit caller headers.
    """

    on_request: Callable[[RequestHookContext], None] | None = field(
        default=None, repr=False
    )
    on_response: Callable[[ResponseHookContext], None] | None = field(
        default=None, repr=False
    )
    on_error: Callable[[RequestErrorHookContext], None] | None = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        _validate(self)


@dataclass(frozen=True)
class AsyncRequestHooks:
    """Logical observers for AsyncClient, awaited on the request's owning loop.

    Callbacks share one total deadline with the request and response body.
    A request callback failure enters on_error. A response callback failure
    drops the unread body without invoking on_error. A failed on_error keeps
    the original error primary and exposes its observer failure as hook_error.
    Dropping the send cancels its callback without starting another phase.
    Client close reports the first callback failure that cancellation prevented
    the request from reporting, after actual callback cleanup.
    """

    on_request: Callable[[RequestHookContext], None | Awaitable[None]] | None = field(
        default=None, repr=False
    )
    on_response: Callable[[ResponseHookContext], None | Awaitable[None]] | None = field(
        default=None, repr=False
    )
    on_error: Callable[[RequestErrorHookContext], None | Awaitable[None]] | None = (
        field(default=None, repr=False)
    )

    def __post_init__(self) -> None:
        _validate(self)


Observers: TypeAlias = RequestHooks | AsyncRequestHooks


def _validate(hooks: Observers) -> None:
    for callback in (hooks.on_request, hooks.on_response, hooks.on_error):
        if callback is not None and not callable(callback):
            raise TypeError("request hook callbacks must be callable")


def _checked(hooks: Observers | None) -> Observers | None:
    if hooks is not None and type(hooks) not in (RequestHooks, AsyncRequestHooks):
        raise TypeError("request_hooks must be RequestHooks or AsyncRequestHooks")
    if hooks is None or _phases((hooks,)) == 0:
        return None
    return hooks


def _phases(hooks: tuple[Observers, ...]) -> int:
    return (
        (1 if any(observer.on_request is not None for observer in hooks) else 0)
        | (2 if any(observer.on_response is not None for observer in hooks) else 0)
        | (4 if any(observer.on_error is not None for observer in hooks) else 0)
    )


_Context = TypeVar("_Context")


async def _call(
    callback: Callable[[_Context], None | Awaitable[None]] | None,
    context: _Context,
    synchronous: bool,
) -> None:
    if callback is None:
        return
    result = callback(context)
    if inspect.isawaitable(result):
        if synchronous:
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError("Client request callbacks must be synchronous")
        await result
        result = None
    if result is not None:
        raise TypeError("request callbacks must return None")


async def _dispatch(
    observers: tuple[Observers, ...],
    invocation: _native._LogicalInvocation,
    synchronous: bool,
) -> None:
    request = RequestHookContext(invocation[2], invocation[3])
    if invocation[1] == "request":
        for hooks in observers:
            await _call(
                hooks.on_request,
                request,
                synchronous or isinstance(hooks, RequestHooks),
            )
    elif invocation[1] == "response":
        response = ResponseHookContext(
            request,
            invocation[4],
            invocation[5],
            ResponseHeaders(ResponseHeader(*field) for field in invocation[6]),
            invocation[7],
            invocation[8],
            invocation[9],
            tuple(invocation[10]),
        )
        for hooks in observers:
            await _call(
                hooks.on_response,
                response,
                synchronous or isinstance(hooks, RequestHooks),
            )
    else:
        error = RequestErrorHookContext(request, _error(invocation[4]))
        for hooks in observers:
            await _call(
                hooks.on_error, error, synchronous or isinstance(hooks, RequestHooks)
            )
