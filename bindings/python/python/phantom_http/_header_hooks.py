"""Ordered header callbacks owned by each sending task's event loop."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeAlias, cast

from . import _native
from ._configuration import Header
from ._redirect import AsyncRedirectCallback, RedirectAttempt, RedirectDecision
from ._request import _request_fields

HeaderHook: TypeAlias = Callable[["HeaderHookContext"], None]
AsyncHeaderHook: TypeAlias = Callable[["HeaderHookContext"], None | Awaitable[None]]
_Edit: TypeAlias = tuple[str, str, bytes, bool]
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _snapshot(hooks: Iterable[AsyncHeaderHook]) -> tuple[AsyncHeaderHook, ...]:
    result: list[AsyncHeaderHook] = []
    for hook in hooks:
        if len(result) >= 256:
            raise ValueError("header hooks exceed 256 callbacks")
        if not callable(hook):
            raise TypeError("header hooks must be callable")
        result.append(hook)
    return tuple(result)


class HeaderHookContext:
    """Ordinary HTTP request and caller fields, including earlier hook edits.

    Generated cookies and template fields are added later. Inspect url before
    adding credentials; sensitive marks control encoding, not redirect policy.
    A retained context cannot mutate headers after its callback completes.
    """

    def __init__(
        self, method: str, url: str, fields: list[tuple[str, bytes, bool]]
    ) -> None:
        self._method = method
        self._url = url
        self._headers = tuple(Header(*field) for field in fields)
        self._maximum_fields = max(256, len(self._headers))
        self._maximum_bytes = max(
            65536,
            sum(len(h.name.encode("utf-8")) + len(h.value) for h in self._headers),
        )
        self._edits: list[_Edit] = []
        self._remaining = 65536
        self._active = True

    @property
    def method(self) -> str:
        return self._method

    @property
    def url(self) -> str:
        return self._url

    @property
    def headers(self) -> tuple[Header, ...]:
        return self._headers

    def __repr__(self) -> str:
        return f"HeaderHookContext(header_count={len(self._headers)})"

    def _record(self, edit: _Edit, headers: tuple[Header, ...]) -> None:
        if not self._active:
            raise RuntimeError("header callback context is closed")
        if len(edit[1]) + len(edit[2]) > self._remaining:
            raise ValueError("header hook edits exceed their bounded capacity")
        size = len(edit[1].encode("utf-8")) + len(edit[2])
        if len(self._edits) >= 256 or size > self._remaining:
            raise ValueError("header hook edits exceed their bounded capacity")
        if (
            len(headers) > self._maximum_fields
            or sum(len(h.name.encode("utf-8")) + len(h.value) for h in headers)
            > self._maximum_bytes
        ):
            raise ValueError("header hook fields exceed their bounded capacity")
        self._edits.append(edit)
        self._remaining -= size
        self._headers = headers

    def append(self, header: Header | tuple[str, str | bytes]) -> None:
        """Append an existing Header or (name, value), keeping duplicates."""
        if not self._active:
            raise RuntimeError("header callback context is closed")
        fields, _ = _request_fields((header,), ())
        name, value, sensitive = fields[0]
        field = Header(name, value, sensitive)
        self._record(("append", name, value, sensitive), (*self._headers, field))

    def set(self, header: Header | tuple[str, str | bytes]) -> None:
        """Replace at the first matching position and remove later duplicates."""
        if not self._active:
            raise RuntimeError("header callback context is closed")
        fields, _ = _request_fields((header,), ())
        name, value, sensitive = fields[0]
        field = Header(name, value, sensitive)
        result = []
        replaced = False
        for old in self._headers:
            if old.name.translate(_ASCII_LOWER) == name.translate(_ASCII_LOWER):
                if not replaced:
                    result.append(field)
                    replaced = True
            else:
                result.append(old)
        if not replaced:
            result.append(field)
        self._record(("set", name, value, sensitive), tuple(result))

    def remove(self, name: str) -> None:
        """Remove all caller overrides with this name, ignoring ASCII case."""
        if not self._active:
            raise RuntimeError("header callback context is closed")
        if not isinstance(name, str):
            raise TypeError("header names must be str")
        if len(name) > self._remaining:
            raise ValueError("header hook edits exceed their bounded capacity")
        self._record(
            ("remove", name, b"", False),
            tuple(
                old
                for old in self._headers
                if old.name.translate(_ASCII_LOWER) != name.translate(_ASCII_LOWER)
            ),
        )

    def _finish(self) -> None:
        self._active = False


class Hooks:
    def __init__(
        self,
        callbacks: tuple[AsyncHeaderHook, ...],
        synchronous: bool,
        redirect: AsyncRedirectCallback | None = None,
    ) -> None:
        self.native = (
            _native.NativeHeaderHooks(len(callbacks), True)
            if redirect is not None
            else _native.NativeHeaderHooks(len(callbacks))
        )
        self.callbacks = callbacks
        self.redirect = redirect
        self.synchronous = synchronous
        self.error: BaseException | None = None
        self.cleanup_error: BaseException | None = None
        self.context: HeaderHookContext | None = None
        self.field_limits: tuple[int, int] | None = None
        self.closing = False
        self.loop = asyncio.get_running_loop()
        self.task = asyncio.create_task(self._pump())
        self.settled = asyncio.create_task(self._watch())

    def check_wait(self) -> None:
        if asyncio.get_running_loop() is not self.loop:
            raise RuntimeError("header callbacks belong to their creating event loop")
        if cast(asyncio.Task[object] | None, asyncio.current_task()) is self.task:
            raise RuntimeError("a header callback cannot wait for its own cleanup")

    def close(self) -> None:
        if asyncio.get_running_loop() is not self.loop:
            raise RuntimeError("header callbacks belong to their creating event loop")
        self.native.abort()
        if self.context is not None:
            self.context._finish()
        if not self.closing:
            self.closing = True
            if not self.task.done():
                self.task.cancel()

    async def _watch(self) -> None:
        await self.native.terminal()
        self.close()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task

    async def _pump(self) -> None:
        try:
            while (invocation := await self.native.next()) is not None:
                serial = invocation[0]
                try:
                    if len(invocation) == 8:
                        await self._redirect(invocation)
                    else:
                        await self._headers(invocation)
                except BaseException as error:
                    if self.closing:
                        if not isinstance(error, asyncio.CancelledError):
                            self.cleanup_error = error
                    else:
                        self.error = error
                        try:
                            self.native.fail(serial, error)
                        except _native.NativeError as delivery:
                            arguments = cast(tuple[object, ...], delivery.args)
                            if arguments[:2] != ("input", "header_hook_closed"):
                                raise
                            # Native closure can precede the watcher cancelling us.
                            self.cleanup_error = error
                    return
                finally:
                    if self.context is not None:
                        self.context._finish()
                    self.context = None
        except asyncio.CancelledError:
            if not self.closing:
                self.native.abort()
            raise
        except BaseException as error:
            self.cleanup_error = error
            self.native.abort()

    async def _headers(self, invocation: _native._HeaderInvocation) -> None:
        serial, index, method, uri, fields = invocation
        context = HeaderHookContext(method, uri, fields)
        if self.field_limits is None:
            self.field_limits = (context._maximum_fields, context._maximum_bytes)
        else:
            context._maximum_fields, context._maximum_bytes = self.field_limits
        self.context = context
        result = self.callbacks[index](context)
        if inspect.isawaitable(result):
            if self.synchronous:
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("Client header callbacks must be synchronous")
            await result
            result = None
        if result is not None:
            raise TypeError("header callbacks must return None")
        context._finish()
        if not self.closing:
            self.native.complete(serial, context._edits)

    async def _redirect(self, invocation: _native._RedirectInvocation) -> None:
        serial, _, source, destination, status, method, next_method, hop = invocation
        callback = self.redirect
        if callback is None:
            raise RuntimeError("redirect callback is unavailable")
        result = callback(
            RedirectAttempt(source, destination, status, method, next_method, hop)
        )
        if inspect.isawaitable(result):
            if self.synchronous:
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("Client redirect callbacks must be synchronous")
            result = await result
        if not isinstance(result, RedirectDecision):
            raise TypeError("redirect callbacks must return RedirectDecision")
        if not self.closing:
            self.native.complete_redirect(serial, result.value)

    async def wait(self, timeout_ms: int = 5000) -> bool:
        self.check_wait()
        done, _ = await asyncio.wait({self.settled}, timeout=timeout_ms / 1000)
        return bool(done)
