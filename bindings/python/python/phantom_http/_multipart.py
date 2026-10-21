"""Single-coordinator ownership for core-encoded multipart sources."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from _thread import LockType
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import cast

from . import _native, _upload


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class Part:
    name: str
    value: object
    filename: str | None
    content_type: str | None
    kind: int
    _lock: LockType = field(default_factory=threading.Lock)
    _claimed: bool = False

    def claim(self) -> bool:
        with self._lock:
            if self._claimed:
                return False
            object.__setattr__(self, "_claimed", True)
            return True

    def __repr__(self) -> str:
        return "MultipartPart(<redacted>)"


class CleanupErrors(Exception):
    """Explicit identities for multiple cleanup failures, with redacted printing."""

    def __init__(self, errors: tuple[BaseException, ...]) -> None:
        super().__init__("multipart source cleanup failed")
        self.errors = errors

    def __repr__(self) -> str:
        return "MultipartCleanupErrors(<redacted>)"


class Sources:
    def __init__(self) -> None:
        self.owned: dict[int, object] = {}
        self.closed: set[int] = set()
        self.failures: list[BaseException] = []

    async def close(self, index: int) -> None:
        if index in self.closed:
            return
        self.closed.add(index)
        source = self.owned[index]
        try:
            method = "aclose" if isinstance(source, AsyncIterator) else "close"
            close = cast(object, getattr(source, method, None))
            if not callable(close):
                raise TypeError("multipart stream must provide close or aclose")
            if isinstance(source, AsyncIterator):
                await cast(Callable[[], Awaitable[None]], close)()
            else:
                cast(Callable[[], None], close)()
        except BaseException as error:
            self.failures.append(error)

    async def close_all(self) -> None:
        for index in self.owned:
            await self.close(index)

    @property
    def error(self) -> BaseException | None:
        if not self.failures:
            return None
        if len(self.failures) == 1:
            return self.failures[0]
        return CleanupErrors(tuple(self.failures))


class Upload(_upload.Upload):
    native: _native.NativeStreamingMultipart

    def __init__(self, sources: Sources) -> None:
        self.sources = sources
        self.failure: BaseException | None = None
        self._ready = asyncio.Event()
        self._prepared = False
        self._started = False
        self.iterator = None
        self.error = None
        self.cleanup_error = None
        self.closing = False
        self.cleaning = False
        self.loop = asyncio.get_running_loop()
        self.task = asyncio.create_task(self._pump())
        self.settled = asyncio.create_task(self._watch())

    def prepare(
        self,
        boundary: str,
        fields: list[tuple[int, str, object, str | None, str | None]],
        maximum: int,
    ) -> None:
        if self.failure is not None:
            raise self.failure
        self.native = _native.NativeStreamingMultipart(boundary, fields, maximum)
        self._prepared = True
        self._ready.set()

    def close(self) -> None:
        self.check_loop()
        if self._prepared:
            self.native.abort()
        if not self.closing:
            self.closing = True
            self._ready.set()
            # Cancellation before the coroutine starts would skip its finally.
            if self._started and not self.task.done() and not self.cleaning:
                self.task.cancel()

    async def _watch(self) -> None:
        await self._ready.wait()
        if self._prepared:
            await self.native.terminal()
        self.close()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task

    async def _pump(self) -> None:
        self._started = True
        try:
            await self._ready.wait()
            if self.closing:
                return
            used: set[int] = set()
            while (index := await self.native.next_part()) is not None:
                if (
                    type(index) is not int
                    or index not in self.sources.owned
                    or index in used
                ):
                    raise RuntimeError("invalid native multipart demand")
                used.add(index)
                source = self.sources.owned[index]
                self.iterator = None
                if isinstance(source, AsyncIterator):
                    selected = source
                else:
                    selected = _upload.SyncSource(cast(Iterator[bytes], source))

                async def finish() -> None:
                    await self.sources.close(index)
                    if self.sources.error is not None:
                        self.cleanup_error = self.sources.error
                        raise CleanupErrors(tuple(self.sources.failures))

                if not await self._send(selected, finish):
                    return
        except asyncio.CancelledError as error:
            if not self.closing:
                self.error = error
            if self._prepared:
                self.native.abort()
            raise
        except CleanupErrors:
            self._fail()
        except BaseException as error:
            self.error = error
            self._fail()
        finally:
            self.cleaning = True
            await self.sources.close_all()
            self.cleanup_error = self.sources.error
            if self.cleanup_error is not None and self._prepared:
                self._fail()
