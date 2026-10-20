"""Owning-loop producer pump; native demand admits one bounded copy at a time."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
)
from typing import cast

from . import _native

CHUNK_SIZE = 65536


def _closed(error: _native.NativeError) -> bool:
    arguments = cast(tuple[object, ...], error.args)
    return len(arguments) >= 2 and arguments[:2] == ("input", "upload_closed")


class SyncSource:
    def __init__(self, source: Iterable[bytes]) -> None:
        self.source = source
        self.iterator: Iterator[bytes] | None = None

    def __aiter__(self) -> SyncSource:
        return self

    async def __anext__(self) -> bytes:
        if self.iterator is None:
            self.iterator = iter(self.source)
        try:
            return next(self.iterator)
        except StopIteration:
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        if self.iterator is not None:
            close = cast(
                Callable[[], None] | None, getattr(self.iterator, "close", None)
            )
            if close is not None:
                close()


class Upload:
    def __init__(self, source: AsyncIterable[bytes], length: int | None) -> None:
        self.native = _native.NativeUpload(length)
        self.source = source
        self.iterator: AsyncIterator[bytes] | None = None
        self.error: BaseException | None = None
        self.cleanup_error: BaseException | None = None
        self.closing = False
        self.cleaning = False
        self.loop = asyncio.get_running_loop()
        self.task = asyncio.create_task(self._pump())
        self.settled = asyncio.create_task(self._watch())

    def check_loop(self) -> None:
        if asyncio.get_running_loop() is not self.loop:
            raise RuntimeError("streaming uploads belong to their creating event loop")

    def check_wait(self) -> None:
        self.check_loop()
        if cast(asyncio.Task[object] | None, asyncio.current_task()) is self.task:
            raise RuntimeError("an upload producer cannot wait for its own cleanup")

    def close(self) -> None:
        self.check_loop()
        self.native.abort()
        if not self.closing:
            self.closing = True
            if not self.task.done() and not self.cleaning:
                self.task.cancel()

    async def _watch(self) -> None:
        await self.native.terminal()
        self.close()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task

    def _fail(self) -> None:
        try:
            self.native.fail()
        except _native.NativeError as error:
            if not _closed(error):
                self.cleanup_error = error

    def _finish(self) -> None:
        try:
            self.native.finish()
        except _native.NativeError as error:
            if not _closed(error):
                raise

    async def _pump(self) -> None:
        try:
            current = b""
            offset = 0
            while await self.native.credit():
                if offset == len(current):
                    if self.iterator is None:
                        self.iterator = aiter(self.source)
                    try:
                        current = await anext(self.iterator)
                    except StopAsyncIteration:
                        self._finish()
                        return
                    if not isinstance(current, bytes):
                        raise TypeError("upload chunks must be bytes")
                    offset = 0
                    # Empty chunks retain the same credit; yield for cooperative
                    # cancellation without requesting another native frame.
                    while not current:
                        await asyncio.sleep(0)
                        try:
                            current = await anext(self.iterator)
                        except StopAsyncIteration:
                            self._finish()
                            return
                        if not isinstance(current, bytes):
                            raise TypeError("upload chunks must be bytes")
                length = min(CHUNK_SIZE, len(current) - offset)
                try:
                    self.native.write(current, offset, length)
                except _native.NativeError as error:
                    if _closed(error):
                        return
                    raise
                offset += length
        except asyncio.CancelledError as error:
            if not self.closing:
                self.error = error
            self.native.abort()
            raise
        except BaseException as error:
            self.error = error
            self._fail()
        finally:
            self.cleaning = True
            if self.iterator is not None:
                close = cast(
                    Callable[[], Awaitable[None]] | None,
                    getattr(self.iterator, "aclose", None),
                )
                if close is not None:
                    try:
                        await close()
                    except BaseException as error:
                        self.cleanup_error = error
                        self._fail()

    async def wait(self, timeout_ms: int = 5000) -> bool:
        # wait() leaves noncooperative producer cleanup owned and observable;
        # cancelling an await must not detach another native operation.
        self.check_wait()
        done, _ = await asyncio.wait({self.settled}, timeout=timeout_ms / 1000)
        return bool(done)


def length(value: int | None, producer: bool) -> int | None:
    if value is not None:
        if not producer:
            raise ValueError("body_length requires a producer body")
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("body_length must be an integer")
        if value < 0 or value > 2**64 - 1:
            raise ValueError("body_length must fit an unsigned 64-bit integer")
    return value
