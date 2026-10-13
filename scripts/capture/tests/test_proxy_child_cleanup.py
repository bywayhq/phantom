import asyncio
import unittest

from scripts.capture.tests import test_browser_remote as remote_fixtures
from scripts.capture.tests.test_proxy_browser_driver import BrowserContext


class ClosingWriter:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        raise self.failure


class ProxyChildCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def check_close(self, failure: BaseException, *, observer: bool) -> None:
        context = BrowserContext(self)
        writer = ClosingWriter(failure)
        if observer:
            reader = asyncio.StreamReader()
            reader.feed_data(b"child-ready\n")
            reader.feed_eof()
            operation = context.observe_child(reader, writer)
        else:
            task = asyncio.create_task(asyncio.sleep(0))
            await task
            context.connections.append((writer, task))
            operation = context.finish()

        expected = isinstance(
            failure, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)
        )
        if expected:
            await operation
        else:
            with self.assertRaises(remote_fixtures.RemoteFailures) as caught:
                await operation
            self.assertIsNone(caught.exception.primary)
            self.assertEqual(len(caught.exception.cleanup), 1)
            if isinstance(failure, asyncio.CancelledError):
                # wait_for can reconstruct an inner task's cancellation.
                self.assertIsInstance(
                    caught.exception.cleanup[0], asyncio.CancelledError
                )
            else:
                self.assertIs(caught.exception.cleanup[0], failure)

        self.assertTrue(writer.closed)
        if observer:
            self.assertTrue(context.child_ready.is_set())
        else:
            self.assertTrue(context.finished)
            self.assertTrue(task.done())

    async def test_child_observer_accepts_only_expected_disconnects_on_close(self):
        for failure in (
            ConnectionResetError("child reset"),
            BrokenPipeError("child pipe closed"),
            ConnectionAbortedError("child aborted"),
            OSError(5, "unrelated I/O failure"),
            asyncio.CancelledError("unrequested cancellation"),
            TimeoutError("close deadline"),
            RuntimeError("unexpected close failure"),
        ):
            with self.subTest(failure=type(failure).__name__):
                await self.check_close(failure, observer=True)

    async def test_context_backup_accepts_only_expected_disconnects_on_close(self):
        for failure in (
            ConnectionResetError("child reset"),
            BrokenPipeError("child pipe closed"),
            ConnectionAbortedError("child aborted"),
            OSError(5, "unrelated I/O failure"),
            asyncio.CancelledError("unrequested cancellation"),
            TimeoutError("close deadline"),
            RuntimeError("unexpected close failure"),
        ):
            with self.subTest(failure=type(failure).__name__):
                await self.check_close(failure, observer=False)
