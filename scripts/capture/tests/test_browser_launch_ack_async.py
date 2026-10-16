"""Keep the loopback server live while a Windows launch awaits its tool."""

import asyncio
import contextlib
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import browser_launch, process_container
from scripts.capture.tests.test_process_container import OwnedWindowsProcess

WAIT_SECONDS = 10


@unittest.skipUnless(sys.platform == "win32", "Windows launch acknowledgement")
class BrowserLaunchAcknowledgementAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def check_held_acknowledgement(self, *, cancel: bool) -> None:
        loop = asyncio.get_running_loop()
        ready = asyncio.Event()
        release = threading.Event()
        expired = threading.Event()
        errors = []
        tool_pids = []
        launch_futures = []
        actual_executor = loop.run_in_executor
        browser = browser_launch.LaunchedBrowser(
            browser_launch.LaunchPlan(
                "chrome", Path(process_container._windows_interpreter()), True
            ),
            "http://127.0.0.1/acknowledgement-control",
        )
        self.assertFalse(browser.plan.android)
        self.assertFalse(browser.plan.takes_turns)

        with contextlib.ExitStack() as cleanup:
            listener = cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(WAIT_SECONDS)

            def hold_acknowledgement() -> None:
                try:
                    with listener.accept()[0] as peer:
                        peer.settimeout(WAIT_SECONDS)
                        with peer.makefile("rb") as reader:
                            tool_pids.append(int(reader.readline(32)))
                        loop.call_soon_threadsafe(ready.set)
                        # A bounded independent release makes the old blocking
                        # path fail an assertion instead of hanging the loop.
                        if not release.wait(3):
                            expired.set()
                        peer.sendall(b"G")
                except BaseException as error:
                    errors.append(error)
                    loop.call_soon_threadsafe(ready.set)

            thread = threading.Thread(target=hold_acknowledgement)
            thread.start()
            barrier = (
                "        import socket\n"
                f"        with socket.create_connection(('127.0.0.1', {listener.getsockname()[1]}), timeout=10) as peer:\n"
                "            peer.settimeout(10)\n"
                "            peer.sendall(str(tool.pid).encode() + b'\\n')\n"
                "            if peer.recv(1) != b'G':\n"
                "                raise OSError('test acknowledgement was not released')\n"
            )
            original = process_container._CONFIRMED_BOOTSTRAP
            anchor = "        status.send_bytes(b'G' + tool.pid.to_bytes(4, 'big'))"
            self.assertEqual(original.count(anchor), 1)
            bootstrap = original.replace(anchor, barrier + anchor)

            def record_executor(executor, function, *arguments):
                future = actual_executor(executor, function, *arguments)
                if function.__name__ == "enter":
                    launch_futures.append(future)
                return future

            async def answer(reader, writer) -> None:
                try:
                    self.assertEqual(await reader.readexactly(1), b"Q")
                    writer.write(b"A")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            server = await asyncio.start_server(answer, "127.0.0.1", 0)
            task = None
            try:
                with (
                    mock.patch.object(
                        process_container, "_CONFIRMED_BOOTSTRAP", bootstrap
                    ),
                    mock.patch.object(
                        browser_launch,
                        "browser_arguments",
                        return_value=[
                            "-c",
                            "import threading; threading.Event().wait(30)",
                        ],
                    ),
                    mock.patch.object(loop, "run_in_executor", record_executor),
                ):
                    task = asyncio.create_task(browser_launch.enter_browser(browser))
                    await asyncio.wait_for(ready.wait(), WAIT_SECONDS)
                    self.assertEqual(errors, [])
                    self.assertFalse(expired.is_set(), "launch stalled the event loop")
                    self.assertFalse(task.done())
                    self.assertEqual(len(launch_futures), 1)
                    container = browser.process
                    profile = browser.profile
                    child = OwnedWindowsProcess(tool_pids[0])
                    cleanup.callback(child.close)
                    self.assertTrue(profile.is_dir())
                    self.assertFalse(child.ended_now())
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(*server.sockets[0].getsockname()),
                        WAIT_SECONDS,
                    )
                    try:
                        writer.write(b"Q")
                        await writer.drain()
                        self.assertEqual(
                            await asyncio.wait_for(reader.readexactly(1), WAIT_SECONDS),
                            b"A",
                        )
                    finally:
                        writer.close()
                        await writer.wait_closed()
                    self.assertFalse(release.is_set())
                    self.assertFalse(expired.is_set())
                    if cancel:
                        self.assertTrue(task.cancel("held launch control"))
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                        self.assertFalse(launch_futures[0].done())
                        self.assertFalse(child.ended_now())
                        self.assertTrue(profile.is_dir())
                    release.set()
                    result = await asyncio.wait_for(
                        asyncio.shield(launch_futures[0]), WAIT_SECONDS
                    )
                    self.assertIs(result, browser)
                    if not cancel:
                        self.assertIs(await task, browser)
                        await browser_launch.exit_browser(browser)
                    self.assertTrue(container._cleanup_complete)
                    self.assertTrue(child.ended_now())
                    self.assertFalse(profile.exists())
            finally:
                release.set()
                if task is not None:
                    if not task.done():
                        task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
                for future in launch_futures:
                    await asyncio.wait_for(asyncio.shield(future), WAIT_SECONDS)
                await browser_launch.exit_browser(browser)
                server.close()
                await server.wait_closed()
                await asyncio.to_thread(thread.join, WAIT_SECONDS)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    async def test_delayed_acknowledgement_keeps_loopback_server_responsive(
        self,
    ) -> None:
        await self.check_held_acknowledgement(cancel=False)

    async def test_cancelled_delayed_acknowledgement_finishes_owned_cleanup(
        self,
    ) -> None:
        await self.check_held_acknowledgement(cancel=True)


if __name__ == "__main__":
    unittest.main()
