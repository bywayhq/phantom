import asyncio
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from scripts.capture import browser_launch, browser_remote, proxy_route
from scripts.capture.tests import test_browser_remote as remote_fixtures
from scripts.capture.tests import test_browser_remote_lifecycle as lifecycle

DEADLINE = 10.0
URL = "http://literal.test/context"
CHILD = (
    "import socket, sys; "
    "peer = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=10); "
    "peer.settimeout(None); peer.sendall(b'child-ready\\n'); "
    "peer.recv(1); peer.close()"
)
COMMANDS = [
    {"id": 1, "method": "Target.getTargets", "params": {}},
    {
        "id": 2,
        "method": "Target.attachToTarget",
        "params": {"targetId": "page-literal", "flatten": True},
    },
    {
        "id": 3,
        "method": "Fetch.enable",
        "params": {"handleAuthRequests": True, "patterns": [{"urlPattern": "*"}]},
        "sessionId": "session-literal",
    },
    {
        "id": 4,
        "method": "Page.navigate",
        "params": {"url": URL},
        "sessionId": "session-literal",
    },
]


class StartupFailure(Exception):
    pass


class BodyFailure(Exception):
    pass


class RemoteCloseFailure(Exception):
    pass


class BrowserCloseFailure(Exception):
    pass


class BrowserContext:
    """Retain independent backup authority over the real context resources."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.case = case
        self.peer = lifecycle.CommandPeer(
            {
                "Target.getTargets": {
                    "targetInfos": [{"type": "page", "targetId": "page-literal"}]
                },
                "Target.attachToTarget": {"sessionId": "session-literal"},
                "Fetch.enable": {},
                "Page.navigate": {"frameId": "frame-literal"},
            },
            {"method": "Probe.idle", "params": {"literal": 31}},
        )
        self.server: asyncio.Server | None = None
        self.children: list[subprocess.Popen] = []
        self.profiles: list[Path] = []
        self.connections: list[tuple[asyncio.StreamWriter, asyncio.Task]] = []
        self.calls: list[asyncio.Task] = []
        self.observed_cancellations: set[asyncio.Task] = set()
        self.patches: list = []
        self.driver: proxy_route.ProxyBrowserDriver | None = None
        self.child_ready = asyncio.Event()
        self.start_ready = asyncio.Event()
        self.release_start = asyncio.Event()
        self.hold_start = False
        self.start_failure: BaseException | None = None
        self.start_cancellation: asyncio.CancelledError | None = None
        self.remote_failure: BaseException | None = None
        self.browser_failure: BaseException | None = None
        self.notes: list[str] = []
        self.diagnostics = io.StringIO()
        self.finished = False

    async def start(self) -> proxy_route.ProxyBrowserDriver:
        port = await asyncio.wait_for(self.peer.listen(), DEADLINE)
        self.server = await asyncio.wait_for(
            asyncio.start_server(self.accept_child, "127.0.0.1", 0), DEADLINE
        )
        child_port = self.server.sockets[0].getsockname()[1]
        context = self

        class ChildBrowser(proxy_route.ProxyLaunchedBrowser):
            def _start(self, profile: Path) -> subprocess.Popen:
                context.profiles.append(profile)
                (profile / browser_remote.CHROMIUM_PORT_FILE).write_text(
                    f"{port}\n/commands\n", encoding="utf-8"
                )
                process = subprocess.Popen(
                    [sys.executable, "-c", CHILD, str(child_port), str(profile)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    **({} if sys.platform == "win32" else {"start_new_session": True}),
                )
                context.children.append(process)
                return process

            def __exit__(self, *details: object) -> None:
                super().__exit__(*details)
                if context.browser_failure is not None:
                    raise context.browser_failure

        class ObservedDriver(browser_remote.ChromiumAuthDriver):
            async def start(self, profile: Path, url: str) -> None:
                await asyncio.wait_for(context.child_ready.wait(), DEADLINE)
                try:
                    await super().start(profile, url)
                finally:
                    context.peer.connection = self.connection

                context.case.assertEqual(context.peer.remote.commands, COMMANDS)
                context.case.assertEqual(len(context.children), 1)
                context.case.assertIsNone(context.children[0].poll())
                context.case.assertTrue(await asyncio.to_thread(profile.is_dir))
                context.case.assertEqual(len(context.connections), 1)
                context.case.assertFalse(context.connections[0][0].is_closing())
                context.case.assertFalse(context.connections[0][1].done())
                context.start_ready.set()

                if context.hold_start:
                    try:
                        await context.release_start.wait()
                    except asyncio.CancelledError as error:
                        context.start_cancellation = error
                        raise

                if context.start_failure is not None:
                    raise context.start_failure

            async def close(self) -> None:
                await super().close()
                if context.remote_failure is not None:
                    raise context.remote_failure

        for replacement in (
            patch.object(proxy_route, "ProxyLaunchedBrowser", ChildBrowser),
            patch.object(proxy_route, "ChromiumAuthDriver", ObservedDriver),
        ):
            replacement.start()
            self.patches.append(replacement)

        self.driver = proxy_route.ProxyBrowserDriver(
            browser_launch.LaunchPlan("chrome", Path(sys.executable), True),
            URL,
            auth=True,
            note=self.notes.append,
        )
        return self.driver

    def accept_child(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self.observe_child(reader, writer))
        self.connections.append((writer, task))

    async def observe_child(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        primary = None
        try:
            literal = await asyncio.wait_for(reader.readline(), DEADLINE)
            self.case.assertEqual(literal, b"child-ready\n")
            self.child_ready.set()
            try:
                remaining = await reader.read(1)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                remaining = b""
            self.case.assertEqual(remaining, b"")
        except BaseException as error:
            primary = error

        cleanup = ()
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), DEADLINE)
        except BaseException as error:
            cleanup = (error,)

        remote_fixtures.raise_remote_failures(primary, cleanup)

    async def entered(self) -> proxy_route.ProxyBrowserDriver:
        driver = await self.start()
        with redirect_stderr(self.diagnostics):
            entered = await asyncio.wait_for(driver.__aenter__(), DEADLINE)
        self.case.assertIs(entered, driver)
        self.case.assertTrue(self.start_ready.is_set())
        return driver

    def snapshot(self) -> tuple[bool, bool, bool]:
        self.case.assertIsNotNone(self.driver)
        self.case.assertEqual(len(self.children), 1)
        self.case.assertEqual(len(self.profiles), 1)
        remote = self.driver.remote
        self.case.assertIsNotNone(remote)
        self.case.assertIsNotNone(remote.connection)
        return (
            self.children[0].poll() is not None,
            not self.profiles[0].exists(),
            remote.connection.socket.writer.is_closing(),
        )

    async def exit(self) -> BaseException | None:
        try:
            await self.driver.__aexit__(None, None, None)
        except BaseException as error:
            return error
        return None

    async def failed_body(self, primary: BaseException) -> BaseException | None:
        try:
            async with self.driver:
                self.case.assertTrue(self.start_ready.is_set())
                raise primary
        except BaseException as error:
            if not self.start_ready.is_set():
                raise
            return error
        return None

    async def finish(self) -> None:
        if self.finished:
            return

        self.finished = True
        errors = []
        stopped = set()
        self.release_start.set()
        for writer, _ in self.connections:
            try:
                writer.close()
            except BaseException as error:
                errors.append(error)
        if self.server is not None:
            try:
                self.server.close()
            except BaseException as error:
                errors.append(error)

        for task in self.calls:
            if not task.done():
                task.cancel()
                stopped.add(task)
        for task in self.calls:
            try:
                await asyncio.wait_for(task, DEADLINE)
            except asyncio.CancelledError as error:
                if task not in stopped and task not in self.observed_cancellations:
                    errors.append(error)
            except BaseException as error:
                errors.append(error)

        if self.driver is not None and self.driver.remote is not None:
            self.peer.connection = self.driver.remote.connection
        try:
            await self.peer.finish()
        except BaseException as error:
            errors.append(error)

        for process in self.children:
            try:
                if process.poll() is None:
                    process.kill()
                await asyncio.to_thread(process.wait, timeout=DEADLINE)
            except BaseException as error:
                errors.append(error)

        for writer, task in self.connections:
            try:
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as error:
                errors.append(error)
            try:
                await asyncio.wait_for(task, DEADLINE)
            except BaseException as error:
                errors.append(error)

        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), DEADLINE)
            except BaseException as error:
                errors.append(error)

        for profile in self.profiles:
            try:
                await asyncio.to_thread(self.remove_profile, profile)
            except BaseException as error:
                errors.append(error)

        for replacement in reversed(self.patches):
            try:
                replacement.stop()
            except BaseException as error:
                errors.append(error)

        remote_fixtures.raise_remote_failures(None, tuple(errors))

    def remove_profile(self, profile: Path) -> None:
        resolved = profile.resolve()
        self.case.assertEqual(resolved.parent, Path(tempfile.gettempdir()).resolve())
        self.case.assertTrue(resolved.name.startswith("phantom-capture-profile-"))
        if profile.exists():
            shutil.rmtree(profile)


class ProxyBrowserDriverTests(unittest.IsolatedAsyncioTestCase):
    def context(self) -> BrowserContext:
        context = BrowserContext(self)
        self.addAsyncCleanup(context.finish)
        return context

    def assert_destroyed(self, snapshot: tuple[bool, bool, bool]) -> None:
        self.assertTrue(
            snapshot[0], "context left its actual child alive before backup"
        )
        self.assertTrue(snapshot[1], "context left its actual profile before backup")
        self.assertTrue(
            snapshot[2], "context left its actual remote socket before backup"
        )

    def assert_causes(
        self,
        error: BaseException | None,
        primary: BaseException | None,
        cleanup: tuple[BaseException, ...],
    ) -> None:
        if primary is None and len(cleanup) == 1 and error is cleanup[0]:
            return

        self.assertIs(getattr(error, "primary", None), primary)
        actual = getattr(error, "cleanup", ())
        self.assertEqual(len(actual), len(cleanup))
        for retained, expected in zip(actual, cleanup, strict=True):
            self.assertIs(retained, expected)

    async def test_healthy_context_releases_actual_browser_and_remote(self) -> None:
        context = self.context()
        await context.entered()
        error = await context.exit()
        snapshot = context.snapshot()
        await context.finish()

        self.assertIsNone(error)
        self.assert_destroyed(snapshot)
        self.assertEqual(context.notes, [])

    async def test_startup_failure_keeps_partial_note_and_releases_resources(
        self,
    ) -> None:
        context = self.context()
        context.start_failure = StartupFailure("controlled startup failure")
        await context.entered()
        error = await context.exit()
        snapshot = context.snapshot()
        await context.finish()

        self.assertIsNone(error)
        self.assert_destroyed(snapshot)
        self.assertEqual(context.notes, ["event:driver-failure,error:StartupFailure"])

    async def test_cancelled_entry_releases_already_acquired_browser(self) -> None:
        context = self.context()
        context.hold_start = True
        driver = await context.start()
        operation = asyncio.create_task(driver.__aenter__())
        context.calls.append(operation)
        await asyncio.wait_for(context.start_ready.wait(), DEADLINE)
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await operation
        context.observed_cancellations.add(operation)
        self.assertIs(caught.exception, context.start_cancellation)

        snapshot = context.snapshot()
        await context.finish()
        self.assert_destroyed(snapshot)
        self.assertEqual(context.notes, [])

    async def test_remote_close_failure_still_releases_actual_browser(self) -> None:
        context = self.context()
        failure = RemoteCloseFailure("controlled remote close failure")
        context.remote_failure = failure
        await context.entered()
        error = await context.exit()
        snapshot = context.snapshot()
        await context.finish()

        self.assert_destroyed(snapshot)
        self.assert_causes(error, None, (failure,))

    async def test_body_and_remote_close_failures_keep_both_original_objects(
        self,
    ) -> None:
        context = self.context()
        primary = BodyFailure("controlled body failure")
        secondary = RemoteCloseFailure("controlled remote close failure")
        context.remote_failure = secondary
        await context.start()
        error = await context.failed_body(primary)
        snapshot = context.snapshot()
        await context.finish()

        self.assert_destroyed(snapshot)
        self.assert_causes(error, primary, (secondary,))

    async def test_body_and_browser_close_failures_keep_both_original_objects(
        self,
    ) -> None:
        context = self.context()
        primary = BodyFailure("controlled body failure")
        secondary = BrowserCloseFailure("controlled browser close failure")
        context.browser_failure = secondary
        await context.start()
        error = await context.failed_body(primary)
        snapshot = context.snapshot()
        await context.finish()

        self.assert_destroyed(snapshot)
        self.assert_causes(error, primary, (secondary,))

    async def test_body_and_both_cleanup_failures_keep_ordered_original_objects(
        self,
    ) -> None:
        context = self.context()
        primary = BodyFailure("controlled body failure")
        remote = RemoteCloseFailure("controlled remote close failure")
        browser = BrowserCloseFailure("controlled browser close failure")
        context.remote_failure = remote
        context.browser_failure = browser
        await context.start()
        error = await context.failed_body(primary)
        snapshot = context.snapshot()
        await context.finish()

        self.assert_destroyed(snapshot)
        self.assert_causes(error, primary, (remote, browser))
