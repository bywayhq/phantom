import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import browser_remote
from scripts.capture.tests import test_browser_remote as fixtures

DEADLINE = 2.0
OBSERVATION = 0.1


class ReceiveFailure(ConnectionError):
    pass


class SendFailure(OSError):
    pass


class HandlerFailure(Exception):
    pass


class NavigationFailure(Exception):
    pass


class CloseFailure(Exception):
    pass


class BrowserCloseRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_uses_the_browser_protocol_without_page_instrumentation(self):
        for browser, replies, expected in (
            ("chrome", {"Browser.close": {}}, ["Browser.close"]),
            (
                "firefox",
                {"session.new": {}, "browser.close": {}},
                ["session.new", "browser.close"],
            ),
        ):
            with self.subTest(browser=browser):
                peer = CommandPeer(replies, {})
                try:
                    port = await peer.listen()

                    async def ignore(_):
                        return None

                    connection = await peer.connect(port, ignore)
                    disconnect = await browser_remote.request_browser_close(
                        connection, browser
                    )

                    self.assertIsNone(disconnect)
                    self.assertEqual(
                        [command["method"] for command in peer.remote.commands],
                        expected,
                    )
                    if browser == "firefox":
                        self.assertEqual(
                            peer.remote.commands[0]["params"], {"capabilities": {}}
                        )
                    self.assertEqual(peer.remote.commands[-1]["params"], {})
                finally:
                    await peer.finish()

    async def test_only_the_owned_clean_disconnect_can_replace_a_close_reply(self):
        clean = asyncio.IncompleteReadError(b"", 2)
        partial = asyncio.IncompleteReadError(b"\x81", 2)
        wrong_length = asyncio.IncompleteReadError(b"", 8)
        unrelated = ConnectionAbortedError("remote protocol endpoint closed")
        foreign = ConnectionError("remote protocol endpoint closed")
        for error, owned, accepted in (
            (clean, clean, True),
            (partial, partial, False),
            (wrong_length, wrong_length, False),
            (unrelated, unrelated, False),
            (foreign, ConnectionError("remote protocol endpoint closed"), False),
        ):
            with self.subTest(error=error, owned=error is owned):

                class Connection:
                    def __init__(self, outcome, failure):
                        self.outcome = outcome
                        self.failure = failure

                    async def send(self, method, params):
                        if method != "Browser.close" or params != {}:
                            raise AssertionError("unexpected close command")
                        future = asyncio.get_running_loop().create_future()
                        future.set_exception(self.outcome)
                        return future

                connection = Connection(error, owned)
                if accepted:
                    self.assertIs(
                        await browser_remote.request_browser_close(
                            connection, "chrome"
                        ),
                        error,
                    )
                else:
                    with self.assertRaises(type(error)) as raised:
                        await browser_remote.request_browser_close(connection, "chrome")
                    self.assertIs(raised.exception, error)


class CommandObservations(list):
    def __init__(self) -> None:
        super().__init__()
        self.seen: dict[str, asyncio.Event] = {}

    def append(self, command: dict) -> None:
        super().append(command)
        self.seen.setdefault(command["method"], asyncio.Event()).set()

    async def observed(self, method: str) -> None:
        await asyncio.wait_for(
            self.seen.setdefault(method, asyncio.Event()).wait(), DEADLINE
        )


async def command_seen(remote: fixtures.FakeRemote, method: str) -> None:
    await remote.commands.observed(method)


class CommandPeer:
    """Own the existing real endpoint and retain client backup authority."""

    def __init__(self, replies: dict, event: dict) -> None:
        self.remote = fixtures.FakeRemote(replies, event)
        self.remote.commands = CommandObservations()
        self.connection: browser_remote.RemoteConnection | None = None
        self.clients: list[asyncio.StreamWriter] = []
        self.original_open = asyncio.open_connection
        self.calls: list[asyncio.Task] = []
        self.observed_cancellations: set[asyncio.Task] = set()
        self.allowed: tuple[BaseException, ...] = ()
        self.finished = False

    async def listen(self) -> int:
        return await self.remote.start()

    async def record_open(self, *args, **kwargs):
        reader, writer = await self.original_open(*args, **kwargs)
        self.clients.append(writer)
        return reader, writer

    async def connect(self, port: int, handler) -> browser_remote.RemoteConnection:
        with patch.object(browser_remote.asyncio, "open_connection", self.record_open):
            socket = await asyncio.wait_for(
                browser_remote.RemoteSocket.connect(f"ws://127.0.0.1:{port}/commands"),
                DEADLINE,
            )
        self.connection = browser_remote.RemoteConnection(socket)
        self.connection.start(handler)
        return self.connection

    async def finish(self) -> None:
        if self.finished:
            return

        self.finished = True

        errors: list[BaseException] = []
        for writer in self.clients:
            try:
                writer.close()
            except BaseException as error:
                errors.append(error)

        connection = self.connection
        tasks = list(self.calls)
        if connection is not None:
            if connection.reader is not None:
                tasks.append(connection.reader)
            for future in connection.pending.values():
                if not future.done():
                    future.cancel()
                elif not future.cancelled():
                    future.exception()

            try:
                connection.socket.close()
            except BaseException as error:
                errors.append(error)

        stopped = set()
        for task in tasks:
            if not task.done():
                task.cancel()
                stopped.add(task)

        for task in tasks:
            try:
                await asyncio.wait_for(task, DEADLINE)
            except asyncio.CancelledError as error:
                if task not in stopped and task not in self.observed_cancellations:
                    errors.append(error)
            except BaseException as error:
                if not any(error is expected for expected in self.allowed):
                    errors.append(error)

        try:
            await self.remote.finish()
        except BaseException as error:
            errors.append(error)

        for writer in self.clients:
            try:
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as error:
                errors.append(error)

        unexpected = tuple(
            error
            for error in errors
            if not any(error is expected for expected in self.allowed)
        )
        fixtures.raise_remote_failures(None, unexpected)


class UpgradePeer:
    """Hold a real upgrade exchange and record all acquired resources eagerly."""

    def __init__(self, partial: bytes | None) -> None:
        self.partial = partial
        self.server: asyncio.Server | None = None
        self.connections: list[tuple[asyncio.StreamWriter, asyncio.Task]] = []
        self.clients: list[asyncio.StreamWriter] = []
        self.calls: list[asyncio.Task] = []
        self.request: bytes | None = None
        self.read_outcome: bytes | OSError | None = None
        self.request_seen = asyncio.Event()
        self.allowed: tuple[BaseException, ...] = ()
        self.finished = False

    def accept(self, reader, writer) -> None:
        task = asyncio.create_task(self.serve(reader, writer))
        self.connections.append((writer, task))

    async def serve(self, reader, writer) -> None:
        primary = None
        try:
            self.request = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), DEADLINE
            )
            self.request_seen.set()

            if self.partial is not None:
                writer.write(self.partial)
                await writer.drain()
                writer.write_eof()

            try:
                self.read_outcome = await reader.read(1)
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ) as error:
                # These are the peer-disconnect categories allowed on Windows.
                self.read_outcome = error
        except BaseException as error:
            primary = error

        cleanup = ()
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), DEADLINE)
        except BaseException as error:
            cleanup = (error,)

        fixtures.raise_remote_failures(primary, cleanup)

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def finish(self) -> None:
        if self.finished:
            return

        self.finished = True

        errors: list[BaseException] = []
        if self.server is not None:
            try:
                self.server.close()
            except BaseException as error:
                errors.append(error)

        for writer in self.clients + [writer for writer, _ in self.connections]:
            try:
                writer.close()
            except BaseException as error:
                errors.append(error)

        stopped = set()
        tasks = self.calls + [task for _, task in self.connections]
        for task in tasks:
            if not task.done():
                task.cancel()
                stopped.add(task)

        for task in tasks:
            try:
                await asyncio.wait_for(task, DEADLINE)
            except asyncio.CancelledError as error:
                if task not in stopped:
                    errors.append(error)
            except BaseException as error:
                if not any(error is expected for expected in self.allowed):
                    errors.append(error)

        for writer in self.clients + [writer for writer, _ in self.connections]:
            try:
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as error:
                errors.append(error)

        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), DEADLINE)
            except BaseException as error:
                errors.append(error)

        fixtures.raise_remote_failures(None, tuple(errors))


async def ignore_event(_event: dict) -> None:
    return None


class RemoteClientLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def command_peer(self, handler=ignore_event, event=None):
        peer = CommandPeer(
            {"Probe.ready": {"ready": "literal"}, "Page.navigate": {}}, event or {}
        )
        self.addAsyncCleanup(peer.finish)
        port = await peer.listen()
        connection = await peer.connect(port, handler)
        result = await asyncio.wait_for(connection.call("Probe.ready", {}), DEADLINE)
        self.assertEqual(result, {"ready": "literal"})
        self.assertEqual(
            peer.remote.commands, [{"id": 1, "method": "Probe.ready", "params": {}}]
        )

        return peer, connection

    async def pending_commands(self, peer, connection):
        first = await connection.send("Pending.first", {"position": 1})
        second = await connection.send("Pending.second", {"position": 2})
        await command_seen(peer.remote, "Pending.second")
        self.assertEqual(
            peer.remote.commands[1:],
            [
                {"id": 2, "method": "Pending.first", "params": {"position": 1}},
                {"id": 3, "method": "Pending.second", "params": {"position": 2}},
            ],
        )
        self.assertFalse(first.done())
        self.assertFalse(second.done())

        return first, second

    async def test_healthy_dispatch_and_close_preserve_real_replies(self) -> None:
        peer, connection = await self.command_peer()
        reply = await asyncio.wait_for(connection.call("Probe.ready", {}), DEADLINE)
        self.assertEqual(reply, {"ready": "literal"})

        await asyncio.wait_for(connection.close(), DEADLINE)
        peer.observed_cancellations.add(connection.reader)
        closed_before_backup = connection.socket.writer.is_closing()
        reader_done_before_backup = connection.reader.done()
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        self.assertTrue(closed_before_backup)
        self.assertTrue(reader_done_before_backup)
        self.assertEqual(pending_before_backup, {})

    async def test_incomplete_upgrade_closes_the_acquired_writer(self) -> None:
        await self.upgrade_exit(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade:")

    async def test_cancelled_upgrade_closes_the_acquired_writer(self) -> None:
        await self.upgrade_exit(None)

    async def test_silent_upgrade_deadline_retains_timeout_and_close_failure(
        self,
    ) -> None:
        for failure in (None, CloseFailure("controlled upgrade close failure")):
            with self.subTest(cleanup_failure=failure):
                await self.setup_deadline_exit("read", failure)

    async def test_stalled_upgrade_drain_is_bounded(self) -> None:
        await self.setup_deadline_exit("drain", None)

    async def test_cancelled_upgrade_retains_original_cancellation_and_close_failure(
        self,
    ) -> None:
        await self.setup_deadline_exit(
            "cancel", CloseFailure("controlled cancelled upgrade close failure")
        )

    async def setup_deadline_exit(
        self, phase: str, cleanup_failure: CloseFailure | None
    ) -> None:
        peer = UpgradePeer(None)
        self.addAsyncCleanup(peer.finish)
        port = await peer.start()
        original_open = asyncio.open_connection
        drain_entered = asyncio.Event()
        release_drain = asyncio.Event()
        original_causes = []
        drain_patches = []

        async def observe_setup():
            try:
                return await browser_remote.RemoteSocket.connect(
                    f"ws://127.0.0.1:{port}/setup-deadline"
                )
            except BaseException as actual:
                # Observe the caller's error before Task transforms cancellation.
                return actual

        async def record_open(*args, **kwargs):
            reader, writer = await original_open(*args, **kwargs)
            peer.clients.append(writer)
            if phase == "drain":
                original_drain = writer.drain

                async def held_drain():
                    await original_drain()
                    drain_entered.set()
                    await release_drain.wait()

                drain_patch = patch.object(writer, "drain", held_drain)
                drain_patch.start()
                drain_patches.append(drain_patch)

            return reader, writer

        error = None
        try:
            with (
                patch.object(browser_remote.asyncio, "open_connection", record_open),
                patch.object(browser_remote, "REMOTE_SETUP_TIMEOUT", 0.5),
            ):
                task = asyncio.create_task(observe_setup())
                peer.calls.append(task)
                await asyncio.wait_for(peer.request_seen.wait(), DEADLINE)
                self.assertEqual(len(peer.clients), 1)
                self.assertEqual(len(peer.connections), 1)
                self.assertTrue(
                    peer.request.startswith(b"GET /setup-deadline HTTP/1.1\r\n")
                )
                self.assertIn(b"\r\nSec-WebSocket-Version: 13\r\n", peer.request)
                if phase == "drain":
                    await asyncio.wait_for(drain_entered.wait(), DEADLINE)

                writer = peer.clients[0]
                original_close = writer.close

                def observed_close():
                    # Observe the actual initiating exception before injecting cleanup.
                    original_causes.append(sys.exc_info()[1])
                    original_close()
                    if cleanup_failure is not None:
                        raise cleanup_failure

                with patch.object(writer, "close", observed_close):
                    self.assertFalse(task.done())
                    if phase == "cancel":
                        task.cancel("controlled setup cancellation")

                    done, _ = await asyncio.wait([task], timeout=DEADLINE)
                    self.assertIn(task, done, "remote setup did not reach its deadline")
                    error = task.result()

            self.assertEqual(len(original_causes), 1)
            primary = original_causes[0]
            if phase == "cancel":
                self.assertIsInstance(primary, asyncio.CancelledError)
                self.assertIs(error, primary)
                self.assertEqual(error.args, ("controlled setup cancellation",))
                peer.calls.remove(task)
                combined = error.__cause__
            else:
                self.assertIsInstance(primary, asyncio.TimeoutError)
                self.assertIsInstance(primary.__cause__, asyncio.CancelledError)
                peer.allowed = (error,)
                combined = error

            if cleanup_failure is None:
                self.assertIs(error, primary)
            else:
                self.assertIsInstance(combined, browser_remote.RemoteFailures)
                self.assertIs(combined.primary, primary)
                self.assertEqual(combined.cleanup, (cleanup_failure,))

            closed_before_backup = writer.is_closing()
            worker = peer.connections[0][1]
            done, _ = await asyncio.wait([worker], timeout=DEADLINE)
            completed_before_backup = worker in done
            read_outcome_before_backup = peer.read_outcome
            if completed_before_backup:
                worker.result()
        finally:
            for drain_patch in reversed(drain_patches):
                drain_patch.stop()

        await peer.finish()
        self.assertTrue(closed_before_backup)
        self.assertTrue(completed_before_backup, "setup failure retained its real peer")
        self.assertTrue(
            read_outcome_before_backup == b""
            or isinstance(
                read_outcome_before_backup,
                (ConnectionResetError, ConnectionAbortedError, BrokenPipeError),
            )
        )

    async def upgrade_exit(self, partial: bytes | None) -> None:
        peer = UpgradePeer(partial)
        self.addAsyncCleanup(peer.finish)
        port = await peer.start()
        original_open = asyncio.open_connection

        async def record_open(*args, **kwargs):
            reader, writer = await original_open(*args, **kwargs)
            peer.clients.append(writer)
            return reader, writer

        with patch.object(browser_remote.asyncio, "open_connection", record_open):
            task = asyncio.create_task(
                browser_remote.RemoteSocket.connect(f"ws://127.0.0.1:{port}/upgrade")
            )
            peer.calls.append(task)
            await asyncio.wait_for(peer.request_seen.wait(), DEADLINE)
            self.assertTrue(peer.request.startswith(b"GET /upgrade HTTP/1.1\r\n"))
            self.assertIn(b"\r\nUpgrade: websocket\r\n", peer.request)
            self.assertIn(b"\r\nSec-WebSocket-Version: 13\r\n", peer.request)
            self.assertEqual(len(peer.clients), 1)
            self.assertEqual(len(peer.connections), 1)

            if partial is None:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, DEADLINE)
                peer.calls.remove(task)
            else:
                with self.assertRaises(asyncio.IncompleteReadError) as caught:
                    await asyncio.wait_for(task, DEADLINE)
                self.assertEqual(caught.exception.partial, partial)
                peer.allowed = (caught.exception,)

        closed_before_backup = peer.clients[0].is_closing()
        worker = peer.connections[0][1]
        done, _ = await asyncio.wait([worker], timeout=OBSERVATION)
        completed_before_backup = worker in done
        read_outcome_before_backup = peer.read_outcome
        await peer.finish()

        self.assertTrue(
            closed_before_backup, "failed upgrade retained its actual acquired writer"
        )
        self.assertTrue(
            completed_before_backup, "failed upgrade left its accepted peer open"
        )
        self.assertTrue(
            read_outcome_before_backup == b""
            or isinstance(
                read_outcome_before_backup,
                (ConnectionResetError, ConnectionAbortedError, BrokenPipeError),
            )
        )

    async def test_receive_failure_retains_both_pending_command_causes(self) -> None:
        peer, connection = await self.command_peer()
        futures = await self.pending_commands(peer, connection)
        failure = ReceiveFailure("controlled receive failure")
        peer.allowed = (failure,)
        connection.socket.reader.set_exception(failure)
        done, _ = await asyncio.wait(futures, timeout=DEADLINE)
        self.assertEqual(len(done), 2)
        errors = [future.exception() for future in futures]
        self.assertIs(connection.failure, failure)
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        for error in errors:
            self.assertIsInstance(error, BaseException)
            self.assertTrue(
                error is failure or error.__cause__ is failure,
                "pending command lost its original typed receive cause",
            )
        self.assertEqual(pending_before_backup, {})

    async def test_handler_failure_settles_both_pending_commands(self) -> None:
        failure = HandlerFailure("controlled handler failure")

        async def failed_handler(event):
            self.assertEqual(event, {"method": "Probe.fail", "params": {"literal": 7}})
            raise failure

        peer, connection = await self.command_peer(
            failed_handler, {"method": "Probe.fail", "params": {"literal": 7}}
        )
        peer.allowed = (failure,)
        futures = await self.pending_commands(peer, connection)
        navigation = await connection.send("Page.navigate", {"url": "http://literal/"})
        self.assertEqual(await asyncio.wait_for(navigation, DEADLINE), {})
        done, _ = await asyncio.wait([connection.reader], timeout=DEADLINE)
        self.assertIn(connection.reader, done)
        self.assertTrue(
            connection.reader.exception() is failure or connection.failure is failure
        )
        done, _ = await asyncio.wait(futures, timeout=OBSERVATION)
        completed_before_backup = len(done)
        errors = [future.exception() if future in done else None for future in futures]
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        self.assertEqual(
            completed_before_backup, 2, "handler failure left actual commands unsettled"
        )
        for error in errors:
            self.assertIsInstance(error, BaseException)
            self.assertTrue(error is failure or error.__cause__ is failure)
        self.assertEqual(pending_before_backup, {})

    async def test_completed_reader_failure_does_not_skip_socket_close(self) -> None:
        failure = HandlerFailure("controlled completed reader failure")
        invoked = asyncio.Event()
        original_read_loop = browser_remote.RemoteConnection.read_loop

        async def failed_handler(event):
            self.assertEqual(event, {"method": "Probe.close", "params": {}})
            invoked.set()
            raise failure

        async def completed_failure(connection):
            await original_read_loop(connection)
            if invoked.is_set():
                # Preserve the failed-reader precondition if dispatch handles the fault.
                raise failure

        with patch.object(
            browser_remote.RemoteConnection, "read_loop", completed_failure
        ):
            peer, connection = await self.command_peer(
                failed_handler, {"method": "Probe.close", "params": {}}
            )
            peer.allowed = (failure,)
            reply = await connection.send("Page.navigate", {"url": "http://literal/"})
            self.assertEqual(await asyncio.wait_for(reply, DEADLINE), {})
            done, _ = await asyncio.wait([connection.reader], timeout=DEADLINE)
        self.assertTrue(invoked.is_set())
        self.assertIn(connection.reader, done)
        self.assertIs(connection.reader.exception(), failure)

        error = None
        try:
            await asyncio.wait_for(connection.close(), DEADLINE)
        except BaseException as actual:
            error = actual
        closed_before_backup = connection.socket.writer.is_closing()
        await peer.finish()

        self.assertIsInstance(error, BaseException)
        self.assertTrue(error is failure or error.__cause__ is failure)
        self.assertTrue(
            closed_before_backup, "failed reader prevented actual socket shutdown"
        )

    async def test_failed_send_removes_its_actual_registered_command(self) -> None:
        peer, connection = await self.command_peer()
        failure = SendFailure("controlled send failure")
        original_send = connection.socket.send

        async def failed_send(text):
            await original_send(text)
            await command_seen(peer.remote, "Pending.send")
            raise failure

        error = None
        with patch.object(connection.socket, "send", failed_send):
            try:
                await connection.send("Pending.send", {"literal": 11})
            except BaseException as actual:
                error = actual
        self.assertIs(error, failure)
        self.assertEqual(
            peer.remote.commands[-1],
            {"id": 2, "method": "Pending.send", "params": {"literal": 11}},
        )
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        self.assertEqual(
            pending_before_backup, {}, "failed send left its actual command registered"
        )

    async def test_actual_call_timeout_removes_its_registered_command(self) -> None:
        peer, connection = await self.command_peer()
        task = asyncio.create_task(connection.call("Pending.timeout", {"literal": 13}))
        peer.calls.append(task)
        await command_seen(peer.remote, "Pending.timeout")
        with self.assertRaises(asyncio.TimeoutError) as caught:
            await asyncio.wait_for(asyncio.shield(task), 20.0)
        peer.allowed = (caught.exception,)
        self.assertTrue(task.done())
        self.assertEqual(
            peer.remote.commands[-1],
            {"id": 2, "method": "Pending.timeout", "params": {"literal": 13}},
        )
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        self.assertEqual(
            pending_before_backup,
            {},
            "actual fifteen-second call left its registration",
        )

    async def test_cancelled_call_removes_its_registered_command(self) -> None:
        peer, connection = await self.command_peer()
        task = asyncio.create_task(connection.call("Pending.cancel", {"literal": 17}))
        peer.calls.append(task)
        await command_seen(peer.remote, "Pending.cancel")
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, DEADLINE)
        peer.calls.remove(task)
        self.assertEqual(
            peer.remote.commands[-1],
            {"id": 2, "method": "Pending.cancel", "params": {"literal": 17}},
        )
        pending_before_backup = dict(connection.pending)
        await peer.finish()

        self.assertEqual(
            pending_before_backup, {}, "cancelled call left its registration"
        )

    async def test_navigation_retains_primary_and_close_failures(self) -> None:
        peer = CommandPeer(
            {
                "Target.getTargets": {
                    "targetInfos": [{"type": "page", "targetId": "p1"}]
                },
                "Target.attachToTarget": {"sessionId": "s1"},
                "Page.navigate": {"frameId": "f1"},
            },
            {"method": "Page.frameNavigated", "params": {}},
        )
        self.addAsyncCleanup(peer.finish)
        port = await peer.listen()
        primary = NavigationFailure("controlled navigation failure")
        secondary = CloseFailure("controlled close failure")
        original_call = browser_remote.RemoteConnection.call
        original_close = browser_remote.RemoteConnection.close

        async def failed_call(connection, method, params, session_id=None):
            peer.connection = connection
            result = await original_call(connection, method, params, session_id)
            if method == "Page.navigate":
                self.assertEqual(result, {"frameId": "f1"})
                raise primary

            return result

        async def failed_close(connection):
            await original_close(connection)
            peer.observed_cancellations.add(connection.reader)
            raise secondary

        error = None
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / browser_remote.CHROMIUM_PORT_FILE).write_text(
                f"{port}\n/devtools/browser/literal\n"
            )
            with (
                patch.object(
                    browser_remote.asyncio, "open_connection", peer.record_open
                ),
                patch.object(browser_remote.RemoteConnection, "call", failed_call),
                patch.object(browser_remote.RemoteConnection, "close", failed_close),
            ):
                try:
                    await asyncio.wait_for(
                        browser_remote.navigate_page(
                            profile, "http://literal/page", 0.0
                        ),
                        DEADLINE,
                    )
                except BaseException as actual:
                    error = actual

        self.assertEqual(
            peer.remote.commands,
            [
                {"id": 1, "method": "Target.getTargets", "params": {}},
                {
                    "id": 2,
                    "method": "Target.attachToTarget",
                    "params": {"targetId": "p1", "flatten": True},
                },
                {
                    "id": 3,
                    "method": "Page.navigate",
                    "params": {"url": "http://literal/page"},
                    "sessionId": "s1",
                },
            ],
        )
        await peer.finish()

        self.assertIs(
            getattr(error, "primary", error),
            primary,
            "navigation cleanup replaced its actual initiating failure",
        )
        cleanup = getattr(error, "cleanup", ())
        self.assertTrue(secondary in cleanup or error.__cause__ is secondary)


class CredentialRepresentationTests(unittest.TestCase):
    def test_credentials_repr_omits_literal_secret_canaries(self) -> None:
        credentials = browser_remote.Credentials(
            "username-canary-41", "password-canary-43"
        )
        self.assertEqual(credentials.username, "username-canary-41")
        self.assertEqual(credentials.password, "password-canary-43")

        representation = repr(credentials)
        self.assertNotIn("password-canary-43", representation)
        self.assertNotIn("username-canary-41", representation)


if __name__ == "__main__":
    unittest.main()
