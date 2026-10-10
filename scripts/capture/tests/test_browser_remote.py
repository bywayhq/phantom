import asyncio
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.capture.browser_remote import (
    CHROMIUM_PORT_FILE,
    FIREFOX_PORT_FILE,
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
    WEBSOCKET_GUID,
    ChromiumAuthDriver,
    Credentials,
    FirefoxAuthDriver,
    RemoteSocket,
    bidi_note,
    bidi_reply,
    cdp_note,
    cdp_reply,
    chromium_endpoint,
    encode_frame,
    firefox_endpoint,
    navigate_page,
    read_frame,
)

CREDENTIALS = Credentials("phantom-user", "phantom-pass")
TIMEOUT = 10.0


def server_frame(opcode: int, payload: bytes) -> bytes:
    """An unmasked server frame, as RFC 6455 section 5.1 requires."""
    length = len(payload)
    if length < 126:
        head = bytes([0x80 | opcode, length])
    else:
        head = bytes([0x80 | opcode, 126]) + length.to_bytes(2, "big")
    return head + payload


def reader_with(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class FrameTests(unittest.TestCase):
    def test_client_frames_are_masked_and_round_trip(self) -> None:
        async def exercise(payload: bytes) -> tuple[bool, int, bytes]:
            frame = encode_frame(OPCODE_TEXT, payload, b"\x01\x02\x03\x04")
            self.assertTrue(frame[1] & 0x80)
            self.assertNotIn(payload, frame)
            return await read_frame(reader_with(frame))

        for size in (5, 300, 70000):
            payload = b"x" * size
            self.assertEqual(asyncio.run(exercise(payload)), (True, 1, payload))

    def test_mask_must_be_four_bytes(self) -> None:
        with self.assertRaises(ValueError):
            encode_frame(OPCODE_TEXT, b"x", b"\x00")

    def test_fragmented_message_is_joined_and_pings_are_answered(self) -> None:
        async def exercise() -> tuple[str, bytes]:
            data = (
                bytes([OPCODE_TEXT, 3])
                + b"abc"
                + server_frame(OPCODE_PING, b"p")
                + bytes([0x80, 3])
                + b"def"
            )
            sent = bytearray()

            class Writer:
                def write(self, chunk: bytes) -> None:
                    sent.extend(chunk)

                async def drain(self) -> None:
                    return None

            socket = RemoteSocket(reader_with(data), Writer())  # type: ignore[arg-type]
            return await socket.receive(), bytes(sent)

        text, sent = asyncio.run(exercise())
        self.assertEqual(text, "abcdef")
        self.assertEqual(sent[0], 0x80 | OPCODE_PONG)

    def test_close_frame_ends_the_connection(self) -> None:
        async def exercise() -> None:
            socket = RemoteSocket(
                reader_with(server_frame(OPCODE_CLOSE, b"")),
                None,  # type: ignore[arg-type]
            )
            await socket.receive()

        with self.assertRaises(ConnectionError):
            asyncio.run(exercise())

    def test_connect_refuses_a_non_loopback_endpoint(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(RemoteSocket.connect("ws://192.0.2.1:9/devtools"))


class CdpMessageTests(unittest.TestCase):
    def test_paused_requests_continue_unchanged(self) -> None:
        event = {"method": "Fetch.requestPaused", "params": {"requestId": "7"}}
        self.assertEqual(
            cdp_reply(event, CREDENTIALS), ("Fetch.continueRequest", {"requestId": "7"})
        )
        self.assertIsNone(cdp_note(event))

    def test_proxy_challenge_gets_credentials(self) -> None:
        event = {
            "method": "Fetch.authRequired",
            "params": {
                "requestId": "9",
                "request": {"url": "http://origin.phantom.test:1/page?run=secret"},
                "authChallenge": {
                    "source": "Proxy",
                    "scheme": "basic",
                    "realm": "phantom-capture",
                },
            },
        }
        method, params = cdp_reply(event, CREDENTIALS)
        self.assertEqual(method, "Fetch.continueWithAuth")
        self.assertEqual(
            params["authChallengeResponse"],
            {
                "response": "ProvideCredentials",
                "username": "phantom-user",
                "password": "phantom-pass",
            },
        )
        note = cdp_note(event)
        self.assertEqual(
            note,
            "event:Fetch.authRequired,source:Proxy,scheme:basic,"
            "realm:phantom-capture,path:/page,answer:ProvideCredentials",
        )
        self.assertNotIn("secret", note)
        self.assertNotIn("phantom-pass", note)

    def test_server_challenge_is_cancelled(self) -> None:
        event = {
            "method": "Fetch.authRequired",
            "params": {"requestId": "9", "authChallenge": {"source": "Server"}},
        }
        _, params = cdp_reply(event, CREDENTIALS)
        self.assertEqual(params["authChallengeResponse"], {"response": "CancelAuth"})

    def test_other_events_get_no_reply(self) -> None:
        self.assertIsNone(cdp_reply({"method": "Page.loadEventFired"}, CREDENTIALS))


class BidiMessageTests(unittest.TestCase):
    def event(self, status: int, blocked: bool = True) -> dict:
        return {
            "type": "event",
            "method": "network.authRequired",
            "params": {
                "isBlocked": blocked,
                "request": {"request": "r1", "url": "http://x/page?run=secret"},
                "response": {
                    "status": status,
                    "authChallenges": [{"scheme": "Basic", "realm": "phantom-capture"}],
                },
            },
        }

    def test_proxy_challenge_gets_credentials(self) -> None:
        method, params = bidi_reply(self.event(407), CREDENTIALS)
        self.assertEqual(method, "network.continueWithAuth")
        self.assertEqual(params["request"], "r1")
        self.assertEqual(params["action"], "provideCredentials")
        self.assertEqual(
            params["credentials"],
            {
                "type": "password",
                "username": "phantom-user",
                "password": "phantom-pass",
            },
        )
        self.assertEqual(
            bidi_note(self.event(407)),
            "event:network.authRequired,status:407,scheme:Basic,"
            "realm:phantom-capture,path:/page,answer:provideCredentials",
        )

    def test_origin_challenge_is_cancelled(self) -> None:
        _, params = bidi_reply(self.event(401), CREDENTIALS)
        self.assertEqual(params, {"request": "r1", "action": "cancel"})

    def test_unblocked_event_gets_no_reply(self) -> None:
        self.assertIsNone(bidi_reply(self.event(407, blocked=False), CREDENTIALS))
        self.assertTrue(
            bidi_note(self.event(407, blocked=False)).endswith("answer:none")
        )


class EndpointTests(unittest.TestCase):
    def test_chromium_port_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            self.assertIsNone(chromium_endpoint(profile))
            (profile / CHROMIUM_PORT_FILE).write_text("9222\n/devtools/browser/abc\n")
            self.assertEqual(
                chromium_endpoint(profile), "ws://127.0.0.1:9222/devtools/browser/abc"
            )

    def test_firefox_port_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            self.assertIsNone(firefox_endpoint(profile))
            (profile / FIREFOX_PORT_FILE).write_text(
                json.dumps({"ws_host": "127.0.0.1", "ws_port": 4444})
            )
            self.assertEqual(firefox_endpoint(profile), "ws://127.0.0.1:4444/session")
            (profile / FIREFOX_PORT_FILE).write_text(
                json.dumps({"ws_host": "192.0.2.1", "ws_port": 4444})
            )
            self.assertIsNone(firefox_endpoint(profile))


class RemoteFailures(Exception):
    def __init__(
        self, primary: BaseException | None, cleanup: tuple[BaseException, ...]
    ) -> None:
        super().__init__("remote fixture cleanup failed")
        self.primary = primary
        self.cleanup = cleanup


class PeerProbe:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.ready = asyncio.Event()
        self.release = asyncio.Event()
        self.failure = failure


class PrimaryFailure(Exception):
    pass


class PeerFailure(Exception):
    pass


class CallerProbe:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure
        self.remote: FakeRemote | None = None
        self.driver: ChromiumAuthDriver | FirefoxAuthDriver | None = None


class FakeRemote:
    """A loopback WebSocket endpoint scripted with one reply per command."""

    def __init__(
        self, replies: dict, event: dict, probe: PeerProbe | None = None
    ) -> None:
        self.replies = replies
        self.event = event
        self.commands: list[dict] = []
        self.answered = asyncio.Event()
        self.server: asyncio.Server | None = None
        self.probe = probe
        self.connections: list[tuple[asyncio.StreamWriter, asyncio.Task[None]]] = []

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Record accepted resources before the handler can suspend.
        task = asyncio.create_task(self.serve(reader, writer))
        self.connections.append((writer, task))

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        key = next(
            line.split(b":", 1)[1].strip()
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key:")
        )
        accept = base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID).digest())
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        try:
            while True:
                _, _, payload = await read_frame(reader)
                command = json.loads(payload)
                self.commands.append(command)
                method = command["method"]
                if method in self.replies:
                    reply = {"id": command["id"], "result": self.replies[method]}
                    writer.write(server_frame(OPCODE_TEXT, json.dumps(reply).encode()))
                if method in {"Page.navigate", "browsingContext.navigate"}:
                    writer.write(
                        server_frame(OPCODE_TEXT, json.dumps(self.event).encode())
                    )
                if method in {"Fetch.continueWithAuth", "network.continueWithAuth"}:
                    self.answered.set()
                await writer.drain()

                if self.probe is not None and method == "Probe.ready":
                    self.probe.ready.set()
                    await self.probe.release.wait()
                    if self.probe.failure is not None:
                        raise self.probe.failure
        except asyncio.IncompleteReadError:
            writer.close()

    async def close(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()

    async def finish(self, primary: BaseException | None = None) -> None:
        await self.close()
        if primary is not None:
            raise primary


class DriverTests(unittest.TestCase):
    def test_chromium_driver_attaches_then_answers_on_the_page_session(self) -> None:
        commands, notes = asyncio.run(self.chromium_exchange())
        self.assertEqual(
            [(item["method"], item.get("sessionId")) for item in commands],
            [
                ("Target.getTargets", None),
                ("Target.attachToTarget", None),
                ("Fetch.enable", "s1"),
                ("Page.navigate", "s1"),
                ("Fetch.continueWithAuth", "s1"),
            ],
        )
        self.assertEqual(commands[1]["params"], {"targetId": "p1", "flatten": True})
        self.assertEqual(
            commands[2]["params"],
            {"handleAuthRequests": True, "patterns": [{"urlPattern": "*"}]},
        )
        self.assertEqual(len(notes), 1)

    def test_navigate_page_attaches_to_the_first_page_then_navigates(self) -> None:
        commands = asyncio.run(self.navigation_exchange())
        self.assertEqual(
            [(item["method"], item.get("sessionId")) for item in commands],
            [
                ("Target.getTargets", None),
                ("Target.attachToTarget", None),
                ("Page.navigate", "s1"),
            ],
        )
        self.assertEqual(
            commands[2]["params"], {"url": "https://server.phantom.test:9/"}
        )

    def test_firefox_driver_intercepts_before_navigating(self) -> None:
        commands = asyncio.run(self.firefox_exchange())
        self.assertEqual(
            [item["method"] for item in commands],
            [
                "session.new",
                "session.subscribe",
                "network.addIntercept",
                "browsingContext.getTree",
                "browsingContext.navigate",
                "network.continueWithAuth",
            ],
        )
        self.assertEqual(commands[2]["params"], {"phases": ["authRequired"]})
        self.assertEqual(commands[4]["params"]["context"], "c1")
        self.assertEqual(commands[5]["params"]["action"], "provideCredentials")

    async def chromium_exchange(
        self, probe: CallerProbe | None = None
    ) -> tuple[list[dict], list[str]]:
        remote = FakeRemote(
            {
                "Target.getTargets": {
                    "targetInfos": [
                        {"type": "browser", "targetId": "b"},
                        {"type": "page", "targetId": "p1"},
                    ]
                },
                "Target.attachToTarget": {"sessionId": "s1"},
                "Fetch.enable": {},
                "Page.navigate": {"frameId": "f"},
            },
            {
                "method": "Fetch.authRequired",
                "sessionId": "s1",
                "params": {
                    "requestId": "r",
                    "request": {"url": "http://x/page"},
                    "authChallenge": {
                        "source": "Proxy",
                        "scheme": "basic",
                        "realm": "phantom-capture",
                    },
                },
            },
        )
        if probe is not None:
            probe.remote = remote

        port = await remote.start()
        notes: list[str] = []
        driver = ChromiumAuthDriver(CREDENTIALS, notes.append)
        if probe is not None:
            probe.driver = driver

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / CHROMIUM_PORT_FILE).write_text(f"{port}\n/devtools/browser/x\n")
            await driver.start(profile, "http://x/page")
            await asyncio.wait_for(remote.answered.wait(), TIMEOUT)

            if probe is not None:
                raise probe.failure

        await driver.close()
        await remote.close()
        return remote.commands, notes

    async def navigation_exchange(self, probe: CallerProbe | None = None) -> list[dict]:
        remote = FakeRemote(
            {
                "Target.getTargets": {
                    "targetInfos": [
                        {"type": "browser", "targetId": "b"},
                        {"type": "page", "targetId": "p1"},
                    ]
                },
                "Target.attachToTarget": {"sessionId": "s1"},
                "Page.navigate": {"frameId": "f"},
            },
            {"method": "Page.frameNavigated", "params": {}},
        )
        if probe is not None:
            probe.remote = remote

        port = await remote.start()
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / CHROMIUM_PORT_FILE).write_text(f"{port}\n/devtools/browser/x\n")
            await asyncio.wait_for(
                navigate_page(profile, "https://server.phantom.test:9/", 0.0),
                TIMEOUT,
            )

            if probe is not None:
                raise probe.failure

        await remote.close()
        return remote.commands

    async def firefox_exchange(self, probe: CallerProbe | None = None) -> list[dict]:
        remote = FakeRemote(
            {
                "session.new": {"sessionId": "x", "capabilities": {}},
                "session.subscribe": {},
                "network.addIntercept": {"intercept": "i"},
                "browsingContext.getTree": {"contexts": [{"context": "c1"}]},
                "browsingContext.navigate": {},
            },
            {
                "type": "event",
                "method": "network.authRequired",
                "params": {
                    "isBlocked": True,
                    "request": {"request": "r", "url": "http://x/page"},
                    "response": {"status": 407, "authChallenges": []},
                },
            },
        )
        if probe is not None:
            probe.remote = remote

        port = await remote.start()
        driver = FirefoxAuthDriver(CREDENTIALS, lambda _: None)
        if probe is not None:
            probe.driver = driver

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / FIREFOX_PORT_FILE).write_text(
                json.dumps({"ws_host": "127.0.0.1", "ws_port": port})
            )
            await driver.start(profile, "http://x/page")
            await asyncio.wait_for(remote.answered.wait(), TIMEOUT)

            if probe is not None:
                raise probe.failure

        await driver.close()
        await remote.close()
        return remote.commands


async def remote_backup(
    remote: FakeRemote,
    driver: ChromiumAuthDriver | FirefoxAuthDriver | None = None,
    socket: RemoteSocket | None = None,
) -> tuple[BaseException, ...]:
    errors: list[BaseException] = []
    if driver is not None:
        try:
            await asyncio.wait_for(driver.close(), TIMEOUT)
        except BaseException as error:
            errors.append(error)

    if remote.server is not None:
        remote.server.close()
        try:
            await asyncio.wait_for(remote.server.wait_closed(), TIMEOUT)
        except BaseException as error:
            errors.append(error)

    writers = [writer for writer, _ in remote.connections]
    if socket is not None:
        socket.close()
        writers.append(socket.writer)
    for writer in writers:
        writer.close()
    for _, task in remote.connections:
        task.cancel()

    for writer in writers:
        try:
            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
        except BaseException as error:
            errors.append(error)

    for _, task in remote.connections:
        try:
            await asyncio.wait_for(task, TIMEOUT)
        except asyncio.CancelledError:
            # This backup deliberately cancels only the actual retained handler.
            pass
        except BaseException as error:
            errors.append(error)
    return tuple(errors)


class RemoteLifecycleTests(unittest.TestCase):
    async def ready_peer(
        self, probe: PeerProbe
    ) -> tuple[FakeRemote, RemoteSocket, asyncio.Task[None]]:
        remote = FakeRemote({"Probe.ready": {}}, {}, probe)
        socket = None
        try:
            port = await remote.start()
            socket = await RemoteSocket.connect(f"ws://127.0.0.1:{port}/control")
            await socket.send(
                json.dumps({"id": 1, "method": "Probe.ready", "params": {}})
            )
            reply = await socket.receive()
            self.assertEqual(json.loads(reply), {"id": 1, "result": {}})
            await asyncio.wait_for(probe.ready.wait(), TIMEOUT)
            self.assertEqual(len(remote.connections), 1)
            return remote, socket, remote.connections[0][1]
        except BaseException as primary:
            errors = await remote_backup(remote, socket=socket)
            if errors:
                raise RemoteFailures(primary, errors) from primary
            raise

    def test_fixture_close_finishes_its_exchanged_handler_and_writer(self) -> None:
        async def exercise() -> None:
            probe = PeerProbe()
            remote, socket, task = await self.ready_peer(probe)
            try:
                await asyncio.wait_for(remote.close(), TIMEOUT)
                done, _ = await asyncio.wait([task], timeout=0.1)
                finished_before_backup = task in done
                writer_closed_before_backup = remote.connections[0][0].is_closing()
            except BaseException as primary:
                errors = await remote_backup(remote, socket=socket)
                if errors:
                    raise RemoteFailures(primary, errors) from primary
                raise
            errors = await remote_backup(remote, socket=socket)
            self.assertEqual(errors, ())

            self.assertTrue(
                finished_before_backup,
                "remote close left its exchanged handler running",
            )
            self.assertTrue(
                writer_closed_before_backup,
                "remote close left its accepted writer open",
            )

        asyncio.run(asyncio.wait_for(exercise(), TIMEOUT * 3))

    async def completed_peer(self, primary: BaseException | None) -> None:
        secondary = PeerFailure("controlled remote peer failure")
        probe = PeerProbe(secondary)
        remote, socket, task = await self.ready_peer(probe)
        error = None
        try:
            probe.release.set()
            done, _ = await asyncio.wait([task], timeout=TIMEOUT)
            self.assertIn(task, done)
            self.assertIs(task.exception(), secondary)
            try:
                await asyncio.wait_for(remote.finish(primary), TIMEOUT)
            except BaseException as actual:
                error = actual
        except BaseException as primary:
            errors = await remote_backup(remote, socket=socket)
            if errors:
                raise RemoteFailures(primary, errors) from primary
            raise
        errors = await remote_backup(remote, socket=socket)
        self.assertTrue(
            not errors or (len(errors) == 1 and errors[0] is secondary),
            "backup reported an unrelated cleanup failure",
        )

        if primary is not None:
            actual_primary = (
                error.primary if isinstance(error, RemoteFailures) else error
            )
            self.assertIs(actual_primary, primary)
        self.assertIsInstance(
            error, RemoteFailures, "remote finish discarded its completed peer failure"
        )
        self.assertIs(error.primary, primary)
        self.assertEqual(error.cleanup, (secondary,))

    def test_fixture_finish_keeps_a_completed_peer_failure(self) -> None:
        asyncio.run(asyncio.wait_for(self.completed_peer(None), TIMEOUT * 3))

    def test_fixture_finish_keeps_primary_and_completed_peer_failures(self) -> None:
        primary = PrimaryFailure("controlled caller failure")
        asyncio.run(asyncio.wait_for(self.completed_peer(primary), TIMEOUT * 3))

    async def failed_caller(self, name: str, expected_last: str) -> None:
        primary = PrimaryFailure("controlled caller failure")
        probe = CallerProbe(primary)
        error = None
        try:
            await getattr(DriverTests(), name)(probe)
        except BaseException as actual:
            error = actual

        self.assertIsNotNone(probe.remote)
        remote = probe.remote
        try:
            self.assertIs(error, primary)
            self.assertEqual(remote.commands[-1]["method"], expected_last)
            self.assertEqual(len(remote.connections), 1)
            listener_closed_before_backup = not remote.server.is_serving()
            writer_closed_before_backup = remote.connections[0][0].is_closing()
        except BaseException as primary:
            errors = await remote_backup(remote, probe.driver)
            if errors:
                raise RemoteFailures(primary, errors) from primary
            raise
        errors = await remote_backup(remote, probe.driver)
        self.assertEqual(errors, ())

        self.assertTrue(
            listener_closed_before_backup,
            "caller failure left its remote listener open",
        )
        self.assertTrue(
            writer_closed_before_backup, "caller failure left its accepted writer open"
        )

    def test_chromium_failure_finishes_its_actual_remote(self) -> None:
        asyncio.run(
            asyncio.wait_for(
                self.failed_caller("chromium_exchange", "Fetch.continueWithAuth"),
                TIMEOUT * 3,
            )
        )

    def test_navigation_failure_finishes_its_actual_remote(self) -> None:
        asyncio.run(
            asyncio.wait_for(
                self.failed_caller("navigation_exchange", "Page.navigate"), TIMEOUT * 3
            )
        )

    def test_firefox_failure_finishes_its_actual_remote(self) -> None:
        asyncio.run(
            asyncio.wait_for(
                self.failed_caller("firefox_exchange", "network.continueWithAuth"),
                TIMEOUT * 3,
            )
        )


if __name__ == "__main__":
    unittest.main()
