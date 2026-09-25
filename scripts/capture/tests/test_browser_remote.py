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


class FakeRemote:
    """A loopback WebSocket endpoint scripted with one reply per command."""

    def __init__(self, replies: dict, event: dict) -> None:
        self.replies = replies
        self.event = event
        self.commands: list[dict] = []
        self.answered = asyncio.Event()
        self.server: asyncio.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.serve, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

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
        except asyncio.IncompleteReadError:
            writer.close()

    async def close(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class DriverTests(unittest.TestCase):
    def test_chromium_driver_attaches_then_answers_on_the_page_session(self) -> None:
        async def exercise() -> tuple[list[dict], list[str]]:
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
            port = await remote.start()
            notes: list[str] = []
            driver = ChromiumAuthDriver(CREDENTIALS, notes.append)
            with tempfile.TemporaryDirectory() as directory:
                profile = Path(directory)
                (profile / CHROMIUM_PORT_FILE).write_text(
                    f"{port}\n/devtools/browser/x\n"
                )
                await driver.start(profile, "http://x/page")
                await asyncio.wait_for(remote.answered.wait(), TIMEOUT)
            await driver.close()
            await remote.close()
            return remote.commands, notes

        commands, notes = asyncio.run(exercise())
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
        async def exercise() -> list[dict]:
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
            port = await remote.start()
            with tempfile.TemporaryDirectory() as directory:
                profile = Path(directory)
                (profile / CHROMIUM_PORT_FILE).write_text(
                    f"{port}\n/devtools/browser/x\n"
                )
                await asyncio.wait_for(
                    navigate_page(profile, "https://server.phantom.test:9/", 0.0),
                    TIMEOUT,
                )
            await remote.close()
            return remote.commands

        commands = asyncio.run(exercise())
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
        async def exercise() -> list[dict]:
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
            port = await remote.start()
            driver = FirefoxAuthDriver(CREDENTIALS, lambda _: None)
            with tempfile.TemporaryDirectory() as directory:
                profile = Path(directory)
                (profile / FIREFOX_PORT_FILE).write_text(
                    json.dumps({"ws_host": "127.0.0.1", "ws_port": port})
                )
                await driver.start(profile, "http://x/page")
                await asyncio.wait_for(remote.answered.wait(), TIMEOUT)
            await driver.close()
            await remote.close()
            return remote.commands

        commands = asyncio.run(exercise())
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


if __name__ == "__main__":
    unittest.main()
