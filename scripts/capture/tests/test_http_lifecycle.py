import argparse
import asyncio
import base64
import contextlib
import errno
import hashlib
import json
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

import h2.config
import h2.connection
import h2.events

from scripts.capture import http_lifecycle
from scripts.capture.http2_session import CONNECTION_PREFACE
from scripts.capture.http_lifecycle import (
    ETAG,
    FORMAT,
    SCENARIOS,
    ConnectionRecord,
    FrameLog,
    LifecycleFailures,
    LifecycleServer,
    Run,
    page,
    recorded_values,
    reply_for,
    request_path,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/lifecycle"
CHROME = FIXTURES / "chrome/154.0.8037.97/windows-11-26200"
FIREFOX = FIXTURES / "firefox/157.0/windows-11-26200"


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream.to_bytes(4, "big")
        + payload
    )


def fixture_lines(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines()
    )


class FrameLogTests(unittest.TestCase):
    def test_counts_data_frames_and_records_goaway_fields(self) -> None:
        record = ConnectionRecord(0, "main", 0.0)
        log = FrameLog(record)
        data = (
            CONNECTION_PREFACE
            + frame(0x1, 0x25, 5, b"\x82")
            + frame(0x0, 0x1, 5, b"x" * 10)
            + frame(
                0x7,
                0x0,
                0,
                (0).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"Failed ping.",
            )
        )
        log.feed(data[:20], 1.0)
        log.feed(data[20:], 2.0)
        log.name_request(5, "/b")

        self.assertEqual(record.data_frames, 1)
        self.assertEqual(
            record.frames,
            [
                "ms:2.000,type:HEADERS,flags:0x25,stream:5,length:1,path:/b",
                "ms:2.000,type:GOAWAY,flags:0x00,stream:0,length:20,"
                'last_stream:0,error:1,debug:"Failed ping."',
            ],
        )

    def test_connection_end_names_each_observed_close(self) -> None:
        record = ConnectionRecord(0, "main", 0.0)
        self.assertEqual(record.end(), "open")
        record.close_notify = 1.0
        record.eof = 1.0
        self.assertEqual(record.end(), "close_notify+eof")
        self.assertTrue(record.ended)

    def test_rejects_oversized_frame_before_payload_and_counts_data_toward_budget(
        self,
    ) -> None:
        record = ConnectionRecord(0, "main", 0.0)
        log = FrameLog(record)
        with self.assertRaisesRegex(ValueError, "advertised"):
            log.feed(CONNECTION_PREFACE + b"\x00\x40\x01\x00\x00\x00\x00\x00\x01", 0)
        log = FrameLog(record)
        with patch.object(http_lifecycle, "MAX_INPUT_FRAMES", 1):
            log.feed(CONNECTION_PREFACE + frame(0, 0, 1, b"x"), 0)
            with self.assertRaisesRegex(ValueError, "input frame"):
                log.feed(frame(0, 0, 1, b"y"), 0)


class ResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = Run("revalidate", "token", 1000, "https://h1")

    def test_a_matching_validator_gets_304_and_a_first_request_200(self) -> None:
        first = reply_for("revalidate", "GET", "/etag", {}, self.run)
        second = reply_for(
            "revalidate", "GET", "/etag", {"if-none-match": ETAG}, self.run
        )
        dated = reply_for(
            "revalidate", "GET", "/last-modified", {"if-modified-since": "x"}, self.run
        )

        self.assertEqual((first.status, first.body), (200, b"v1"))
        self.assertEqual((second.status, second.body), (304, b""))
        self.assertEqual(dated.status, 304)
        self.assertIn(("etag", ETAG), first.fields)

    def test_stall_sends_part_of_a_declared_body(self) -> None:
        reply = reply_for("close", "GET", "/stall", {}, self.run)
        self.assertTrue(reply.stall)
        self.assertIn(("content-length", str(1024 * 1024)), reply.fields)

    def test_recorded_values_hide_the_multipart_boundary(self) -> None:
        values = recorded_values(
            [
                ("Content-Type", "multipart/form-data; boundary=----abc"),
                ("Expect", "100-continue"),
                ("accept", "*/*"),
            ]
        )
        self.assertEqual(
            values,
            {
                "content-type": "multipart/form-data; boundary=<boundary>",
                "expect": "100-continue",
            },
        )

    def test_request_path_drops_the_run_token(self) -> None:
        self.assertEqual(request_path("/b?run=0123"), "/b")

    def test_every_scenario_has_a_page_that_reports_to_done(self) -> None:
        for scenario in SCENARIOS:
            body = page(scenario, "token", "https://h1", 75000).decode()
            self.assertIn("/done?run=token", body)
        self.assertIn("await wait(75000);", page("idle-ping", "t", "", 75000).decode())
        self.assertIn("https://h1/stall", page("close", "t", "https://h1", 1).decode())


def options(**changes) -> argparse.Namespace:
    values = {
        "browser": "chrome",
        "browser_path": Path("unused"),
        "headful": False,
        "scenario": "revalidate",
        "listen": "127.0.0.1",
        "idle": 75.0,
        "output_dir": Path("unused-output"),
        "client_version": "test",
        "operating_system": "test",
    }
    values.update(changes)
    return argparse.Namespace(**values)


class OptionTests(unittest.TestCase):
    def test_invalid_idle_and_firefox_addresses_fail_before_acquisition(self) -> None:
        for args in (
            *(
                options(idle=value)
                for value in (0, -1, float("nan"), float("inf"), 2_147_484)
            ),
            options(browser="firefox", listen="127.0.0.2"),
            options(browser="firefox", listen="0:0:0:0:0:0:0:1"),
        ):
            with (
                self.subTest(args=args),
                patch.object(http_lifecycle, "generate_certificate") as acquire,
                self.assertRaises(ValueError),
            ):
                asyncio.run(http_lifecycle.capture(args))
            acquire.assert_not_called()

    def test_ipv6_mapping_and_firefox_loopback_policy(self) -> None:
        certificate = http_lifecycle.generate_certificate()
        chromium = http_lifecycle.launch_plan(
            options(listen="::1"), certificate, (1, 2)
        )
        self.assertIn(
            "--host-resolver-rules=MAP "
            + http_lifecycle.HOSTNAME
            + " [::1], EXCLUDE localhost",
            chromium.extra_arguments,
        )
        for address, disabled, preferred in (
            ("127.0.0.1", True, False),
            ("::1", False, True),
        ):
            args = options(browser="firefox", listen=address)
            http_lifecycle.validate_options(args)
            preferences = dict(
                http_lifecycle.launch_plan(
                    args, certificate, (1, 2)
                ).firefox_preferences
            )
            self.assertIs(preferences["network.dns.disableIPv6"], disabled)
            self.assertIs(preferences["network.dns.preferIPv6"], preferred)


class LifecycleOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.certificate = http_lifecycle.generate_certificate()
        self.context = http_lifecycle.server_context(self.certificate)
        self.context.set_alpn_protocols(["http/1.1"])
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.check_hostname = False
        self.client_context.verify_mode = ssl.CERT_NONE
        self.client_context.set_alpn_protocols(["http/1.1"])

    async def connect(self, owner):
        self.addAsyncCleanup(self.backup, owner)
        port = await owner.start("127.0.0.1", self.context, "main")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=self.client_context),
            5,
        )
        self.addAsyncCleanup(self.close_writer, writer)
        return port, reader, writer

    async def close_writer(self, writer) -> None:
        writer.close()
        with contextlib.suppress(ConnectionError, ssl.SSLError):
            await asyncio.wait_for(writer.wait_closed(), 5)

    async def backup(self, owner, *writers) -> None:
        for writer in writers:
            await self.close_writer(writer)
        with contextlib.suppress(LifecycleFailures, ValueError, asyncio.CancelledError):
            await owner.close()

    async def response(self, reader) -> bytes:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        length = next(
            int(line.split(b":", 1)[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length:")
        )
        await asyncio.wait_for(reader.readexactly(length), 5)
        return head

    async def test_native_parser_failures_wake_and_retire_before_publication(
        self,
    ) -> None:
        async def observe(payload, message, head_limit):
            run = Run("revalidate", "token", 1000)
            owner = LifecycleServer(run)
            _, reader, writer = await self.connect(owner)
            try:
                with patch.object(http_lifecycle, "MAX_REQUEST_HEAD", head_limit):
                    writer.write(payload)
                    await writer.drain()
                    with self.assertRaises(ValueError) as failed:
                        await owner.wait_done(5)
                    primary = failed.exception
                    self.assertIs(primary, run.failure)
                    self.assertIn(message, str(primary))
                    with self.assertRaises(ValueError) as closed:
                        await owner.close(primary)
                    self.assertIs(closed.exception, primary)
                    self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
                    self.assertFalse(owner.protocols)
                    self.assertTrue(
                        all(listener.waiter.done() for listener in owner.listeners)
                    )
                    self.assertEqual(run.requests, [])
            finally:
                await self.backup(owner, writer)

        for payload, message, limit in (
            (b"GET / HTTP/1.1\r\nX: " + b"x" * 128 + b"\r\n\r\n", "head exceeds", 128),
            (b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", "body length", 65_536),
        ):
            with self.subTest(message=message):
                await observe(payload, message, limit)

    async def test_partial_second_listener_failure_retires_actual_first_listener(
        self,
    ) -> None:
        loop = asyncio.get_running_loop()
        create_server = loop.create_server
        acquired = []
        original = OSError("second listener failed")

        async def acquire(*args, **kwargs):
            if acquired:
                raise original
            server = await create_server(*args, **kwargs)
            acquired.append((server, server.sockets[0].getsockname()[1]))
            return server

        with (
            patch.object(loop, "create_server", acquire),
            patch.object(http_lifecycle, "write_text_fixture") as publish,
        ):
            with self.assertRaises(OSError) as raised:
                await http_lifecycle.capture(options())
            self.assertIs(raised.exception, original)
            publish.assert_not_called()
        server, port = acquired[0]
        self.assertFalse(server.is_serving())
        self.assertFalse(server.sockets)
        replacement = await create_server(asyncio.Protocol, "127.0.0.1", port)
        replacement.close()
        await replacement.wait_closed()

    async def test_failed_stream_setup_collects_original_native_close_before_publication(
        self,
    ) -> None:
        primary = ValueError("original accepted stream setup failure")
        native_loss = OSError(errno.EIO, "original accepted native close failure")
        connected = asyncio.Event()
        protocols = []
        owners = []
        clients = []
        original_made = http_lifecycle.LifecycleProtocol.connection_made

        def server(run):
            owner = LifecycleServer(run)
            owners.append(owner)
            self.addAsyncCleanup(self.backup, owner)
            return owner

        test = self

        class WireDriver:
            def __init__(self, _plan, url):
                self.port = http_lifecycle.urlsplit(url).port

            async def __aenter__(self):
                client = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.port), 5
                )
                clients.append(client)
                test.addAsyncCleanup(test.close_writer, client[1])
                await asyncio.wait_for(connected.wait(), 5)
                return self

            async def __aexit__(self, _kind, _value, _traceback):
                return False

        try:
            with contextlib.ExitStack() as faults:

                def made(protocol, transport):
                    protocols.append(protocol)
                    faults.enter_context(
                        patch.object(
                            transport,
                            "abort",
                            side_effect=lambda: transport._force_close(native_loss),
                        )
                    )
                    with patch.object(
                        protocol._stream_reader, "set_transport", side_effect=primary
                    ):
                        original_made(protocol, transport)
                    self.assertIsNone(protocol.writer)
                    self.assertFalse(protocol.retired)
                    connected.set()

                faults.enter_context(
                    patch.object(
                        http_lifecycle.LifecycleProtocol, "connection_made", made
                    )
                )
                faults.enter_context(
                    patch.object(http_lifecycle, "LifecycleServer", server)
                )
                faults.enter_context(
                    patch.object(http_lifecycle, "BrowserDriver", WireDriver)
                )
                publish = faults.enter_context(
                    patch.object(http_lifecycle, "write_text_fixture")
                )
                with self.assertRaises(ValueError) as raised:
                    await asyncio.wait_for(http_lifecycle.capture(options()), 5)
                self.assertIs(raised.exception, primary)
                self.assertIs(owners[0].run.failure, primary)
                group = primary.__cause__
                self.assertIsInstance(group, LifecycleFailures)
                self.assertIs(group.primary, primary)
                self.assertEqual(group.cleanup, (native_loss,))
                self.assertIs(group.cleanup[0], native_loss)
                publish.assert_not_called()
                protocol = protocols[0]
                self.assertIsNone(protocol.writer)
                self.assertIsNone(protocol.handler)
                self.assertTrue(protocol.retired)
                self.assertTrue(protocol.closed_observed)
                self.assertTrue(protocol.stream_closed.done())
                # Check observation before this test retrieves the outcome itself.
                self.assertFalse(protocol.stream_closed._log_traceback)
                self.assertIs(protocol.stream_closed.exception(), native_loss)
                self.assertIsNone(protocol.transport._sock)
                self.assertFalse(owners[0].protocols)
                self.assertTrue(
                    all(listener.waiter.done() for listener in owners[0].listeners)
                )
                self.assertEqual(await asyncio.wait_for(clients[0][0].read(), 5), b"")
        finally:
            for protocol in protocols:
                protocol.transport.abort()
            for owner in owners:
                await self.backup(owner, *(writer for _, writer in clients))

    async def test_malformed_wire_cannot_publish_after_a_later_healthy_done_request(
        self,
    ) -> None:
        async def observe(payload, message, protocol="http/1.1"):
            owners = []
            clients = []
            drivers = []
            server_type = LifecycleServer
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            client_context.set_alpn_protocols([protocol])

            def server(run):
                owner = server_type(run)
                owners.append(owner)
                self.addAsyncCleanup(self.backup, owner)
                return owner

            test = self

            class WireDriver:
                def __init__(self, _plan, url):
                    self.url = http_lifecycle.urlsplit(url)
                    self.token = http_lifecycle.parse_qs(self.url.query)["run"][0]
                    drivers.append(self)

                async def __aenter__(self):
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            "127.0.0.1", self.url.port, ssl=client_context
                        ),
                        5,
                    )
                    clients.append((reader, writer))
                    test.addAsyncCleanup(test.close_writer, writer)
                    if protocol == "h2":
                        self.connection = h2.connection.H2Connection(
                            h2.config.H2Configuration(client_side=True)
                        )
                        self.connection.initiate_connection()
                        fields = [
                            (":method", "GET"),
                            (":scheme", "https"),
                            (":authority", "local"),
                        ]
                        self.connection.send_headers(
                            1,
                            fields + [(":path", f"/start?run={self.token}&other=x,y")],
                            end_stream=True,
                        )
                        writer.write(self.connection.data_to_send())
                        await writer.drain()
                        ended = False
                        status = None
                        while not ended:
                            data = await asyncio.wait_for(reader.read(65_536), 5)
                            test.assertTrue(data)
                            for event in self.connection.receive_data(data):
                                if isinstance(event, h2.events.ResponseReceived):
                                    test.assertEqual(event.stream_id, 1)
                                    test.assertIn((b":status", b"200"), event.headers)
                                    status = dict(event.headers)[b":status"]
                                if isinstance(event, h2.events.StreamEnded):
                                    test.assertEqual(event.stream_id, 1)
                                    ended = True
                        test.assertEqual(status, b"200")
                        self.connection.send_headers(
                            3, fields + payload, end_stream=True
                        )
                        self.connection.send_headers(
                            5,
                            fields + [(":path", f"/done?run={self.token}&result=ok")],
                            end_stream=True,
                        )
                        writer.write(self.connection.data_to_send())
                    else:
                        writer.write(
                            f"GET /start?run={self.token}&other=x,y HTTP/1.1\r\nHost: local\r\n\r\n".encode()
                        )
                        await writer.drain()
                        test.assertIn(b"200 OK", await test.response(reader))
                        writer.write(
                            payload
                            + f"GET /done?run={self.token}&result=ok HTTP/1.1\r\nHost: local\r\n\r\n".encode()
                        )
                    await writer.drain()
                    return self

                async def __aexit__(self, _kind, _value, _traceback):
                    return False

            try:
                with (
                    patch.object(http_lifecycle, "LifecycleServer", server),
                    patch.object(http_lifecycle, "BrowserDriver", WireDriver),
                    patch.object(http_lifecycle, "write_text_fixture") as publish,
                ):
                    with self.assertRaisesRegex(ValueError, message) as raised:
                        await asyncio.wait_for(http_lifecycle.capture(options()), 5)
                    original = raised.exception
                    self.assertIs(original, owners[0].run.failure)
                    publish.assert_not_called()
                self.assertIsNone(owners[0].run.completion)
                self.assertEqual(len(owners[0].run.requests), 1)
                self.assertEqual(owners[0].run.requests[0].path, "/start")
                self.assertFalse(owners[0].protocols)
                self.assertFalse(owners[0].event_tasks)
                self.assertTrue(
                    all(listener.waiter.done() for listener in owners[0].listeners)
                )
                remaining = await asyncio.wait_for(clients[0][0].read(), 5)
                self.assertTrue(clients[0][0].at_eof())
                if protocol == "h2":
                    for event in drivers[0].connection.receive_data(remaining):
                        self.assertNotIsInstance(event, h2.events.ResponseReceived)
                else:
                    self.assertEqual(remaining, b"")
            finally:
                for owner in owners:
                    await self.backup(owner, *(writer for _, writer in clients))

        cases = (
            (b"GET /a\nformat=forged HTTP/1.1\r\nHost: local\r\n\r\n", "visible ASCII"),
            *(
                (
                    f"GET /a{control}forged HTTP/1.1\r\nHost: local\r\n\r\n".encode(),
                    "visible ASCII",
                )
                for control in ("\t", "\r", "\x00", "\x7f")
            ),
            (b"GET /a forged HTTP/1.1\r\nHost: local\r\n\r\n", "request line"),
            (b"GET \x01/a HTTP/1.1\r\nHost: local\r\n\r\n", "visible ASCII"),
            (b"G\tET /a HTTP/1.1\r\nHost: local\r\n\r\n", "method"),
            (b"GET /a HTTP/1.1\r\nHo\nst: local\r\n\r\n", "header name"),
            (b"GET /a HTTP/1.1\r\nHost : local\r\n\r\n", "header name"),
            (b"GET /a HTTP/1.1\r\nX|Forged: value\r\n\r\n", "name separator"),
            (
                b"GET /a,status:304,fields:forged HTTP/1.1\r\nHost: local\r\n\r\n",
                "field separator",
            ),
        )
        for payload, message in cases:
            with self.subTest(payload=payload):
                await observe(payload, message)
        for fields, message in (
            ([(":path", "/a,status:304,fields:forged")], "field separator"),
            ([(":path", "/a"), ("x|forged", "value")], "name separator"),
        ):
            with self.subTest(protocol="h2", fields=fields):
                await observe(fields, message, "h2")

    async def test_connection_budget_retires_admitted_and_rejected_native_sockets(
        self,
    ) -> None:
        run = Run("revalidate", "token", 1000)
        owner = LifecycleServer(run)
        self.addAsyncCleanup(self.backup, owner)
        port = await owner.start("127.0.0.1", self.context, "main")
        peers = []
        try:
            with patch.object(http_lifecycle, "MAX_CONNECTIONS", 1):
                for _ in range(2):
                    peers.append(
                        await asyncio.wait_for(
                            asyncio.open_connection("127.0.0.1", port), 5
                        )
                    )
                    self.addAsyncCleanup(self.close_writer, peers[-1][1])
                with self.assertRaisesRegex(ValueError, "connection limit") as raised:
                    await owner.wait_done(5)
                primary = raised.exception
                self.assertIs(primary, run.failure)
                with self.assertRaises(ValueError) as closed:
                    await owner.close(primary)
                self.assertIs(closed.exception, primary)
                self.assertEqual(len(run.connections), 1)
                self.assertFalse(owner.protocols)
                for reader, _ in peers:
                    self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        finally:
            await self.backup(owner, *(writer for _, writer in peers))

    async def test_request_and_aggregate_budgets_retain_actual_worker_failures(
        self,
    ) -> None:
        async def observe(bound, value, message):
            run = Run("revalidate", "token", 1000)
            owner = LifecycleServer(run)
            _, reader, writer = await self.connect(owner)
            try:
                writer.write(b"GET /a HTTP/1.1\r\nHost: local\r\n\r\n")
                await writer.drain()
                self.assertIn(b"200 OK", await self.response(reader))
                with patch.object(http_lifecycle, bound, value):
                    writer.write(b"GET /b HTTP/1.1\r\nHost: local\r\n\r\n")
                    await writer.drain()
                    with self.assertRaisesRegex(ValueError, message) as raised:
                        await owner.wait_done(5)
                    primary = raised.exception
                    self.assertIs(primary, run.failure)
                    with self.assertRaises(ValueError) as closed:
                        await owner.close(primary)
                    self.assertIs(closed.exception, primary)
                    self.assertFalse(owner.protocols)
                    self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
                    self.assertEqual(len(run.requests), 1)
            finally:
                await self.backup(owner, writer)

        for bound, value, message in (
            ("MAX_REQUESTS", 1, "request limit"),
            ("MAX_CAPTURE_BYTES", 0, "aggregate capture byte limit"),
        ):
            with self.subTest(bound=bound):
                await observe(bound, value, message)

    async def test_active_h2_stream_budget_collects_original_callback_error(
        self,
    ) -> None:
        from h2.config import H2Configuration
        from h2.connection import H2Connection

        self.context.set_alpn_protocols(["h2"])
        self.client_context.set_alpn_protocols(["h2"])
        run = Run("revalidate", "token", 1000)
        owner = LifecycleServer(run)
        _, reader, writer = await self.connect(owner)
        client = H2Connection(H2Configuration(client_side=True))
        client.initiate_connection()
        for stream in (1, 3):
            client.send_headers(
                stream,
                [
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "local"),
                    (":path", "/a"),
                ],
                end_stream=False,
            )
        try:
            with patch.object(http_lifecycle, "MAX_STREAMS", 1):
                writer.write(client.data_to_send())
                await writer.drain()
                with self.assertRaisesRegex(
                    ValueError, "active stream limit"
                ) as raised:
                    await owner.wait_done(5)
                primary = raised.exception
                self.assertIs(primary, run.failure)
                with self.assertRaises(ValueError) as closed:
                    await owner.close(primary)
                self.assertIs(closed.exception, primary)
                self.assertFalse(owner.protocols)
                output = await asyncio.wait_for(reader.read(), 5)
                self.assertGreaterEqual(len(output), 9)
                self.assertEqual(
                    output[3], 4
                )  # The original server SETTINGS precede failure.
                self.assertEqual(len(run.requests), 1)
                self.assertIsNone(run.requests[0].status)
        finally:
            await self.backup(owner, writer)

    async def test_exact_done_token_and_selected_connection_own_completion(
        self,
    ) -> None:
        run = Run("revalidate", "token", 1000)
        owner = LifecycleServer(run)
        port, reader, writer = await self.connect(owner)
        other_reader, other_writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=self.client_context),
            5,
        )
        self.addAsyncCleanup(self.close_writer, other_writer)
        try:
            malformed = (
                "/{path}?run=token&run=",
                "/{path}?run=token&run=token",
                "/{path}?run=token#",
                "//local/{path}?run=token",
                "https://local/{path}?run=token",
                "{path}?run=token",
            )
            for path in ("start", "done"):
                for target in (
                    f"/{path}?run=to\tken",
                    f"/{path}?run=to\rken",
                    f"/{path}?run=to\nken",
                    f"/{path}?run=to\x00ken",
                    f"/{path}?run=to ken",
                    f"/{path}?run=to\x7fken",
                    f"\x01/{path}?run=token",
                    f" /{path}?run=token",
                ):
                    self.assertFalse(run.belongs(target), repr(target))
            for pattern in malformed:
                target = pattern.format(path="start")
                self.assertFalse(run.belongs(target), repr(target))
                writer.write(f"GET {target} HTTP/1.1\r\nHost: local\r\n\r\n".encode())
                await writer.drain()
                await self.response(reader)
                self.assertIsNone(run.page_connection, repr(target))
            writer.write(b"GET /start?run=token HTTP/1.1\r\nHost: local\r\n\r\n")
            await writer.drain()
            self.assertIn(b"200 OK", await self.response(reader))
            selected = run.page_connection
            other_writer.write(b"GET /done?run=token HTTP/1.1\r\nHost: local\r\n\r\n")
            await other_writer.drain()
            await self.response(other_reader)
            for target in (
                "/done?run=other",
                *(pattern.format(path="done") for pattern in malformed),
            ):
                self.assertFalse(run.belongs(target), repr(target))
                writer.write(f"GET {target} HTTP/1.1\r\nHost: local\r\n\r\n".encode())
                await writer.drain()
                await self.response(reader)
                self.assertIsNone(run.completion, repr(target))
                self.assertIsNone(run.page_result, repr(target))
            self.assertIsNone(run.completion)
            self.assertIsNone(run.page_result)
            self.assertEqual(run.page_connection, selected)
            writer.write(
                b"GET /done?run=token&result=ok HTTP/1.1\r\nHost: local\r\n\r\n"
            )
            await writer.drain()
            await self.response(reader)
            self.assertEqual(run.page_result, "ok")
            timer = run.completion
            self.assertIsNotNone(timer)
            await owner.close()
            self.assertTrue(timer.cancelled())
            self.assertFalse(owner.protocols)
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
            self.assertEqual(await asyncio.wait_for(other_reader.read(), 5), b"")
            # Local cleanup must not become a measured browser EOF or close_notify.
            self.assertTrue(all(record.end() == "open" for record in run.connections))
        finally:
            await self.backup(owner, writer, other_writer)

    async def test_pending_external_worker_cancellation_is_an_original_failure(
        self,
    ) -> None:
        run = Run("revalidate", "token", 1000)
        owner = LifecycleServer(run)
        _, reader, writer = await self.connect(owner)
        try:
            protocol = next(iter(owner.protocols))
            protocol.handler.cancel("external peer interruption")
            with self.assertRaises(asyncio.CancelledError) as raised:
                await owner.wait_done(5)
            original = raised.exception
            self.assertIs(original, run.failure)
            self.assertEqual(original.args, ("external peer interruption",))
            with self.assertRaises(asyncio.CancelledError) as closed:
                await owner.close(original)
            self.assertIs(closed.exception, original)
            self.assertFalse(owner.protocols)
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        finally:
            await self.backup(owner, writer)

    async def test_actual_tls_alert_and_bare_tcp_end_remain_distinct(self) -> None:
        async def observe(notify):
            run = Run("close", "token", 1000)
            owner = LifecycleServer(run)
            self.addAsyncCleanup(self.backup, owner)
            port = await owner.start("127.0.0.1", self.context, "main")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), 5
            )
            self.addAsyncCleanup(self.close_writer, writer)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = self.client_context.wrap_bio(
                incoming, outgoing, server_hostname="localhost"
            )
            try:
                while True:
                    try:
                        tls.do_handshake()
                        break
                    except ssl.SSLWantReadError:
                        writer.write(outgoing.read())
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(65_536), 5)
                        self.assertTrue(data)
                        incoming.write(data)
                writer.write(outgoing.read())
                await writer.drain()
                if notify:
                    with contextlib.suppress(ssl.SSLWantReadError):
                        tls.unwrap()
                    alert = outgoing.read()
                    self.assertTrue(alert)
                    writer.write(alert)
                    await writer.drain()
                writer.write_eof()
                await asyncio.wait_for(reader.read(), 5)
                await asyncio.wait_for(run.connection_ended.wait(), 5)
                record = run.connections[0]
                self.assertIsNone(run.failure)
                self.assertIsNotNone(record.eof)
                self.assertIsNone(record.reset)
                self.assertEqual(record.end(), "close_notify+eof" if notify else "eof")
                await owner.close()
                self.assertFalse(owner.protocols)
            finally:
                await self.backup(owner, writer)

        for notify in (True, False):
            with self.subTest(notify=notify):
                await observe(notify)

    async def test_cleanup_cancellation_preserves_prior_parser_failure_and_chain(
        self,
    ) -> None:
        run = Run("revalidate", "token", 1000)
        owner = LifecycleServer(run)
        entered = asyncio.Event()
        release = asyncio.Event()
        wait_writer = owner.wait_writer
        interruption_cause = RuntimeError("prior interruption cause")
        interruption_context = RuntimeError("prior interruption context")
        observed = []

        async def delayed(protocol):
            await wait_writer(protocol)
            entered.set()
            await release.wait()

        owner.wait_writer = delayed
        _, reader, writer = await self.connect(owner)
        task = None
        try:
            writer.write(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
            await writer.drain()
            with self.assertRaises(ValueError) as failed:
                await owner.wait_done(5)
            primary = failed.exception
            await asyncio.wait_for(entered.wait(), 5)

            async def finish():
                try:
                    await owner.close(primary)
                except asyncio.CancelledError as original:
                    self.assertEqual(original.args, ("interrupted cleanup",))
                    group = original.__cause__
                    self.assertIsInstance(group, LifecycleFailures)
                    self.assertIs(group.primary, primary)
                    self.assertIn(original, group.cleanup)
                    self.assertIs(group.interruption_cause, interruption_cause)
                    self.assertIs(group.interruption_context, interruption_context)
                    self.assertIs(group.owner, owner)
                    observed.append(original)
                    raise

            collecting = asyncio.Event()
            wait = asyncio.wait

            async def wait_with_chain(*args, **kwargs):
                collecting.set()
                try:
                    return await wait(*args, **kwargs)
                except asyncio.CancelledError as original:
                    original.__cause__ = interruption_cause
                    original.__context__ = interruption_context
                    raise

            with patch.object(http_lifecycle.asyncio, "wait", wait_with_chain):
                task = asyncio.create_task(finish())
                await asyncio.wait_for(collecting.wait(), 5)
                task.cancel("interrupted cleanup")
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 5)
            self.assertEqual(len(observed), 1)
            self.assertFalse(owner.protocols)
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        finally:
            release.set()
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.wait_for(task, 5)
            await self.backup(owner, writer)


class RemoteCloseTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_endpoint_accepts_clean_close_and_retains_truncated_frame(
        self,
    ) -> None:
        from scripts.capture.browser_remote import (
            WEBSOCKET_GUID,
            RemoteConnection,
            read_frame,
        )

        async def observe(response, clean):
            tasks = []
            writers = []
            connections = []
            run = Run("close", "token", 1000)

            async def serve(reader, writer):
                try:
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    key = next(
                        line.split(b":", 1)[1].strip()
                        for line in head.split(b"\r\n")
                        if line.lower().startswith(b"sec-websocket-key:")
                    )
                    accept = base64.b64encode(
                        hashlib.sha1(key + WEBSOCKET_GUID).digest()
                    )
                    writer.write(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        b"Connection: Upgrade\r\nSec-WebSocket-Accept: "
                        + accept
                        + b"\r\n\r\n"
                    )
                    await writer.drain()
                    _, opcode, payload = await asyncio.wait_for(read_frame(reader), 5)
                    self.assertEqual(opcode, 1)
                    self.assertEqual(json.loads(payload)["method"], "Browser.close")
                    writer.write(response)
                    await writer.drain()
                finally:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), 5)

            def accepted(reader, writer):
                writers.append(writer)
                tasks.append(asyncio.create_task(serve(reader, writer)))

            listener = await asyncio.start_server(accepted, "127.0.0.1", 0)
            port = listener.sockets[0].getsockname()[1]

            async def endpoint(_find, _profile):
                return f"ws://127.0.0.1:{port}/session"

            def connection(socket):
                owner = RemoteConnection(socket)
                connections.append(owner)
                return owner

            try:
                with (
                    patch.object(http_lifecycle, "wait_for_endpoint", endpoint),
                    patch.object(http_lifecycle, "RemoteConnection", connection),
                ):
                    if clean:
                        await http_lifecycle.close_browser(
                            "chrome", Path("unused"), run
                        )
                        self.assertIs(run.remote_disconnect, connections[0].failure)
                        self.assertEqual(
                            str(run.remote_disconnect),
                            "remote protocol endpoint closed",
                        )
                    else:
                        with self.assertRaises(asyncio.IncompleteReadError) as raised:
                            await http_lifecycle.close_browser(
                                "chrome", Path("unused"), run
                            )
                        self.assertIs(raised.exception, connections[0].failure)
                        self.assertEqual(raised.exception.partial, b"\x81")
                        self.assertIsNone(run.remote_disconnect)
                completed, pending = await asyncio.wait(tasks, timeout=5)
                self.assertFalse(pending)
                for task in completed:
                    task.result()
                self.assertTrue(connections[0].socket.writer.transport.is_closing())
            finally:
                listener.close()
                for writer in writers:
                    writer.close()
                    with contextlib.suppress(ConnectionError):
                        await asyncio.wait_for(writer.wait_closed(), 5)
                if tasks:
                    completed, pending = await asyncio.wait(tasks, timeout=5)
                    for task in pending:
                        task.cancel()
                    for task in completed:
                        task.result()
                    for task in pending:
                        with contextlib.suppress(asyncio.CancelledError):
                            await asyncio.wait_for(task, 5)
                await listener.wait_closed()

        for response, clean in ((b"\x88\x00", True), (b"\x81", False)):
            with self.subTest(clean=clean):
                await observe(response, clean)


class RetainedFixtureTests(unittest.TestCase):
    def test_fixtures_hold_no_token_or_certificate(self) -> None:
        for path in sorted(FIXTURES.glob("*/*/*/*.txt")):
            text = path.read_text(encoding="ascii")
            self.assertTrue(text.startswith(f"format={FORMAT}\n"), path)
            self.assertIn("run=<token>", text, path)
            self.assertNotIn("BEGIN CERTIFICATE", text, path)

    def test_chrome_ends_every_connection_without_close_notify(self) -> None:
        for name in ("close.txt", "ping-unanswered.txt"):
            lines = fixture_lines(CHROME / name)
            ends = [
                value
                for key, value in lines.items()
                if key.startswith("connection_") and key.count("_") == 1
            ]
            self.assertTrue(ends, name)
            for value in ends:
                self.assertNotIn("close_notify+", value, name)

    def test_firefox_sends_close_notify_on_each_close(self) -> None:
        lines = fixture_lines(FIREFOX / "close.txt")
        for index in range(int(lines["connection_count"])):
            self.assertIn("end:close_notify+eof", lines[f"connection_{index}"])

    def test_no_upload_carries_expect(self) -> None:
        for directory in (CHROME, FIREFOX):
            for name in ("upload-h1.txt", "upload-h2.txt"):
                text = (directory / name).read_text(encoding="ascii").lower()
                self.assertNotIn("expect", text, directory / name)


if __name__ == "__main__":
    unittest.main()
