import asyncio
import contextlib
import ssl
import unittest
from dataclasses import replace
from unittest.mock import patch

import h2.config
import h2.connection
import h2.events
import h2.settings
from hpack import Encoder

from scripts.capture import http_lifecycle, http_lifecycle_resources
from scripts.capture.http2_analysis import Priority
from scripts.capture.http2_session import CONNECTION_PREFACE, HOSTNAME
from scripts.capture.http_lifecycle import LifecycleFailures, LifecycleServer, Run
from scripts.capture.http_lifecycle_resources import ResourceCapture, resource_page
from scripts.capture.tests.test_http_lifecycle import frame, options


def fields(port: int, target: str) -> list[tuple[bytes, bytes]]:
    return [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", f"{HOSTNAME}:{port}".encode()),
        (b":path", target.encode()),
        (b"user-agent", b"synthetic-resource-test"),
        (b"accept", b"one"),
        (b"accept", b"two"),
    ]


def complete_evidence() -> ResourceCapture:
    capture = ResourceCapture("token", 12345)
    tap = capture.tap(0, "main", 0)
    encoder = Encoder()
    data = CONNECTION_PREFACE + frame(4, 0, 0, b"")
    targets = (
        "/start?run=token",
        "/resource.js?run=token",
        "/resource.css?run=token",
        "/resource.gif?run=token",
        "/resource.ttf?run=token",
        "/done?run=token&result=resources%3Aok",
    )
    for index, target in enumerate(targets):
        stream = 2 * index + 1
        head = fields(12345, target)
        priority = h2.events.PriorityUpdated()
        priority.exclusive, priority.depends_on, priority.weight = True, 0, 183
        capture.observe(0, stream, head, priority)
        data += frame(1, 0x25, stream, b"\x80\0\0\0\xb6" + encoder.encode(head))
    # A later PRIORITY frame must not replace a request's initial HEADERS priority.
    data += frame(2, 0, 3, b"\0\0\0\x01\x10")
    capture.retain(tap, "client", 0.1, data[:31])
    capture.retain(tap, "client", 0.2, data[31:])
    capture.retain(tap, "server", 0.3, frame(4, 0, 0, b""))
    capture.responded = {
        "/start",
        "/done",
        "/resource.js",
        "/resource.css",
        "/resource.gif",
        "/resource.ttf",
    }
    return capture


class ResourceEvidenceTests(unittest.TestCase):
    def test_assets_are_local_and_page_requires_real_decoding_and_font_load(
        self,
    ) -> None:
        capture = ResourceCapture("token", 12345)
        page = resource_page("token")
        self.assertIn(b"image.naturalWidth !== 1", page)
        self.assertIn(b"document.fonts.load('20px PhantomCapture', 'A')", page)
        self.assertIn(b"faces.length !== 1", page)
        self.assertIn(b"resources:error", page)
        self.assertNotIn(b"http:", page)
        self.assertNotIn(b"https:", page)
        self.assertIn(b"/resource.ttf?run=token", capture.asset("/resource.css")[1])
        self.assertEqual(capture.asset("/resource.gif")[1][:10], b"GIF89a\x01\0\x01\0")
        self.assertEqual(capture.asset("/resource.ttf")[0], "font/ttf")
        self.assertEqual(len(capture.font), 21768)
        self.assertEqual(capture.font[:4], b"\0\x01\0\0")
        with self.assertRaisesRegex(ValueError, "unknown local resource"):
            capture.asset("/unowned")
        with (
            patch.object(http_lifecycle_resources, "FONT_SHA256", "wrong"),
            self.assertRaisesRegex(ValueError, "retained source"),
        ):
            ResourceCapture("token", 12345)

    def test_invalid_origin_identity_fails_before_acquiring_font(self) -> None:
        for token, port in (
            ("", 1),
            ("x" * 65, 1),
            ("a&b", 1),
            ("é", 1),
            ("token", 0),
            ("token", 65536),
        ):
            with (
                self.subTest(token=token, port=port),
                patch("pathlib.Path.read_bytes") as read,
            ):
                with self.assertRaises(ValueError):
                    ResourceCapture(token, port)
                read.assert_not_called()

    def test_credential_unknown_origin_and_token_fail_without_retaining_fields(
        self,
    ) -> None:
        base = fields(12345, "/resource.js?run=token")
        cases = [
            base + [(name, b"sensitive")]
            for name in (
                b"cookie",
                b"authorization",
                b"proxy-authorization",
                b"x-private",
            )
        ]
        cases += [
            fields(12346, "/resource.js?run=token"),
            fields(12345, "/resource.js?run=wrong"),
            fields(12345, "/resource.js?run=token&other=1"),
            fields(12345, "/other?run=token"),
            base + [(b"referer", b"https://unowned.test/private")],
            base + [(b"origin", b"https://unowned.test")],
        ]
        for head in cases:
            capture = ResourceCapture("token", 12345)
            with self.subTest(head=head), self.assertRaises(ValueError) as error:
                capture.observe(0, 1, head, None)
            self.assertNotIn("sensitive", str(error.exception))
            self.assertEqual(capture.requests, [])

    def test_font_accepts_owned_stylesheet_referrer_and_preserves_it(self) -> None:
        capture = complete_evidence()
        font = capture.requests[4]
        head = font.fields + (
            (b"referer", b"https://server.phantom.test:12345/resource.css?run=token"),
        )
        isolated = ResourceCapture("token", 12345)
        isolated.observe(0, 9, head, None)
        self.assertEqual(isolated.requests[0].fields, head)
        with self.assertRaisesRegex(ValueError, "repeats"):
            isolated.observe(0, 11, head, None)

    def test_literal_peer_bytes_keep_duplicate_fields_and_initial_priority(
        self,
    ) -> None:
        capture = complete_evidence()
        lines = dict(line.split("=", 1) for line in capture.lines("resources:ok"))
        self.assertEqual(lines["resource_script_field_count"], "7")
        self.assertEqual(
            lines["resource_script_field_5"], "name_hex:616363657074,value_hex:6f6e65"
        )
        self.assertEqual(
            lines["resource_script_field_6"], "name_hex:616363657074,value_hex:74776f"
        )
        self.assertEqual(
            lines["resource_script_initial_priority"],
            "exclusive:true,depends_on:0,weight:183",
        )
        authority = lines["resource_script_field_2"].split("value_hex:")[1]
        self.assertEqual(bytes.fromhex(authority), b"server.phantom.test:<port>")
        self.assertEqual(lines["resource_connection_0_client_chunk_count"], "2")
        self.assertTrue(
            lines["resource_connection_0_client_chunk_0"].endswith(
                capture.taps[0].client_chunks[0][1].hex()
            )
        )

    def test_missing_failed_or_unanswered_asset_prevents_evidence(self) -> None:
        for change in ("failed", "missing", "unanswered"):
            capture = complete_evidence()
            if change == "missing":
                capture.requests.pop(3)
            elif change == "unanswered":
                capture.responded.remove("/resource.gif")
            result = "resources:error" if change == "failed" else "resources:ok"
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "complete every"),
            ):
                capture.lines(result)

    def test_changed_order_priority_or_missing_raw_request_prevents_evidence(
        self,
    ) -> None:
        for change in ("order", "priority", "missing"):
            capture = complete_evidence()
            request = capture.requests[1]
            if change == "order":
                capture.requests[1] = replace(
                    request, fields=request.fields[:-2] + request.fields[-2:][::-1]
                )
            elif change == "priority":
                capture.requests[1] = replace(request, priority=Priority(False, 0, 1))
            else:
                capture.taps.clear()
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "disagree|omit"),
            ):
                capture.lines("resources:ok")

    def test_partial_or_unowned_frames_prevent_evidence(self) -> None:
        additions = (
            ("client", b"\0"),
            ("server", b"\0"),
            ("client", frame(9, 4, 13, b"\x82")),
            ("client", frame(1, 1, 13, b"\x82")),
            ("client", frame(0, 1, 1, b"private")),
            ("client", frame(7, 0, 0, b"\0" * 8 + b"private")),
            ("client", frame(0xFA, 0, 0, b"private")),
        )
        for direction, data in additions:
            capture = complete_evidence()
            capture.retain(capture.taps[0], direction, 0.4, data)
            with (
                self.subTest(direction=direction, data=data),
                self.assertRaises(ValueError),
            ):
                capture.lines("resources:ok")

    def test_peer_limit_rejects_addition_without_losing_earlier_bytes(self) -> None:
        capture = ResourceCapture("token", 12345)
        tap = capture.tap(0, "main", 0)
        with patch.object(http_lifecycle_resources, "MAX_PEER_BYTES", 4):
            capture.retain(tap, "client", 0, b"1234")
            with self.assertRaisesRegex(ValueError, "capture limit"):
                capture.retain(tap, "server", 0, b"5")
        self.assertEqual(tap.client_chunks, [(0, b"1234")])
        self.assertEqual(tap.server_chunks, [])
        with self.assertRaisesRegex(ValueError, "owned connection"):
            capture.retain(None, "client", 0, b"x")

    def test_launch_is_local_and_does_not_change_existing_close_switches(self) -> None:
        certificate = http_lifecycle.generate_certificate()
        resource = http_lifecycle.launch_plan(
            options(scenario="resources"), certificate, (1, 1)
        )
        self.assertIn("--remote-debugging-address=127.0.0.1", resource.extra_arguments)
        self.assertIn(
            "--host-resolver-rules=MAP server.phantom.test 127.0.0.1, MAP * ~NOTFOUND",
            resource.extra_arguments,
        )
        close = http_lifecycle.launch_plan(
            options(scenario="close"), certificate, (1, 2)
        )
        self.assertNotIn("--remote-debugging-address=127.0.0.1", close.extra_arguments)


class ResourcePeerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        certificate = http_lifecycle.generate_certificate()
        self.context = http_lifecycle.server_context(certificate)
        self.context.set_alpn_protocols(["h2"])
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.load_verify_locations(
            cadata=certificate.certificate_pem.decode()
        )
        self.client_context.set_alpn_protocols(["h2"])
        self.run = Run("resources", "token", 1000)
        self.owner = LifecycleServer(self.run)
        self.addAsyncCleanup(self.retire)
        self.port = await self.owner.start("127.0.0.1", self.context, "main")
        self.run.resources = ResourceCapture("token", self.port)
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                self.port,
                ssl=self.client_context,
                server_hostname=HOSTNAME,
            ),
            5,
        )
        self.connection = h2.connection.H2Connection(
            h2.config.H2Configuration(
                client_side=True, normalize_outbound_headers=False
            )
        )
        self.connection.initiate_connection()

    async def retire(self) -> None:
        if hasattr(self, "writer"):
            # The observer waits for TCP EOF after close_notify; an asyncio TLS
            # writer instead waits for a reciprocal alert. End this synthetic peer.
            self.writer.transport.abort()
            with contextlib.suppress(ConnectionError, ssl.SSLError):
                await asyncio.wait_for(self.writer.wait_closed(), 5)
        try:
            await self.owner.close(self.run.failure)
        except ValueError as error:
            if error is not self.run.failure or isinstance(
                error.__cause__, LifecycleFailures
            ):
                raise

    async def send(self, stream: int, target: str, extra=()) -> bytes:
        self.connection.send_headers(
            stream,
            fields(self.port, target) + list(extra),
            end_stream=True,
            priority_weight=37,
            priority_depends_on=0,
            priority_exclusive=True,
        )
        self.writer.write(self.connection.data_to_send())
        await self.writer.drain()
        body = bytearray()
        while True:
            data = await asyncio.wait_for(self.reader.read(65536), 5)
            self.assertTrue(data, "peer ended before its full response")
            ended = False
            for event in self.connection.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    self.assertIn((b":status", b"200"), event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    body.extend(event.data)
                    self.connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    self.assertEqual(event.stream_id, stream)
                    ended = True
            self.writer.write(self.connection.data_to_send())
            await self.writer.drain()
            if ended:
                return bytes(body)

    async def test_real_verified_h2_peer_retains_complete_assets_and_wire_order(
        self,
    ) -> None:
        self.assertEqual(
            self.writer.get_extra_info("ssl_object").selected_alpn_protocol(), "h2"
        )
        page = await self.send(
            1, "/start?run=token", [(b"upgrade-insecure-requests", b"1")]
        )
        self.assertIn(b"document.fonts.load", page)
        self.assertEqual(
            await self.send(3, "/resource.js?run=token"),
            b"window.phantomResourceLoaded = true;",
        )
        self.assertIn(b"@font-face", await self.send(5, "/resource.css?run=token"))
        self.assertEqual((await self.send(7, "/resource.gif?run=token"))[:6], b"GIF89a")
        font = await self.send(
            9,
            "/resource.ttf?run=token",
            [
                (
                    b"referer",
                    f"https://{HOSTNAME}:{self.port}/resource.css?run=token".encode(),
                )
            ],
        )
        self.assertEqual(font, self.run.resources.font)
        self.assertEqual(
            await self.send(11, "/done?run=token&result=resources%3Aok"), b"ok"
        )
        await self.owner.wait_done(5)
        await self.retire()
        lines = dict(
            line.split("=", 1)
            for line in self.run.resources.lines(self.run.page_result)
        )
        self.assertEqual(
            lines["resource_font_initial_priority"],
            "exclusive:true,depends_on:0,weight:37",
        )
        self.assertEqual(lines["resource_font_field_count"], "8")
        value = lines["resource_font_field_7"].split("value_hex:")[1]
        self.assertEqual(
            bytes.fromhex(value),
            b"https://server.phantom.test:<port>/resource.css?run=<token>",
        )
        self.assertFalse(self.owner.protocols)

        self.assertTrue(
            all(listener.waiter.done() for listener in self.owner.listeners)
        )

    async def test_insufficient_receive_window_is_an_observed_failure(self) -> None:
        self.connection.update_settings(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1}
        )
        self.connection.send_headers(
            1, fields(self.port, "/start?run=token"), end_stream=True
        )
        self.writer.write(self.connection.data_to_send())
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "client receive window") as raised:
            await self.owner.wait_done(5)
        self.assertIs(raised.exception, self.run.failure)
        self.assertEqual(self.run.resources.responded, set())
        with self.assertRaises(ValueError):
            self.run.resources.lines("resources:ok")
        await self.retire()
        self.assertTrue(
            all(listener.waiter.done() for listener in self.owner.listeners)
        )

    async def test_completion_on_a_new_h2_connection_retains_both_peers(self) -> None:
        for stream, path in zip(
            range(1, 10, 2),
            (
                "/start",
                "/resource.js",
                "/resource.css",
                "/resource.gif",
                "/resource.ttf",
            ),
            strict=True,
        ):
            body = await self.send(stream, self.run.resources.target(path))
            self.assertEqual(
                body,
                http_lifecycle.reply_for("resources", "GET", path, {}, self.run).body,
            )
        self.assertEqual(self.run.page_connection, 0)
        self.writer.transport.abort()
        await asyncio.wait_for(self.writer.wait_closed(), 5)

        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                self.port,
                ssl=self.client_context,
                server_hostname=HOSTNAME,
            ),
            5,
        )
        self.connection = h2.connection.H2Connection(
            h2.config.H2Configuration(
                client_side=True, normalize_outbound_headers=False
            )
        )
        self.connection.initiate_connection()
        self.assertEqual(
            await self.send(1, self.run.resources.done_target("resources:ok")), b"ok"
        )
        self.assertEqual(self.run.page_result, "resources:ok")
        await self.owner.wait_done(5)
        await self.retire()

        self.assertEqual(len(self.run.connections), 2)
        self.assertEqual(self.run.page_connection, 0)
        self.assertEqual(self.run.resources.requests[-1].connection, 1)
        lines = dict(
            line.split("=", 1)
            for line in self.run.resources.lines(self.run.page_result)
        )
        for connection in (0, 1):
            self.assertGreater(
                int(lines[f"resource_connection_{connection}_client_chunk_count"]), 0
            )
        self.assertFalse(self.owner.protocols)
        self.assertIsNone(self.run.failure)

    async def test_real_credential_failure_is_observed_and_prevents_fixture(
        self,
    ) -> None:
        self.connection.send_headers(
            1,
            fields(self.port, "/start?run=token") + [(b"cookie", b"sensitive")],
            end_stream=True,
        )
        self.writer.write(self.connection.data_to_send())
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "unapproved header") as raised:
            await self.owner.wait_done(5)
        self.assertIs(raised.exception, self.run.failure)
        self.assertNotIn("sensitive", str(raised.exception))
        with self.assertRaises(ValueError):
            self.run.resources.lines("resources:ok")
        self.assertEqual(self.run.resources.requests, [])
        await self.retire()
        self.assertFalse(self.owner.protocols)


def h1_head(port: int, target: str, extra: bytes = b"") -> bytes:
    return (
        f"GET {target} HTTP/1.1\r\nHost: {HOSTNAME}:{port}\r\n".encode()
        + b"aCcEpT: one\r\nAccept:\ttwo \t\r\nConnection: keep-alive\r\n"
        + extra
        + b"\r\n"
    )


class ResourceH1EvidenceTests(unittest.TestCase):
    def test_explicit_protocol_options_are_scoped_and_default_remains_h2(self) -> None:
        http_lifecycle.validate_options(options(scenario="resources"))
        http_lifecycle.validate_options(options(scenario="resources", protocol="h1"))
        for changes in (
            {"scenario": "close", "protocol": "h1"},
            {"scenario": "resources", "protocol": "h4"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(ValueError, "--protocol"),
            ):
                http_lifecycle.validate_options(options(**changes))
        self.assertEqual(ResourceCapture("token", 12345).protocol, "h2")

    def test_unowned_malformed_credential_and_body_heads_are_redacted(self) -> None:
        valid = h1_head(12345, "/start?run=token")
        cases = (
            (valid[:-1], "incomplete"),
            (valid.replace(b"GET ", b"POST ", 1), "GET"),
            (valid.replace(b"HTTP/1.1", b"HTTP/1.0"), "HTTP/1.1"),
            (valid.replace(b"run=token", b"run=wrong"), "owned path"),
            (valid.replace(b"/start?", b"/other?"), "owned path"),
            (valid.replace(b"12345", b"12346"), "owned HTTPS origin"),
            (valid.replace(b"aCcEpT:", b"accept"), "malformed"),
            (valid.replace(b"one", b"one\x00"), "control byte"),
            (valid.replace(b"one", b"one\nprivate"), "control byte"),
            (
                h1_head(12345, "/start?run=token", b"Cookie: sensitive\r\n"),
                "unapproved",
            ),
            (
                h1_head(12345, "/start?run=token", b"Authorization: sensitive\r\n"),
                "unapproved",
            ),
            (
                h1_head(12345, "/start?run=token", b"Host: other\r\n"),
                "owned HTTPS origin",
            ),
            (h1_head(12345, "/start?run=token", b"Content-Length: 1\r\n"), "bodies"),
            (
                h1_head(
                    12345,
                    "/start?run=token",
                    b"Content-Length: 0\r\nContent-Length: 0\r\n",
                ),
                "bodies",
            ),
            (
                h1_head(12345, "/start?run=token", b"Transfer-Encoding: chunked\r\n"),
                "unapproved",
            ),
            (
                h1_head(12345, "/start?run=token", b"Connection: upgrade\r\n"),
                "connection options",
            ),
            (
                h1_head(
                    12345,
                    "/start?run=token",
                    b"Referer: https://unowned.test/private\r\n",
                ),
                "referrer",
            ),
        )
        for raw, message in cases:
            capture = ResourceCapture("token", 12345, "h1")
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(ValueError, message) as raised,
            ):
                capture.observe_h1(0, raw)
            self.assertNotIn("sensitive", str(raised.exception))
            self.assertEqual(capture.requests, [])


class ResourceH1PeerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        certificate = http_lifecycle.generate_certificate()
        context = http_lifecycle.server_context(certificate)
        context.set_alpn_protocols(["http/1.1"])
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.load_verify_locations(
            cadata=certificate.certificate_pem.decode()
        )
        self.client_context.set_alpn_protocols(["http/1.1"])
        self.run = Run("resources", "token", 1000)
        self.owner = LifecycleServer(self.run)
        self.writers = []
        self.addAsyncCleanup(self.retire)
        self.port = await self.owner.start("127.0.0.1", context, "main")
        self.run.resources = ResourceCapture("token", self.port, "h1")
        self.reader, self.writer = await self.connect()

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                self.port,
                ssl=self.client_context,
                server_hostname=HOSTNAME,
            ),
            5,
        )
        self.writers.append(writer)
        return reader, writer

    async def retire(self) -> None:
        for writer in self.writers:
            writer.transport.abort()
            with contextlib.suppress(ConnectionError, ssl.SSLError):
                await asyncio.wait_for(writer.wait_closed(), 5)
        try:
            await self.owner.close(self.run.failure)
        except (ValueError, EOFError) as error:
            if error is not self.run.failure or isinstance(
                error.__cause__, LifecycleFailures
            ):
                raise

    async def send(self, target: str, extra: bytes = b"") -> bytes:
        raw = h1_head(self.port, target, extra)
        # Exercise a head split inside a field name, rather than one full TLS write.
        split = raw.index(b"aCcEpT") + 3
        self.writer.write(raw[:split])
        await self.writer.drain()
        await asyncio.sleep(0)
        self.writer.write(raw[split:])
        await self.writer.drain()
        head = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), 5)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
        length = next(
            int(line.split(b":", 1)[1])
            for line in head.split(b"\r\n")
            if line.startswith(b"content-length:")
        )
        return await asyncio.wait_for(self.reader.readexactly(length), 5)

    async def test_verified_h1_assets_keep_raw_case_order_duplicates_and_complete_bodies(
        self,
    ) -> None:
        self.assertEqual(
            self.writer.get_extra_info("ssl_object").selected_alpn_protocol(),
            "http/1.1",
        )
        self.assertIn(b"document.fonts.load", await self.send("/start?run=token"))
        for path in http_lifecycle_resources.ASSETS:
            expected = self.run.resources.asset(path)[1]
            self.assertEqual(await self.send(path + "?run=token"), expected)
        # H1 can dispatch completion on a connection different from the navigation.
        self.reader, self.writer = await self.connect()
        self.assertEqual(
            await self.send("/done?run=token&result=resources%3Aok"), b"ok"
        )
        await self.owner.wait_done(5)
        await self.retire()
        capture = self.run.resources
        lines = dict(line.split("=", 1) for line in capture.lines(self.run.page_result))
        self.assertEqual(lines["resource_protocol"], "http/1.1")
        self.assertEqual(lines["resource_script_field_count"], "4")
        self.assertEqual(
            lines["resource_script_field_1"], "name_hex:614363457054,value_hex:6f6e65"
        )
        self.assertEqual(
            lines["resource_script_field_2"], "name_hex:416363657074,value_hex:74776f"
        )
        self.assertEqual(
            bytes.fromhex(lines["resource_script_head_hex"]),
            h1_head(self.port, "/resource.js?run=token"),
        )
        self.assertNotEqual(
            capture.requests[0].connection, capture.requests[-1].connection
        )
        self.assertFalse(self.owner.protocols)
        tap = capture.taps[0]
        tap.client_chunks.append((1, b"unowned trailing bytes"))
        with self.assertRaisesRegex(ValueError, "disagree with owned request heads"):
            capture.lines(self.run.page_result)
        tap.client_chunks.pop()
        tap.server_chunks[-1] = (
            tap.server_chunks[-1][0],
            tap.server_chunks[-1][1][:-1],
        )
        with self.assertRaisesRegex(ValueError, "response body"):
            capture.lines(self.run.page_result)

    async def test_actual_h1_credential_failure_prevents_retained_fixture(self) -> None:
        self.writer.write(
            h1_head(self.port, "/start?run=token", b"Cookie: sensitive\r\n")
        )
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "unapproved header") as raised:
            await self.owner.wait_done(5)
        self.assertIs(raised.exception, self.run.failure)
        self.assertNotIn("sensitive", str(raised.exception))
        self.assertEqual(self.run.resources.requests, [])
        with self.assertRaises(ValueError):
            self.run.resources.lines("resources:ok")

    async def test_partial_head_eof_is_an_observed_failure(self) -> None:
        partial = h1_head(self.port, "/start?run=token")[:-1]
        received = bytearray()
        delivered = asyncio.Event()
        read = http_lifecycle.Channel.read

        async def observe(channel):
            data = await read(channel)
            if channel.run is self.run and data is not None:
                received.extend(data)
                if len(received) >= len(partial):
                    delivered.set()
            return data

        with patch.object(http_lifecycle.Channel, "read", observe):
            # The setup peer's first read is already in flight.
            self.reader, self.writer = await self.connect()
            self.writer.write(partial)
            await self.writer.drain()
            # Local drain alone does not establish that TLS plaintext reached the peer.
            await asyncio.wait_for(delivered.wait(), 5)
            self.assertEqual(received, partial)
            self.writer.transport.abort()
            with self.assertRaisesRegex(EOFError, "head is truncated") as raised:
                await self.owner.wait_done(5)
        self.assertIs(raised.exception, self.run.failure)
        self.assertEqual(self.run.resources.requests, [])

    async def test_unnegotiated_protocol_fails_before_request_admission(self) -> None:
        self.client_context.set_alpn_protocols(["h2"])
        await self.connect()
        with self.assertRaisesRegex(ValueError, "requires http/1.1 negotiation"):
            await self.owner.wait_done(5)
        self.assertEqual(self.run.resources.requests, [])

    async def test_actual_body_fails_before_response(self) -> None:
        self.writer.write(
            h1_head(self.port, "/start?run=token", b"Content-Length: 1\r\n") + b"x"
        )
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "request bodies"):
            await self.owner.wait_done(5)
        self.assertEqual(self.run.resources.responded, set())

    async def test_actual_malformed_header_fails_before_admission(self) -> None:
        self.writer.write(
            h1_head(self.port, "/start?run=token").replace(b"aCcEpT:", b"broken")
        )
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "header field is malformed"):
            await self.owner.wait_done(5)
        self.assertEqual(self.run.resources.requests, [])

    async def test_actual_wrong_token_fails_before_admission(self) -> None:
        self.writer.write(h1_head(self.port, "/start?run=wrong"))
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "owned path and token"):
            await self.owner.wait_done(5)
        self.assertEqual(self.run.resources.requests, [])

    async def test_actual_peer_limit_counts_request_and_response_together(self) -> None:
        raw = h1_head(self.port, "/start?run=token")
        with patch.object(http_lifecycle_resources, "MAX_PEER_BYTES", len(raw)):
            self.writer.write(raw)
            await self.writer.drain()
            with self.assertRaisesRegex(
                ValueError, "peer bytes exceed the capture limit"
            ):
                await self.owner.wait_done(5)
        self.assertEqual(self.run.resources.retained, len(raw))
        self.assertEqual(self.run.resources.responded, set())
        self.assertEqual(self.run.resources.taps[0].server_chunks, [])


class ResourceH1OptionPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_capture_option_negotiates_h1_and_retires_after_driver_failure(
        self,
    ) -> None:
        certificate = http_lifecycle.generate_certificate()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=certificate.certificate_pem.decode())
        context.set_alpn_protocols(["http/1.1"])
        primary = ValueError("controlled driver stop after verified H1 response")
        test = self
        owners = []

        def server(run: Run) -> LifecycleServer:
            owner = LifecycleServer(run)
            owners.append(owner)
            return owner

        class WireDriver:
            def __init__(self, _plan, url: str) -> None:
                self.url = http_lifecycle.urlsplit(url)

            async def __aenter__(self) -> None:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1",
                        self.url.port,
                        ssl=context,
                        server_hostname=HOSTNAME,
                    ),
                    5,
                )
                try:
                    test.assertEqual(
                        writer.get_extra_info("ssl_object").selected_alpn_protocol(),
                        "http/1.1",
                    )
                    writer.write(
                        h1_head(self.url.port, self.url.path + "?" + self.url.query)
                    )
                    await writer.drain()
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    test.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
                finally:
                    writer.transport.abort()
                    with contextlib.suppress(ConnectionError, ssl.SSLError):
                        await asyncio.wait_for(writer.wait_closed(), 5)
                raise primary

            async def __aexit__(self, _kind, _value, _traceback) -> bool:
                return False

        with (
            patch.object(
                http_lifecycle, "generate_certificate", return_value=certificate
            ),
            patch.object(http_lifecycle, "LifecycleServer", server),
            patch.object(http_lifecycle, "BrowserDriver", WireDriver),
            patch.object(http_lifecycle, "write_text_fixture") as publish,
            self.assertRaises(ValueError) as raised,
        ):
            await asyncio.wait_for(
                http_lifecycle.capture(options(scenario="resources", protocol="h1")),
                5,
            )
        self.assertIs(raised.exception, primary)
        publish.assert_not_called()
        self.assertEqual(owners[0].run.resources.protocol, "h1")
        self.assertEqual(owners[0].run.connections[0].alpn, "http/1.1")
        self.assertFalse(owners[0].protocols)
        self.assertTrue(all(listener.waiter.done() for listener in owners[0].listeners))
