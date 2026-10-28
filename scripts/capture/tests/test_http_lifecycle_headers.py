import asyncio
import contextlib
import json
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

import h2.config
import h2.connection
import h2.events

from scripts.capture import http_lifecycle as lifecycle
from scripts.capture.browser_launch import LaunchPlan
from scripts.capture.http2_analysis import Priority
from scripts.capture.http2_session import HOSTNAME
from scripts.capture.tests.test_http_lifecycle import options

ORIGIN = f"https://{HOSTNAME}:12345"


def owned_run(scenario: str = "upload-h1") -> lifecycle.Run:
    run = lifecycle.Run(scenario, "token", 1000)
    run.header_origin = ORIGIN
    return run


def post_record(stream: int | None = None) -> lifecycle.RequestRecord:
    return lifecycle.RequestRecord(0, stream, 0, "POST", "/post-small", [], {})


class HeaderBoundaryTests(unittest.TestCase):
    def test_wrong_origin_path_token_and_credentials_cannot_enter_header_evidence(
        self,
    ) -> None:
        base = [("Host", f"{HOSTNAME}:12345")]
        cases = [
            ("/post-small?run=other", base),
            ("/post-small?run=token&run=token", base),
            ("https://other.test/post-small?run=token", base),
            ("/unowned?run=token", base),
            ("/post-small?run=token", [("Host", "other.test:12345")]),
            ("/post-small?run=token", base * 2),
            ("/post-small?run=token", base + [("Origin", "https://other.test")]),
            ("/post-small?run=token", base + [("Referer", ORIGIN + "/private")]),
            ("/post-small?run=token", base + [("Accept", "bad\x00value")]),
            *(
                ("/post-small?run=token", base + [(name, "private-value")])
                for name in (
                    "Cookie",
                    "Authorization",
                    "Proxy-Authorization",
                    "X-Token",
                )
            ),
        ]
        for target, fields in cases:
            with self.subTest(target=target, fields=fields):
                run = owned_run()
                request = post_record()
                with self.assertRaises(ValueError) as failed:
                    run.record_headers(request, target, fields)
                self.assertNotIn("private-value", str(failed.exception))
                self.assertIsNone(request.ordered_fields)
                self.assertEqual(run.retained_bytes, 0)

    def test_method_and_http2_identity_match_the_actual_owned_request(self) -> None:
        run = owned_run("upload-h2")
        fields = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", f"{HOSTNAME}:12345"),
            (":path", "/post-small?run=token"),
        ]
        for index, value in ((0, "GET"), (1, "http"), (2, "other.test"), (3, "/other")):
            changed = fields.copy()
            changed[index] = (changed[index][0], value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                run.record_headers(post_record(1), "/post-small?run=token", changed)
        request = post_record()
        request.method = "GET"
        with self.assertRaisesRegex(ValueError, "scenario path"):
            run.record_headers(
                request, "/post-small?run=token", [("Host", f"{HOSTNAME}:12345")]
            )

    def test_exact_header_and_aggregate_byte_limits_apply_before_retention(
        self,
    ) -> None:
        # Host contributes 33 bytes and Accept contributes 31, including framing.
        fields = [("Host", f"{HOSTNAME}:12345"), ("Accept", "x" * 21)]
        run = owned_run()
        request = post_record()
        with (
            patch.object(lifecycle, "MAX_REQUEST_HEAD", 64),
            patch.object(lifecycle, "MAX_CAPTURE_BYTES", 64),
        ):
            run.record_headers(request, "/post-small?run=token", fields)
            self.assertEqual(run.retained_bytes, 64)
            with self.assertRaisesRegex(ValueError, "aggregate"):
                run.record_headers(post_record(), "/post-small?run=token", fields)
            fields[-1] = ("Accept", "x" * 22)
            rejected = post_record()
            with self.assertRaisesRegex(ValueError, "head limit"):
                owned_run().record_headers(rejected, "/post-small?run=token", fields)
            self.assertIsNone(rejected.ordered_fields)


class CaptureSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_selected_and_default_alpn_serve_the_unchanged_request(self) -> None:
        cases = (
            ("revalidate", "h1", "http/1.1", ("h2", "http/1.1")),
            ("revalidate", "h2", "h2", ("h2", "http/1.1")),
            ("revalidate", None, "h2", ("h2", "http/1.1")),
            ("revalidate", None, "http/1.1", ("http/1.1",)),
            ("resources", None, "h2", ("h2", "http/1.1")),
            ("resources", "h1", "http/1.1", ("h2", "http/1.1")),
            ("resources", "h2", "h2", ("h2", "http/1.1")),
            ("upload-h1", None, "http/1.1", ("h2", "http/1.1")),
            ("upload-h2", None, "h2", ("h2", "http/1.1")),
        )
        for scenario, selected, expected, offered in cases:
            with self.subTest(scenario=scenario, selected=selected, offered=offered):
                await self.capture_case(scenario, selected, expected, offered)

    async def capture_case(
        self,
        scenario: str,
        selected: str | None,
        expected: str,
        offered: tuple[str, ...],
    ) -> None:
        certificate = lifecycle.generate_certificate()
        server_type = lifecycle.LifecycleServer
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=certificate.certificate_pem.decode())
        context.set_alpn_protocols(list(offered))
        owners = []
        sent = []
        primary = ValueError("controlled stop after the complete response")
        test = self

        def server(run: lifecycle.Run) -> lifecycle.LifecycleServer:
            owner = server_type(run)
            owners.append(owner)
            return owner

        class WireDriver:
            def __init__(self, _plan: LaunchPlan, url: str) -> None:
                self.url = lifecycle.urlsplit(url)

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
                        expected,
                    )
                    target = (
                        ("/etag" if scenario == "revalidate" else "/start")
                        + "?"
                        + self.url.query
                    )
                    authority = f"{HOSTNAME}:{self.url.port}"
                    if expected == "http/1.1":
                        sent.extend((("Host", authority), ("aCcEpT", "*/*")))
                        writer.write(
                            f"GET {target} HTTP/1.1\r\nHost: {authority}\r\n"
                            "aCcEpT: */*\r\n\r\n".encode()
                        )
                        await writer.drain()
                        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                        test.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
                        length = next(
                            int(line.split(b":", 1)[1])
                            for line in head.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        )
                        body = await asyncio.wait_for(reader.readexactly(length), 5)
                    else:
                        client = h2.connection.H2Connection()
                        client.initiate_connection()
                        sent.extend(
                            (
                                (":method", "GET"),
                                (":scheme", "https"),
                                (":authority", authority),
                                (":path", target),
                                ("accept", "*/*"),
                            )
                        )
                        client.send_headers(1, sent, end_stream=True)
                        writer.write(client.data_to_send())
                        await writer.drain()
                        body = bytearray()
                        ended = False
                        while not ended:
                            data = await asyncio.wait_for(reader.read(65536), 5)
                            test.assertTrue(data, "response ended before END_STREAM")
                            for event in client.receive_data(data):
                                if isinstance(event, h2.events.DataReceived):
                                    body.extend(event.data)
                                elif isinstance(event, h2.events.StreamEnded):
                                    ended = True
                    if scenario == "revalidate":
                        test.assertEqual(body, b"v1")
                    else:
                        test.assertIn(b"<!doctype html>", body)
                finally:
                    writer.transport.abort()
                    with contextlib.suppress(ConnectionError, ssl.SSLError):
                        await asyncio.wait_for(writer.wait_closed(), 5)
                raise primary

            async def __aexit__(self, _kind, _value, _traceback) -> bool:
                return False

        with (
            patch.object(lifecycle, "generate_certificate", return_value=certificate),
            patch.object(lifecycle, "LifecycleServer", server),
            patch.object(lifecycle, "BrowserDriver", WireDriver),
            patch.object(lifecycle, "write_text_fixture") as publish,
            self.assertRaises(ValueError) as raised,
        ):
            await asyncio.wait_for(
                lifecycle.capture(options(scenario=scenario, protocol=selected)),
                5,
            )
        self.assertIs(raised.exception, primary)
        publish.assert_not_called()
        run = owners[0].run
        self.assertEqual(run.connections[0].alpn, expected)
        self.assertEqual(run.requests[0].status, 200)
        if scenario != "resources":
            self.assertEqual(run.requests[0].ordered_fields, tuple(sent))
        self.assertFalse(owners[0].protocols)
        self.assertTrue(all(item.waiter.done() for item in owners[0].listeners))


class HeaderPeerTests(unittest.IsolatedAsyncioTestCase):
    async def connect(self, scenario: str, protocol: str) -> None:
        certificate = lifecycle.generate_certificate()
        context = lifecycle.server_context(certificate)
        context.set_alpn_protocols([protocol])
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(
            cadata=certificate.certificate_pem.decode()
        )
        client_context.set_alpn_protocols([protocol])
        self.run = lifecycle.Run(scenario, "token", 1000)
        self.owner = lifecycle.LifecycleServer(self.run)
        self.addAsyncCleanup(self.retire)
        self.port = await self.owner.start("127.0.0.1", context, "main")
        self.origin = f"https://{HOSTNAME}:{self.port}"
        self.run.header_origin = self.origin
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1", self.port, ssl=client_context, server_hostname=HOSTNAME
            ),
            5,
        )
        self.assertEqual(
            self.writer.get_extra_info("ssl_object").selected_alpn_protocol(), protocol
        )

    async def retire(self) -> None:
        if hasattr(self, "writer"):
            # End the synthetic peer without waiting for a reciprocal TLS alert.
            self.writer.transport.abort()
            with contextlib.suppress(ConnectionError, ssl.SSLError):
                await asyncio.wait_for(self.writer.wait_closed(), 5)
        try:
            await self.owner.close(self.run.failure)
        except ValueError as error:
            if error is not self.run.failure or isinstance(
                error.__cause__, lifecycle.LifecycleFailures
            ):
                raise

    def evidence(self) -> dict[str, str]:
        return dict(
            line.split("=", 1)
            for line in lifecycle.fixture(
                options(scenario=self.run.scenario),
                LaunchPlan("chrome", Path("unused"), True),
                "synthetic peer",
                self.run,
                None,
            ).splitlines()
        )

    async def h1(
        self, method: str, target: str, extra: bytes = b"", body: bytes = b""
    ) -> bytes:
        self.writer.write(
            f"{method} {target} HTTP/1.1\r\nHost: {HOSTNAME}:{self.port}\r\n".encode()
            + extra
            + b"\r\n"
            + body
        )
        await self.writer.drain()
        head = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), 5)
        length = next(
            int(line.split(b":", 1)[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length:")
        )
        return await asyncio.wait_for(self.reader.readexactly(length), 5)

    async def test_h1_retains_case_duplicates_literals_and_completed_upload(
        self,
    ) -> None:
        await self.connect("upload-h1", "http/1.1")
        self.assertIn(b"<!doctype html>", await self.h1("GET", "/start?run=token"))
        extra = (
            b"aCcEpT: one\r\nAccept: two\r\nUser-Agent: \xa0literal\xa0\r\n"
            b"Content-Type: multipart/form-data; boundary=----actual\r\n"
            b"Content-Length: 3\r\n"
        )
        self.assertEqual(
            await self.h1("POST", "/post-small?run=token", extra, b"abc"), b"ok"
        )
        self.assertEqual(await self.h1("GET", "/done?run=token&result=ok"), b"ok")
        await self.owner.wait_done(5)

        evidence = self.evidence()
        self.assertEqual(
            json.loads(evidence["request_1_headers_json"]),
            [
                ["Host", f"{HOSTNAME}:{self.port}"],
                ["aCcEpT", "one"],
                ["Accept", "two"],
                ["User-Agent", "\xa0literal\xa0"],
                ["Content-Type", "multipart/form-data; boundary=----actual"],
                ["Content-Length", "3"],
            ],
        )
        self.assertIsNone(json.loads(evidence["request_1_priority"]))
        self.assertEqual(self.run.requests[1].body_bytes, 3)
        self.assertEqual(self.run.requests[1].status, 200)
        self.assertIn("boundary=<boundary>", evidence["request_1"])
        self.assertEqual(self.run.page_result, "ok")
        await self.retire()
        self.assertFalse(self.owner.protocols)

    async def h2_requests(
        self,
        scenario: str,
        request_method: bytes,
        request_target: bytes,
        upload: bytes = b"",
    ) -> tuple[list[list[tuple[bytes, bytes]]], dict[int, bytearray]]:
        await self.connect(scenario, "h2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(
                client_side=True, normalize_outbound_headers=False
            )
        )
        client.initiate_connection()
        sent = []
        for stream, method, target, body in (
            (1, b"GET", b"/start?run=token", b""),
            (3, request_method, request_target, upload),
            (5, b"GET", b"/done?run=token&result=ok", b""),
        ):
            fields = [
                (b":method", method),
                (b":scheme", b"https"),
                (b":authority", f"{HOSTNAME}:{self.port}".encode()),
                (b":path", target),
                (b"accept", b"one"),
                (b"accept", b"two"),
                (b"user-agent", b"\xa0literal\xa0"),
            ]
            if stream != 1:
                fields.append((b"referer", f"{self.origin}/start?run=token".encode()))
            if body:
                fields.extend(
                    [
                        (b"content-type", b"text/plain"),
                        (b"content-length", b"3"),
                        (b"origin", self.origin.encode()),
                    ]
                )
            sent.append(fields)
            client.send_headers(
                stream,
                fields,
                end_stream=not body,
                priority_weight=37,
                priority_depends_on=0,
                priority_exclusive=True,
            )
            if body:
                client.prioritize(stream, weight=9)
                client.send_data(stream, body, end_stream=True)
        self.writer.write(client.data_to_send())
        await self.writer.drain()
        completed = set()
        responses = {1: bytearray(), 3: bytearray(), 5: bytearray()}
        while len(completed) < 3:
            data = await asyncio.wait_for(self.reader.read(65536), 5)
            self.assertTrue(data, "peer ended before its complete responses")
            for event in client.receive_data(data):
                if isinstance(event, h2.events.DataReceived):
                    responses[event.stream_id].extend(event.data)
                elif isinstance(event, h2.events.StreamEnded):
                    completed.add(event.stream_id)
        await self.owner.wait_done(5)
        return sent, responses

    async def test_h2_retains_order_bytes_initial_priority_and_complete_bodies(
        self,
    ) -> None:
        sent, responses = await self.h2_requests(
            "upload-h2", b"POST", b"/post-small?run=token", b"abc"
        )
        evidence = self.evidence()
        self.assertEqual(
            json.loads(evidence["request_1_headers_json"]),
            [[n.decode("ascii"), v.decode("latin-1")] for n, v in sent[1]],
        )
        self.assertEqual(
            json.loads(evidence["request_1_priority"]),
            {"exclusive": True, "depends_on": 0, "weight": 37},
        )
        self.assertEqual(self.run.requests[1].initial_priority, Priority(True, 0, 37))
        self.assertEqual(self.run.requests[1].body_bytes, 3)
        self.assertIn(b"<!doctype html>", responses[1])
        self.assertEqual(responses[3], b"ok")
        self.assertEqual(responses[5], b"ok")
        await self.retire()
        self.assertFalse(self.owner.protocols)

    async def test_ordinary_h2_fetch_keeps_all_literals_without_no_store(self) -> None:
        sent, responses = await self.h2_requests(
            "revalidate", b"GET", b"/etag?run=token"
        )
        evidence = self.evidence()
        headers = json.loads(evidence["request_1_headers_json"])
        self.assertEqual(
            headers, [[n.decode("ascii"), v.decode("latin-1")] for n, v in sent[1]]
        )
        self.assertNotIn("cache-control", [name for name, _ in headers])
        self.assertEqual(responses[3], b"v1")
        self.assertEqual(self.run.requests[1].body_bytes, 0)
        self.assertEqual(self.run.requests[1].status, 200)
        self.assertEqual(self.run.page_result, "ok")
        await self.retire()
        self.assertFalse(self.owner.protocols)

    async def test_credential_failure_retains_no_values_and_retires_the_peer(
        self,
    ) -> None:
        await self.connect("revalidate", "http/1.1")
        self.writer.write(
            f"GET /start?run=token HTTP/1.1\r\nHost: {HOSTNAME}:{self.port}\r\n".encode()
            + b"Authorization: private-value\r\n\r\n"
        )
        await self.writer.drain()
        with self.assertRaisesRegex(ValueError, "unapproved header") as failed:
            await self.owner.wait_done(5)
        self.assertNotIn("private-value", str(failed.exception))
        self.assertEqual(self.run.requests, [])
        self.assertEqual(await asyncio.wait_for(self.reader.read(), 5), b"")
        await self.retire()
        self.assertFalse(self.owner.protocols)

    async def test_h2_rejects_separate_cookie_fields_without_normalizing_them(
        self,
    ) -> None:
        await self.connect("revalidate", "h2")
        client = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        client.initiate_connection()
        client.send_headers(
            1,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{HOSTNAME}:{self.port}".encode()),
                (b":path", b"/start?run=token"),
                (b"cookie", b"first=probe"),
                (b"cookie", b"second=probe"),
            ],
            end_stream=True,
        )
        original = self.run.record_headers
        observed = []

        def observe(
            request: lifecycle.RequestRecord,
            target: str,
            fields: list[tuple[str, str]],
            priority: Priority | None,
        ) -> None:
            observed.extend(fields)
            original(request, target, fields, priority)

        with patch.object(self.run, "record_headers", observe):
            self.writer.write(client.data_to_send())
            await self.writer.drain()
            with self.assertRaisesRegex(ValueError, "unapproved header") as failed:
                await self.owner.wait_done(5)
        self.assertEqual(
            [(n, v) for n, v in observed if n == "cookie"],
            [("cookie", "first=probe"), ("cookie", "second=probe")],
        )
        self.assertNotIn("probe", str(failed.exception))
        self.assertEqual(self.run.requests, [])
        await self.retire()
        self.assertFalse(self.owner.protocols)
