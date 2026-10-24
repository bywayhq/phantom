"""Scripted EventSource captures over actual loopback TLS H2."""

import asyncio
import contextlib
import dataclasses
import ssl
import unittest
from unittest import mock
from urllib.parse import urlsplit

import h2.events
from h2.config import H2Configuration
from h2.connection import H2Connection

from scripts.capture.sse_multiplexed import H2ReconnectServer
from scripts.capture.sse_reconnect import (
    CATALOG,
    PROBE_COOKIE,
    ScenarioRun,
    capture_scenario,
    fixture,
)
from scripts.capture.tests.test_sse_reconnect import (
    METADATA,
    ScriptedEventSource,
)

# Literal wire bytes: SETTINGS 4=1000, 1=4096; connection credit +123;
# a split HPACK GET header block on stream 1, then unrelated DATA.
STARTUP = bytes.fromhex(
    "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
    "00000c0400000000000004000003e8000100001000"
    "0000040800000000000000007b"
    "00000101010000000182"
    "0000020904000000018784"
)


class H2StartupTests(unittest.TestCase):
    def test_literal_startup_preserves_order_and_exact_boundary(self):
        from scripts.capture.sse_multiplexed import decode_h2_startup

        result = decode_h2_startup(STARTUP + bytes.fromhex("000000000100000001"))
        self.assertEqual(result.wire, STARTUP)
        self.assertEqual(result.settings, ((4, 1000), (1, 4096)))
        self.assertEqual(result.connection_window_updates, (123,))
        self.assertEqual(result.first_stream_id, 1)

    def test_every_fragment_and_truncation_waits_for_complete_headers(self):
        from scripts.capture.sse_multiplexed import decode_h2_startup

        for boundary in range(len(STARTUP)):
            with self.subTest(boundary=boundary):
                self.assertIsNone(decode_h2_startup(STARTUP[:boundary]))
                pending = bytearray(STARTUP[:boundary])
                pending.extend(STARTUP[boundary:])
                self.assertEqual(decode_h2_startup(bytes(pending)).wire, STARTUP)

    def test_default_connection_credit_needs_no_window_update(self):
        from scripts.capture.sse_multiplexed import decode_h2_startup

        wire = STARTUP[:45] + STARTUP[58:]
        result = decode_h2_startup(wire)
        self.assertEqual(result.connection_window_updates, ())
        self.assertEqual(result.wire, wire)

    def test_startup_is_bounded_and_requires_preface_and_initial_settings(self):
        from scripts.capture.sse_multiplexed import (
            MAX_H2_STARTUP,
            decode_h2_startup,
        )

        for wire in (b"x" * 24, STARTUP[:24] + STARTUP[45:]):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                decode_h2_startup(wire)
        with self.assertRaisesRegex(ValueError, "startup.*limit"):
            decode_h2_startup(b"x" * (MAX_H2_STARTUP + 1))


class H2EventSource(ScriptedEventSource):
    async def start(self, server):
        context = ssl.create_default_context(
            cadata=server.certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["h2"])
        self.reader, self.writer = await asyncio.open_connection(
            "127.0.0.1",
            server.address[1],
            ssl=context,
            server_hostname="server.phantom.test",
        )
        if self.writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            raise AssertionError("client did not negotiate h2")
        self.engine = H2Connection(
            H2Configuration(header_encoding=None, normalize_outbound_headers=False)
        )
        self.engine.initiate_connection()
        self.writer.write(self.engine.data_to_send())
        await self.writer.drain()

    async def close(self):
        if not self.reader.at_eof():
            # Stop H2 responses and consume queued data before TLS close_notify.
            self.engine.close_connection()
            self.writer.write(self.engine.data_to_send())
            await self.writer.drain()
            await asyncio.wait_for(self.reader.read(), 2)
        self.writer.close()
        await asyncio.wait_for(self.writer.wait_closed(), 2)

    async def fetch(self, url, fields):
        parts = urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", parts.netloc.encode()),
            (b":path", target.encode()),
        ]
        headers.extend(
            (name.lower(), value.strip())
            for name, _, value in (field.partition(b":") for field in fields)
        )
        stream = self.engine.get_next_available_stream_id()
        self.engine.send_headers(stream, headers, end_stream=False)
        self.engine.send_data(stream, b"", end_stream=True)
        self.writer.write(self.engine.data_to_send())
        await self.writer.drain()
        result_headers = {}
        body = bytearray()
        while True:
            data = await self.reader.read(64 * 1024)
            if not data:
                raise ConnectionError("H2 connection ended before response")
            ended = False
            reset = False
            for event in self.engine.receive_data(data):
                if (
                    isinstance(event, h2.events.ResponseReceived)
                    and event.stream_id == stream
                ):
                    result_headers = dict(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    self.engine.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id == stream:
                        body.extend(event.data)
                elif (
                    isinstance(event, h2.events.StreamEnded)
                    and event.stream_id == stream
                ):
                    ended = True
                elif (
                    isinstance(event, h2.events.StreamReset)
                    and event.stream_id == stream
                ):
                    reset = True
            self.writer.write(self.engine.data_to_send())
            await self.writer.drain()
            if reset:
                raise ConnectionResetError("SSE stream reset")
            if ended:
                return self.response(result_headers, bytes(body))

    async def abort_response(self, stream):
        self.engine.reset_stream(stream, 8)
        self.writer.write(self.engine.data_to_send())
        await self.writer.drain()

    def response(self, headers, body):
        if b"set-cookie" in headers:
            self.cookies.append(headers[b"set-cookie"].split(b";")[0])
        return int(headers[b":status"]), headers, body


def quick(scenario):
    attempts = tuple(
        dataclasses.replace(
            stimulus,
            body=stimulus.body.replace(b"retry: 750", b"retry: 10")
            .replace(b"retry: 600", b"retry: 10")
            .replace(b"retry: 200", b"retry: 10")
            .replace(b"retry: 100", b"retry: 10"),
            hold_seconds=min(stimulus.hold_seconds, 0.02),
        )
        for stimulus in scenario.attempts
    )
    return dataclasses.replace(scenario, attempts=attempts, observation_seconds=0.02)


@contextlib.asynccontextmanager
async def drive_source(client, server):
    await client.start(server)
    task = asyncio.create_task(client.run())
    try:
        yield
    finally:
        task.cancel()
        try:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        finally:
            await client.close()


class H2CaptureTests(unittest.IsolatedAsyncioTestCase):
    server_type = H2ReconnectServer
    client_type = H2EventSource
    protocol = "h2"

    async def capture(self, scenario, *, repeat=1, **options):
        server = self.server_type()
        await server.start("127.0.0.1", 0)
        try:

            def drive(url):
                return drive_source(
                    self.client_type(url, default_delay=0.01, **options), server
                )

            runs = await capture_scenario(
                server, quick(scenario), repeat=repeat, run_timeout=4, drive=drive
            )
            self.assertFalse(server.tasks)
            self.assertFalse(server.writers)
            return runs
        finally:
            await server.close()

    async def test_catalog_uses_actual_protocol_and_distinct_reused_streams(self):
        for scenario in CATALOG:
            with self.subTest(scenario=scenario.name):
                runs = await self.capture(scenario)
                run = runs[0]
                self.assertIsNotNone(run.terminated)
                self.assertEqual(len(run.connections), 1)
                self.assertEqual(run.connections[0].protocol, self.protocol)
                requests = [
                    request for request in run.requests if request.kind == "sse"
                ]
                self.assertEqual(len(requests), len(scenario.attempts))
                self.assertEqual(
                    [request.attempt for request in requests],
                    list(range(len(scenario.attempts))),
                )
                self.assertEqual(
                    len({request.stream_id for request in run.requests}),
                    len(run.requests),
                )
                self.assertTrue(
                    all(request.connection_request > 0 for request in requests)
                )
                self.assertTrue(
                    all(
                        request.decoded_headers[0] == (b":method", b"GET")
                        for request in run.requests
                    )
                )
                self.assertEqual(requests[-1].stimulus, "end-stream")
                if scenario.name == "reset-before-head":
                    self.assertEqual(
                        [request.stimulus for request in requests[:-1]],
                        ["stream-reset"] * 3,
                    )
                if scenario.name in {"id-then-close", "redirect-307-then-close"}:
                    self.assertEqual(
                        requests[-1].header(b"last-event-id"), b"phantom-1"
                    )
                if scenario.name == "empty-id-resets":
                    self.assertEqual(requests[1].header(b"last-event-id"), b"phantom-1")
                    self.assertIsNone(requests[2].header(b"last-event-id"))
                if scenario.name == "non-ascii-id":
                    self.assertEqual(
                        requests[1].header(b"last-event-id"), "é-☃".encode()
                    )
                if scenario.name == "set-cookie-then-close":
                    self.assertEqual(requests[1].header(b"cookie"), PROBE_COOKIE)
                text = fixture(
                    quick(scenario),
                    runs,
                    dataclasses.replace(METADATA, protocol=self.protocol),
                )
                self.assertIn("format=phantom-sse-reconnect-v2", text)
                self.assertIn(f"_alpn={self.protocol}", text)
                self.assertIn("header_encoding=ordered-decoded-name-value-bytes", text)
                self.assertIn("_field_0=3a6d6574686f64:474554", text)
                if self.protocol == "h2":
                    from scripts.capture.sse_multiplexed import decode_h2_startup

                    startup = decode_h2_startup(run.connections[0].h2_startup)
                    self.assertEqual(startup.first_stream_id, run.requests[0].stream_id)
                    self.assertIn(f"_h2_startup_hex={startup.wire.hex()}", text)
                    self.assertIn("_h2_startup_settings=", text)
                    self.assertIn("_h2_startup_connection_credit=65535", text)

    async def test_ordered_fields_keep_cookie_in_its_opening_position(self):
        runs = await self.capture(
            CATALOG[0],
            extra_headers=(
                b"X-Before: a",
                b"Cookie: phantom_probe=1",
                b"X-After: z",
            ),
        )
        request = next(request for request in runs[0].requests if request.kind == "sse")
        fields = request.decoded_headers
        index = fields.index((b"x-before", b"a"))
        self.assertEqual(
            fields[index : index + 3],
            [
                (b"x-before", b"a"),
                (b"cookie", PROBE_COOKIE),
                (b"x-after", b"z"),
            ],
        )

    async def test_credentials_prevent_fixture_publication_and_cleanup(self):
        connections = []
        original = self.server_type.record_connection

        def record(server, *args):
            result = original(server, *args)
            connections.append(result[0])
            return result

        with (
            mock.patch.object(self.server_type, "record_connection", record),
            self.assertRaisesRegex(ValueError, "credential-bearing"),
        ):
            await self.capture(CATALOG[0], extra_headers=(b"Authorization: probe",))
        self.assertTrue(connections)
        if self.protocol == "h2":
            from hpack import Decoder

            from scripts.capture.http2_analysis import headers_priority, split_frames

            for connection in connections:
                frames, trailing = split_frames(
                    [(0, connection.h2_startup)], "client", preface=True
                )
                self.assertEqual(trailing, 0)
                block = b"".join(
                    headers_priority(frame)[1]
                    if frame.frame_type == 1
                    else frame.payload
                    for frame in frames
                    if frame.frame_type in (1, 9)
                )
                names = {name for name, _ in Decoder().decode(block, raw=True)}
                self.assertNotIn(b"authorization", names)
                self.assertNotIn(b"proxy-authorization", names)

    async def test_foreign_cookie_prevents_fixture_publication_and_cleanup(self):
        with self.assertRaisesRegex(ValueError, "cookie the scenario did not set"):
            await self.capture(CATALOG[0], extra_headers=(b"Cookie: foreign=1",))

    async def test_repeated_runs_retire_previous_connection_owners(self):
        runs = await self.capture(CATALOG[0], repeat=2)
        self.assertEqual(len(runs), 2)
        self.assertNotEqual(runs[0].token, runs[1].token)
        self.assertTrue(all(len(run.connections) == 1 for run in runs))
        self.assertTrue(all(run.terminated is not None for run in runs))

    async def test_client_stream_cancellation_is_recorded_and_worker_retires(self):
        server = self.server_type()
        await server.start("127.0.0.1", 0)
        opened = asyncio.Event()
        reset = asyncio.Event()
        original_opening, original_reset = server.opening, server.client_reset

        def opening(*args):
            result = original_opening(*args)
            opened.set()
            return result

        def client_reset(*args):
            original_reset(*args)
            reset.set()

        server.opening, server.client_reset = opening, client_reset
        run = ScenarioRun(CATALOG[-3], "cancel-probe")
        server.run = run
        client = self.client_type(server.url(run))
        task = None
        started = False
        try:
            await client.start(server)
            started = True
            task = asyncio.create_task(
                client.fetch(
                    server.url(run).replace(run.page_path(), run.stream_path()), ()
                )
            )

            await asyncio.wait_for(opened.wait(), 2)
            request = run.requests[0]
            await client.abort_response(request.stream_id)
            await asyncio.wait_for(reset.wait(), 2)
            self.assertEqual(request.stimulus, "client-stream-reset")
            self.assertEqual(
                request.client_reset_code, 8 if self.protocol == "h2" else 0x10C
            )
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                    await task
            try:
                if started:
                    await client.close()
            finally:
                await server.close()
        self.assertFalse(server.tasks)
        self.assertFalse(server.writers)

    async def test_timeout_retires_idle_stream_workers(self):
        server = self.server_type()
        await server.start("127.0.0.1", 0)
        scenario = dataclasses.replace(CATALOG[-3], observation_seconds=0.01)

        def idle(url):
            return drive_source(self.client_type(url, default_delay=0.01), server)

        try:
            with self.assertRaises(asyncio.TimeoutError):
                await capture_scenario(
                    server, scenario, repeat=1, run_timeout=0.02, drive=idle
                )
            self.assertIsNone(server.run)
            self.assertFalse(server.tasks)
            self.assertFalse(server.writers)
        finally:
            await server.close()


class H2StartupPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_request_credentials_leave_no_retained_startup(self):
        server = H2ReconnectServer()
        await server.start("127.0.0.1", 0)
        run = ScenarioRun(CATALOG[0], "credential-probe")
        server.run = run
        client = H2EventSource(server.url(run))
        try:
            await client.start(server)
            remote_settings = acknowledged = False
            while not (remote_settings and acknowledged):
                data = await asyncio.wait_for(client.reader.read(65536), 2)
                self.assertTrue(data)
                for event in client.engine.receive_data(data):
                    if isinstance(event, h2.events.RemoteSettingsChanged):
                        remote_settings = True
                    elif isinstance(event, h2.events.SettingsAcknowledged):
                        acknowledged = True
                client.writer.write(client.engine.data_to_send())
                await client.writer.drain()

            client.engine.send_headers(
                1,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"server.phantom.test"),
                    (b":path", run.page_path().encode()),
                    (b"authorization", b"probe"),
                ],
                end_stream=True,
            )
            client.writer.write(client.engine.data_to_send())
            await client.writer.drain()
            # The peer rejects this request and closes TLS. Do not send an ACK
            # or GOAWAY after its close_notify while draining that rejection.
            self.assertEqual(await asyncio.wait_for(client.reader.read(), 2), b"")
            self.assertEqual(len(run.connections), 1)
            self.assertEqual(run.connections[0].h2_startup, b"")
            with self.assertRaisesRegex(ValueError, "credential-bearing"):
                fixture(CATALOG[0], [run], dataclasses.replace(METADATA, protocol="h2"))
        finally:
            try:
                client.writer.close()
                await asyncio.wait_for(client.writer.wait_closed(), 2)
            finally:
                with self.assertRaisesRegex(ValueError, "credential-bearing"):
                    await server.close()
        self.assertFalse(server.tasks)
        self.assertFalse(server.writers)

    async def test_bytewise_client_startup_retains_only_first_header_block(self):
        server = H2ReconnectServer()
        await server.start("127.0.0.1", 0)
        run = ScenarioRun(CATALOG[0], "fragment-probe")
        server.run = run
        client = H2EventSource(server.url(run))
        context = ssl.create_default_context(
            cadata=server.certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["h2"])
        client.reader, client.writer = await asyncio.open_connection(
            "127.0.0.1",
            server.address[1],
            ssl=context,
            server_hostname="server.phantom.test",
        )
        client.engine = H2Connection(H2Configuration(header_encoding=None))
        client.engine.initiate_connection()
        client.engine.send_headers(
            1,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"server.phantom.test"),
                (b":path", run.page_path().encode()),
            ],
            end_stream=True,
        )
        wire = client.engine.data_to_send()
        try:
            for byte in wire:
                client.writer.write(bytes([byte]))
                await client.writer.drain()
                await asyncio.sleep(0)
            ended = False
            while not ended:
                data = await asyncio.wait_for(client.reader.read(65536), 2)
                self.assertTrue(data)
                ended = any(
                    isinstance(event, h2.events.StreamEnded)
                    for event in client.engine.receive_data(data)
                )
            self.assertEqual(run.connections[0].h2_startup, wire)
            await client.fetch(server.url(run), ())
            self.assertEqual(run.connections[0].h2_startup, wire)
        finally:
            try:
                await client.close()
            finally:
                await server.close()
        self.assertFalse(server.tasks)
        self.assertFalse(server.writers)


class MatrixProtocolTests(unittest.TestCase):
    def test_explicit_protocol_jobs_have_distinct_ids_and_outputs(self):
        from pathlib import Path

        from scripts.capture.run_matrix import expand_manifest

        manifest = {
            "operating_system": "scripted",
            "browsers": {"chrome": {"path": "unused-browser", "version": "0"}},
            "captures": [
                {
                    "tool": "sse_reconnect",
                    "browsers": ["chrome"],
                    "scenarios": ["reconnect-204"],
                    "repeat": 1,
                    "args": ["--protocol", protocol],
                    "output_dir": f"out/{protocol}",
                }
                for protocol in ("h1", "h2", "h3")
            ],
        }
        jobs = expand_manifest(manifest, base=Path.cwd())
        self.assertEqual(
            [job.id for job in jobs],
            [
                f"sse_reconnect/chrome/reconnect-204/{protocol}"
                for protocol in ("h1", "h2", "h3")
            ],
        )
        self.assertEqual(len({job.outputs[0] for job in jobs}), 3)
        manifest["captures"] = [manifest["captures"][0]]
        manifest["captures"][0]["args"] = []
        self.assertEqual(
            expand_manifest(manifest, base=Path.cwd())[0].id,
            "sse_reconnect/chrome/reconnect-204",
        )
