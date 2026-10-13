import asyncio
import contextlib
import errno
import io
import socket
import ssl
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from aioquic import tls
from cryptography.exceptions import InvalidTag

from scripts.capture import tls_resumption as capture
from scripts.capture.http2_session import HOSTNAME, generate_certificate
from scripts.capture.quic_resumption import PRE_SHARED_KEY, parse_client_hello
from scripts.capture.tls_resumption import (
    FORMAT,
    FORMATS,
    PARTITION_HOSTNAME,
    SCENARIOS,
    WEBSOCKET_CLOSE,
    Http1Parser,
    RecordProtection,
    RunResult,
    TlsRecord,
    chromium_extra_arguments,
    firefox_cert_override,
    issue_ticket,
    launch_plan,
    offered_alpn,
    page_index,
    psk_identities,
    pull_record,
    render_fixture,
    render_page,
    server_name,
    serving,
)


def client_context(alpn: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols([alpn])
    return context


# One context for every connection: OpenSSL resumes a session only through
# the context that created it.
HTTP1_CLIENT = client_context("http/1.1")


def blocking_http1_request(
    port: int, path: str, session: ssl.SSLSession | None
) -> tuple[bytes, ssl.SSLSession, bool]:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with HTTP1_CLIENT.wrap_socket(
        raw, server_hostname=HOSTNAME, session=session
    ) as stream:
        stream.sendall(
            f"GET {path} HTTP/1.1\r\nhost: {HOSTNAME}:{port}\r\n\r\n".encode("ascii")
        )
        response = b""
        while chunk := stream.recv(65536):
            response += chunk
        return response, stream.session, stream.session_reused


async def http1_request(
    port: int, path: str, *, session: ssl.SSLSession | None = None
) -> tuple[bytes, ssl.SSLSession, bool]:
    """Send one GET over HTTP/1.1 and read until the server closes.

    OpenSSL reads the server's tickets while it reads the response, so the
    returned session can resume. The flag says whether this one resumed.
    """
    return await asyncio.to_thread(blocking_http1_request, port, path, session)


def certificates() -> dict:
    return {
        HOSTNAME: generate_certificate(HOSTNAME),
        PARTITION_HOSTNAME: generate_certificate(PARTITION_HOSTNAME),
    }


class RecordLayerTests(unittest.TestCase):
    def test_sealed_records_open_with_the_same_secret(self) -> None:
        for suite in (
            tls.CipherSuite.AES_128_GCM_SHA256,
            tls.CipherSuite.AES_256_GCM_SHA384,
            tls.CipherSuite.CHACHA20_POLY1305_SHA256,
        ):
            secret = bytes(
                range(48 if suite == tls.CipherSuite.AES_256_GCM_SHA384 else 32)
            )
            sealed = bytearray(RecordProtection(suite, secret).seal(22, b"x" * 20000))
            reader = RecordProtection(suite, secret)
            contents = []
            while (record := pull_record(sealed)) is not None:
                self.assertEqual(record.content_type, 23)
                contents.append(reader.open(record))
            self.assertEqual([kind for kind, _ in contents], [22, 22])
            self.assertEqual(b"".join(data for _, data in contents), b"x" * 20000)

    def test_a_record_that_fails_to_open_keeps_the_sequence(self) -> None:
        suite = tls.CipherSuite.AES_128_GCM_SHA256
        sealed = bytearray(RecordProtection(suite, b"\x01" * 32).seal(23, b"early"))
        record = pull_record(sealed)
        assert record is not None
        reader = RecordProtection(suite, b"\x02" * 32)
        with self.assertRaises(InvalidTag):
            reader.open(record)
        self.assertEqual(reader.sequence, 0)

    def test_partial_and_oversized_records(self) -> None:
        data = bytearray(b"\x16\x03\x01\x00\x05abc")
        self.assertIsNone(pull_record(data))
        self.assertEqual(len(data), 8)
        with self.assertRaises(ValueError):
            pull_record(bytearray(b"\x17\x03\x03\xff\xff"))

    def test_padding_is_removed_and_an_all_zero_record_is_rejected(self) -> None:
        suite = tls.CipherSuite.AES_128_GCM_SHA256
        writer = RecordProtection(suite, b"\x03" * 32)
        header = b"\x17\x03\x03\x00\x14"
        padded = writer.aead.encrypt(
            writer._nonce(), b"ab\x17\x00\x00", b"\x17\x03\x03\x00\x15"
        )
        reader = RecordProtection(suite, b"\x03" * 32)
        self.assertEqual(
            reader.open(TlsRecord(23, b"\x17\x03\x03\x00\x15", padded)), (23, b"ab")
        )
        empty = writer.aead.encrypt(writer._nonce(), b"\x00\x00\x00\x00", header)
        with self.assertRaises(ValueError):
            reader.open(TlsRecord(23, header, empty))


class PageAndParserTests(unittest.TestCase):
    def test_pages_resolve_placeholders_and_chain_to_the_next_page(self) -> None:
        origins = {
            "a": "https://server.phantom.test:1",
            "b": "https://server.phantom.test:2",
            "p": "https://top.partition.test:1",
        }
        scenario = SCENARIOS["partition"]
        first = render_page(scenario, 0, origins).decode()
        self.assertIn('"https://top.partition.test:1/page/1"', first)
        second = render_page(scenario, 1, origins).decode()
        self.assertIn(
            '["https://top.partition.test:1/retire", '
            '"https://server.phantom.test:1/retire"',
            second,
        )
        last = render_page(scenario, 2, origins).decode()
        self.assertIn("const next = null;", last)
        parallel = render_page(SCENARIOS["parallel"], 0, origins).decode()
        self.assertIn('["https://server.phantom.test:1/slow/0"', parallel)
        self.assertEqual(page_index("/"), 0)
        self.assertEqual(page_index("/page/2"), 2)
        self.assertIsNone(page_index("/retire"))

    def test_a_websocket_step_opens_the_wss_origin_after_the_page_connection_retires(
        self,
    ) -> None:
        origins = {
            "a": "https://server.phantom.test:1",
            "b": "https://server.phantom.test:2",
            "p": "https://top.partition.test:1",
            "w": "wss://server.phantom.test:1",
        }
        page = render_page(SCENARIOS["websocket-http1"], 0, origins).decode()
        self.assertIn(
            '["https://server.phantom.test:1/retire", '
            '{"websocket": "wss://server.phantom.test:1/socket"}, '
            '"https://server.phantom.test:1/done"]',
            page,
        )
        self.assertIn("new WebSocket(url)", page)
        self.assertNotIn("WEBSOCKET_WAIT", page)

    def test_http1_parser_splits_pipelined_requests_with_bodies(self) -> None:
        parser = Http1Parser()
        self.assertEqual(
            parser.feed(b"POST /a HTTP/1.1\r\ncontent-length: 3\r\n\r\nab"), []
        )
        requests = parser.feed(b"cGET /b HTTP/1.1\r\nhost: x\r\n\r\n")
        self.assertEqual(
            requests,
            [
                (b"POST /a HTTP/1.1", [(b"content-length", b"3")], 3),
                (b"GET /b HTTP/1.1", [(b"host", b"x")], 0),
            ],
        )

    def test_every_scenario_ends_the_run(self) -> None:
        for scenario in SCENARIOS.values():
            last_steps = scenario.pages[-1][1]
            self.assertTrue(str(last_steps[-1]).endswith("/done"), scenario.name)


class TicketTests(unittest.TestCase):
    def test_tickets_carry_early_data_only_when_the_scenario_permits_it(self) -> None:
        for early_data, expected in ((True, 0xFFFFFFFF), (False, None)):
            context = tls.Context(is_client=False)
            context.key_schedule = tls.KeySchedule(tls.CipherSuite.AES_128_GCM_SHA256)
            context.key_schedule.extract(None)
            message, ticket = issue_ticket(context, 3, early_data=early_data)
            parsed = tls.pull_new_session_ticket(tls.Buffer(data=message))
            self.assertEqual(parsed.ticket_nonce, b"")
            self.assertEqual(parsed.max_early_data_size, expected)
            self.assertEqual(ticket.max_early_data_size, expected)
            self.assertEqual(ticket.ticket, parsed.ticket)

    def test_no_early_data_scenario_is_the_only_one_without_early_data(self) -> None:
        self.assertEqual(
            [
                name
                for name, value in SCENARIOS.items()
                if not value.tickets_permit_early_data
            ],
            ["no-early-data"],
        )


ROOT = Path(__file__).resolve().parents[3]
# Scenarios captured only with Firefox, the one browser that offers early data
# over TCP.
FIREFOX_ONLY = {"websocket", "websocket-http1"}


class RetainedFixtureTests(unittest.TestCase):
    def test_every_retained_fixture_matches_its_scenario(self) -> None:
        paths = sorted(ROOT.glob("fixtures/tls/*/*/windows-11-26200/resumption-*.txt"))
        self.assertEqual(
            len(paths), 5 * len(SCENARIOS.keys() - FIREFOX_ONLY) + len(FIREFOX_ONLY)
        )
        for path in paths:
            fields = dict(
                line.split("=", 1)
                for line in path.read_text(encoding="ascii").splitlines()
            )
            scenario = SCENARIOS[fields["scenario"]]
            self.assertEqual(path.name, f"resumption-{scenario.name}.txt")
            self.assertIn(fields["format"], FORMATS)
            self.assertEqual(fields["server_alpn"], scenario.alpn)
            if scenario.name in FIREFOX_ONLY:
                self.assertEqual(fields["client"], "Mozilla Firefox")
                self.assertEqual(fields["format"], FORMAT)
                self.assertEqual(fields["server_websocket"], "true")
            self.assertEqual(
                int(fields["server_tickets_per_connection"]),
                scenario.tickets_per_connection,
            )
            self.assertEqual(
                fields["server_tickets_on"],
                "first_completed_handshake"
                if scenario.tickets_on_first_connection_only
                else "every_connection",
            )
            self.assertEqual(
                fields["server_ticket_max_early_data_size"] == "none",
                not scenario.tickets_permit_early_data,
            )
            self.assertEqual(fields["run_count"], "3")
            self.assertEqual(fields["launch_mode"], "headless")
            for index in range(3):
                self.assertEqual(fields[f"run_{index}_timed_out"], "false")
                self.assertEqual(fields[f"run_{index}_page_error"], "none")

    def test_retained_client_hellos_parse_and_resumed_ones_offer_one_psk(self) -> None:
        for path in ROOT.glob("fixtures/tls/*/*/windows-11-26200/resumption-*.txt"):
            for line in path.read_text(encoding="ascii").splitlines():
                key, _, value = line.partition("=")
                if not key.endswith("_client_hello_hex"):
                    continue
                shape = parse_client_hello(bytes.fromhex(value))
                identities = psk_identities(shape)
                if identities:
                    self.assertEqual(len(identities), 1, path.name)
                    self.assertEqual(shape.extension_types[-1], PRE_SHARED_KEY)


class LaunchTests(unittest.TestCase):
    def test_chromium_maps_both_names_and_trusts_both_certificates(self) -> None:
        arguments = chromium_extra_arguments("127.0.0.1", ["one", "two"])
        self.assertIn(
            "--host-resolver-rules=MAP server.phantom.test 127.0.0.1, "
            "MAP top.partition.test 127.0.0.1, MAP * ~NOTFOUND",
            arguments,
        )
        self.assertIn("--ignore-certificate-errors-spki-list=one,two", arguments)
        self.assertIn("--disable-quic", arguments)

    def test_firefox_overrides_each_name_on_each_port(self) -> None:
        values = certificates()
        text = firefox_cert_override([1, 2], values)
        for name in values:
            for port in (1, 2):
                self.assertIn(f"{name}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t", text)
        plan = launch_plan(
            "firefox",
            None,
            headless=True,
            listen_host="127.0.0.1",
            ports=[1, 2],
            certificates=values,
        )
        self.assertIn(
            ("network.dns.localDomains", "server.phantom.test,top.partition.test"),
            plan.firefox_preferences,
        )


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_openssl_client_resumes_a_recorded_ticket(self) -> None:
        scenario = SCENARIOS["sequential-http1"]
        async with serving(scenario, "127.0.0.1", certificates()) as server:
            port = int(server.origins["a"].rsplit(":", 1)[1])
            response, session, reused = await http1_request(port, "/retire")
            self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
            self.assertIn(b"connection: close\r\n", response)
            self.assertFalse(reused)
            _, _, reused = await http1_request(port, "/done", session=session)
            self.assertTrue(reused)
            await asyncio.wait_for(server.run.done.wait(), timeout=5)
        run = server.run
        self.assertIsNone(run.error)
        self.assertEqual(len(run.connections), 2)
        issued = run.connections[0].tickets_issued
        self.assertEqual(issued, ("connection_0.ticket_0", "connection_0.ticket_1"))
        resumed = run.connections[1]
        self.assertTrue(resumed.resumed)
        self.assertIn(resumed.psk_ticket_from, issued)
        self.assertEqual(resumed.offered_tickets, (resumed.psk_ticket_from,))
        self.assertEqual(resumed.alpn, "http/1.1")
        shape = parse_client_hello(resumed.client_hello)
        self.assertEqual(shape.extension_types[-1], PRE_SHARED_KEY)
        self.assertEqual(len(psk_identities(shape)), 1)
        self.assertEqual(server_name(shape), HOSTNAME)
        self.assertEqual(offered_alpn(shape), ("http/1.1",))
        self.assertEqual(
            [(request.path, request.connection) for request in run.requests],
            [("/retire", 0), ("/done", 1)],
        )

        result = RunResult(run, (port, port + 1), "manual", False)
        fixture = render_fixture(
            scenario,
            [result],
            client="test",
            client_version="0",
            operating_system="test",
            launch_mode="manual",
            listen_host="127.0.0.1",
        )
        self.assertTrue(fixture.startswith(f"format={FORMAT}\n"))
        self.assertIn("summary_client_hellos_resumed=1\n", fixture)
        self.assertIn(
            f"run_0_connection_1_psk_ticket_from={resumed.psk_ticket_from}\n", fixture
        )
        self.assertIn(
            "run_0_connection_1_versus_connection_0_added_extensions=", fixture
        )
        self.assertIn("run_0_connection_0_client_hello_hex=", fixture)
        fixture.encode("ascii")

    async def test_tickets_only_on_the_first_connection_when_the_scenario_says(
        self,
    ) -> None:
        scenario = replace(SCENARIOS["issue-once"], alpn="http/1.1")
        async with serving(scenario, "127.0.0.1", certificates()) as server:
            port = int(server.origins["a"].rsplit(":", 1)[1])
            # A connection abandoned before its handshake issues nothing, so
            # the next one to complete a handshake receives the tickets.
            await asyncio.to_thread(
                lambda: socket.create_connection(("127.0.0.1", port), timeout=5).close()
            )
            _, session, _ = await http1_request(port, "/retire")
            _, _, reused = await http1_request(port, "/retire", session=session)
            self.assertTrue(reused)
            await http1_request(port, "/done")
            await asyncio.wait_for(server.run.done.wait(), timeout=5)
        issued = [record.tickets_issued for record in server.run.connections]
        self.assertEqual(issued[0], ())
        self.assertEqual(len(issued[1]), scenario.tickets_per_connection)
        self.assertEqual(issued[2:], [(), ()])

    async def test_a_second_listener_serves_the_same_ticket_store(self) -> None:
        scenario = replace(SCENARIOS["origins"], alpn="http/1.1")
        async with serving(scenario, "127.0.0.1", certificates()) as server:
            port_a = int(server.origins["a"].rsplit(":", 1)[1])
            port_b = int(server.origins["b"].rsplit(":", 1)[1])
            _, session, _ = await http1_request(port_a, "/retire")
            _, _, reused = await http1_request(port_b, "/done", session=session)
            self.assertTrue(reused)
            await asyncio.wait_for(server.run.done.wait(), timeout=5)
        self.assertEqual(
            [record.listener for record in server.run.connections], ["a", "b"]
        )


class WebSocketServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_an_http1_websocket_opening_gets_101_and_a_close(self) -> None:
        scenario = SCENARIOS["websocket-http1"]
        async with serving(scenario, "127.0.0.1", certificates()) as server:
            port = int(server.origins["a"].rsplit(":", 1)[1])
            head, close = await asyncio.to_thread(blocking_http1_websocket, port)
            await http1_request(port, "/done")
            await asyncio.wait_for(server.run.done.wait(), timeout=5)
        self.assertTrue(head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"))
        # RFC 6455 section 1.3's sample key and answer.
        self.assertIn(b"sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n", head)
        self.assertEqual(close, WEBSOCKET_CLOSE)
        self.assertIsNone(server.run.error)
        self.assertEqual(
            [(request.method, request.path) for request in server.run.requests],
            [("GET", "/socket"), ("GET", "/done")],
        )
        self.assertEqual(server.run.connections[0].closed_by, "server")

    async def test_an_http2_websocket_opening_gets_200_and_a_close(self) -> None:
        scenario = SCENARIOS["websocket"]
        async with serving(scenario, "127.0.0.1", certificates()) as server:
            port = int(server.origins["a"].rsplit(":", 1)[1])
            enabled, status, data = await asyncio.to_thread(
                blocking_http2_websocket, port
            )
            await asyncio.wait_for(server.run.done.wait(), timeout=5)
        self.assertEqual(enabled, 1)
        self.assertEqual(status, b"200")
        self.assertEqual(data, WEBSOCKET_CLOSE)
        self.assertIsNone(server.run.error)
        self.assertEqual(
            [(request.method, request.path) for request in server.run.requests],
            [("CONNECT", "/socket"), ("GET", "/done")],
        )


# A masked client close frame with status 1000 and an all-zero mask.
CLIENT_CLOSE = b"\x88\x82\x00\x00\x00\x00\x03\xe8"


def blocking_http1_websocket(port: int) -> tuple[bytes, bytes]:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with HTTP1_CLIENT.wrap_socket(raw, server_hostname=HOSTNAME) as stream:
        stream.sendall(
            (
                f"GET /socket HTTP/1.1\r\nhost: {HOSTNAME}:{port}\r\n"
                "upgrade: websocket\r\nconnection: Upgrade\r\n"
                "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "sec-websocket-version: 13\r\n\r\n"
            ).encode("ascii")
        )
        received = b""
        while b"\r\n\r\n" not in received:
            chunk = stream.recv(65536)
            if not chunk:
                raise EOFError("peer closed before the WebSocket response head")
            received += chunk
        head, _, rest = received.partition(b"\r\n\r\n")
        stream.sendall(CLIENT_CLOSE)
        while chunk := stream.recv(65536):
            rest += chunk
        return head + b"\r\n\r\n", rest


def blocking_http2_websocket(port: int) -> tuple[int | None, bytes | None, bytes]:
    import h2.config
    import h2.connection
    import h2.events
    from h2.settings import SettingCodes

    authority = f"{HOSTNAME}:{port}".encode()
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with client_context("h2").wrap_socket(raw, server_hostname=HOSTNAME) as stream:
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        stream.sendall(client.data_to_send())
        enabled = status = None
        data = b""
        ended = False
        while not ended:
            chunk = stream.recv(65536)
            if not chunk:
                raise EOFError("peer closed before the WebSocket stream ended")
            for event in client.receive_data(chunk):
                if (
                    isinstance(event, h2.events.RemoteSettingsChanged)
                    and enabled is None
                ):
                    enabled = client.remote_settings.get(
                        SettingCodes.ENABLE_CONNECT_PROTOCOL
                    )
                    client.send_headers(
                        1,
                        [
                            (b":method", b"CONNECT"),
                            (b":protocol", b"websocket"),
                            (b":scheme", b"https"),
                            (b":path", b"/socket"),
                            (b":authority", authority),
                        ],
                    )
                elif isinstance(event, h2.events.ResponseReceived):
                    status = dict(event.headers)[b":status"]
                    client.send_data(1, CLIENT_CLOSE)
                elif isinstance(event, h2.events.DataReceived):
                    data += event.data
                    client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    ended = True
            stream.sendall(client.data_to_send())
        client.send_headers(
            3,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/done"),
                (b":authority", authority),
            ],
            end_stream=True,
        )
        stream.sendall(client.data_to_send())
        while chunk := stream.recv(65536):
            client.receive_data(chunk)
        return enabled, status, data


class CaptureBoundaryTests(unittest.TestCase):
    def test_complete_http1_heads_respect_the_declared_limit(self):
        prefix = b"GET / HTTP/1.1\r\nX-Pad: "
        for size in (capture.MAX_HEAD, capture.MAX_HEAD + 1):
            head = prefix + b"x" * (size - len(prefix) - 4) + b"\r\n\r\n"
            with self.subTest(size=size):
                if size == capture.MAX_HEAD:
                    self.assertEqual(len(Http1Parser().feed(head)), 1)
                else:
                    with self.assertRaises(ValueError):
                        Http1Parser().feed(head)

    def test_negative_content_length_is_not_a_complete_request(self):
        with self.assertRaises(ValueError):
            Http1Parser().feed(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\nx")

    def test_oversized_incomplete_client_hello_is_rejected_before_retention(self):
        server = capture.CaptureServer(SCENARIOS["sequential-http1"], {})
        connection = capture.Connection(server, "a", mock.Mock(), mock.Mock())
        header = b"\x01" + capture.MAX_CLIENT_HELLO.to_bytes(3, "big")
        record = TlsRecord(22, b"", header)
        with self.assertRaises(ValueError):
            connection.handle_record(record)
        self.assertLessEqual(len(connection.handshake_bytes), capture.MAX_CLIENT_HELLO)


class CaptureCompletionTests(unittest.IsolatedAsyncioTestCase):
    async def connect(self, server):
        port = int(server.origins["a"].rsplit(":", 1)[1])
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context("http/1.1"), server_hostname=HOSTNAME
        )
        writer.write(b"GET /hold HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b"ok")
        return reader, writer

    async def test_completed_response_failure_retains_the_original_cause(self):
        primary = OSError(errno.EIO, "original response completion failure")
        entered = asyncio.Event()
        release = asyncio.Event()
        finished = asyncio.Event()
        original = capture.Connection.respond
        tasks = []
        client = None

        async def respond(connection, request, delay):
            tasks.append(asyncio.current_task())
            await original(connection, request, delay)
            entered.set()
            await release.wait()
            finished.set()
            raise primary

        try:
            with mock.patch.object(capture.Connection, "respond", new=respond):
                with self.assertRaises(OSError) as raised:
                    async with serving(
                        SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                    ) as server:
                        client = await self.connect(server)
                        await asyncio.wait_for(entered.wait(), 5)
                        release.set()
                        await asyncio.wait_for(finished.wait(), 5)
                self.assertIs(raised.exception, primary)
        finally:
            release.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if client is not None:
                client[1].close()
                await client[1].wait_closed()

    async def test_unrelated_read_failure_is_not_a_peer_reset(self):
        primary = OSError(errno.EIO, "original accepted read failure")
        original = capture.Connection.serve
        entered = asyncio.Event()
        release = asyncio.Event()
        tasks = []
        client = None

        async def serve(connection):
            tasks.append(asyncio.current_task())
            read = connection.reader.read

            async def observed_read(size):
                if release.is_set():
                    raise primary
                data = await read(size)
                if entered.is_set():
                    raise primary
                return data

            with mock.patch.object(connection.reader, "read", new=observed_read):
                await original(connection)

        try:
            with mock.patch.object(capture.Connection, "serve", new=serve):
                with self.assertRaises(OSError) as raised:
                    async with serving(
                        SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                    ) as server:
                        client = await self.connect(server)
                        entered.set()
                        release.set()
                        # Wake the original read with actual TLS application bytes.
                        client[1].write(
                            b"GET /next HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
                        )
                        await client[1].drain()
                        await asyncio.wait_for(asyncio.shield(tasks[0]), 5)
                self.assertIs(raised.exception, primary)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if client is not None:
                client[1].close()
                await client[1].wait_closed()

    async def test_close_notify_failure_still_closes_the_original_writer(self):
        primary = OSError(errno.EIO, "original close_notify write failure")
        client = None
        try:
            async with serving(
                SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
            ) as server:
                client = await self.connect(server)
                connection = server.connections[0]
                with (
                    mock.patch.object(connection.writer, "write", side_effect=primary),
                    self.assertRaises(OSError) as raised,
                ):
                    connection.close_by("server")
                self.assertIs(raised.exception, primary)
                self.assertTrue(connection.writer.is_closing())
        finally:
            if "connection" in locals():
                connection.writer.transport.abort()
            if client is not None:
                client[1].close()
                with contextlib.suppress(
                    ConnectionResetError, ConnectionAbortedError, BrokenPipeError
                ):
                    await asyncio.wait_for(client[1].wait_closed(), 5)


class CaptureInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_waits_fail_before_certificate_or_listener_acquisition(self):
        for timeout in (0, -1, float("inf"), float("nan")):
            with (
                self.subTest(timeout=timeout),
                mock.patch.object(capture, "generate_certificate") as generate,
                self.assertRaises(ValueError),
            ):
                await capture.capture_run(
                    SCENARIOS["sequential-http1"],
                    browser="manual",
                    executable=None,
                    headless=False,
                    listen_host="127.0.0.1",
                    timeout=timeout,
                )
            generate.assert_not_called()

    def test_invalid_cli_metadata_and_repeats_fail_before_runs(self):
        base = ["--browser", "manual", "--client-version", "1"]
        cases = (
            ["--repeat", "0"],
            ["--timeout", "inf"],
            ["--timeout", "nan"],
            ["--client", "name\ninjected=value"],
            ["--client-version", "1\rnext=value"],
            ["--operating-system", "système"],
        )
        for args in cases:
            with (
                self.subTest(args=args),
                mock.patch.object(capture, "capture_run") as run,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                capture.main([*base, *args])
            self.assertEqual(raised.exception.code, 2)
            run.assert_not_called()

    def test_fixture_metadata_cannot_insert_new_records(self):
        valid = {
            "client": "test",
            "client_version": "1",
            "operating_system": "test",
            "launch_mode": "manual",
            "listen_host": "127.0.0.1",
        }
        result = RunResult(capture.RunRecord(), (1, 2), "manual", False)
        self.assertIn(
            "client=test\n",
            render_fixture(SCENARIOS["sequential-http1"], [result], **valid),
        )
        for field in valid:
            for invalid in (
                "value\nforged=true",
                "value\rforged=true",
                "value\vforged=true",
                "value\0",
                "café",
            ):
                with (
                    self.subTest(field=field, invalid=invalid),
                    self.assertRaises(ValueError),
                ):
                    render_fixture(
                        SCENARIOS["sequential-http1"],
                        [result],
                        **{**valid, field: invalid},
                    )
        with self.assertRaises(ValueError):
            render_fixture(
                SCENARIOS["sequential-http1"],
                [replace(result, launch_arguments="launch\nforged=true")],
                **valid,
            )


class CaptureRetirementTests(unittest.IsolatedAsyncioTestCase):
    connect = CaptureCompletionTests.connect

    async def test_caller_failure_collects_the_actual_response_and_accepted_peer(self):
        primary = OSError(errno.EINVAL, "original caller failure")
        entered = asyncio.Event()
        retired = asyncio.Event()
        original = capture.Connection.respond
        client = None

        async def respond(connection, request, delay):
            await original(connection, request, delay)
            entered.set()
            try:
                await asyncio.Future()
            finally:
                retired.set()

        try:
            with (
                mock.patch.object(capture.Connection, "respond", new=respond),
                self.assertRaises(OSError) as raised,
            ):
                async with serving(
                    SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                ) as server:
                    client = await self.connect(server)
                    await asyncio.wait_for(entered.wait(), 5)
                    raise primary
            self.assertIs(raised.exception, primary)
            self.assertTrue(retired.is_set())
            self.assert_retired(server)
        finally:
            await self.close_client(client)

    async def test_interrupted_cleanup_retains_caller_and_original_child_failure(self):
        primary = OSError(errno.EINVAL, "original interrupted caller")
        cleanup = ValueError("original cancelled response failure")
        entered = asyncio.Event()
        cancelling = asyncio.Event()
        interrupted = asyncio.Event()
        release = asyncio.Event()
        original_response = capture.Connection.respond
        original_failed = capture.CaptureServer.failed
        client = None
        server = None
        completed = asyncio.get_running_loop().create_future()

        async def respond(connection, request, delay):
            await original_response(connection, request, delay)
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError as cancellation:
                cancelling.set()
                await release.wait()
                raise cleanup from cancellation

        def failed(owner, error):
            original_failed(owner, error)
            if isinstance(error, asyncio.CancelledError):
                interrupted.set()

        async def run():
            nonlocal client, server
            try:
                async with serving(
                    SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                ) as owner:
                    server = owner
                    client = await self.connect(owner)
                    await entered.wait()
                    raise primary
            except BaseException as error:
                completed.set_result(error)
                raise

        with (
            mock.patch.object(capture.Connection, "respond", new=respond),
            mock.patch.object(capture.CaptureServer, "failed", new=failed),
        ):
            task = asyncio.create_task(run())
            try:
                await asyncio.wait_for(cancelling.wait(), 5)
                task.cancel()
                await asyncio.wait_for(interrupted.wait(), 5)
                release.set()
                done, pending = await asyncio.wait({task}, timeout=5)
                self.assertEqual(done, {task})
                self.assertFalse(pending)
                with self.assertRaises(asyncio.CancelledError):
                    await task
                failure = completed.result()
                self.assertIsInstance(failure, asyncio.CancelledError)
                self.assertIn(failure, server.failures)
                packet = failure.__cause__
                self.assertIsInstance(packet, capture.CaptureFailures)
                self.assertIs(packet.primary, primary)
                self.assertIn(cleanup, packet.cleanup)
                self.assertIs(packet.server, server)
                self.assert_retired(server)
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await self.close_client(client)

    async def test_connection_limit_closes_the_adopted_second_writer(self):
        client = second = None
        try:
            with (
                mock.patch.object(capture, "MAX_CONNECTIONS", 1),
                self.assertRaises(ValueError) as raised,
            ):
                async with serving(
                    SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                ) as server:
                    client = await self.connect(server)
                    port = int(server.origins["a"].rsplit(":", 1)[1])
                    second = await asyncio.open_connection("127.0.0.1", port)
                    self.assertEqual(await asyncio.wait_for(second[0].read(1), 5), b"")
            self.assertIs(raised.exception, server.failures[0])
            self.assertEqual(len(server.accepted), 2)
            self.assertIsNone(server.accepted[1].connection)
            self.assertTrue(server.accepted[1].writer.is_closing())
            self.assert_retired(server)
        finally:
            await self.close_client(second)
            await self.close_client(client)

    async def test_close_notify_and_close_failures_keep_both_original_causes(self):
        primary = OSError(errno.EIO, "original alert write")
        cleanup = ValueError("original writer close")
        client = None
        try:
            async with serving(
                SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
            ) as server:
                client = await self.connect(server)
                connection = server.connections[0]
                original_close = connection.writer.close

                def close():
                    original_close()
                    raise cleanup

                with (
                    mock.patch.object(connection.writer, "write", side_effect=primary),
                    mock.patch.object(connection.writer, "close", new=close),
                    self.assertRaises(OSError) as raised,
                ):
                    connection.close_by("server")
                self.assertIs(raised.exception, primary)
                packet = primary.__cause__
                self.assertIsInstance(packet, capture.CaptureFailures)
                self.assertEqual(packet.cleanup, (cleanup,))
                self.assertTrue(connection.writer.is_closing())
        finally:
            await self.close_client(client)

    async def test_peer_gone_response_preserves_an_independent_close_failure(self):
        async def check(with_cleanup):
            primary = BrokenPipeError("original response close_notify disconnect")
            cleanup = ValueError("original one-shot writer close failure")
            client = None
            raised = None
            closes = 0
            try:
                with contextlib.ExitStack() as patches:
                    try:
                        async with serving(
                            SCENARIOS["sequential-http1"],
                            "127.0.0.1",
                            certificates(),
                        ) as server:
                            client = await self.connect(server)
                            connection = server.connections[0]
                            original_write = connection.writer.write
                            original_close = connection.writer.close

                            def write(data):
                                if connection.closing:
                                    raise primary
                                original_write(data)

                            def close(with_close_failure=with_cleanup):
                                nonlocal closes
                                closes += 1
                                original_close()
                                if with_close_failure and closes == 1:
                                    raise cleanup

                            patches.enter_context(
                                mock.patch.object(connection.writer, "write", new=write)
                            )
                            patches.enter_context(
                                mock.patch.object(connection.writer, "close", new=close)
                            )
                            before = set(connection.tasks)
                            client[1].write(
                                b"GET /retire HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
                            )
                            await client[1].drain()
                            head = await asyncio.wait_for(
                                client[0].readuntil(b"\r\n\r\n"), 5
                            )
                            self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
                            self.assertIn(b"connection: close\r\n", head)
                            self.assertEqual(
                                await asyncio.wait_for(client[0].readexactly(2), 5),
                                b"ok",
                            )
                            response = connection.tasks - before
                            self.assertEqual(len(response), 1)
                            done, pending = await asyncio.wait(response, timeout=5)
                            self.assertEqual(done, response)
                            self.assertFalse(pending)
                    except BaseException as error:
                        raised = error
                self.assertGreaterEqual(closes, 2)
                self.assert_retired(server)
                if with_cleanup:
                    self.assertIsInstance(raised, capture.CaptureFailures)
                    self.assertTrue(any(error is primary for error in raised.cleanup))
                    self.assertTrue(any(error is cleanup for error in raised.cleanup))
                else:
                    self.assertIsNone(raised)
                    self.assertIsNone(server.run.error)
                    self.assertFalse(server.failures)
            finally:
                await self.close_client(client)

        for with_cleanup in (False, True):
            with self.subTest(with_cleanup=with_cleanup):
                await check(with_cleanup)

    async def test_completed_external_child_cancellation_is_observed(self):
        entered = asyncio.Event()
        original = capture.Connection.respond
        client = None

        async def respond(connection, request, delay):
            await original(connection, request, delay)
            entered.set()
            await asyncio.Future()

        try:
            with (
                mock.patch.object(capture.Connection, "respond", new=respond),
                self.assertRaises(asyncio.CancelledError) as raised,
            ):
                async with serving(
                    SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                ) as server:
                    client = await self.connect(server)
                    await asyncio.wait_for(entered.wait(), 5)
                    child = next(iter(server.connections[0].tasks))
                    child.cancel()
                    await asyncio.gather(child, return_exceptions=True)
            self.assertIs(raised.exception, server.failures[0])
            self.assert_retired(server)
        finally:
            await self.close_client(client)

    async def test_real_tls_eof_stops_both_websocket_workers(self):
        def close_after_input(connection, data):
            self.assertTrue(data)
            connection.close_by("server")

        for scenario, worker in (
            ("websocket-http1", blocking_http1_websocket),
            ("websocket", blocking_http2_websocket),
        ):
            with (
                self.subTest(scenario=scenario),
                mock.patch.object(
                    capture.Connection, "handle_application_data", new=close_after_input
                ),
            ):
                async with serving(
                    SCENARIOS[scenario], "127.0.0.1", certificates()
                ) as server:
                    port = int(server.origins["a"].rsplit(":", 1)[1])
                    with self.assertRaises(EOFError):
                        await asyncio.to_thread(worker, port)
                self.assert_retired(server)

    async def test_partial_second_listener_failure_collects_the_first_listener(self):
        primary = OSError(errno.EIO, "original second listener failure")
        loop = asyncio.get_running_loop()
        original_create = loop.create_server
        original_start = capture.CaptureServer.start
        owners = []
        calls = 0

        async def create(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise primary
            return await original_create(*args, **kwargs)

        async def start(owner, host):
            owners.append(owner)
            await original_start(owner, host)

        with (
            mock.patch.object(loop, "create_server", new=create),
            mock.patch.object(capture.CaptureServer, "start", new=start),
            self.assertRaises(OSError) as raised,
        ):
            async with serving(
                SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
            ):
                self.fail("a failed listener acquisition cannot start a run")
        self.assertIs(raised.exception, primary)
        self.assertEqual(len(owners[0].listeners), 1)
        self.assertFalse(owners[0].listeners[0].is_serving())
        self.assertEqual(owners[0].listeners[0].sockets, ())
        self.assert_retired(owners[0])

    async def test_cleanup_deadline_retains_the_actual_child_for_collection_retry(self):
        primary = OSError(errno.EINVAL, "original caller before cleanup deadline")
        entered = asyncio.Event()
        release = asyncio.Event()
        original = capture.Connection.respond
        client = None
        server = None

        async def respond(connection, request, delay):
            await original(connection, request, delay)
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await release.wait()

        try:
            with (
                mock.patch.object(capture.Connection, "respond", new=respond),
                mock.patch.object(capture, "CLEANUP_SECONDS", 0.2),
                self.assertRaises(OSError) as raised,
            ):
                async with serving(
                    SCENARIOS["sequential-http1"], "127.0.0.1", certificates()
                ) as server:
                    client = await self.connect(server)
                    await asyncio.wait_for(entered.wait(), 5)
                    raise primary
            self.assertIs(raised.exception, primary)
            packet = primary.__cause__
            self.assertIsInstance(packet, capture.CaptureFailures)
            self.assertIs(packet.server, server)
            self.assertTrue(
                any(isinstance(error, TimeoutError) for error in packet.cleanup)
            )
            self.assertFalse(server.finished)
            child = next(iter(server.connections[0].tasks))
            self.assertFalse(child.done())

            release.set()
            with self.assertRaises((capture.CaptureFailures, TimeoutError)):
                await server.close()
            self.assert_retired(server)
        finally:
            release.set()
            if server is not None:
                await asyncio.gather(
                    *(task for peer in server.connections for task in peer.tasks),
                    return_exceptions=True,
                )
            await self.close_client(client)

    async def test_capture_run_keeps_timeout_and_page_error_observations(self):
        for path in ("/hold", "/error"):
            with self.subTest(path=path):

                @contextlib.asynccontextmanager
                async def driver(plan, url, request_path=path):
                    port = int(url.rsplit(":", 1)[1].rstrip("/"))
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1",
                        port,
                        ssl=client_context("http/1.1"),
                        server_hostname=HOSTNAME,
                    )
                    try:
                        writer.write(
                            f"GET {request_path} HTTP/1.1\r\nHost: {HOSTNAME}\r\n\r\n".encode()
                        )
                        await writer.drain()
                        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
                        self.assertEqual(
                            await asyncio.wait_for(reader.readexactly(2), 5), b"ok"
                        )
                        yield
                    finally:
                        await self.close_client((reader, writer))

                with mock.patch.object(capture, "BrowserDriver", new=driver):
                    result = await capture.capture_run(
                        SCENARIOS["sequential-http1"],
                        browser="manual",
                        executable=None,
                        headless=False,
                        listen_host="127.0.0.1",
                        timeout=0.01,
                    )
                self.assertEqual(result.timed_out, path == "/hold")
                self.assertEqual(result.run.error, path if path == "/error" else None)
                self.assertEqual(
                    [request.path for request in result.run.requests], [path]
                )
                self.assertTrue(
                    all(
                        record.closed_ms is not None
                        for record in result.run.connections
                    )
                )

    def assert_retired(self, server):
        self.assertTrue(server.finished)
        self.assertTrue(all(task.done() for task in server.listener_tasks))
        for peer in server.accepted:
            self.assertTrue(peer.retired.done())
            self.assertTrue(peer.transport.is_closing())
            self.assertTrue(peer.close_task.done())
            if peer.task is not None:
                self.assertTrue(peer.task.done())
            if peer.connection is not None:
                self.assertTrue(all(task.done() for task in peer.connection.tasks))

    async def close_client(self, client):
        if client is not None:
            client[1].close()
            with contextlib.suppress(
                ConnectionResetError, ConnectionAbortedError, BrokenPipeError
            ):
                await asyncio.wait_for(client[1].wait_closed(), 5)


if __name__ == "__main__":
    unittest.main()
