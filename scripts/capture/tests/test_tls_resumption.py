import asyncio
import socket
import ssl
import unittest
from dataclasses import replace
from pathlib import Path

from aioquic import tls
from cryptography.exceptions import InvalidTag

from scripts.capture.http2_session import HOSTNAME, generate_certificate
from scripts.capture.quic_resumption import PRE_SHARED_KEY, parse_client_hello
from scripts.capture.tls_resumption import (
    FORMAT,
    PARTITION_HOSTNAME,
    SCENARIOS,
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


class RetainedFixtureTests(unittest.TestCase):
    def test_every_retained_fixture_matches_its_scenario(self) -> None:
        paths = sorted(ROOT.glob("fixtures/tls/*/*/windows-11-26200/resumption-*.txt"))
        self.assertEqual(len(paths), 5 * len(SCENARIOS))
        for path in paths:
            fields = dict(
                line.split("=", 1)
                for line in path.read_text(encoding="ascii").splitlines()
            )
            scenario = SCENARIOS[fields["scenario"]]
            self.assertEqual(path.name, f"resumption-{scenario.name}.txt")
            self.assertEqual(fields["format"], FORMAT)
            self.assertEqual(fields["server_alpn"], scenario.alpn)
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


if __name__ == "__main__":
    unittest.main()
