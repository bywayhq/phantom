import asyncio
import unittest
from pathlib import Path

from scripts.capture import firefox_socket_hooks
from scripts.capture.firefox_socket_hooks import (
    AGENT,
    DECODER,
    EXTENSION,
    FORMAT,
    SCENARIOS,
    TARGET_HOST,
    Origins,
    browser_process,
    decode_ai_flags,
    decode_events,
    moz_log_lines,
    origin_sockets,
    recorded_arguments_placeholder,
    render_fixture,
    summarize,
    websocket_accept,
)
from scripts.capture.socket_hooks import file_digest

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "socket-hooks" / "firefox"


def sockaddr_in(port: int) -> str:
    return (
        b"\x02\x00" + port.to_bytes(2, "big") + bytes([127, 0, 0, 1]) + bytes(8)
    ).hex()


def sockaddr_in6(port: int) -> str:
    loopback = bytes(15) + b"\x01"
    return (
        b"\x17\x00" + port.to_bytes(2, "big") + bytes(4) + loopback + bytes(4)
    ).hex()


def report(kind: str, time_ms: int, **fields: object) -> dict[str, object]:
    return {"kind": kind, "time_ms": time_ms, "thread": 1, **fields}


class DecodingTests(unittest.TestCase):
    def test_address_info_flags_are_named(self) -> None:
        self.assertEqual(decode_ai_flags(0x2), "AI_CANONNAME")
        self.assertEqual(decode_ai_flags(0x402), "AI_CANONNAME|AI_ADDRCONFIG")
        self.assertEqual(decode_ai_flags(0), "0")
        self.assertEqual(decode_ai_flags(0x80002), "AI_CANONNAME|0x80000")

    def reports(self) -> list[dict[str, object]]:
        nodelay = {
            "level": 6,
            "option": 1,
            "value": "01000000",
            "caller": "WSOCK32.dll",
        }
        keepalive = "0100000010270000e8030000"
        return [
            report("firefox-config", 1000, rewrite_host=None, rewrite_to=None),
            # A socket the browser opened before the hooks attached.
            report("wsaioctl", 1001, socket="0x10", code=0x98000004, input=keepalive),
            report("socket", 1002, socket="0x20", family=23, type=1, protocol=6),
            report("setsockopt", 1002, socket="0x20", **nodelay),
            report("setsockopt-return", 1002, result=0),
            report("connect", 1003, socket="0x20", address=sockaddr_in6(8080)),
            report("connect-return", 1003, socket="0x20", result=-1, error=10035),
            report("socket", 1004, socket="0x30", family=2, type=1, protocol=6),
            report("setsockopt", 1004, socket="0x30", **nodelay),
            report("connect", 1253, socket="0x30", address=sockaddr_in(8080)),
            report("wsaioctl", 1255, socket="0x30", code=0x98000004, input=keepalive),
            report("socket-error", 3003, socket="0x20", value=10061),
            report("shutdown", 3004, socket="0x20", how=2, caller="nss3.dll"),
            report("close", 3004, socket="0x20"),
            report(
                "resolve-hints",
                1001,
                function="getaddrinfo",
                host=TARGET_HOST,
                flags=2,
                family=0,
                socktype=1,
                protocol=0,
                caller="nss3.dll",
            ),
            report(
                "resolve-hints",
                1001,
                function="getaddrinfo",
                host=TARGET_HOST,
                flags=2,
                family=0,
                socktype=1,
                protocol=0,
                caller="WS2_32.dll",
            ),
            report(
                "dnsquery-return",
                1002,
                function="DnsQuery_A",
                host=TARGET_HOST,
                query_type=1,
                status=0,
                records=[[1, 1, 3600], [6, 2, 3600]],
            ),
        ]

    def test_events_name_sockets_that_predate_the_hooks(self) -> None:
        events = decode_events(self.reports(), 1000)
        self.assertEqual(events[1]["socket"], "s0")
        self.assertEqual(events[1]["value"], "1/10000/1000")
        self.assertEqual(events[2]["socket"], "s1")
        self.assertNotIn("setsockopt-return", [event["kind"] for event in events])
        shutdown = next(event for event in events if event["kind"] == "shutdown")
        self.assertEqual(shutdown["how"], "SD_BOTH")
        query = next(event for event in events if event["kind"] == "dnsquery-return")
        self.assertEqual(query["records"], ["A/answer/3600", "6/authority/3600"])

    def test_origin_sockets_split_options_at_the_connect(self) -> None:
        sockets = origin_sockets(decode_events(self.reports(), 1000), 8080)
        self.assertEqual(len(sockets), 2)
        ipv6, ipv4 = sockets
        self.assertEqual(ipv6.address, "[::1]:8080")
        self.assertEqual(ipv6.before_connect, ["TCP_NODELAY=1"])
        self.assertEqual(ipv6.failed, "10061+2000")
        self.assertEqual(ipv6.after_connect, ["+2001:shutdown=SD_BOTH"])
        self.assertEqual(ipv6.closed, "+2001")
        self.assertEqual(ipv4.connect_ms, 253)
        self.assertEqual(ipv4.after_connect, ["+2:SIO_KEEPALIVE_VALS=1/10000/1000"])
        self.assertEqual(ipv4.closed, "open")

    def test_summary_keeps_the_browser_lookups_only(self) -> None:
        lines = dict(summarize(decode_events(self.reports(), 1000), 8080))
        self.assertEqual(lines["origin_tcp_socket_count"], "2")
        self.assertEqual(
            lines["origin_connect_attempts"], "3:[::1]:8080 253:127.0.0.1:8080"
        )
        self.assertEqual(
            lines["lookup_calls"],
            "1:getaddrinfo:flags=AI_CANONNAME:family=0 "
            "2:DnsQuery_A:A:status=0:A/answer/3600",
        )


class MozLogTests(unittest.TestCase):
    def test_lines_about_the_origin_are_kept_with_objects_renamed(self) -> None:
        stamp = "2026-10-02 12:00:00.250000 UTC - [Parent 1: Socket Thread]: "
        text = "\n".join(
            [
                stamp
                + "D/nsSocketTransport nsSocketTransport::ResolveHost "
                + f"[this=1a2b3c4d5e {TARGET_HOST}:8080] mProxyTransparentResolvesHost=0",
                stamp
                + "D/nsSocketTransport nsSocketTransport::SetKeepaliveVals [1a2b3c4d5e] "
                + "keepalive disabled, idle time[10s] retry interval[1s] packet count[10]",
                stamp
                + "D/nsSocketTransport nsSocketTransport::SetKeepaliveVals [9f9f9f9f9f] "
                + "keepalive disabled, idle time[10s] retry interval[1s] packet count[10]",
                stamp + "V/nsHttp nsHttpConnection::Init this=7777777777 "
                "sockettransport=1a2b3c4d5e forWebSocket=0",
                stamp + "V/nsHttp nsHttpConnection::DisableTCPKeepalives [7777777777]",
                stamp + "V/nsHttp unrelated line [7777777777]",
                "not a log line",
            ]
        )
        start = 1790942400000
        self.assertEqual(
            moz_log_lines(text, 8080, start),
            [
                f"250 nsSocketTransport nsSocketTransport::ResolveHost [this=p0 "
                f"{TARGET_HOST}:8080] mProxyTransparentResolvesHost=0",
                "250 nsSocketTransport nsSocketTransport::SetKeepaliveVals [p0] "
                "keepalive disabled, idle time[10s] retry interval[1s] packet count[10]",
                "250 nsHttp nsHttpConnection::Init this=p1 sockettransport=p0 "
                "forWebSocket=0",
                "250 nsHttp nsHttpConnection::DisableTCPKeepalives [p1]",
            ],
        )


class LaunchTests(unittest.TestCase):
    def test_the_parent_process_is_the_launcher_child(self) -> None:
        launcher = {
            "ProcessId": 1,
            "ParentProcessId": 9,
            "CommandLine": "firefox.exe -p",
        }
        parent = {"ProcessId": 2, "ParentProcessId": 1, "CommandLine": "firefox.exe -p"}
        content = {
            "ProcessId": 3,
            "ParentProcessId": 2,
            "CommandLine": "firefox.exe -contentproc -p",
        }
        self.assertEqual(browser_process([launcher, parent, content]), 2)
        self.assertEqual(browser_process([launcher, content]), 1)
        self.assertIsNone(browser_process([content]))

    def test_recorded_arguments_drop_the_run_port(self) -> None:
        self.assertEqual(
            recorded_arguments_placeholder("--headless http://127.0.0.1:51234/"),
            "--headless http://127.0.0.1:<port>/",
        )

    def test_fixture_header_names_every_digest(self) -> None:
        text = render_fixture(
            client_version="157.0",
            build_id="1",
            operating_system="test",
            frida_version="0",
            launch_arguments="--x",
            scenario=SCENARIOS["backup"],
            runs=[["run_0_event_count=0"]],
        )
        fields = dict(line.split("=", 1) for line in text.splitlines())
        self.assertEqual(fields["format"], FORMAT)
        self.assertEqual(fields["browser"], "Mozilla Firefox")
        self.assertEqual(fields["hook_agent_sha256"], file_digest(AGENT))
        self.assertEqual(fields["hook_agent_extension_sha256"], file_digest(EXTENSION))
        self.assertEqual(fields["decoder_sha256"], file_digest(DECODER))
        self.assertIn("[::1] then 127.0.0.1", fields["hook_intervention"])
        self.assertTrue(text.endswith("run_0_event_count=0\n"))


class OriginTests(unittest.TestCase):
    def test_websocket_accept_matches_rfc_6455(self) -> None:
        self.assertEqual(
            websocket_accept(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )

    def test_page_waits_for_the_hooks_before_the_target(self) -> None:
        origins = Origins(SCENARIOS["h2"], port=4242)
        page = origins.page().decode()
        self.assertIn(f"const T = 'https://{TARGET_HOST}:4242'", page)
        self.assertLess(page.index("fetch('/go'"), page.index("T + '/fast?i=0'"))

    def exchange(self, scenario: str, requests: bytes) -> tuple[bytes, Origins]:
        async def run() -> tuple[bytes, Origins]:
            origins = Origins(SCENARIOS[scenario])
            server = await asyncio.start_server(origins.handle_target, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(requests)
                await writer.drain()
                received = await reader.read(4096)
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(0.1)
            return received, origins

        return asyncio.run(run())

    def test_close_path_ends_the_connection_from_the_origin(self) -> None:
        received, origins = self.exchange(
            "dns-cache", b"GET /close?i=0 HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        self.assertIn(b"Connection: close", received)
        self.assertEqual(origins.connections[0].close_kind, "server")

    def test_a_client_close_is_recorded_as_end_of_stream(self) -> None:
        received, origins = self.exchange(
            "http1-idle", b"GET /fast?i=0 HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        self.assertIn(b"Connection: keep-alive", received)
        self.assertEqual(origins.connections[0].close_kind, "fin")
        self.assertEqual(origins.connections[0].requests[0][1], "/fast?i=0")

    def test_websocket_upgrade_answers_101(self) -> None:
        received, _ = self.exchange(
            "websocket",
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        self.assertIn(b"101 Switching Protocols", received)
        self.assertIn(b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", received)


class RetainedFixtureTests(unittest.TestCase):
    def test_retained_logs_name_the_agents_and_tools_they_were_taken_with(self) -> None:
        paths = sorted(FIXTURES.glob("*/*/hooks-*.txt"))
        self.assertTrue(paths)
        tool = Path(firefox_socket_hooks.__file__)
        for path in paths:
            with self.subTest(path=path.relative_to(FIXTURES)):
                fields = dict(
                    line.split("=", 1)
                    for line in path.read_text(encoding="ascii").splitlines()
                )
                self.assertEqual(fields["format"], FORMAT)
                self.assertEqual(fields["evidence"], "hook")
                self.assertEqual(fields["browser"], "Mozilla Firefox")
                self.assertEqual(fields["hook_agent_sha256"], file_digest(AGENT))
                self.assertEqual(
                    fields["hook_agent_extension_sha256"], file_digest(EXTENSION)
                )
                self.assertEqual(fields["capture_tool_sha256"], file_digest(tool))
                self.assertEqual(fields["decoder_sha256"], file_digest(DECODER))
                for run in range(int(fields["run_count"])):
                    self.assertEqual(fields[f"run_{run}_timed_out"], "false")
                    self.assertEqual(fields[f"run_{run}_hook_error_count"], "0")


if __name__ == "__main__":
    unittest.main()
