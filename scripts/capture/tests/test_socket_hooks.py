import asyncio
import unittest
from pathlib import Path

from scripts.capture import socket_hooks
from scripts.capture.socket_hooks import (
    AGENT,
    FORMAT,
    LOOKUP_HOST,
    SCENARIOS,
    Origin,
    decode_events,
    decode_keepalive,
    decode_option,
    decode_sockaddr,
    dns_question,
    file_digest,
    ipv4_after_ipv6,
    is_network_service,
    merged_disabled_features,
    portable_argv,
    render_fixture,
    summarize,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "socket-hooks"


def sockaddr_in(address: bytes, port: int) -> str:
    return (b"\x02\x00" + port.to_bytes(2, "big") + address + bytes(8)).hex()


def sockaddr_in6(address: bytes, port: int) -> str:
    return (b"\x17\x00" + port.to_bytes(2, "big") + bytes(4) + address + bytes(4)).hex()


def dns_query(name: str, kind: int) -> str:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    header = bytes.fromhex("12340100000100000000 0000".replace(" ", ""))
    return (header + labels + b"\x00" + kind.to_bytes(2, "big") + b"\x00\x01").hex()


class DecodingTests(unittest.TestCase):
    def test_loopback_addresses_keep_their_value_and_port(self) -> None:
        self.assertEqual(
            decode_sockaddr(sockaddr_in(bytes([127, 0, 0, 1]), 443)), "127.0.0.1:443"
        )
        self.assertEqual(
            decode_sockaddr(sockaddr_in6(bytes(15) + b"\x01", 80)), "[::1]:80"
        )

    def test_other_addresses_are_not_retained(self) -> None:
        self.assertEqual(
            decode_sockaddr(sockaddr_in(bytes([192, 168, 1, 1]), 53)), "<external>:53"
        )
        self.assertEqual(
            decode_sockaddr(
                sockaddr_in6(bytes.fromhex("20014860486000000000000000008888"), 53)
            ),
            "[<external>]:53",
        )

    def test_unspecified_address_is_kept(self) -> None:
        self.assertEqual(decode_sockaddr(sockaddr_in(bytes(4), 0)), "0.0.0.0:0")

    def test_options_are_named_and_read_as_little_endian_integers(self) -> None:
        self.assertEqual(decode_option(6, 1, "01000000"), ("TCP_NODELAY", "1"))
        self.assertEqual(
            decode_option(0xFFFF, 0x1002, "00001000"), ("SO_RCVBUF", "1048576")
        )
        self.assertEqual(
            decode_option(0xFFFF, 0x3005, "01000000"), ("SO_RANDOMIZE_PORT", "1")
        )
        self.assertEqual(decode_option(9, 9, "02000000"), ("level_9_option_9", "2"))

    def test_keepalive_values_are_onoff_time_and_interval(self) -> None:
        value = (1).to_bytes(4, "little") + (45000).to_bytes(4, "little") * 2
        self.assertEqual(decode_keepalive(value.hex()), "1/45000/45000")
        self.assertEqual(decode_keepalive("0102"), "0102")

    def test_dns_question_reads_name_and_type(self) -> None:
        self.assertEqual(dns_question(dns_query(LOOKUP_HOST, 1)), (LOOKUP_HOST, "A"))
        self.assertEqual(
            dns_question(dns_query(LOOKUP_HOST, 65)), (LOOKUP_HOST, "HTTPS")
        )
        self.assertIsNone(dns_question("00"))

    def test_network_service_is_found_by_its_switch(self) -> None:
        self.assertTrue(
            is_network_service(
                [
                    "chrome.exe",
                    "--type=utility",
                    "--utility-sub-type=network.mojom.NetworkService",
                ]
            )
        )
        self.assertFalse(is_network_service(["chrome.exe", "--type=renderer"]))
        self.assertFalse(is_network_service(None))


class EventTests(unittest.TestCase):
    def reports(self) -> list[dict[str, object]]:
        keepalive = (
            (1).to_bytes(4, "little") + (45000).to_bytes(4, "little") * 2
        ).hex()
        origin = sockaddr_in(bytes([127, 0, 0, 1]), 8080)
        return [
            {"kind": "ready", "time_ms": 1000, "thread": 1},
            {
                "kind": "socket",
                "time_ms": 1000,
                "thread": 1,
                "socket": "0x2a4",
                "function": "WSASocketW",
                "family": 2,
                "type": 1,
                "protocol": 6,
            },
            {
                "kind": "setsockopt",
                "time_ms": 1001,
                "thread": 1,
                "socket": "0x2a4",
                "level": 6,
                "option": 1,
                "value": "01000000",
                "caller": "chrome.dll",
            },
            {"kind": "setsockopt-return", "time_ms": 1001, "thread": 1, "result": 0},
            {
                "kind": "wsaioctl",
                "time_ms": 1002,
                "thread": 1,
                "socket": "0x2a4",
                "code": 0x98000004,
                "input": keepalive,
            },
            {
                "kind": "wsaioctl-return",
                "time_ms": 1002,
                "thread": 1,
                "code": 0x98000004,
                "result": 0,
            },
            {
                "kind": "connect",
                "time_ms": 1003,
                "thread": 1,
                "socket": "0x2a4",
                "function": "connect",
                "address": origin,
            },
            {
                "kind": "resolve",
                "time_ms": 1100,
                "thread": 2,
                "function": "getaddrinfo",
                "host": LOOKUP_HOST,
                "overlapped": False,
            },
            {
                "kind": "resolve-return",
                "time_ms": 1101,
                "thread": 2,
                "function": "getaddrinfo",
                "host": LOOKUP_HOST,
                "result": 0,
                "answers": [sockaddr_in(bytes([127, 0, 0, 1]), 0)],
            },
            {
                "kind": "dns-send",
                "time_ms": 1200,
                "thread": 3,
                "socket": "0x300",
                "function": "WSASend",
                "address": "",
                "payload": dns_query(LOOKUP_HOST, 28),
            },
            {"kind": "close", "time_ms": 1300, "thread": 1, "socket": "0x2a4"},
        ]

    def test_events_rename_sockets_and_drop_bookkeeping(self) -> None:
        events = decode_events(self.reports())
        self.assertEqual(
            [event["kind"] for event in events],
            [
                "socket",
                "setsockopt",
                "wsaioctl",
                "connect",
                "resolve",
                "resolve-return",
                "dns-send",
                "close",
            ],
        )
        self.assertEqual(events[0]["socket"], "s0")
        self.assertEqual(events[0]["t"], 0)
        self.assertEqual(events[2]["value"], "1/45000/45000")
        self.assertEqual(events[3]["address"], "127.0.0.1:8080")
        self.assertEqual(events[5]["answers"], ["127.0.0.1:0"])
        self.assertEqual(events[6]["socket"], "s1")
        self.assertEqual(events[6]["query_type"], "AAAA")

    def test_failed_option_calls_are_kept(self) -> None:
        reports = self.reports()
        reports[3] = {**reports[3], "result": -1}
        events = decode_events(reports)
        self.assertIn({"t": 1, "kind": "setsockopt-return", "result": -1}, events)

    def test_summary_groups_origin_socket_options_and_lookups(self) -> None:
        lines = dict(summarize(decode_events(self.reports()), 8080))
        self.assertEqual(lines["origin_tcp_socket_count"], "1")
        self.assertEqual(
            lines["origin_tcp_option_set_0"],
            "1x TCP_NODELAY=1,SIO_KEEPALIVE_VALS=1/45000/45000",
        )
        self.assertEqual(lines["origin_connect_attempts"], "3:127.0.0.1:8080")
        self.assertEqual(lines["origin_ipv4_after_ipv6_ms"], "-")
        self.assertEqual(lines["origin_tcp_option_callers"], "chrome.dll")
        self.assertEqual(lines["lookup_count"], "2")
        self.assertEqual(
            lines["lookups"],
            f"100:getaddrinfo:-:{LOOKUP_HOST} 200:WSASend:AAAA:{LOOKUP_HOST}",
        )


class FallbackTests(unittest.TestCase):
    def test_each_ipv4_attempt_pairs_with_the_ipv6_attempt_of_its_job(self) -> None:
        def connect(t: int, address: str) -> dict[str, object]:
            return {"t": t, "kind": "connect", "address": address}

        events = [
            connect(188, "[::1]:80"),
            connect(200, "[::1]:443"),
            connect(449, "[::1]:80"),
            connect(497, "127.0.0.1:80"),
            connect(756, "127.0.0.1:80"),
        ]
        self.assertEqual(ipv4_after_ipv6(events, 80), "309,307")
        self.assertEqual(ipv4_after_ipv6(events[:3], 80), "-")
        fast = [connect(58, "[::1]:80"), connect(58, "127.0.0.1:80")]
        self.assertEqual(ipv4_after_ipv6(fast, 80), "0")


class LaunchTests(unittest.TestCase):
    def test_disabled_features_join_the_existing_switch(self) -> None:
        arguments = ["--a", "--disable-features=MediaRouter,OptimizationHints", "url"]
        self.assertEqual(
            merged_disabled_features(arguments, ("AsyncDns",)),
            ["--a", "--disable-features=MediaRouter,OptimizationHints,AsyncDns", "url"],
        )
        self.assertEqual(merged_disabled_features(arguments, ()), arguments)
        self.assertEqual(
            merged_disabled_features(["--a", "url"], ("AsyncDns",)),
            ["--a", "--disable-features=AsyncDns", "url"],
        )

    def test_network_service_arguments_drop_handles_and_the_profile(self) -> None:
        argv = [
            "chrome.exe",
            "--type=utility",
            "--user-data-dir=C:\\tmp\\profile-1",
            "--field-trial-handle=3,i,123",
            "--pseudonymization-salt-handle=7,i,9",
        ]
        self.assertEqual(
            portable_argv(argv, "C:\\tmp\\profile-1"),
            "--type=utility '--user-data-dir=<temporary-profile>' "
            "'--field-trial-handle=<handle>' '--pseudonymization-salt-handle=<handle>'",
        )

    def test_fixture_header_names_the_agent_digest(self) -> None:
        text = render_fixture(
            browser="chrome",
            client_version="1",
            operating_system="test",
            frida_version="0",
            launch_arguments="--x",
            scenario=SCENARIOS["single"],
            runs=[["run_0_event_count=0"]],
        )
        lines = text.splitlines()
        self.assertEqual(lines[0], f"format={FORMAT}")
        self.assertIn("evidence=hook", lines)
        self.assertIn("browser=Google Chrome", lines)
        self.assertTrue(any(line.startswith("hook_agent_sha256=") for line in lines))
        self.assertEqual(lines[-1], "run_0_event_count=0")
        self.assertTrue(text.endswith("\n"))


class OriginTests(unittest.TestCase):
    def fetch(
        self, scenario: str, path: str, host: str = "127.0.0.1"
    ) -> tuple[bytes, Origin]:
        async def run() -> tuple[bytes, Origin]:
            origin = Origin(SCENARIOS[scenario])
            server = await asyncio.start_server(origin.handle, "127.0.0.1", 0)
            origin.port = server.sockets[0].getsockname()[1]
            async with server:
                reader, writer = await asyncio.open_connection("127.0.0.1", origin.port)
                writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
                head = await reader.readuntil(b"\r\n\r\n")
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(0.05)
            return head, origin

        return asyncio.run(run())

    def test_close_path_ends_the_connection_so_the_next_fetch_resolves_again(
        self,
    ) -> None:
        head, origin = self.fetch("lookups", "/close?i=0", host=f"{LOOKUP_HOST}:1")
        self.assertIn(b"Connection: close", head)
        self.assertEqual(
            origin.connections[0].requests[0][1:], (f"{LOOKUP_HOST}:1", "/close?i=0")
        )

    def test_done_ends_the_run(self) -> None:
        head, origin = self.fetch("single", "/done")
        self.assertIn(b"Connection: keep-alive", head)
        self.assertTrue(origin.done.is_set())

    def test_lookup_page_fetches_the_lookup_host_on_the_origin_port(self) -> None:
        origin = Origin(SCENARIOS["lookups"], port=4242)
        self.assertIn(f"http://{LOOKUP_HOST}:4242/close".encode(), origin.page())


class RetainedFixtureTests(unittest.TestCase):
    def test_retained_logs_name_the_agent_they_were_taken_with(self) -> None:
        paths = sorted(FIXTURES.glob("*/*/*/hooks-*.txt"))
        self.assertTrue(paths)
        digests = set()
        for path in paths:
            with self.subTest(path=path.relative_to(FIXTURES)):
                fields = dict(
                    line.split("=", 1)
                    for line in path.read_text(encoding="ascii").splitlines()
                )
                self.assertEqual(fields["format"], FORMAT)
                self.assertEqual(fields["evidence"], "hook")
                self.assertEqual(fields["hook_agent"], f"scripts/capture/{AGENT.name}")
                self.assertEqual(fields["run_0_timed_out"], "false")
                self.assertEqual(fields["run_0_hook_error_count"], "0")
                digests.add(
                    (fields["hook_agent_sha256"], fields["capture_tool_sha256"])
                )
        # A retained log is evidence for the agent and tool in the repository
        # only: the tool writes the summary lines the recipe tests read.
        tool = Path(socket_hooks.__file__)
        self.assertEqual(digests, {(file_digest(AGENT), file_digest(tool))})


if __name__ == "__main__":
    unittest.main()
