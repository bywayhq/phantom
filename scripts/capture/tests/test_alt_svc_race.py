import asyncio
import datetime
import json
import ssl
import unittest

import h2.config
import h2.connection
import h2.events

from scripts.capture.alt_svc_race import (
    SCENARIOS,
    Http2Origin,
    Origin,
    RunSummary,
    Scenario,
    chromium_extra_arguments,
    goaway_frame,
    new_run,
    render_fixture,
    render_page,
    reserve_ports,
)
from scripts.capture.chrome_netlog import NetLog, broken_until_seconds, observe_races
from scripts.capture.http2_session import generate_certificate

HOST = "server.phantom.test"
PORT = 21000
TYPES = [
    "HTTP_STREAM_JOB_CONTROLLER",
    "HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND",
    "HTTP_STREAM_JOB",
    "HTTP_STREAM_JOB_WAITING",
    "HTTP_STREAM_JOB_DELAYED",
    "HTTP_STREAM_JOB_RESUMED",
    "HTTP_STREAM_JOB_INIT_CONNECTION",
    "HTTP_STREAM_JOB_BOUND_TO_REQUEST",
    "HTTP_STREAM_JOB_ORPHANED",
    "BOUND_TO_QUIC_SESSION_POOL_JOB",
    "QUIC_SESSION_CREATED",
    "QUIC_SESSION_POOL_JOB",
    "QUIC_SESSION_POOL_JOB_CONNECT",
    "QUIC_SESSION_PACKET_SENT",
    "SOCKET_POOL",
    "CONNECT_JOB",
    "TCP_CONNECT_JOB_CONNECTOR_CONNECT_START",
    "TCP_CONNECT_ATTEMPT",
    "SOCKET_POOL_BOUND_TO_CONNECT_JOB",
    "SOCKET_POOL_BOUND_TO_SOCKET",
    "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION",
    "CANCELLED",
]
SOURCES = [
    "HTTP_STREAM_JOB_CONTROLLER",
    "HTTP_STREAM_JOB",
    "QUIC_SESSION_POOL_DIRECT_JOB",
    "QUIC_SESSION",
    "SSL_CONNECT_JOB",
    "SOCKET",
]
PHASES = ["PHASE_NONE", "PHASE_BEGIN", "PHASE_END"]
TICK_OFFSET = 1_790_000_000_000


class NetLogBuilder:
    """Builds a minimal Chrome NetLog with the constants Chrome writes."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def add(
        self,
        time: int,
        source: tuple[str, int],
        event: str,
        phase: str = "PHASE_NONE",
        **params: object,
    ) -> None:
        self.events.append(
            {
                "time": str(time),
                "type": TYPES.index(event),
                "phase": PHASES.index(phase),
                "source": {"id": source[1], "type": SOURCES.index(source[0])},
                "params": params,
            }
        )

    def constants(self) -> dict:
        return {
            "logEventTypes": {name: index for index, name in enumerate(TYPES)},
            "logSourceType": {name: index for index, name in enumerate(SOURCES)},
            "logEventPhase": {name: index for index, name in enumerate(PHASES)},
            "timeTickOffset": str(TICK_OFFSET),
        }

    def complete(self, polled: list[dict]) -> str:
        return json.dumps(
            {"constants": self.constants(), "events": self.events, "polledData": polled}
        )

    def truncated(self) -> str:
        lines = ['{"constants": ' + json.dumps(self.constants()) + ",", '"events": [']
        lines.extend(json.dumps(event) + "," for event in self.events)
        return "\n".join(lines) + "\n"


def controller(builder: NetLogBuilder, source: int, time: int, path: str) -> tuple:
    source_ref = ("HTTP_STREAM_JOB_CONTROLLER", source)
    builder.add(
        time,
        source_ref,
        "HTTP_STREAM_JOB_CONTROLLER",
        "PHASE_BEGIN",
        url=f"https://{HOST}:{PORT}{path}",
        is_preconnect=False,
    )
    return source_ref


def job(
    builder: NetLogBuilder, source: int, time: int, kind: str, parent: int
) -> tuple:
    source_ref = ("HTTP_STREAM_JOB", source)
    builder.add(
        time,
        source_ref,
        "HTTP_STREAM_JOB",
        "PHASE_BEGIN",
        type=kind,
        source_dependency={"id": parent, "type": 1},
    )
    return source_ref


def blackholed_race() -> NetLogBuilder:
    """A fresh-profile race whose TCP job wins while QUIC later times out."""
    log = NetLogBuilder()
    control = controller(log, 10, 1000, "/r/r1")
    log.add(1000, control, "HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND", is_broken=False)
    alternative = job(log, 11, 1000, "alternative", 10)
    log.add(
        1000,
        alternative,
        "BOUND_TO_QUIC_SESSION_POOL_JOB",
        source_dependency={"id": 13},
    )
    pool = ("QUIC_SESSION_POOL_DIRECT_JOB", 13)
    log.add(1000, pool, "QUIC_SESSION_CREATED", source_dependency={"id": 14})
    log.add(1001, ("QUIC_SESSION", 14), "QUIC_SESSION_PACKET_SENT")
    main = job(log, 12, 1001, "main", 10)
    log.add(1001, main, "HTTP_STREAM_JOB_WAITING", "PHASE_BEGIN", should_wait=True)
    log.add(1001, control, "HTTP_STREAM_JOB_DELAYED", delay=0)
    log.add(1002, main, "HTTP_STREAM_JOB_RESUMED", delay=0)
    log.add(1002, main, "HTTP_STREAM_JOB_INIT_CONNECTION", "PHASE_BEGIN")
    log.add(1002, main, "SOCKET_POOL", "PHASE_BEGIN")
    connect = ("SSL_CONNECT_JOB", 15)
    log.add(1002, connect, "CONNECT_JOB", "PHASE_BEGIN")
    log.add(
        1002,
        connect,
        "TCP_CONNECT_JOB_CONNECTOR_CONNECT_START",
        source_dependency={"id": 16},
    )
    log.add(1003, ("SOCKET", 16), "TCP_CONNECT_ATTEMPT", "PHASE_BEGIN")
    log.add(
        1004, main, "SOCKET_POOL_BOUND_TO_CONNECT_JOB", source_dependency={"id": 15}
    )
    log.add(1004, main, "SOCKET_POOL_BOUND_TO_SOCKET", source_dependency={"id": 16})
    log.add(1004, main, "HTTP_STREAM_JOB_BOUND_TO_REQUEST")
    log.add(1004, alternative, "HTTP_STREAM_JOB_ORPHANED")
    log.add(5004, pool, "QUIC_SESSION_POOL_JOB_CONNECT", "PHASE_END", net_error=-356)
    log.add(5004, control, "HTTP_STREAM_JOB_CONTROLLER", "PHASE_END")
    later = controller(log, 20, 9000, "/r/r2")
    log.add(9000, later, "HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND", is_broken=True)
    reuse = job(log, 21, 9000, "main", 20)
    log.add(9000, reuse, "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION")
    log.add(9000, reuse, "HTTP_STREAM_JOB_BOUND_TO_REQUEST")
    return log


def broken_until(mark_tick: int, seconds: int) -> str:
    """Chrome's unpadded local-time rendering of a brokenness expiry."""
    until = datetime.datetime.fromtimestamp((TICK_OFFSET + mark_tick) / 1000 + seconds)
    return (
        f"{until.year}-{until.month}-{until.day} "
        f"{until.hour}:{until.minute}:{until.second}"
    )


class ChromeNetLogTests(unittest.TestCase):
    def test_blackholed_alternative_loses_and_later_request_skips_it(self) -> None:
        netlog = NetLog.parse(blackholed_race().truncated())

        first, second = observe_races(netlog, HOST, PORT)

        self.assertFalse(netlog.complete)
        self.assertEqual(first.path, "/r/r1")
        self.assertEqual(first.jobs, ("alternative", "main"))
        self.assertEqual(first.main_job_wait_ms, 0)
        self.assertEqual(first.main_resumed_ms, 2)
        self.assertEqual(first.quic_first_packet_ms, 1)
        self.assertEqual(first.tcp_connect_ms, 3)
        self.assertEqual(first.tcp_minus_quic_start_ms, 2)
        self.assertEqual(first.main_outcome, "new-connection")
        self.assertEqual(first.alternative_outcome, "orphaned-failed:-356")
        self.assertEqual(first.bound_job, "main")
        self.assertIn("controller_ms:4004", first.render())
        self.assertTrue(second.alt_svc_broken)
        self.assertEqual(second.jobs, ("main",))
        self.assertEqual(second.main_outcome, "existing-h2-session")

    def test_polled_brokenness_is_measured_from_the_failed_controller(self) -> None:
        mapping = (
            f"quic :{PORT}, expires 2026-09-22 15:30:30 "
            f"(broken until {broken_until(5004, 300)})"
        )
        polled = [
            {"altSvcMappings": []},
            {
                "altSvcMappings": [
                    {
                        "server": f"https://{HOST}:{PORT}",
                        "alternative_service": [mapping],
                    }
                ]
            },
        ]
        netlog = NetLog.parse(blackholed_race().complete(polled))

        self.assertTrue(netlog.complete)
        self.assertEqual(broken_until_seconds(netlog, 5004), [300])

    def test_idle_preconnected_socket_is_not_a_new_connection(self) -> None:
        log = NetLogBuilder()
        controller(log, 1, 0, "/r/r1")
        main = job(log, 2, 0, "main", 1)
        log.add(0, main, "HTTP_STREAM_JOB_INIT_CONNECTION", "PHASE_BEGIN")
        log.add(0, main, "SOCKET_POOL", "PHASE_BEGIN")
        log.add(0, main, "SOCKET_POOL_BOUND_TO_SOCKET", source_dependency={"id": 3})

        (race,) = observe_races(NetLog.parse(log.truncated()), HOST, PORT)

        self.assertEqual(race.main_outcome, "idle-socket")
        self.assertIsNone(race.tcp_connect_ms)

    def test_preconnects_and_other_origins_are_ignored(self) -> None:
        log = NetLogBuilder()
        log.add(
            0,
            ("HTTP_STREAM_JOB_CONTROLLER", 1),
            "HTTP_STREAM_JOB_CONTROLLER",
            "PHASE_BEGIN",
            url=f"https://{HOST}:{PORT}/",
            is_preconnect=True,
        )
        log.add(
            0,
            ("HTTP_STREAM_JOB_CONTROLLER", 2),
            "HTTP_STREAM_JOB_CONTROLLER",
            "PHASE_BEGIN",
            url="https://other.test/",
            is_preconnect=False,
        )

        self.assertEqual(observe_races(NetLog.parse(log.truncated()), HOST, PORT), [])


class ScenarioTests(unittest.TestCase):
    def test_catalog_steps_are_valid_and_pages_embed_them(self) -> None:
        for scenario in SCENARIOS.values():
            page = render_page(scenario).decode()
            self.assertIn(json.dumps(list(scenario.steps)), page)
            self.assertIn('<img src="/hold"', page)
        self.assertEqual(SCENARIOS["udp-blackhole"].page_milliseconds, 15600)

    def test_unknown_steps_and_modes_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Scenario("bad", "?", "serve", ("fetch:../x",))
        with self.assertRaises(ValueError):
            Scenario("bad", "?", "tcp-only", ())

    def test_launch_keeps_the_origin_unforced_and_other_names_unresolvable(
        self,
    ) -> None:
        arguments = chromium_extra_arguments("127.0.0.1", "spki", "log.json")

        self.assertIn("--enable-quic", arguments)
        self.assertIn(
            f"--host-resolver-rules=MAP {HOST} 127.0.0.1, MAP * ~NOTFOUND", arguments
        )
        forced = [
            arg for arg in arguments if arg.startswith("--origin-to-force-quic-on")
        ]
        self.assertEqual(forced, [f"--origin-to-force-quic-on={HOST}:9"])

    def test_goaway_names_the_last_stream_with_no_error(self) -> None:
        self.assertEqual(
            goaway_frame(5).hex(), "000008070000000000" + "00000005" + "00000000"
        )

    def test_paired_ports_share_one_number(self) -> None:
        udp, tcp = reserve_ports("127.0.0.1")
        try:
            self.assertEqual(udp.getsockname()[1], tcp.getsockname()[1])
        finally:
            udp.close()
            tcp.close()

    def test_fixture_aggregates_raced_controllers_by_path(self) -> None:
        netlog = NetLog.parse(blackholed_race().truncated())
        races = tuple(observe_races(netlog, HOST, PORT))
        summary = RunSummary(
            run=0,
            page=(("fetch:r1", 200, "h2"),),
            requests=(("/r/r1", "h2"),),
            tcp_connections=2,
            idle_tcp_connections=0,
            udp_peers=1,
            server_first_tcp_minus_first_udp_ms=1.5,
            races=races,
            netlog_complete=False,
            broken_lifetimes_s=(300,),
        )

        fixture = render_fixture(
            SCENARIOS["udp-blackhole"],
            [summary],
            client="test",
            client_version="0",
            operating_system="test",
            launch_mode="headless",
            launch_arguments="none",
            listen_host="127.0.0.1",
        )

        lines = fixture.splitlines()
        self.assertEqual(lines[0], "format=phantom-alt-svc-race-v1")
        self.assertIn("run_0_page=fetch:r1>200>h2", lines)
        self.assertIn("aggregate_race_r1_controllers=1", lines)
        self.assertIn(
            "aggregate_race_r1_alternative_outcome=orphaned-failed:-356:1", lines
        )
        self.assertIn(
            "aggregate_broken_lifetime_s=min:300,median:300,max:300,values:300", lines
        )
        self.assertNotIn("aggregate_race_r2_controllers=1", lines)


class OriginServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_learn_retire_advertises_h3_then_goaway_keeps_held_stream(
        self,
    ) -> None:
        udp, tcp = reserve_ports("127.0.0.1")
        udp.close()
        port = tcp.getsockname()[1]
        origin = Origin(SCENARIOS["race-after-learning"], port)
        run = new_run()
        origin.begin(run)
        server = Http2Origin(origin, generate_certificate(HOST))
        await server.start(tcp)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname=HOST
        )
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", HOST.encode()),
        ]
        client.send_headers(1, [*headers, (b":path", b"/hold")], end_stream=True)
        client.send_headers(
            3, [*headers, (b":path", b"/learn-retire")], end_stream=True
        )
        writer.write(client.data_to_send())
        responses: dict[int, dict[bytes, bytes]] = {}
        goaway = None
        try:
            while goaway is None or 3 not in responses:
                data = await asyncio.wait_for(reader.read(65536), 5)
                self.assertTrue(data)
                for event in client.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        responses[event.stream_id] = dict(event.headers)
                    if isinstance(event, h2.events.ConnectionTerminated):
                        goaway = event.last_stream_id
                writer.write(client.data_to_send())
            self.assertEqual(goaway, 3)
            self.assertEqual(
                responses[3][b"alt-svc"], f'h3=":{port}"; ma=86400'.encode()
            )
            self.assertNotIn(1, responses)
            # Finishing the page releases the held stream on the retired connection.
            origin.request(
                "h2", 0, "/done?results=%5B%5D", lambda response: None, lambda: None
            )
            self.assertEqual(run.page_results, [])
            self.assertTrue(run.done.is_set())
        finally:
            writer.close()
            await server.close()
        self.assertEqual(
            [request.path for request in run.requests],
            ["/hold", "/learn-retire", "/done"],
        )
        self.assertEqual(run.tcp[0].alpn, "h2")
        self.assertIsNotNone(run.tcp[0].retired_ms)


if __name__ == "__main__":
    unittest.main()
