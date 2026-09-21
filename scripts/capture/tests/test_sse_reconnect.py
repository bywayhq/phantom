import asyncio
import contextlib
import dataclasses
import re
import unittest
from urllib.parse import urljoin, urlsplit

from scripts.capture.sse_reconnect import (
    CATALOG,
    FORMAT,
    NO_CONTENT,
    PROBE_COOKIE,
    SCENARIOS,
    CaptureMetadata,
    ReconnectServer,
    Scenario,
    Stimulus,
    capture_scenario,
    event_stream,
    fixture,
    main,
    stream,
)

METADATA = CaptureMetadata(
    client="scripted EventSource",
    client_version="0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
QUICK = 0.2
# Windows timers can fire one clock tick (about 15.6 ms) early.
CLOCK_TICK = 0.02


class ScriptedEventSource:
    """A minimal HTML EventSource reconnect loop driven over raw HTTP/1.1."""

    def __init__(
        self,
        page_url: str,
        *,
        default_delay: float = 0.05,
        extra_headers: tuple[bytes, ...] = (),
        honor_termination: bool = True,
        close_idle_after: float | None = None,
    ) -> None:
        self.page_url = page_url
        self.default_delay = default_delay
        self.extra_headers = extra_headers
        self.honor_termination = honor_termination
        self.close_idle_after = close_idle_after
        self.cookies: list[bytes] = []

    async def run(self) -> None:
        status, headers, body = await self.fetch(self.page_url, ())
        if status != 200:
            raise AssertionError(f"page returned {status}")
        match = re.search(rb"new EventSource\('([^']+)'\)", body)
        if match is None:
            raise AssertionError("page does not open an EventSource")
        url = urljoin(self.page_url, match.group(1).decode())
        last_id = b""
        delay = self.default_delay
        for _ in range(16):
            fields = [b"Accept: text/event-stream", b"Cache-Control: no-cache"]
            fields.extend(self.extra_headers)
            if self.cookies:
                fields.append(b"Cookie: " + b"; ".join(self.cookies))
            if last_id:
                fields.append(b"Last-Event-ID: " + last_id)
            try:
                status, headers, body = await self.fetch(url, fields)
            except ConnectionError:
                await asyncio.sleep(delay)
                continue
            if status == 307:
                url = urljoin(url, headers[b"location"].decode())
                continue
            if (
                status != 200 or headers.get(b"content-type") != b"text/event-stream"
            ) and self.honor_termination:
                return
            last_id, delay = parse_events(body, last_id, delay)
            await asyncio.sleep(delay)

    async def fetch(self, url, fields):
        parts = urlsplit(url)
        reader, writer = await asyncio.open_connection(parts.hostname, parts.port)
        try:
            target = parts.path + (f"?{parts.query}" if parts.query else "")
            head = [f"GET {target} HTTP/1.1".encode(), f"Host: {parts.netloc}".encode()]
            writer.write(b"\r\n".join([*head, *fields]) + b"\r\n\r\n")
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            status_line, *lines = response[:-4].split(b"\r\n")
            headers = {}
            for line in lines:
                name, _, value = line.partition(b":")
                headers[name.strip().lower()] = value.strip()
                if name.strip().lower() == b"set-cookie":
                    self.cookies.append(value.strip().split(b";")[0])
            status = int(status_line.split(b" ")[1])
            if b"content-length" in headers:
                body = await reader.readexactly(int(headers[b"content-length"]))
            elif self.close_idle_after is not None:
                body = b""
                with contextlib.suppress(asyncio.TimeoutError):
                    body = await asyncio.wait_for(
                        reader.read(), timeout=self.close_idle_after
                    )
            else:
                body = await reader.read()
            return status, headers, body
        except asyncio.IncompleteReadError as error:
            raise ConnectionResetError("response ended before its head") from error
        finally:
            writer.close()


def parse_events(body: bytes, last_id: bytes, delay: float) -> tuple[bytes, float]:
    pending_id = last_id
    for line in body.split(b"\n"):
        name, _, value = line.partition(b":")
        value = value[1:] if value.startswith(b" ") else value
        if line == b"":
            last_id = pending_id
        elif name == b"id" and b"\0" not in value:
            pending_id = value
        elif name == b"retry" and value.isdigit():
            delay = int(value) / 1000
    return last_id, delay


def driver(**options):
    @contextlib.asynccontextmanager
    async def drive(url):
        task = asyncio.create_task(ScriptedEventSource(url, **options).run())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                await task

    return drive


def quick(scenario: Scenario) -> Scenario:
    return dataclasses.replace(scenario, observation_seconds=QUICK)


async def capture(scenario: Scenario, *, repeat=1, **options):
    server = ReconnectServer()
    await server.start("127.0.0.1", 0)
    try:
        return await capture_scenario(
            server,
            scenario,
            repeat=repeat,
            run_timeout=10.0,
            drive=driver(**options),
        )
    finally:
        await server.close()


def sse_requests(run):
    return [request for request in run.requests if request.kind == "sse"]


def fixture_fields(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise AssertionError(f"invalid fixture line: {line!r}")
        fields[key] = value
    return fields


class SseReconnectTests(unittest.TestCase):
    def test_reconnect_request_records_last_event_id_after_committed_id(self) -> None:
        [run] = asyncio.run(capture(quick(SCENARIOS["id-then-close"])))

        first, second = sse_requests(run)
        self.assertIsNone(first.header(b"last-event-id"))
        self.assertEqual(second.header(b"last-event-id"), b"phantom-1")
        self.assertEqual(second.header_lines[-1], b"Last-Event-ID: phantom-1")
        self.assertEqual((first.attempt, second.attempt), (0, 1))

    def test_empty_id_omits_last_event_id_on_next_request(self) -> None:
        [run] = asyncio.run(capture(quick(SCENARIOS["empty-id-resets"])))

        requests = sse_requests(run)
        self.assertEqual(
            [request.header(b"last-event-id") for request in requests],
            [None, b"phantom-1", None],
        )

    def test_retry_field_bounds_measured_delay_window(self) -> None:
        scenario = Scenario(
            "retry-150",
            "test retry",
            (stream(event_stream(b"retry: 150\ndata: a")), NO_CONTENT),
            observation_seconds=QUICK,
        )

        runs = asyncio.run(capture(scenario, repeat=3))

        delays = [sse_requests(run)[1].after_stimulus for run in runs]
        for delay in delays:
            self.assertGreaterEqual(delay, 0.15 - CLOCK_TICK)
            self.assertLess(delay, 0.65)
        fields = fixture_fields(fixture(scenario, runs, METADATA))
        summary = fields["attempt_1_after_stimulus_ms"]
        self.assertRegex(summary, r"^min:[0-9.]+,median:[0-9.]+,max:[0-9.]+,spread:")
        self.assertEqual(summary.split("values:")[1].count(";"), 2)

    def test_no_content_reconnect_ends_scenario_without_further_requests(
        self,
    ) -> None:
        [run] = asyncio.run(capture(quick(SCENARIOS["reconnect-204"])))

        requests = sse_requests(run)
        self.assertEqual(len(requests), 2)
        self.assertFalse(any(request.extra for request in requests))
        self.assertIsNotNone(run.terminated)
        self.assertEqual(requests[-1].stimulus, "response")

    def test_requests_after_termination_are_recorded_as_extra(self) -> None:
        scenario = dataclasses.replace(
            SCENARIOS["reconnect-404"], observation_seconds=1.0
        )

        [run] = asyncio.run(capture(scenario, honor_termination=False))

        extra = [request for request in sse_requests(run) if request.extra]
        self.assertTrue(extra)
        self.assertTrue(all(request.attempt is None for request in extra))
        fields = fixture_fields(fixture(scenario, [run], METADATA))
        self.assertIn("extra:true", "\n".join(fields.values()))

    def test_reset_before_head_is_observed_as_a_network_error(self) -> None:
        scenario = Scenario(
            "reset",
            "test reset",
            (Stimulus(ending="reset"), NO_CONTENT),
            observation_seconds=QUICK,
        )

        [run] = asyncio.run(capture(scenario))

        first, second = sse_requests(run)
        self.assertEqual(first.stimulus, "reset")
        self.assertNotEqual(first.connection, second.connection)
        self.assertIsNotNone(second.after_stimulus)

    def test_idle_hold_records_client_close_time(self) -> None:
        scenario = Scenario(
            "idle",
            "test idle",
            (Stimulus(ending="hold-close", hold_seconds=5.0), NO_CONTENT),
            observation_seconds=QUICK,
        )

        [run] = asyncio.run(capture(scenario, close_idle_after=0.1))

        first = sse_requests(run)[0]
        eof = run.connections[first.connection].client_eof
        self.assertIsNotNone(eof)
        self.assertLess(eof - first.received, 2.0)

    def test_redirected_stream_records_reconnect_target(self) -> None:
        [run] = asyncio.run(capture(quick(SCENARIOS["redirect-307-then-close"])))

        targets = [request.target for request in sse_requests(run)]
        self.assertEqual(len(targets), 3)
        self.assertNotIn(b"/target", targets[0])
        self.assertIn(b"/target", targets[1])
        self.assertEqual(sse_requests(run)[1].stimulus, "close")

    def test_probe_cookie_is_retained_on_reconnect(self) -> None:
        scenario = quick(SCENARIOS["set-cookie-then-close"])

        [run] = asyncio.run(capture(scenario))

        self.assertEqual(sse_requests(run)[1].header(b"cookie"), PROBE_COOKIE)
        fixture(scenario, [run], METADATA)

    def test_fixture_round_trips_ordered_raw_header_lines(self) -> None:
        scenario = quick(SCENARIOS["id-then-close"])
        extra = (b"X-Order: second", b"x-order: first", b"X-Mixed-CASE:  spaced ")

        [run] = asyncio.run(capture(scenario, extra_headers=extra))

        fields = fixture_fields(fixture(scenario, [run], METADATA))
        self.assertEqual(fields["format"], FORMAT)
        for index, request in enumerate(run.requests):
            key = f"run_0_request_{index}"
            count = int(fields[f"{key}_header_count"])
            lines = [
                bytes.fromhex(fields[f"{key}_header_{position}"])
                for position in range(count)
            ]
            self.assertEqual(lines, request.header_lines)
            self.assertEqual(
                bytes.fromhex(fields[f"{key}_line_hex"]), request.request_line
            )
        stream_lines = sse_requests(run)[0].header_lines
        self.assertEqual(stream_lines[-3:], list(extra))

    def test_fixture_refuses_credential_bearing_headers(self) -> None:
        scenario = quick(SCENARIOS["reconnect-204"])
        for header in (
            b"Authorization: Basic cGhhbnRvbTo=",
            b"Proxy-Authorization: Basic cGhhbnRvbTo=",
            b"Cookie: session=secret",
        ):
            with self.subTest(header=header):
                [run] = asyncio.run(capture(scenario, extra_headers=(header,)))
                with self.assertRaises(ValueError):
                    fixture(scenario, [run], METADATA)

    def test_listener_rejects_non_loopback_address(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(ReconnectServer().start("0.0.0.0", 0))
        with self.assertRaises(SystemExit):
            main(
                [
                    "--browser",
                    "manual",
                    "--client-version",
                    "0",
                    "--listen",
                    "192.0.2.1:0",
                    "--output-dir",
                    "unused",
                ]
            )

    def test_catalog_scenarios_end_with_exactly_one_terminal_response(self) -> None:
        self.assertEqual(len({scenario.name for scenario in CATALOG}), len(CATALOG))
        for scenario in CATALOG:
            with self.subTest(scenario=scenario.name):
                self.assertTrue(scenario.attempts[-1].terminal)
                self.assertFalse(
                    any(attempt.terminal for attempt in scenario.attempts[:-1])
                )
        with self.assertRaises(ValueError):
            Scenario("bad", "early terminal", (NO_CONTENT, NO_CONTENT))
        with self.assertRaises(ValueError):
            Scenario("bad", "no terminal", (stream(b""),))


if __name__ == "__main__":
    unittest.main()
