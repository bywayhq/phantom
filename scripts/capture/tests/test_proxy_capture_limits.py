"""Proxy request head and duration validation at the actual entry points."""

import math
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture.proxy_route import (
    MAX_REQUEST_HEAD,
    PROXY_HOST,
    CaptureRun,
    CaptureServer,
    Http1Exchange,
    capture_scenario,
    generate_certificate,
    main,
    validate_capture_durations,
)


class HeadLimitTests(unittest.TestCase):
    def exchange(self):
        run = CaptureRun("0123456789abcdef", "http-proxy-hostname")
        return run, Http1Exchange(run, 0)

    def head(self, size):
        prefix = (
            b"GET /page?run=0123456789abcdef HTTP/1.1\r\n"
            b"Host: origin.phantom.test\r\nX-Pad: "
        )
        suffix = b"\r\n\r\n"
        return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix

    def test_exact_limit_completed_head_is_accepted(self) -> None:
        run, exchange = self.exchange()
        output = exchange.feed(self.head(MAX_REQUEST_HEAD))
        self.assertTrue(output.startswith(b"HTTP/1.1 200"))
        self.assertEqual(len(run.requests), 1)

    def test_over_limit_completed_head_is_rejected_before_recording(self) -> None:
        run, exchange = self.exchange()
        with self.assertRaises(ValueError):
            exchange.feed(self.head(MAX_REQUEST_HEAD + 1))
        self.assertEqual(run.requests, [])

    def test_terminator_fragment_does_not_bypass_limit(self) -> None:
        run, exchange = self.exchange()
        head = self.head(MAX_REQUEST_HEAD + 1)
        self.assertEqual(exchange.feed(head[:-2]), b"")
        with self.assertRaises(ValueError):
            exchange.feed(head[-2:])
        self.assertEqual(run.requests, [])

    def test_limit_applies_to_each_head_in_a_combined_chunk(self) -> None:
        run, exchange = self.exchange()
        output = exchange.feed(self.head(MAX_REQUEST_HEAD) * 2)
        self.assertEqual(output.count(b"HTTP/1.1 200"), 2)
        self.assertEqual(len(run.requests), 2)


class DurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_callable_rejects_nonfinite_durations_before_driver_entry(
        self,
    ) -> None:
        server = CaptureServer(generate_certificate(PROXY_HOST))
        entered = []
        for value in (math.nan, math.inf, -math.inf):
            for run_timeout, observation in ((value, 0.0), (1.0, value)):
                with self.assertRaises(ValueError):
                    await capture_scenario(
                        server,
                        "http-proxy-hostname",
                        repeat=1,
                        run_timeout=run_timeout,
                        observation_seconds=observation,
                        drive=lambda url: entered.append(url),
                    )
        self.assertEqual(entered, [])
        self.assertIsNone(server.run)
        self.assertEqual(server.servers, [])

    def test_direct_capture_run_rejects_nonfinite_observation(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                CaptureRun("0123456789abcdef", "http-proxy-hostname", value)

    def test_finite_immediate_expiry_durations_remain_valid(self) -> None:
        validate_capture_durations(0.0, 0.0)
        validate_capture_durations(-1.0, -1.0)

    def test_cli_rejects_nonfinite_durations_before_execution(self) -> None:
        for option in ("--run-timeout", "--observation"):
            for value in ("nan", "inf", "-inf"):
                with (
                    patch("scripts.capture.proxy_route.asyncio.run") as execute,
                    patch("scripts.capture.proxy_route.metadata.version") as version,
                    self.assertRaises(SystemExit) as caught,
                ):
                    main(
                        [
                            "--browser",
                            "manual",
                            "--client-version",
                            "test",
                            "--output-dir",
                            str(Path("unused")),
                            f"{option}={value}",
                        ]
                    )
                self.assertEqual(caught.exception.code, 2)
                execute.assert_not_called()
                version.assert_not_called()
