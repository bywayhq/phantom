"""Actual IPv6 proxy listeners and browser route validation."""

import argparse
import asyncio
import contextlib
import errno
import io
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from scripts.capture.android_device import ANDROID_BROWSERS
from scripts.capture.proxy_route import (
    ORIGIN_HOST,
    PROXY_HOST,
    SCENARIOS,
    CaptureRun,
    CaptureServer,
    is_capture_authority,
    launch_plan,
    main,
    page_url,
    run,
)
from scripts.capture.tests.test_proxy_capture_ownership import CERTIFICATE, DEADLINE
from scripts.capture.tests.test_proxy_route import read_response


class Ipv6LaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = CaptureServer(CERTIFICATE)
        self.server.addresses = {
            "origin": ("::1", 1001),
            "http-proxy": ("::1", 1002),
            "https-proxy": ("::1", 1003),
        }

    def test_desktop_launch_uses_bracketed_authorities_and_ipv6_resolution(
        self,
    ) -> None:
        self.assertEqual(self.server.address("origin"), "[::1]:1001")
        self.assertEqual(
            page_url(self.server, SCENARIOS["direct-loopback"], "token"),
            "http://[::1]:1001/page?run=token",
        )
        for scenario in ("http-proxy-loopback", "https-proxy-hostname"):
            with self.subTest(scenario=scenario):
                plan = launch_plan(
                    "chrome",
                    Path("chrome"),
                    True,
                    SCENARIOS[scenario],
                    self.server,
                    CERTIFICATE,
                )
                self.assertIn(
                    f"--host-resolver-rules=MAP {ORIGIN_HOST} [::1], "
                    f"MAP {PROXY_HOST} [::1], EXCLUDE localhost",
                    plan.extra_arguments,
                )
                expected = (
                    "--proxy-server=http://[::1]:1002"
                    if scenario == "http-proxy-loopback"
                    else f"--proxy-server=https://{PROXY_HOST}:1003"
                )
                self.assertIn(expected, plan.extra_arguments)

        plan = launch_plan(
            "firefox",
            Path("firefox"),
            True,
            SCENARIOS["https-proxy-hostname"],
            self.server,
            CERTIFICATE,
        )
        preferences = dict(plan.firefox_preferences)
        self.assertFalse(preferences["network.dns.disableIPv6"])
        self.assertEqual(
            preferences["network.dns.localDomains"], f"{ORIGIN_HOST},{PROXY_HOST}"
        )

    def test_ipv6_capture_authorities_are_not_classified_as_background(self) -> None:
        self.assertTrue(is_capture_authority(b"[::1]:1001"))
        self.assertTrue(is_capture_authority(b"127.0.0.2:1001"))
        self.assertFalse(is_capture_authority(b"[2001:db8::1]:1001"))
        self.assertFalse(is_capture_authority(b"[broken]:1001"))

    def test_android_ipv6_launch_is_rejected_before_device_acquisition(self) -> None:
        for browser in ANDROID_BROWSERS:
            with (
                self.subTest(browser=browser),
                self.assertRaisesRegex(ValueError, "IPv4 loopback"),
            ):
                launch_plan(
                    browser,
                    Path("adb"),
                    False,
                    SCENARIOS["direct-loopback"],
                    self.server,
                    CERTIFICATE,
                )

    def test_cli_rejects_android_ipv6_before_capture_runtime(self) -> None:
        with (
            patch("scripts.capture.proxy_route.run") as operation,
            patch("scripts.capture.proxy_route.metadata.version") as version,
            contextlib.redirect_stderr(io.StringIO()) as output,
            self.assertRaises(SystemExit) as caught,
        ):
            main(
                [
                    "--browser",
                    "chrome-android",
                    "--browser-path",
                    "adb",
                    "--client-version",
                    "test",
                    "--listen",
                    "::1",
                    "--output-dir",
                    "unused",
                ]
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("IPv4 loopback", output.getvalue())
        operation.assert_not_called()
        version.assert_not_called()


class Ipv6ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def test_callable_rejects_android_ipv6_before_acquisition(self) -> None:
        args = argparse.Namespace(
            browser="chrome-android", listen="::1", run_timeout=1, observation=0
        )
        with (
            patch("scripts.capture.proxy_route.generate_certificate") as certificate,
            self.assertRaisesRegex(ValueError, "IPv4 loopback"),
        ):
            await run(args)
        certificate.assert_not_called()

    async def test_direct_ipv6_page_and_proxy_connect_reach_actual_listeners(
        self,
    ) -> None:
        server = CaptureServer(CERTIFICATE)
        clients = []
        try:
            try:
                await server.start("::1")
            except OSError as error:
                if error.errno in {
                    errno.EAFNOSUPPORT,
                    errno.EADDRNOTAVAIL,
                    errno.ENETUNREACH,
                }:
                    self.skipTest(f"IPv6 loopback unavailable: {error}")
                raise

            capture = CaptureRun("0123456789abcdef", "direct-loopback")
            server.run = capture
            url = urlsplit(
                page_url(server, SCENARIOS["direct-loopback"], capture.token)
            )
            self.assertEqual(url.hostname, "::1")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(url.hostname, url.port), DEADLINE
            )
            clients.append(writer)
            writer.write(
                f"GET {url.path}?{url.query} HTTP/1.1\r\n"
                f"Host: {url.netloc}\r\n\r\n".encode()
            )
            head, body = await asyncio.wait_for(read_response(reader), DEADLINE)
            self.assertTrue(head.startswith(b"HTTP/1.1 200"))
            self.assertEqual(body, capture.page())
            self.assertEqual(capture.requests[0].kind, "page")

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("::1", server.addresses["http-proxy"][1]),
                DEADLINE,
            )
            clients.append(writer)
            writer.write(b"CONNECT [::1]:9 HTTP/1.1\r\nHost: [::1]:9\r\n\r\n")
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), DEADLINE)
            self.assertEqual(head, b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.assertEqual(capture.requests[1].kind, "connect")
        finally:
            for writer in clients:
                writer.close()
            for writer in clients:
                with contextlib.suppress(
                    ConnectionResetError, ConnectionAbortedError, BrokenPipeError
                ):
                    await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            await server.close()
