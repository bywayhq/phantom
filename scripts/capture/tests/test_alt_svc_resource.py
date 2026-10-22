import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import h2.events

from scripts.capture import alt_svc_race as race
from scripts.capture.alt_svc_race import (
    SCENARIOS,
    Http2Origin,
    Origin,
    RunRecord,
    RunResult,
    TcpRecord,
    new_run,
    observe_image_request,
    render_fixture,
    summarize_run,
)
from scripts.capture.chrome_netlog import NetLog
from scripts.capture.http2_session import (
    CONNECTION_PREFACE,
    MAX_HEADER_FIELDS,
    MAX_REQUEST_HEAD,
    generate_certificate,
)

HOST = b"server.phantom.test"
PORT = 23456
AUTHORITY = HOST + b":23456"
HEADERS = (
    (b":method", b"GET"),
    (b":authority", AUTHORITY),
    (b":scheme", b"https"),
    (b":path", b"/hold"),
    (b"x-marker", b"first"),
    (b"sec-fetch-dest", b"image"),
    (b"x-marker", b"second"),
    (b"sec-fetch-mode", b"no-cors"),
    (b"referer", b"https://" + AUTHORITY + b"/start"),
    (b"priority", b"u=2, i"),
)


class IncomingFrames:
    """Feed explicit HTTP/2 bytes into the existing server state machine."""

    def __init__(self, frames: bytes) -> None:
        self.frames = frames

    async def read(self) -> bytes:
        frames, self.frames = self.frames, b""
        return frames

    def write(self, data: bytes) -> None:
        # These tests inspect received requests, not server response encoding.
        pass


def headers_frame(
    headers: tuple[tuple[bytes, bytes], ...], priority: bytes | None
) -> bytes:
    # RFC 7541 section 6.2.2: literal without indexing, literal name and no Huffman.
    # Each test field is below the one-byte string-length boundary.
    block = b"".join(
        b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value
        for name, value in headers
    )
    flags = 0x05  # END_HEADERS | END_STREAM
    if priority is not None:
        flags |= 0x20
        block = priority + block
    return (
        len(block).to_bytes(3, "big")
        + bytes([1, flags])
        + (7).to_bytes(4, "big")
        + block
    )


class ImageObservationTests(unittest.IsolatedAsyncioTestCase):
    async def capture(
        self,
        headers: tuple[tuple[bytes, bytes], ...] = HEADERS,
        priority: bytes | None = None,
        following: bytes = b"",
        observe_images: bool = True,
    ) -> tuple[Origin, RunRecord]:
        origin = Origin(
            SCENARIOS["existing-h2-session"], PORT, observe_images=observe_images
        )
        run = new_run()
        origin.begin(run)
        server = Http2Origin(origin, generate_certificate(HOST.decode()))
        record = TcpRecord(index=0, accepted_ms=0)
        run.tcp.append(record)
        # RFC 9113: client preface, empty SETTINGS, then the request HEADERS.
        frames = (
            CONNECTION_PREFACE
            + bytes.fromhex("000000040000000000")
            + headers_frame(headers, priority)
            + following
        )
        await server.serve_h2(IncomingFrames(frames), record, run)
        return origin, run

    def fixture(self, run: RunRecord) -> str:
        summary = summarize_run(
            0,
            RunResult(run, PORT, Path("unused.json"), "none", True),
            NetLog({}, [], []),
        )
        self.assertEqual(summary.requests, ())
        return render_fixture(
            SCENARIOS["existing-h2-session"],
            [summary],
            client="wire-control",
            client_version="0",
            operating_system="test",
            launch_mode="none",
            launch_arguments="none",
            listen_host="127.0.0.1",
        )

    async def test_wire_order_duplicates_fetch_metadata_and_initial_priority_survive(
        self,
    ) -> None:
        # RFC 9113 section 6.2: exclusive dependency 3 and encoded weight 36 => 37.
        origin, run = await self.capture(priority=bytes.fromhex("8000000324"))

        self.assertIsNone(origin.failure)
        image = run.images[0]
        self.assertIsNotNone(image)
        expected = tuple(
            (name, value.replace(b":23456", b":<port>")) for name, value in HEADERS
        )
        self.assertEqual(image.headers, expected)
        self.assertEqual((image.connection, image.stream_id), (0, 7))
        self.assertEqual(
            (
                image.headers_priority.exclusive,
                image.headers_priority.depends_on,
                image.headers_priority.weight,
            ),
            (True, 3, 37),
        )
        fixture = self.fixture(run)
        self.assertIn("run_0_image_h2_count=1\n", fixture)
        self.assertIn("run_0_image_h2_0_stream=7\n", fixture)
        for index, (name, value) in enumerate(expected):
            self.assertIn(
                f"run_0_image_h2_0_header_{index}=name_hex:{name.hex()},value_hex:{value.hex()}\n",
                fixture,
            )
        self.assertIn(
            "run_0_image_h2_0_initial_headers_priority=exclusive:true,depends_on:3,weight:37\n",
            fixture,
        )

    async def test_later_priority_does_not_become_initial_headers_priority(
        self,
    ) -> None:
        # A standalone PRIORITY frame follows a HEADERS frame with no priority.
        later = bytes.fromhex("0000050200000000078000000324")
        origin, run = await self.capture(following=later)

        self.assertIsNone(origin.failure)
        self.assertIsNone(run.images[0].headers_priority)
        self.assertIn(
            "run_0_image_h2_0_initial_headers_priority=none\n", self.fixture(run)
        )

    async def test_credentials_fail_without_retaining_an_image(self) -> None:
        for name in (b"cookie", b"authorization", b"proxy-authorization"):
            with self.subTest(name=name):
                origin, run = await self.capture((*HEADERS, (name, b"private-value")))

                self.assertIsInstance(origin.failure, ValueError)
                self.assertNotIn("private-value", str(origin.failure))
                self.assertEqual(run.requests, [])
                self.assertEqual(origin.holds, [])

    async def test_authority_and_referrer_must_match_the_exact_owned_page(self) -> None:
        cases = (
            (b":authority", HOST),
            (b":authority", HOST + b":23457"),
            (b":authority", b"attacker.test:23456"),
            (b"referer", b"https://" + AUTHORITY + b"/start?secret=value"),
            (b"referer", b"https://" + AUTHORITY + b"/other"),
            (b"referer", b"https://server.phantom.test:23457/start"),
            (b"referer", b"https://user:secret@" + AUTHORITY + b"/start"),
            (b"origin", b"https://" + AUTHORITY + b"/"),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                headers = tuple(field for field in HEADERS if field[0] != name)
                # Pseudo-fields must precede all ordinary fields on the wire.
                headers = (
                    ((name, value), *headers)
                    if name.startswith(b":")
                    else (*headers, (name, value))
                )
                origin, run = await self.capture(headers)

                self.assertIsInstance(origin.failure, ValueError)
                self.assertEqual(run.requests, [])
                self.assertNotIn("secret", str(origin.failure))

    async def test_consistent_foreign_authority_and_host_reach_the_owned_origin_guard(
        self,
    ) -> None:
        foreign = b"attacker.test:23456"
        headers = tuple(
            (name, foreign if name == b":authority" else value)
            for name, value in HEADERS
        )
        origin, run = await self.capture((*headers, (b"host", foreign)))

        self.assertIsInstance(origin.failure, ValueError)
        self.assertIn(":authority", str(origin.failure))
        self.assertIsNone(run.tcp[0].failure)
        self.assertEqual(run.requests, [])

    async def test_sanitization_changes_only_owned_url_fields(self) -> None:
        headers = (
            *HEADERS,
            (b"x-marker", b"preserve:23456"),
            (b"origin", b"https://" + AUTHORITY),
            (b"host", AUTHORITY),
        )
        origin, run = await self.capture(headers)

        self.assertIsNone(origin.failure)
        fields = run.images[0].headers
        self.assertIn((b"x-marker", b"preserve:23456"), fields)
        self.assertIn((b"origin", b"https://server.phantom.test:<port>"), fields)
        self.assertIn((b"host", b"server.phantom.test:<port>"), fields)

    async def test_header_count_is_bounded_before_retention(self) -> None:
        headers = (*HEADERS, *((b"x", b"") for _ in range(MAX_HEADER_FIELDS)))
        origin, run = await self.capture(headers)

        self.assertIsInstance(origin.failure, ValueError)
        self.assertEqual(run.requests, [])

    def test_decoded_header_bytes_are_bounded_before_retention(self) -> None:
        headers = (*HEADERS, (b"x", b"a" * MAX_REQUEST_HEAD))
        event = h2.events.RequestReceived(stream_id=1, headers=list(headers))

        with self.assertRaisesRegex(ValueError, "headers exceed the capture limit"):
            observe_image_request(0, event, PORT)

    async def test_disabled_observation_preserves_ordinary_routing_and_fixture(
        self,
    ) -> None:
        headers = (*HEADERS, (b"cookie", b"not-retained"))
        origin, run = await self.capture(headers, observe_images=False)

        self.assertIsNone(origin.failure)
        self.assertIsNone(run.images)
        self.assertEqual([request.path for request in run.requests], ["/hold"])
        self.assertNotIn("image_h2", self.fixture(run))

    async def test_request_limit_rejection_does_not_retain_an_image(self) -> None:
        with patch.object(race, "MAX_RUN_REQUESTS", 0):
            origin, run = await self.capture()

        self.assertIsInstance(origin.failure, ValueError)
        self.assertEqual(run.images, [])
        self.assertEqual(run.requests, [])

    async def test_capture_option_reaches_origin_without_launching_a_browser(
        self,
    ) -> None:
        marker = RuntimeError("origin construction reached")
        with (
            patch.object(race, "Origin", side_effect=marker) as origin,
            patch.object(race, "BrowserDriver") as browser,
            self.assertRaisesRegex(RuntimeError, "origin construction reached"),
        ):
            await race.capture_run(
                SCENARIOS["existing-h2-session"],
                listen_host="127.0.0.1",
                browser="chrome",
                executable=None,
                headless=True,
                netlog=Path("unused.json"),
                timeout=1,
                observe_images=True,
            )

        self.assertTrue(origin.call_args.kwargs["observe_images"])
        browser.assert_not_called()


class ImageCliTests(unittest.TestCase):
    def test_opt_in_reaches_capture_and_default_remains_disabled(self) -> None:
        for enabled in (False, True):
            with self.subTest(enabled=enabled), TemporaryDirectory() as directory:
                root = Path(directory)
                arguments = [
                    "alt_svc_race",
                    "--browser-path",
                    str(root / "browser.exe"),
                    "--client-version",
                    "test",
                    "--scenario",
                    "existing-h2-session",
                    "--repeat",
                    "1",
                    "--netlog-dir",
                    str(root / "netlog"),
                ]
                if enabled:
                    arguments.append("--observe-images")
                marker = RuntimeError("capture dispatch reached")

                with (
                    patch.object(sys, "argv", arguments),
                    patch.object(race, "capture_run", side_effect=marker) as capture,
                    redirect_stdout(StringIO()),
                    redirect_stderr(StringIO()),
                    self.assertRaisesRegex(RuntimeError, "capture dispatch reached"),
                ):
                    race.main()

                capture.assert_awaited_once()
                self.assertEqual(capture.await_args.kwargs["observe_images"], enabled)


if __name__ == "__main__":
    unittest.main()
