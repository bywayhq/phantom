import io
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from scripts.capture.startup_capture import (
    REMOTE_FLAG,
    RESERVED_UDP,
    START_URL,
    free_udp_port,
    launch_arguments,
    launch_mode,
    main,
    recorded_arguments,
    wait_until_listening,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


def fixture_field(path: str, field: str) -> str:
    prefix = f"{field}="
    for line in (FIXTURES / path).read_text(encoding="ascii").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].rstrip("\r")
    raise AssertionError(f"{path} has no {field}")


def fixture_port(path: str) -> int:
    return int(fixture_field(path, "listen_address").rsplit(":", 1)[1])


class RecordedArgumentTests(unittest.TestCase):
    """The tool records exactly what the retained startup fixtures hold."""

    def assert_reproduces(self, path: str, layer: str, *, port: int = 0) -> None:
        devtools = fixture_field(path, "launch_mode") == "devtools-navigate"
        self.assertEqual(
            recorded_arguments(layer, port=port, devtools=devtools),
            fixture_field(path, "launch_arguments"),
        )

    def test_command_line_tls_and_http2_fixtures(self) -> None:
        for path, layer in (
            ("tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt", "tls"),
            ("tls/brave/154.1.96.59/windows-11-26200/client-hello.txt", "tls"),
            ("tls/opera/135.0.5973.92/windows-11-26200/client-hello.txt", "tls"),
            ("http2/chrome/154.0.8037.58/windows-11-26200/client-startup.txt", "http2"),
            ("http2/brave/154.1.96.59/windows-11-26200/client-startup.txt", "http2"),
        ):
            with self.subTest(path):
                self.assertEqual(fixture_field(path, "launch_mode"), "command-line")
                self.assert_reproduces(path, layer)

    def test_devtools_http2_fixture(self) -> None:
        path = "http2/opera/135.0.5973.92/windows-11-26200/client-startup.txt"
        self.assertEqual(fixture_field(path, "launch_mode"), "devtools-navigate")
        self.assert_reproduces(path, "http2")

    def test_http3_fixtures_in_both_modes(self) -> None:
        for path in (
            "http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt",
            "http3/brave/154.1.96.59/windows-11-26200/client-startup.txt",
            "http3/brave/154.1.96.59/windows-11-26200/launch-mode/"
            "client-startup-devtools.txt",
            "http3/opera/135.0.5973.92/windows-11-26200/client-startup.txt",
            "http3/opera/135.0.5973.92/windows-11-26200/quic-client-hello-2.txt",
        ):
            with self.subTest(path):
                self.assert_reproduces(path, "http3", port=fixture_port(path))


class LaunchArgumentTests(unittest.TestCase):
    def test_devtools_mode_starts_blank_with_a_remote_port(self) -> None:
        arguments = launch_arguments("http2", "profile", devtools=True)

        self.assertEqual(arguments[-2:], [REMOTE_FLAG, START_URL])
        self.assertNotIn("--dump-dom", arguments)
        self.assertEqual(launch_mode(True), "devtools-navigate")

    def test_command_line_mode_leaves_the_url_to_the_caller(self) -> None:
        arguments = launch_arguments("tls", "profile", devtools=False)

        self.assertEqual(arguments[-1], "--dump-dom")
        self.assertNotIn(REMOTE_FLAG, arguments)
        self.assertEqual(arguments[1], "--user-data-dir=profile")
        self.assertEqual(launch_mode(False), "command-line")

    def test_http3_port_is_outside_the_reserved_range(self) -> None:
        self.assertNotIn(free_udp_port(), RESERVED_UDP)


if __name__ == "__main__":
    unittest.main()


class AndroidBrowserRefusalTests(unittest.TestCase):
    def test_android_browsers_are_refused(self) -> None:
        for browser in ("chrome-android", "brave-android", "edge-android"):
            with (
                self.subTest(browser=browser),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                main(
                    [
                        "--browser",
                        browser,
                        "--browser-path",
                        "adb",
                        "--client-version",
                        "1",
                        "--layer",
                        "tls",
                        "--output-dir",
                        "out",
                    ]
                )


def server(script: str) -> subprocess.Popen[bytes]:
    """A stand-in for chrome_http3.py that runs `script`."""
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


class ListeningWaitTests(unittest.TestCase):
    def test_a_late_listening_line_ends_the_wait_and_keeps_later_output(
        self,
    ) -> None:
        process = server(
            "import sys, time; "
            "print('warming up', file=sys.stderr, flush=True); "
            "time.sleep(0.5); "
            "sys.stderr.write('listening on 127.0.0.1:1\\nafter\\n'); "
            "sys.stderr.flush(); "
            "time.sleep(0.2); "
            "print('later', file=sys.stderr, flush=True)"
        )

        listening = wait_until_listening(process, 30)
        _, rest = process.communicate(timeout=30)

        self.assertTrue(listening.reported)
        # The line after the listening line arrives in the same read.
        output = (listening.stderr + rest).replace(b"\r\n", b"\n")
        self.assertEqual(output, b"after\nlater\n")

    def test_a_server_that_exits_without_the_line_ends_the_wait_early(self) -> None:
        process = server("import sys; print('no', file=sys.stderr); sys.exit(3)")
        begin = time.monotonic()

        listening = wait_until_listening(process, 30)

        self.assertLess(time.monotonic() - begin, 20)
        self.assertFalse(listening.reported)
        self.assertEqual(listening.stderr.replace(b"\r\n", b"\n"), b"no\n")
        process.communicate(timeout=30)
        self.assertEqual(process.returncode, 3)

    def test_a_silent_server_is_stopped_at_the_limit(self) -> None:
        process = server("import time; time.sleep(60)")

        self.assertFalse(wait_until_listening(process, 0.5).reported)

        process.communicate(timeout=30)
        self.assertIsNotNone(process.returncode)
