import unittest
from pathlib import Path

from scripts.capture.startup_capture import (
    REMOTE_FLAG,
    RESERVED_UDP,
    START_URL,
    free_udp_port,
    launch_arguments,
    launch_mode,
    recorded_arguments,
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
