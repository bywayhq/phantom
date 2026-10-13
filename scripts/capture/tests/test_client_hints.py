import asyncio
import contextlib
import io
import unittest
from unittest import mock
from urllib.parse import urljoin, urlsplit

from scripts.capture import client_hints
from scripts.capture.client_hints import (
    FORMAT,
    USER_AGENT_HINTS,
    CaptureMetadata,
    HintRun,
    HintServer,
    Navigation,
    capture_runs,
    derived_hints,
    fixture,
    main,
    parse_navigation,
)

METADATA = CaptureMetadata(
    client="scripted navigation",
    client_version="0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
DEFAULT = (
    (b"sec-ch-ua", b'"Scripted";v="1"'),
    (b"sec-ch-ua-mobile", b"?0"),
    (b"sec-ch-ua-platform", b'"Test"'),
)
REQUESTED = (
    (b"sec-ch-ua", b'"Scripted";v="1"'),
    (b"sec-ch-ua-mobile", b"?0"),
    (b"sec-ch-ua-full-version", b'"1.0"'),
    (b"sec-ch-ua-platform", b'"Test"'),
    (b"sec-ch-ua-model", b'""'),
)


class ScriptedBrowser:
    """Two navigations: default hints, then the fields the origin requested."""

    def __init__(self, url: str, *, extra: tuple[bytes, ...] = ()) -> None:
        self.url = url
        self.extra = extra
        self.accept_ch: list[bytes] = []

    async def run(self) -> None:
        headers, body = await self.fetch(self.url, DEFAULT)
        self.accept_ch = [
            name.strip() for name in headers.get(b"accept-ch", b"").split(b",")
        ]
        start = body.index(b"location.replace('") + len(b"location.replace('")
        path = body[start : body.index(b"'", start)].decode()
        requested = tuple(
            (name, value) for name, value in REQUESTED if name in self.accept_ch
        )
        await self.fetch(urljoin(self.url, path), requested)

    async def fetch(
        self, url: str, hints: tuple[tuple[bytes, bytes], ...]
    ) -> tuple[dict[bytes, bytes], bytes]:
        parts = urlsplit(url)
        reader, writer = await asyncio.open_connection(parts.hostname, parts.port)
        lines = [
            f"GET {parts.path} HTTP/1.1".encode(),
            b"Host: " + parts.netloc.encode(),
        ]
        lines.extend(name + b": " + value for name, value in hints)
        lines.append(b"User-Agent: scripted")
        lines.extend(self.extra)
        writer.write(b"\r\n".join(lines) + b"\r\n\r\n")
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        headers = {}
        for line in head[:-4].split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            headers[name.strip().lower()] = value.strip()
        body = await reader.readexactly(int(headers[b"content-length"]))
        writer.close()
        return headers, body


@contextlib.asynccontextmanager
async def scripted(url: str, **options):
    browser = ScriptedBrowser(url, **options)
    task = asyncio.create_task(browser.run())
    try:
        yield browser
    finally:
        await task


async def capture(repeat: int = 2, **options) -> list[HintRun]:
    server = HintServer()
    await server.start("127.0.0.1", 0)
    try:
        return await capture_runs(
            server,
            repeat=repeat,
            accept_ch=USER_AGENT_HINTS,
            run_timeout=5.0,
            drive=lambda url: scripted(url, **options),
        )
    finally:
        await server.close()


def navigation(*hints: tuple[str, bytes]) -> Navigation:
    return Navigation((b"Host",), tuple(hints))


class ClientHintCaptureTest(unittest.TestCase):
    def test_second_navigation_order_with_first_navigation_delivery(self) -> None:
        runs = asyncio.run(capture())
        text = fixture(runs, METADATA, USER_AGENT_HINTS)
        lines = text.splitlines()
        self.assertEqual(lines[0], f"format={FORMAT}")
        self.assertIn("transport=HTTP/1.1", lines)
        self.assertIn("accept_ch=" + ",".join(USER_AGENT_HINTS), lines)
        self.assertIn("launch_arguments=none", lines)
        self.assertIn("repeat_count=2", lines)
        self.assertIn(
            "run_1_second_field_order=Host,sec-ch-ua,sec-ch-ua-mobile,"
            "sec-ch-ua-full-version,sec-ch-ua-platform,sec-ch-ua-model,User-Agent",
            lines,
        )
        hints = [line for line in lines if line.startswith("hint_")]
        self.assertEqual(
            hints,
            [
                "hint_count=5",
                'hint_0=default|sec-ch-ua|"Scripted";v="1"',
                "hint_1=default|sec-ch-ua-mobile|?0",
                'hint_2=accept-ch|sec-ch-ua-full-version|"1.0"',
                'hint_3=default|sec-ch-ua-platform|"Test"',
                'hint_4=accept-ch|sec-ch-ua-model|""',
            ],
        )

    def test_runs_that_disagree_are_rejected(self) -> None:
        first = HintRun("a", USER_AGENT_HINTS)
        first.first = navigation(("sec-ch-ua", b"1"))
        first.second = navigation(("sec-ch-ua", b"1"), ("sec-ch-ua-arch", b'"x86"'))
        second = HintRun("b", USER_AGENT_HINTS)
        second.first = first.first
        second.second = navigation(("sec-ch-ua", b"1"), ("sec-ch-ua-arch", b'"arm"'))
        with self.assertRaisesRegex(ValueError, "second-navigation"):
            derived_hints([first, second])

    def test_default_hint_that_changes_value_is_rejected(self) -> None:
        run = HintRun("a", USER_AGENT_HINTS)
        run.first = navigation(("sec-ch-ua", b"1"))
        run.second = navigation(("sec-ch-ua", b"2"))
        with self.assertRaisesRegex(ValueError, "changed after Accept-CH"):
            derived_hints([run])

    def test_default_hints_must_keep_relative_order(self) -> None:
        run = HintRun("a", USER_AGENT_HINTS)
        run.first = navigation(("sec-ch-ua", b"1"), ("sec-ch-ua-mobile", b"?0"))
        run.second = navigation(("sec-ch-ua-mobile", b"?0"), ("sec-ch-ua", b"1"))
        with self.assertRaisesRegex(ValueError, "relative order"):
            derived_hints([run])

    def test_browser_without_hints_records_an_empty_set(self) -> None:
        run = HintRun("a", USER_AGENT_HINTS)
        run.first = navigation()
        run.second = navigation()
        text = fixture([run], METADATA, USER_AGENT_HINTS)
        self.assertIn("hint_count=0", text.splitlines())

    def test_credential_fields_are_refused(self) -> None:
        head = b"GET / HTTP/1.1\r\nHost: a\r\nCookie: secret=1\r\n\r\n"
        with self.assertRaisesRegex(ValueError, "credential"):
            parse_navigation(head, USER_AGENT_HINTS)

    def test_only_requested_or_sec_ch_fields_are_hints(self) -> None:
        head = (
            b"GET / HTTP/1.1\r\nHost: a\r\nSec-CH-Prefers-Color-Scheme: light\r\n"
            b"Device-Memory: 8\r\nUser-Agent: x\r\n\r\n"
        )
        parsed = parse_navigation(head, ("device-memory",))
        self.assertEqual(
            parsed.hints,
            (("sec-ch-prefers-color-scheme", b"light"), ("device-memory", b"8")),
        )
        self.assertEqual(
            parsed.field_names,
            (b"Host", b"Sec-CH-Prefers-Color-Scheme", b"Device-Memory", b"User-Agent"),
        )

    def test_arguments_require_loopback_and_lowercase_names(self) -> None:
        base = ["--browser", "manual", "--client-version", "0", "--output", "x.txt"]
        with self.assertRaises(SystemExit):
            main([*base, "--listen", "192.0.2.1:0"])
        with self.assertRaises(SystemExit):
            main([*base, "--accept-ch", "Sec-CH-UA"])
        with self.assertRaises(SystemExit):
            main(["--browser", "chrome", "--client-version", "0", "--output", "x.txt"])

    def test_invalid_arguments_fail_before_starting_capture(self) -> None:
        base = ["--browser", "manual", "--client-version", "0", "--output", "x.txt"]
        invalid = [
            ["--accept-ch", name]
            for name in (
                "sec-ch-ua\r\nx-injected: yes",
                "sec-ch-ua\t",
                "bad:name",
                "x|y",
                "é",
                "",
            )
        ]
        invalid.extend(
            ["--run-timeout", value] for value in ("nan", "inf", "-inf", "0", "-1")
        )
        invalid.extend(
            ["--listen", value]
            for value in ("not-an-ip:0", "127.0.0.1:-1", "[::1]:65536", "127.0.0.1")
        )
        with mock.patch.object(client_hints, "run") as capture_run:
            for arguments in invalid:
                with (
                    self.subTest(arguments=arguments),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        main([*base, *arguments])
                    self.assertEqual(raised.exception.code, 2)
            capture_run.assert_not_called()

    def test_direct_capture_rejects_invalid_options_before_driving(self) -> None:
        server = HintServer()
        drive = mock.Mock()
        options = [
            (1, ("sec-ch-ua\r\nx-injected: yes",), 1.0),
            (1, ("x|y",), 1.0),
            (1, USER_AGENT_HINTS, float("nan")),
            (1, USER_AGENT_HINTS, float("inf")),
            (1, USER_AGENT_HINTS, 0.0),
            (0, USER_AGENT_HINTS, 1.0),
        ]
        for repeat, names, timeout in options:
            with self.subTest(repeat=repeat, names=names, timeout=timeout):
                with self.assertRaises(ValueError):
                    asyncio.run(
                        capture_runs(
                            server,
                            repeat=repeat,
                            accept_ch=names,
                            run_timeout=timeout,
                            drive=drive,
                        )
                    )
                self.assertIsNone(server.run)
        drive.assert_not_called()

    def test_ipv6_navigation_url_and_listen_address_are_valid(self) -> None:
        server = HintServer()
        server.address = ("::1", 12345)
        run = HintRun("literal-token", USER_AGENT_HINTS)
        address = urlsplit(server.url(run))
        self.assertEqual(address.hostname, "::1")
        self.assertEqual(address.port, 12345)
        self.assertEqual(address.path, "/run/literal-token/first")
        self.assertEqual(client_hints.parse_listen("[::1]:0"), ("::1", 0))
        self.assertEqual(client_hints.parse_listen("::1:0"), ("::1", 0))

    def test_hint_separator_is_rejected_in_requests_and_fixture_records(self) -> None:
        head = b"GET / HTTP/1.1\r\nHost: a\r\nSec-CH-X|Y: literal\r\n\r\n"
        with self.assertRaisesRegex(ValueError, "fixture separator"):
            parse_navigation(head, USER_AGENT_HINTS)

        run = HintRun("literal", USER_AGENT_HINTS)
        run.first = navigation()
        run.second = navigation(("sec-ch-x|y", b"literal"))
        with self.assertRaisesRegex(ValueError, "fixture separator"):
            fixture([run], METADATA, USER_AGENT_HINTS)


if __name__ == "__main__":
    unittest.main()
