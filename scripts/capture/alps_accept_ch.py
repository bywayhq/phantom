"""Record whether a Chromium navigation starts again for ALPS `ACCEPT_CH` hints.

The `capture_alps_accept_ch` example serves `server.phantom.test` over TLS
and HTTP/2 on loopback, with an ALPS `ACCEPT_CH` frame that names
`--accept-ch` for the origin. Its page fetches `/fetch` and then `/done`. The
tool launches the browser at `/` on a fresh profile with a NetLog, and writes
one fixture: each connection and request the server saw, with request field
names in the order the server decoded them, and the NetLog events of the
navigation's URL request that show a restart. The NetLog is not retained.
"""

from __future__ import annotations

import argparse
import json
import platform
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from .browser_launch import DESKTOP_CHROMIUM_BROWSERS, LaunchedBrowser, LaunchPlan
from .fixture_file import write_text_fixture

FORMAT = "phantom-alps-accept-ch-v1"
HOSTNAME = "server.phantom.test"
DEFAULT_ACCEPT_CH = "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version"
LISTENING_PREFIX = "listening on "
RUN_TIMEOUT_SECONDS = 90
PIPE_TIMEOUT_SECONDS = 10


def launch_plan(args: argparse.Namespace, netlog: Path) -> LaunchPlan:
    return LaunchPlan(
        browser=args.browser,
        executable=args.browser_path,
        headless=not args.headful,
        extra_arguments=(
            # Every other name fails to resolve, so the fresh profile's
            # background connections stay off the network.
            f"--host-resolver-rules=MAP {HOSTNAME} 127.0.0.1, MAP * ~NOTFOUND",
            "--ignore-certificate-errors",
            "--disable-quic",
            f"--log-net-log={netlog}",
            "--net-log-capture-mode=Everything",
        ),
    )


def load_netlog(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace").rstrip()
    if not text.endswith("}"):
        # A NetLog cut off by the browser's exit lacks its closing brackets.
        text = text.rstrip(",") + "]}"
    return json.loads(text)


def field_name(line: str) -> str:
    """The name in a NetLog header line such as `:path: /` or `accept: */*`."""
    if line.startswith(":"):
        return ":" + line[1:].split(":", 1)[0]
    return line.split(":", 1)[0]


def _https_origin(value: str) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme != "https" or hostname is None:
        return None

    return hostname, port if port is not None else 443


def netlog_lines(data: dict, origin: str) -> list[str]:
    """The origin's ACCEPT_CH frames, then each URL request to the origin.

    A navigation that starts again for ACCEPT_CH shows as a request whose
    `URL_REQUEST_DELEGATE_CONNECTED` ends with an error and that sends no
    headers, followed by a new request for the same path.
    """
    expected = _https_origin(origin)
    if expected is None:
        raise ValueError("capture origin must name an HTTPS host and port")

    types = {value: name for name, value in data["constants"]["logEventTypes"].items()}
    sources = {
        value: name for name, value in data["constants"]["logSourceType"].items()
    }

    lines = []
    requests: dict[int, dict] = {}
    for event in data.get("events", []):
        name = types.get(event.get("type"), "")
        params = event.get("params") or {}
        source = event.get("source", {})
        if (
            name == "HTTP2_SESSION_RECV_ACCEPT_CH"
            and _https_origin(params.get("origin", "")) == expected
        ):
            lines.append(f"accept_ch_frame={json.dumps(params.get('accept_ch'))}")
            continue

        if sources.get(source.get("type")) != "URL_REQUEST":
            continue

        identifier = source.get("id")
        url = params.get("url", "")
        if (
            name == "URL_REQUEST_START_JOB"
            and _https_origin(url) == expected
            and identifier not in requests
        ):
            requests[identifier] = {
                "path": urlsplit(url).path,
                "connected_error": "none",
                "fields": None,
            }

        request = requests.get(identifier)
        if request is None:
            continue

        if name == "URL_REQUEST_DELEGATE_CONNECTED" and "net_error" in params:
            request["connected_error"] = params["net_error"]
        if name == "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS":
            request["fields"] = [field_name(line) for line in params.get("headers", [])]
    for number, request in enumerate(requests.values()):
        fields = request["fields"]
        lines.append(
            f"url_request_{number}=path:{request['path']},"
            f"delegate_connected_error:{request['connected_error']},"
            f"sent_headers:{str(fields is not None).lower()},"
            f"fields:{'|'.join(fields) if fields else 'none'}"
        )
    return lines


class _CaptureCleanupError(RuntimeError):
    def __init__(self, owner, failures, primary) -> None:
        self.owner = owner
        self.failures = failures
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        detail = "; ".join(f"{operation}: {error}" for operation, error in failures)
        super().__init__(f"capture server cleanup failed: {detail}")


class _CaptureServer:
    def __init__(self) -> None:
        self.server = None
        self.readers = []
        self.ready = queue.Queue()
        self.output = []
        self.stdout_error = None
        self.stderr_error = None

    def start(self, args: argparse.Namespace) -> None:
        self.server = subprocess.Popen(
            [str(args.capture_binary), "127.0.0.1:0", args.accept_ch],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        if self.server.stdout is None or self.server.stderr is None:
            raise RuntimeError("capture server has no output pipes")

        for name, stream, target in (
            ("stdout", self.server.stdout, self.read_stdout),
            ("stderr", self.server.stderr, self.read_stderr),
        ):
            reader = threading.Thread(target=target, args=(stream,), daemon=True)
            self.readers.append((name, reader))
            reader.start()

    def read_stdout(self, stream) -> None:
        try:
            self.output.extend(stream.read().splitlines())
        except BaseException as error:
            self.stdout_error = error
            self.ready.put(error)

    def read_stderr(self, stream) -> None:
        listening = False
        try:
            for line in stream:
                if not listening and line.startswith(LISTENING_PREFIX):
                    port = int(line.strip().rsplit(":", 1)[1])
                    if not 1 <= port <= 65535:
                        raise ValueError("capture server advertised an invalid port")

                    self.ready.put(port)
                    listening = True
                else:
                    print(line.rstrip(), file=sys.stderr)
        except BaseException as error:
            self.stderr_error = error
            if not listening:
                self.ready.put(error)
        else:
            if not listening:
                self.ready.put(None)

    def listening_port(self) -> int:
        try:
            result = self.ready.get(timeout=RUN_TIMEOUT_SECONDS)
        except queue.Empty as error:
            raise TimeoutError(
                "capture server did not listen before its deadline"
            ) from error

        if isinstance(result, BaseException):
            raise result

        if result is None:
            raise RuntimeError("the capture server exited before it listened")

        return result

    def reader_failures(self):
        return [
            (name, error)
            for name, error in (
                ("stdout", self.stdout_error),
                ("stderr", self.stderr_error),
            )
            if error is not None
        ]

    def join_readers(self, deadline: float):
        failures = []
        for name, reader in self.readers:
            if reader.ident is None:
                continue

            try:
                reader.join(timeout=max(0, deadline - time.monotonic()))
                if reader.is_alive():
                    failures.append(
                        (
                            name,
                            TimeoutError(
                                f"capture {name} reader did not finish; "
                                "Python cannot force-stop the reader"
                            ),
                        )
                    )
            except BaseException as error:
                failures.append((name, error))
        return failures

    def finish_readers(self) -> None:
        failures = self.join_readers(time.monotonic() + PIPE_TIMEOUT_SECONDS)
        failures.extend(self.reader_failures())
        if not failures:
            return

        primary = failures[0][1]
        if len(failures) > 1:
            raise primary from _CaptureCleanupError(self, failures[1:], primary)

        raise primary

    def close(self, primary: BaseException | None) -> None:
        if self.server is None:
            return

        deadline = time.monotonic() + PIPE_TIMEOUT_SECONDS
        failures = []
        try:
            if self.server.poll() is None:
                self.server.kill()
            self.server.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException as error:
            failures.append(("server", error))

        failures.extend(self.join_readers(deadline))
        failures.extend(self.reader_failures())
        for name, stream in (
            ("stdout", self.server.stdout),
            ("stderr", self.server.stderr),
        ):
            reader = next(
                (thread for role, thread in self.readers if role == name), None
            )
            if reader is not None and reader.is_alive():
                # Python cannot force-stop a blocked reader. Closing its TextIO
                # can wait on that read's lock; the failure retains this owner.
                continue

            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    failures.append((name, error))

        secondary = [
            (operation, error) for operation, error in failures if error is not primary
        ]
        if secondary:
            failure = _CaptureCleanupError(self, secondary, primary)
            if primary is not None:
                raise primary from failure

            raise failure from secondary[0][1]


def capture(args: argparse.Namespace) -> str:
    started = time.monotonic()
    owner = _CaptureServer()
    primary = None
    try:
        owner.start(args)
        port = owner.listening_port()
        server = owner.server
        url = f"https://{HOSTNAME}:{port}/"

        with tempfile.TemporaryDirectory(prefix="phantom-alps-netlog-") as directory:
            netlog = args.netlog or Path(directory) / "netlog.json"
            plan = launch_plan(args, netlog)
            with LaunchedBrowser(plan, url):
                server.wait(timeout=RUN_TIMEOUT_SECONDS)

            owner.finish_readers()
            if server.returncode != 0:
                raise RuntimeError(
                    f"capture server failed with exit code {server.returncode}"
                )

            events = netlog_lines(load_netlog(netlog), f"https://{HOSTNAME}:{port}")
            arguments = (
                plan.recorded_arguments(url)
                .replace(str(netlog), "<netlog>")
                .replace(f":{port}", ":<port>")
            )
    except BaseException as error:
        primary = error
        raise
    finally:
        owner.close(primary)

    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={plan.client_name}",
        f"client_version={args.client_version}",
        f"operating_system={args.operating_system}",
        f"hostname={HOSTNAME}",
        f"launch_mode={plan.launch_mode}",
        f"launch_arguments={arguments}",
        f"alps_accept_ch_origin=https://{HOSTNAME}:<port>",
        f"alps_accept_ch={args.accept_ch}",
        f"wall_clock_ms={(time.monotonic() - started) * 1000:.0f}",
    ]
    lines.extend(f"server_{index}={line}" for index, line in enumerate(owner.output))
    lines.extend(f"netlog_{line}" for line in events)
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--browser", choices=DESKTOP_CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--accept-ch", default=DEFAULT_ACCEPT_CH)
    parser.add_argument("--capture-binary", type=Path, required=True)
    parser.add_argument("--netlog", type=Path, help="keep the NetLog at this path")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    fixture = capture(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_text_fixture(args.output, fixture)
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
