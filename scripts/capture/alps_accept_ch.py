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


def netlog_lines(data: dict) -> list[str]:
    """The origin's ACCEPT_CH frames, then each URL request to the origin.

    A navigation that starts again for ACCEPT_CH shows as a request whose
    `URL_REQUEST_DELEGATE_CONNECTED` ends with an error and that sends no
    headers, followed by a new request for the same path.
    """
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
        if name == "HTTP2_SESSION_RECV_ACCEPT_CH" and HOSTNAME in params.get(
            "origin", ""
        ):
            lines.append(f"accept_ch_frame={json.dumps(params.get('accept_ch'))}")
            continue
        if sources.get(source.get("type")) != "URL_REQUEST":
            continue
        identifier = source.get("id")
        url = params.get("url", "")
        if (
            name == "URL_REQUEST_START_JOB"
            and HOSTNAME in url
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


def capture(args: argparse.Namespace) -> str:
    started = time.monotonic()
    server = subprocess.Popen(
        [str(args.capture_binary), "127.0.0.1:0", args.accept_ch],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        assert server.stderr is not None and server.stdout is not None
        port = None
        for line in server.stderr:
            if line.startswith(LISTENING_PREFIX):
                port = int(line.strip().rsplit(":", 1)[1])
                break
            print(line.rstrip(), file=sys.stderr)
        if port is None:
            raise RuntimeError("the capture server exited before it listened")
        threading.Thread(
            target=lambda: [
                print(line.rstrip(), file=sys.stderr) for line in server.stderr
            ],
            daemon=True,
        ).start()
        output: list[str] = []
        reader = threading.Thread(
            target=lambda: output.extend(server.stdout.read().splitlines()), daemon=True
        )
        reader.start()
        url = f"https://{HOSTNAME}:{port}/"
        with tempfile.TemporaryDirectory(prefix="phantom-alps-netlog-") as directory:
            netlog = args.netlog or Path(directory) / "netlog.json"
            plan = launch_plan(args, netlog)
            with LaunchedBrowser(plan, url):
                server.wait(timeout=RUN_TIMEOUT_SECONDS)
            reader.join(timeout=10)
            if server.returncode != 0:
                raise RuntimeError(
                    f"capture server failed with exit code {server.returncode}"
                )
            events = netlog_lines(load_netlog(netlog))
            arguments = (
                plan.recorded_arguments(url)
                .replace(str(netlog), "<netlog>")
                .replace(f":{port}", ":<port>")
            )
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=10)
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
    lines.extend(f"server_{index}={line}" for index, line in enumerate(output))
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
