"""Launch a Chromium browser against one connection-startup capture listener.

The TLS ClientHello, raw HTTP/2 startup, and QUIC/HTTP/3 startup listeners
(`capture_client_hello`, `capture_http2_tls`, and `chrome_http3.py`) each
record the first connection they accept and take the browser's launch
arguments as a fixture field. This tool starts one listener per run, launches
a fresh browser process with the launch arguments of the retained Chrome 154
fixtures for that layer, and writes the listener's fixture.

`--navigate command-line` puts the page URL on the command line, as the
Chrome 154 fixtures were taken. `--navigate devtools` starts the browser on
`about:blank` with `--remote-debugging-port=0` and navigates its first page
over DevTools after `--settle` seconds. Opera 135 abandons the connections
it opens at startup, which the single-connection listeners would record in
place of its request, so its retained H2 and H3 startups use this mode.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .browser_launch import (
    CLIENT_NAMES,
    DESKTOP_CHROMIUM_BROWSERS,
    terminate_process_tree,
    terminate_profile_processes,
)
from .browser_remote import navigate_page
from .fixture_file import write_atomically

HOSTNAME = "server.phantom.test"
LAYERS = ("tls", "http2", "http3")
BASE_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
)
REMOTE_FLAG = "--remote-debugging-port=0"
START_URL = "about:blank"
# The placeholders the retained fixtures of each layer record.
PROFILE_PLACEHOLDERS = {
    "tls": "<temporary-directory>",
    "http2": "<temporary-profile>",
    "http3": "<temporary-profile>",
}
SPKI_PLACEHOLDER = "<certificate-spki>"
EXAMPLES = {"tls": "capture_client_hello", "http2": "capture_http2_tls"}
# Windows reserves these UDP ports on the capture host.
RESERVED_UDP = range(49841, 50960)
# The line a capture listener writes to standard error once it has bound.
LISTENING_LINE = re.compile(rb"^listening on [^\n]*\n", re.MULTILINE)


def launch_arguments(
    layer: str, profile: str, *, port: int = 0, spki: str = "", devtools: bool
) -> list[str]:
    """Return the browser arguments for `layer`, without the page URL.

    In devtools mode the list ends with the remote debugging flag and
    `about:blank`; otherwise it ends with `--dump-dom`, and the caller
    appends the page URL.
    """
    arguments = ["--headless=new", f"--user-data-dir={profile}", *BASE_FLAGS]
    if layer == "http3":
        arguments += [
            "--no-proxy-server",
            "--enable-quic",
            f"--origin-to-force-quic-on={HOSTNAME}:{port}",
            f"--host-resolver-rules=MAP {HOSTNAME}:{port} 127.0.0.1:{port}, "
            "EXCLUDE localhost",
            f"--ignore-certificate-errors-spki-list={spki}",
        ]
    else:
        arguments += [
            "--disable-quic",
            "--no-proxy-server",
            f"--host-resolver-rules=MAP {HOSTNAME} 127.0.0.1, EXCLUDE localhost",
            "--ignore-certificate-errors",
        ]
    if devtools:
        return [*arguments, REMOTE_FLAG, START_URL]
    return [*arguments, "--dump-dom"]


def recorded_arguments(layer: str, *, port: int = 0, devtools: bool) -> str:
    """The `launch_arguments` fixture value: space-joined, placeholders kept."""
    return " ".join(
        launch_arguments(
            layer,
            PROFILE_PLACEHOLDERS[layer],
            port=port,
            spki=SPKI_PLACEHOLDER,
            devtools=devtools,
        )
    )


def launch_mode(devtools: bool) -> str:
    return "devtools-navigate" if devtools else "command-line"


def free_udp_port() -> int:
    """A loopback UDP port outside the host's reserved range, then released."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port not in RESERVED_UDP:
            return port


class Browser:
    """One browser process on a fresh profile, removed with its process tree."""

    def __init__(self, executable: Path, arguments: Sequence[str]) -> None:
        self.executable = executable
        self.arguments = list(arguments)
        self.profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
        self.process: subprocess.Popen[bytes] | None = None

    def start(self, url: str | None) -> None:
        arguments = [
            argument.replace("<profile>", str(self.profile))
            for argument in self.arguments
        ]
        if url is not None:
            arguments.append(url)
        self.process = subprocess.Popen(
            [str(self.executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def stop(self) -> None:
        try:
            if self.process is not None:
                terminate_process_tree(self.process)
            terminate_profile_processes(self.profile)
        finally:
            shutil.rmtree(self.profile, ignore_errors=True)


def open_page(browser: Browser, url: str, devtools: bool, settle: float) -> None:
    if devtools:
        browser.start(None)
        asyncio.run(navigate_page(browser.profile, url, settle))
    else:
        browser.start(url)


def tcp_run(args: argparse.Namespace, output: Path, timeout: float) -> bool:
    devtools = args.navigate == "devtools"
    binary = args.capture_binary or Path(
        f"target/debug/examples/{EXAMPLES[args.layer]}.exe"
        if sys.platform == "win32"
        else f"target/debug/examples/{EXAMPLES[args.layer]}"
    )
    listener = subprocess.Popen(
        [
            str(binary),
            "127.0.0.1:0",
            args.client,
            args.client_version,
            args.operating_system,
            launch_mode(devtools),
            recorded_arguments(args.layer, devtools=devtools),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    listening = wait_until_listening(listener, args.server_start)
    line = listening.line.decode(errors="replace")
    match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
    if match is None:
        listener.kill()
        _, stderr = listener.communicate()
        stderr = listening.stderr + stderr
        print(f"listener did not start: {line.strip()}", file=sys.stderr)
        print(stderr.decode(errors="replace").strip()[-2000:], file=sys.stderr)
        return False
    url = f"https://{HOSTNAME}:{match.group(1)}/"
    browser = Browser(
        args.browser_path,
        launch_arguments(args.layer, "<profile>", devtools=devtools),
    )
    try:
        open_page(browser, url, devtools, args.settle)
        stdout, stderr = listener.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        listener.kill()
        stdout, stderr = listener.communicate()
    finally:
        browser.stop()
    if listener.returncode != 0:
        stderr = listening.stderr + stderr
        print(stderr.decode(errors="replace").strip(), file=sys.stderr)
        return False
    write_atomically(output, stdout.decode("ascii"), encoding="ascii")
    return True


@dataclass(frozen=True)
class Listening:
    """What `wait_until_listening` saw on the server's standard error."""

    reported: bool
    # The listening line itself, or empty when there was none.
    line: bytes
    # Bytes read past the listening line, or everything read when there was
    # none. communicate() with a timeout reads the pipe's descriptor on POSIX,
    # so it never returns these; put them in front of what it returns.
    stderr: bytes


def wait_until_listening(server: subprocess.Popen[bytes], limit: float) -> Listening:
    """Wait up to `limit` seconds for a capture listener to report its bind.

    chrome_http3.py and the TLS and HTTP/2 capture examples each write a line
    that starts with `listening on` to standard error once bound.

    Returns early when the server exits without the line. A server that has
    not reported by `limit` is killed. The reader reads the pipe's descriptor
    without a buffer and has stopped before this returns, so every byte it
    read is in the result and the rest is left for communicate().
    """
    assert server.stderr is not None
    descriptor = server.stderr.fileno()
    finished = threading.Event()
    seen = bytearray()
    reported: list[int] = []

    def read() -> None:
        try:
            while True:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    return
                seen.extend(chunk)
                line = LISTENING_LINE.search(seen)
                if line is not None:
                    reported.extend(line.span())
                    return
        finally:
            finished.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    finished.wait(limit)
    if not reported and server.poll() is None:
        server.kill()
    reader.join()
    if reported:
        start, end = reported
        return Listening(True, bytes(seen[start:end]), bytes(seen[end:]))
    return Listening(False, b"", bytes(seen))


def quic_run(
    args: argparse.Namespace, startup: Path, client_hello: Path, timeout: float
) -> bool:
    from .http2_session import generate_certificate

    devtools = args.navigate == "devtools"
    certificate = generate_certificate(HOSTNAME)
    material = Path(tempfile.mkdtemp(prefix="phantom-h3-certificate-"))
    (material / "certificate.pem").write_bytes(certificate.certificate_pem)
    (material / "key.pem").write_bytes(certificate.private_key_pem)
    port = free_udp_port()
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.capture.chrome_http3",
            "--certificate",
            str(material / "certificate.pem"),
            "--private-key",
            str(material / "key.pem"),
            "--listen",
            f"127.0.0.1:{port}",
            "--client",
            args.client,
            "--client-version",
            args.client_version,
            "--operating-system",
            args.operating_system,
            "--launch-mode",
            launch_mode(devtools),
            "--launch-arguments",
            recorded_arguments("http3", port=port, devtools=devtools),
            "--client-hello",
            str(client_hello),
            "--output",
            str(startup),
            "--timeout",
            str(timeout),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    listening = wait_until_listening(server, args.server_start)
    if not listening.reported:
        server.kill()
        _, stderr = server.communicate()
        shutil.rmtree(material, ignore_errors=True)
        stderr = listening.stderr + stderr
        print(stderr.decode(errors="replace").strip()[-2000:], file=sys.stderr)
        return False
    browser = Browser(
        args.browser_path,
        launch_arguments(
            "http3",
            "<profile>",
            port=port,
            spki=certificate.spki_sha256_base64,
            devtools=devtools,
        ),
    )
    try:
        open_page(browser, f"https://{HOSTNAME}:{port}/", devtools, args.settle)
        _, stderr = server.communicate(timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        server.kill()
        _, stderr = server.communicate()
    finally:
        browser.stop()
        shutil.rmtree(material, ignore_errors=True)
    if server.returncode != 0:
        stderr = listening.stderr + stderr
        print(stderr.decode(errors="replace").strip()[-2000:], file=sys.stderr)
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # Android browsers take their switches through a device file instead; see
    # `android_run.py`.
    parser.add_argument("--browser", choices=DESKTOP_CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--layer", choices=LAYERS, required=True)
    parser.add_argument(
        "--navigate", choices=("command-line", "devtools"), default="command-line"
    )
    parser.add_argument("--settle", type=float, default=5.0)
    parser.add_argument("--server-start", type=float, default=30.0)
    parser.add_argument("--capture-binary", type=Path)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.client = args.client or CLIENT_NAMES[args.browser]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    succeeded = 0
    for run in range(1, args.repeat + 1):
        if args.layer == "http3":
            ok = quic_run(
                args,
                args.output_dir / f"client-startup-{run}.txt",
                args.output_dir / f"quic-client-hello-{run}.txt",
                args.timeout,
            )
        else:
            name = "client-hello" if args.layer == "tls" else "client-startup"
            ok = tcp_run(args, args.output_dir / f"{name}-{run}.txt", args.timeout)
        succeeded += ok
        print(f"run {run}: {'captured' if ok else 'failed'}", file=sys.stderr)
    print(f"{succeeded} of {args.repeat} runs captured", file=sys.stderr)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
