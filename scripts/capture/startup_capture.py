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
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .browser_failures import raise_browser_failures
from .browser_launch import (
    CLIENT_NAMES,
    DESKTOP_CHROMIUM_BROWSERS,
    host_chromium_flags,
    terminate_profile_processes,
)
from .browser_remote import navigate_page
from .fixture_file import write_atomically
from .process_container import ProcessCleanupError, ProcessContainer

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
# The line a capture listener writes to standard error once it has bound.
LISTENING_LINE = re.compile(rb"^listening on [^\n]*\n", re.MULTILINE)
# These are command guardrails, not measured browser maxima. The TCP examples
# already bound their raw input; leave room for its hexadecimal fixture text.
MAX_CAPTURE_OUTPUT = 1024 * 1024
MAX_CAPTURE_DIAGNOSTICS = 64 * 1024
POLL_SECONDS = 0.02


def launch_arguments(
    layer: str,
    profile: str,
    *,
    port: int | str = 0,
    spki: str = "",
    devtools: bool,
    platform: str = sys.platform,
) -> list[str]:
    """Return the browser arguments for `layer`, without the page URL.

    In devtools mode the list ends with the remote debugging flag and
    `about:blank`; otherwise it ends with `--dump-dom`, and the caller
    appends the page URL. `platform` selects the host's own switches.
    """
    arguments = [
        "--headless=new",
        f"--user-data-dir={profile}",
        *BASE_FLAGS,
        *host_chromium_flags(platform),
    ]
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


def recorded_arguments(
    layer: str, *, port: int | str = 0, devtools: bool, platform: str = sys.platform
) -> str:
    """The `launch_arguments` fixture value: space-joined, placeholders kept."""
    return " ".join(
        launch_arguments(
            layer,
            PROFILE_PLACEHOLDERS[layer],
            port=port,
            spki=SPKI_PLACEHOLDER,
            devtools=devtools,
            platform=platform,
        )
    )


def launch_mode(devtools: bool) -> str:
    return "devtools-navigate" if devtools else "command-line"


class Browser:
    """One browser process on a fresh profile, removed with its process tree."""

    def __init__(self, executable: Path, arguments: Sequence[str]) -> None:
        self.executable = executable
        self.arguments = list(arguments)
        self.profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
        self.process: ProcessContainer | None = None

    def start(self, url: str | None) -> None:
        arguments = [
            argument.replace("<profile>", str(self.profile))
            for argument in self.arguments
        ]
        if url is not None:
            arguments.append(url)
        try:
            self.process = ProcessContainer(
                [str(self.executable), *arguments],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not self.process.start():
                raise RuntimeError("startup browser stopped before launch")
        except BaseException as error:
            self.process = getattr(error, "container", self.process)
            raise

    def stop(self) -> None:
        failures = []
        if self.process is not None:
            try:
                self.process.close()
            except BaseException as error:
                failures.append(error)
        try:
            terminate_profile_processes(self.profile)
        except BaseException as error:
            failures.append(error)
        try:
            _remove_directory(self.profile)
        except BaseException as error:
            failures.append(error)
        raise_browser_failures(None, tuple(failures))


def open_page(browser: Browser, url: str, devtools: bool, settle: float) -> None:
    if devtools:
        browser.start(None)
        asyncio.run(navigate_page(browser.profile, url, settle))
    else:
        browser.start(url)


def tcp_run(args: argparse.Namespace, output: Path, timeout: float) -> bool:
    _validate_bounds(args, timeout)
    devtools = args.navigate == "devtools"
    binary = args.capture_binary or Path(
        f"target/debug/examples/{EXAMPLES[args.layer]}.exe"
        if sys.platform == "win32"
        else f"target/debug/examples/{EXAMPLES[args.layer]}"
    )
    listener = CaptureListener(
        [
            str(binary),
            "127.0.0.1:0",
            args.client,
            args.client_version,
            args.operating_system,
            launch_mode(devtools),
            recorded_arguments(args.layer, devtools=devtools),
        ]
    )
    browser = None
    primary = None
    code = None
    failed_run = False
    try:
        listener.start()
        listening = wait_until_listening(listener, args.server_start)
        match = re.search(rb"listening on 127\.0\.0\.1:(\d+)", listening.line)
        if match is not None:
            browser = Browser(
                args.browser_path,
                launch_arguments(args.layer, "<profile>", devtools=devtools),
            )
            open_page(
                browser,
                f"https://{HOSTNAME}:{int(match.group(1))}/",
                devtools,
                args.settle,
            )
            try:
                code = listener.wait(timeout)
            except subprocess.TimeoutExpired:
                failed_run = True
                raise
        if code != 0:
            primary = _capture_failure(listener)
            failed_run = True
    except BaseException as error:
        primary = error

    cleanup = _cleanup_run(browser, listener)
    if failed_run and not cleanup:
        print(str(primary), file=sys.stderr)
        print(listener.stderr.decode(errors="replace").strip(), file=sys.stderr)
        return False
    raise_browser_failures(primary, cleanup)
    write_atomically(output, listener.stdout.decode("ascii"), encoding="ascii")
    return True


@dataclass(frozen=True)
class Listening:
    """The listening line and diagnostics after it, or all diagnostics on failure."""

    reported: bool
    line: bytes
    stderr: bytes


class CaptureListener:
    """One contained listener with bounded, file-backed output observation.

    Readers have separate open descriptions from the child writers. Polling a
    regular file never waits for inherited pipe handles to close. close() stops
    the process tree before the final snapshot and retains failed cleanup owners.
    """

    def __init__(self, command: Sequence[str]) -> None:
        self.command = list(command)
        self.process: ProcessContainer | None = None
        self.directory: Path | None = None
        self.files: list[BinaryIO] = []
        self.output_reader: BinaryIO | None = None
        self.diagnostics_reader: BinaryIO | None = None
        self.stdout = b""
        self.stderr = b""
        self.code: int | None = None
        self.exit_failure: subprocess.CalledProcessError | None = None
        self.output_error: BaseException | None = None
        self.final_snapshot = False

    def start(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="phantom-startup-output-"))
        output_path = self.directory / "fixture"
        diagnostics_path = self.directory / "diagnostics"
        output = output_path.open("wb", buffering=0)
        self.files.append(output)
        diagnostics = diagnostics_path.open("wb", buffering=0)
        self.files.append(diagnostics)
        self.output_reader = output_path.open("rb")
        self.files.append(self.output_reader)
        self.diagnostics_reader = diagnostics_path.open("rb")
        self.files.append(self.diagnostics_reader)
        try:
            self.process = ProcessContainer(
                self.command, stdout=output, stderr=diagnostics
            )
            if not self.process.start():
                raise RuntimeError("startup listener stopped before launch")
        except BaseException as error:
            self.process = getattr(error, "container", self.process)
            raise

    def observe(self) -> None:
        if self.output_error is not None:
            raise self.output_error
        try:
            for reader, limit, field in (
                (self.output_reader, MAX_CAPTURE_OUTPUT, "stdout"),
                (self.diagnostics_reader, MAX_CAPTURE_DIAGNOSTICS, "stderr"),
            ):
                if reader is None:
                    continue
                reader.seek(0)
                data = reader.read(limit + 1)
                if len(data) > limit:
                    raise ValueError(
                        f"startup listener {field} exceeds the capture limit"
                    )
                setattr(self, field, data)
        except BaseException as error:
            if self.exit_failure is not None:
                self.exit_failure.output = self.stdout
                self.exit_failure.stderr = self.stderr
            try:
                raise_browser_failures(
                    error, (self.exit_failure,) if self.exit_failure is not None else ()
                )
            except BaseException as outcome:
                self.output_error = outcome
                raise

    def poll(self) -> int | None:
        if self.process is None:
            raise RuntimeError("startup listener has not started")

        code = self.process.poll()
        self.code = code
        if code is not None and code != 0 and self.exit_failure is None:
            self.exit_failure = subprocess.CalledProcessError(
                code, self.command, output=self.stdout, stderr=self.stderr
            )

        self.observe()
        if self.exit_failure is not None:
            self.exit_failure.output = self.stdout
            self.exit_failure.stderr = self.stderr
        return code

    def wait(self, timeout: float) -> int:
        _positive_duration(timeout, "capture timeout")
        deadline = time.monotonic() + timeout
        if self.process is None:
            raise RuntimeError("startup listener has not started")
        while True:
            code = self.poll()
            if code is not None:
                return code
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.command, timeout)
            time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    def close(self) -> None:
        failures = []
        stopped = True
        if self.process is not None:
            try:
                self.process.close()
            except BaseException as error:
                failures.append(("close startup listener", error))
                stopped = False
        if (
            stopped
            and self.files
            and self.output_error is None
            and not self.final_snapshot
        ):
            try:
                self.observe()
            except BaseException as error:
                failures.append(("read final startup output", error))
            else:
                self.final_snapshot = True
        # A failed stop retains the files with the original process owner.
        streams = self.files[:] if stopped else ()
        for stream in streams:
            try:
                stream.close()
            except BaseException as error:
                failures.append(("close startup output file", error))
            else:
                self.files.remove(stream)
            if stream.closed:
                if self.output_reader is stream:
                    self.output_reader = None
                if self.diagnostics_reader is stream:
                    self.diagnostics_reader = None
        if stopped and not self.files and self.directory is not None:
            try:
                _remove_directory(self.directory)
            except BaseException as error:
                failures.append(("remove startup output directory", error))
            else:
                self.directory = None
        if failures:
            interruption = next(
                (error for _, error in failures if not isinstance(error, Exception)),
                None,
            )
            failure = ProcessCleanupError(
                failures, container=self.process, primary=interruption
            )
            failure.listener = self
            if interruption is not None:
                raise interruption from failure
            raise failure from failures[0][1]


def wait_until_listening(server: CaptureListener, limit: float) -> Listening:
    """Poll bounded diagnostics for the bind line, exit, or readiness deadline.

    The caller retains the listener and must close it on every outcome, including
    readiness failure. No background reader or pipe EOF is needed for shutdown.
    """
    _positive_duration(limit, "server start timeout")
    if server.process is None:
        raise RuntimeError("startup listener has not started")
    deadline = time.monotonic() + limit
    while True:
        code = server.poll()
        line = LISTENING_LINE.search(server.stderr)
        if line is not None:
            start, end = line.span()
            return Listening(True, server.stderr[start:end], server.stderr[end:])
        if code is not None or time.monotonic() >= deadline:
            return Listening(False, b"", server.stderr)
        time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def _remove_directory(directory: Path) -> None:
    try:
        shutil.rmtree(directory)
    except FileNotFoundError as error:
        if error.filename != os.fspath(directory):
            raise


def _capture_failure(listener: CaptureListener) -> BaseException:
    if listener.exit_failure is not None:
        return listener.exit_failure
    return RuntimeError("startup listener did not report a valid bind")


def _cleanup_run(
    browser: Browser | None,
    listener: CaptureListener | None,
    material: Path | None = None,
) -> tuple[BaseException, ...]:
    failures = []
    if browser is not None:
        try:
            browser.stop()
        except BaseException as error:
            failures.append(error)
    if listener is not None:
        try:
            listener.close()
        except BaseException as error:
            failures.append(error)
    if material is not None:
        try:
            _remove_directory(material)
        except BaseException as error:
            failures.append(error)
    return tuple(failures)


def _positive_duration(value: float, name: str) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")


def _validate_bounds(args: argparse.Namespace, timeout: float) -> None:
    _positive_duration(timeout, "capture timeout")
    _positive_duration(args.server_start, "server start timeout")
    if not math.isfinite(args.settle) or args.settle < 0:
        raise ValueError("settle time must be finite and nonnegative")
    if args.repeat < 1:
        raise ValueError("repeat count must be positive")


def quic_run(
    args: argparse.Namespace, startup: Path, client_hello: Path, timeout: float
) -> bool:
    _validate_bounds(args, timeout)
    from .chrome_http3 import PORT_PLACEHOLDER
    from .http2_session import generate_certificate

    devtools = args.navigate == "devtools"
    material = None
    server = None
    browser = None
    primary = None
    code = None
    failed_run = False
    try:
        certificate = generate_certificate(HOSTNAME)
        material = Path(tempfile.mkdtemp(prefix="phantom-h3-certificate-"))
        (material / "certificate.pem").write_bytes(certificate.certificate_pem)
        (material / "key.pem").write_bytes(certificate.private_key_pem)
        server = CaptureListener(
            [
                sys.executable,
                "-m",
                "scripts.capture.chrome_http3",
                "--certificate",
                str(material / "certificate.pem"),
                "--private-key",
                str(material / "key.pem"),
                "--listen",
                "127.0.0.1:0",
                "--client",
                args.client,
                "--client-version",
                args.client_version,
                "--operating-system",
                args.operating_system,
                "--launch-mode",
                launch_mode(devtools),
                "--launch-arguments",
                recorded_arguments("http3", port=PORT_PLACEHOLDER, devtools=devtools),
                "--client-hello",
                str(client_hello),
                "--output",
                str(startup),
                "--timeout",
                str(timeout),
            ]
        )
        server.start()
        listening = wait_until_listening(server, args.server_start)
        match = re.search(rb"listening on 127\.0\.0\.1:(\d+)", listening.line)
        if match is not None:
            port = int(match.group(1))
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
            open_page(browser, f"https://{HOSTNAME}:{port}/", devtools, args.settle)
            try:
                code = server.wait(timeout + 10)
            except subprocess.TimeoutExpired:
                failed_run = True
                raise
        if code != 0:
            primary = _capture_failure(server)
            failed_run = True
    except BaseException as error:
        primary = error

    cleanup = _cleanup_run(browser, server, material)
    if failed_run and not cleanup:
        print(str(primary), file=sys.stderr)
        if server is not None:
            print(
                server.stderr.decode(errors="replace").strip()[-2000:], file=sys.stderr
            )
        return False
    raise_browser_failures(primary, cleanup)
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
    try:
        _validate_bounds(args, args.timeout)
    except ValueError as error:
        parser.error(str(error))
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
