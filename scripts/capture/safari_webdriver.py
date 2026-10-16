"""Attempt one HTTP SSE capture with the Safari installed on a macOS runner."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.client
import io
import json
import os
import platform
import plistlib
import re
import socket
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

from .fixture_file import write_text_fixture
from .sse_reconnect import (
    SCENARIOS,
    CaptureMetadata,
    ReconnectServer,
    capture_scenario,
    fixture,
)

COMMAND_SECONDS = 10.0
CLEANUP_SECONDS = 5.0
MAX_OUTPUT = 64 * 1024
MAX_WIRE = MAX_OUTPUT + 16 * 1024
DRIVER = Path("/usr/bin/safaridriver")
SAFARI = Path("/Applications/Safari.app")
SCENARIO = SCENARIOS["reconnect-204"]


class WebDriverError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        super().__init__(f"WebDriver HTTP {status}: {code}: {message[:2048]}")


class SafariFailure(RuntimeError):
    """Keep the original operation and each cleanup failure inspectable."""

    def __init__(self, primary, cleanup) -> None:
        self.primary = primary
        self.cleanup = tuple(cleanup)
        errors = ([primary] if primary is not None else []) + list(cleanup)
        super().__init__("; ".join(f"{type(e).__name__}: {e}" for e in errors))


def error_record(error: BaseException, seen=None) -> dict:
    seen = set() if seen is None else seen
    result = {"type": type(error).__name__, "message": str(error)[:4096]}
    if id(error) in seen:
        result["repeated_reference"] = True
        return result
    seen.add(id(error))
    if isinstance(error, SafariFailure):
        result["primary"] = (
            error_record(error.primary, seen) if error.primary is not None else None
        )
        result["cleanup"] = [error_record(e, seen) for e in error.cleanup]
    if error.__cause__ is not None and error.__cause__ is not error:
        result["cause"] = error_record(error.__cause__, seen)
    return result


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate WebDriver JSON member")
        result[name] = value
    return result


class ResponseSocket:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def makefile(self, *_args):
        return io.BytesIO(self.data)


def response_value(wire: bytes):
    if len(wire) > MAX_WIRE or wire.find(b"\r\n\r\n") > 16 * 1024:
        raise ValueError("WebDriver response exceeds the wire limit")
    response = http.client.HTTPResponse(ResponseSocket(wire))
    try:
        response.begin()
        # The entire wire buffer is already bounded; read all framing so a
        # truncated Content-Length cannot masquerade as a complete JSON reply.
        body = response.read()
        if len(body) > MAX_OUTPUT:
            raise ValueError("WebDriver JSON exceeds the body limit")
        document = json.loads(body, object_pairs_hook=unique_object)
        if not isinstance(document, dict) or "value" not in document:
            raise ValueError("WebDriver response has no value")
        value = document["value"]
        if isinstance(value, dict) and "error" in value:
            raise WebDriverError(
                response.status, str(value["error"]), str(value.get("message", ""))
            )
        if not 200 <= response.status < 300:
            raise WebDriverError(response.status, "http error", "no protocol error")
        return value
    finally:
        response.close()


async def request(port: int, method: str, path: str, payload=None):
    """Bound the entire exchange, including a peer that trickles its response."""
    body = b"" if payload is None else json.dumps(payload).encode()
    if method not in {"GET", "POST", "DELETE"} or not re.fullmatch(
        r"/[A-Za-z0-9/._~%+-]*", path
    ):
        raise ValueError("invalid WebDriver command")
    if len(body) > MAX_OUTPUT:
        raise ValueError("WebDriver request exceeds the body limit")

    async def exchange():
        _reader, _writer = await asyncio.open_connection("127.0.0.1", port)
        primary = None
        try:
            _writer.write(
                f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode()
                + body
            )
            await _writer.drain()
            wire = bytearray()
            while chunk := await _reader.read(min(8192, MAX_WIRE + 1 - len(wire))):
                wire.extend(chunk)
                if len(wire) > MAX_WIRE:
                    raise ValueError("WebDriver response exceeds the wire limit")
            return response_value(bytes(wire))
        except BaseException as error:
            primary = error
            raise
        finally:
            _writer.close()
            try:
                await asyncio.wait_for(_writer.wait_closed(), CLEANUP_SECONDS)
            except BaseException as error:
                if primary is not None:
                    raise SafariFailure(primary, [error]) from primary
                raise

    return await asyncio.wait_for(exchange(), COMMAND_SECONDS)


async def settle(task: asyncio.Task):
    """Observe an owned acquisition/cleanup even when its caller is cancelled."""
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            cancellation = error
        except BaseException:
            break
    try:
        result = task.result()
    except BaseException as error:
        if cancellation is not None:
            raise cancellation from error
        raise
    if cancellation is not None:
        raise cancellation
    return result


async def command(*arguments: str, allow_failure=False) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    primary = None
    try:

        async def collect():
            output = bytearray()
            while chunk := await process.stdout.read(8192):
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise ValueError("command output exceeds the limit")
            code = await process.wait()
            if code and not allow_failure:
                raise RuntimeError(
                    f"{Path(arguments[0]).name} exited {code}: "
                    f"{output.decode(errors='replace')[:2048]}"
                )
            return code, output.decode(errors="replace").strip()

        return await asyncio.wait_for(collect(), COMMAND_SECONDS)
    except BaseException as error:
        primary = error
        raise
    finally:
        if process.returncode is None:
            try:
                process.kill()
                await settle(
                    asyncio.create_task(
                        asyncio.wait_for(process.wait(), CLEANUP_SECONDS)
                    )
                )
            except BaseException as error:
                raise SafariFailure(primary, [error]) from primary


class SafariSession:
    def __init__(self, url: str, provenance: dict) -> None:
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or not parts.port:
            raise ValueError("Safari capture requires a loopback HTTP URL")
        if parts.username or parts.password or parts.fragment:
            raise ValueError("Safari capture URL contains unsupported components")
        self.url = url
        self.provenance = provenance
        self.process = None
        self.port = None
        self.session = None
        self.log_task = None
        self.close_task = None

    async def command(self, method, suffix, payload=None):
        if self.process is None or self.process.returncode is not None:
            raise RuntimeError("owned Safari driver is not running")
        result = await request(self.port, method, suffix, payload)
        if self.process.returncode is not None:
            raise RuntimeError("owned Safari driver exited during the command")
        return result

    def session_path(self, suffix="") -> str:
        return "/session/" + quote(self.session, safe="") + suffix

    async def collect_log(self):
        output = bytearray()
        count = 0
        while chunk := await self.process.stdout.read(8192):
            count += len(chunk)
            output.extend(chunk[: max(0, MAX_OUTPUT - len(output))])
        self.provenance["driver_log"] = output.decode(errors="replace")
        self.provenance["driver_log_bytes"] = count
        self.provenance["driver_log_truncated"] = count > MAX_OUTPUT

    async def open(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        # Native Safari service arguments: Selenium's safari/service.py.
        self.process = await asyncio.create_subprocess_exec(
            str(DRIVER),
            "-p",
            str(self.port),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.provenance["driver_pid"] = self.process.pid
        self.log_task = asyncio.create_task(self.collect_log())
        deadline = asyncio.get_running_loop().time() + COMMAND_SECONDS
        while True:
            if self.process.returncode is not None:
                raise RuntimeError("Safari driver exited before listener readiness")
            # Safari hosts REST in its XPC service, which need not have the
            # launcher PID. Observe this one port; never terminate its census.
            code, listing = await command(
                "/usr/sbin/lsof",
                "-nP",
                f"-iTCP:{self.port}",
                "-sTCP:LISTEN",
                "-Fpn",
                allow_failure=True,
            )
            names = [line[1:] for line in listing.splitlines() if line.startswith("n")]
            if (
                code == 0
                and any(
                    re.fullmatch(r"p[1-9][0-9]*", line) for line in listing.splitlines()
                )
                and names
            ):
                if any(
                    name not in {f"127.0.0.1:{self.port}", f"[::1]:{self.port}"}
                    for name in names
                ):
                    raise RuntimeError("Safari driver listener is not loopback-only")
                break
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Safari WebDriver listener was not observed")
            await asyncio.sleep(0.05)
        self.provenance["listener_observation"] = listing
        self.provenance["listener_scope"] = (
            "released ephemeral port, live launched driver, loopback REST; "
            "XPC listener PID is observed, not treated as a child owner"
        )
        status = await self.command("GET", "/status")
        if not isinstance(status, dict) or status.get("ready") is not True:
            raise RuntimeError("Safari driver is not ready for a new session")
        value = await self.command(
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "safari",
                        "acceptInsecureCerts": False,
                        "pageLoadStrategy": "normal",
                    }
                }
            },
        )
        if not isinstance(value, dict) or not isinstance(value.get("sessionId"), str):
            raise ValueError("Safari driver omitted the session identity")
        self.session = value["sessionId"]
        if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", self.session):
            raise ValueError("Safari driver returned an invalid session identity")
        capabilities = value.get("capabilities")
        self.provenance["capabilities"] = capabilities
        if (
            not isinstance(capabilities, dict)
            or capabilities.get("browserName") != "safari"
        ):
            raise ValueError("WebDriver did not select Safari")
        if capabilities.get("browserVersion") != self.provenance["safari_version"]:
            raise ValueError("Safari capabilities and installed version differ")
        await self.command(
            "POST",
            self.session_path("/timeouts"),
            {
                "pageLoad": 10000,
                "script": 10000,
                "implicit": 0,
            },
        )
        self.provenance["user_agent"] = await self.command(
            "POST",
            self.session_path("/execute/sync"),
            {"script": "return navigator.userAgent", "args": []},
        )
        await self.command("POST", self.session_path("/url"), {"url": self.url})

    async def __aenter__(self):
        try:
            await settle(asyncio.create_task(self.open()))
        except BaseException as primary:
            self.provenance["launch_failure"] = error_record(primary)
            try:
                await self.close()
            except BaseException as cleanup:
                raise SafariFailure(primary, [cleanup]) from primary
            raise
        return self

    async def close(self):
        if self.close_task is None:
            self.close_task = asyncio.create_task(self.finish())
        await settle(self.close_task)

    async def finish(self):
        failures = []
        if self.session is not None:
            try:
                await self.command("DELETE", self.session_path())
                self.provenance["session_delete_acknowledged"] = True
            except BaseException as error:
                failures.append(error)
        if self.process is not None and self.process.returncode is None:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), CLEANUP_SECONDS)
            except BaseException as error:
                failures.append(error)
                if self.process.returncode is None:
                    try:
                        self.process.kill()
                        await asyncio.wait_for(self.process.wait(), CLEANUP_SECONDS)
                    except BaseException as kill_error:
                        failures.append(kill_error)
        if self.process is not None:
            self.provenance["driver_exit"] = self.process.returncode
        if self.log_task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self.log_task), CLEANUP_SECONDS)
            except BaseException as error:
                failures.append(error)
                self.log_task.cancel()
                await asyncio.gather(self.log_task, return_exceptions=True)
        self.provenance["cleanup_failures"] = [error_record(e) for e in failures]
        if failures:
            raise SafariFailure(None, failures)

    async def __aexit__(self, _kind, primary, _traceback):
        try:
            await self.close()
        except BaseException as cleanup:
            raise SafariFailure(primary, [cleanup]) from primary


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


async def provenance() -> dict:
    if sys.platform != "darwin":
        raise RuntimeError("Safari capture requires macOS and its installed driver")
    with (SAFARI / "Contents/Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    result = {
        "safari_version": info["CFBundleShortVersionString"],
        "safari_build": info["CFBundleVersion"],
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "launch_mode": "webdriver-headed",
        "scenario": "reconnect-204",
        "repeat": 1,
        "retries": 0,
        "protocol": "http/1.1",
        "driver_sha256": file_hash(DRIVER),
        "safari_sha256": file_hash(SAFARI / "Contents/MacOS/Safari"),
        "image_os": os.environ.get("ImageOS"),  # noqa: SIM112 - runner's exact key
        "image_version": os.environ.get("ImageVersion"),  # noqa: SIM112 - runner's exact key
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "cleanup_scope": "owned WebDriver session and driver; no global XPC census",
    }
    for name, args in {
        "driver_version": (str(DRIVER), "--version"),
        "operating_system": ("/usr/bin/sw_vers",),
        "safari_signature": ("/usr/bin/codesign", "-d", "--verbose=2", str(SAFARI)),
        "source_head": ("git", "rev-parse", "HEAD"),
        "source_status": ("git", "status", "--porcelain", "--untracked-files=no"),
    }.items():
        _, result[name] = await command(*args)
    if result["source_status"]:
        raise RuntimeError("Safari capture requires a clean source checkout")
    if os.environ.get("GITHUB_SHA", result["source_head"]) != result["source_head"]:
        raise RuntimeError("capture checkout does not match the workflow SHA")
    result["source_files"] = {
        name: file_hash(Path(name))
        for name in (
            "scripts/capture/safari_webdriver.py",
            "scripts/capture/sse_reconnect.py",
            "scripts/capture/browser_launch.py",
            "scripts/capture/fixture_file.py",
            "scripts/requirements.txt",
            ".github/workflows/safari-capture.yml",
        )
    }
    return result


def check_run(run) -> None:
    requests = [request for request in run.requests if request.kind == "sse"]
    if (
        not any(r.kind == "page" for r in run.requests)
        or [r.attempt for r in requests] != [0, 1]
        or any(r.extra for r in requests)
        or run.terminated is None
    ):
        raise RuntimeError(
            "Safari did not complete the observed reconnect-204 sequence"
        )


async def run(output: Path) -> None:
    await asyncio.to_thread(output.mkdir, parents=True, exist_ok=False)
    record = {"status": "failed", "launch_mode": "webdriver-headed"}
    server = ReconnectServer()
    session = None
    observed = None
    metadata = None
    primary = None
    cleanup = []
    try:
        record.update(await provenance())
        await server.start("127.0.0.1", 0)
        metadata = CaptureMetadata(
            client="safari",
            client_version=record["safari_version"],
            operating_system=platform.platform(),
            listen_address=f"127.0.0.1:{server.address[1]}",
            launch_mode="webdriver-headed",
            launch_arguments="safaridriver -p <port>; WebDriver navigate loopback HTTP",
        )

        def drive(url):
            nonlocal session, observed
            observed = server.run
            session = SafariSession(url, record)
            return session

        runs = await capture_scenario(
            server,
            SCENARIO,
            repeat=1,
            run_timeout=120.0,
            drive=drive,
        )
        check_run(runs[0])
        record["status"] = "success"
    except BaseException as error:
        primary = error
    finally:
        if session is not None:
            try:
                await session.close()
            except BaseException as error:
                cleanup.append(error)
        try:
            await server.close()
        except BaseException as error:
            cleanup.append(error)
        if observed is not None and metadata is not None:
            try:
                write_text_fixture(
                    output / "reconnect-204.txt",
                    fixture(SCENARIO, [observed], metadata),
                )
            except BaseException as error:
                cleanup.append(error)
        if primary is not None or cleanup:
            record["status"] = "failed"
        record["failure"] = error_record(primary) if primary is not None else None
        record["final_cleanup_failures"] = [error_record(e) for e in cleanup]
        try:
            (output / "result.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )
        except BaseException as error:
            raise SafariFailure(primary, [*cleanup, error]) from primary
    if primary is not None or cleanup:
        raise SafariFailure(primary, cleanup) from primary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.output_dir))


if __name__ == "__main__":
    main()
