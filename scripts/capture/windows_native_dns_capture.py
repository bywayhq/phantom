"""Capture one native DNS lookup on a disposable hosted Windows 2025 runner."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from scripts.capture import firefox_socket_hooks as firefox
from scripts.capture.browser_failures import raise_browser_failures
from scripts.capture.capture_report import file_digest
from scripts.capture.native_dns import NativeDnsServer

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "target/windows-native-dns-capture"
GUARD = ROOT / "scripts/capture/windows_native_dns_guard.ps1"
INSTALLER_URL = (
    "https://archive.mozilla.org/pub/firefox/releases/157.0/win64/en-US/"
    "Firefox%20Setup%20157.0.exe"
)
INSTALLER_SHA512 = (
    "8b3517df9d9e55a00aca4aa04023558030c8c8704d8aa0bd684607c19c49302ed778ee9d34d4"
    "b6e7fba3e6854df5c006bcec79c2ab8c024dc1cda8c36c85204a"
)
EXECUTABLE_SHA256 = "6a6175344a8cb4215d3c5202f718531adc0c13828e36f47a13a934cee61c0c7b"
BUILD_ID = "20260924084938"
SCENARIO = firefox.Scenario(
    "native-dns",
    "Does a post-attachment native DNS answer reach the owned HTTP origin?",
    30,
    "http1",
    firefox._readable_get("/close?i=0")
    + ".then(text => { if (text !== 'ok\\n') throw new Error('target body mismatch'); "
    + f"return {firefox.DONE}; }})",
)
SOURCE_PATHS = (
    "scripts/capture/windows_native_dns_capture.py",
    "scripts/capture/windows_native_dns_guard.ps1",
    "scripts/capture/native_dns.py",
    "scripts/capture/firefox_socket_hooks.py",
    "scripts/capture/firefox_socket_hooks.js",
    "scripts/capture/socket_hooks.js",
    "scripts/capture/socket_hooks.py",
    "scripts/capture/browser_launch.py",
    "scripts/capture/process_container.py",
    "scripts/requirements.txt",
    "scripts/capture/hooks-requirements.txt",
    ".github/workflows/windows-native-dns-capture.yml",
)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def require_hosted() -> None:
    if (
        sys.platform != "win32"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Windows"
        or os.environ.get("IMAGEOS") not in ("win25", "win25-vs2026")
    ):
        raise RuntimeError("native DNS capture requires hosted windows-2025")


def command(record: dict, *args: str, timeout: float = 60) -> str:
    entry = {"argv": list(args), "timeout_seconds": timeout, "exit": None}
    record.setdefault("commands", []).append(entry)
    # The watchdog can inherit pipe handles after the guard has exited.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        failure = None
        try:
            result = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            failure = error
            entry["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            stdout.seek(0)
            stderr.seek(0)
            output, errors = stdout.read(), stderr.read()
            entry["stdout"] = output.decode("utf-8", "replace")
            entry["stderr"] = errors.decode("utf-8", "replace")
            if isinstance(failure, subprocess.TimeoutExpired):
                failure.output, failure.stderr = output, errors
    entry["exit"] = result.returncode
    result.stdout, result.stderr = output, errors
    result.check_returncode()
    return entry["stdout"].strip()


def guard(record: dict, action: str, *extra: str) -> dict:
    return json.loads(
        command(
            record,
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(GUARD),
            "-Action",
            action,
            "-StatePath",
            str(OUTPUT / "nrpt-state.json"),
            *extra,
        )
    )


def browser_identity(executable: Path) -> dict:
    version, build = firefox.installed_build(executable)
    identity = {
        "version": version,
        "build_id": build,
        "executable_sha256": file_digest(executable),
        "application_ini_sha256": file_digest(executable.parent / "application.ini"),
        "application_ini": (executable.parent / "application.ini").read_text(
            encoding="utf-8"
        ),
    }
    if (version, build) != ("157.0", BUILD_ID):
        raise RuntimeError("staged Firefox version or build ID differs from pinned157")
    if identity["executable_sha256"] != EXECUTABLE_SHA256:
        raise RuntimeError("staged Firefox executable hash differs from pinned157")
    return identity


def stage_browser(record: dict) -> Path:
    stage = Path(
        tempfile.mkdtemp(prefix="phantom-native-dns-", dir=os.environ["RUNNER_TEMP"])
    )
    record["staging_directory"] = str(stage)
    installer = stage / "Firefox Setup 157.0.exe"
    command(
        record,
        "curl.exe",
        "--fail",
        "--location",
        "--proto",
        "=https",
        "--max-time",
        "150",
        "--max-filesize",
        "100000000",
        "--dump-header",
        str(OUTPUT / "download.headers"),
        "--output",
        str(installer),
        INSTALLER_URL,
        timeout=160,
    )
    digest = hashlib.sha512(installer.read_bytes()).hexdigest()
    record["installer"] = {
        "url": INSTALLER_URL,
        "sha512": digest,
        "bytes": installer.stat().st_size,
    }
    if digest != INSTALLER_SHA512:
        raise RuntimeError("Firefox installer hash differs from pinned157")
    guard(record, "Identity", "-Executable", str(installer))
    command(
        record,
        "7z.exe",
        "x",
        "-y",
        f"-o{stage / 'extracted'}",
        str(installer),
        timeout=120,
    )
    executable = stage / "extracted/core/firefox.exe"
    record["browser_before"] = browser_identity(executable)
    record["signature"] = guard(record, "Identity", "-Executable", str(executable))
    return executable


def validate_result(result: firefox.RunResult, records: list[dict]) -> dict:
    ready = [
        entry["time_ms"]
        for entry in result.reports
        if entry.get("kind") == "firefox-config"
    ]
    if (
        result.timed_out
        or result.errors
        or not ready
        or not result.origins.done.is_set()
    ):
        raise RuntimeError(
            "Firefox capture did not complete with ready hooks and no errors"
        )
    if result.frida_version != "17.24.3":
        raise RuntimeError("Firefox capture used an unexpected Frida version")
    if not any(
        path == "/close?i=0"
        for connection in result.origins.connections
        for _, path in connection.requests
    ):
        raise RuntimeError("owned origin did not receive the measured request")
    answered = [
        entry
        for entry in records
        if entry.get("name") == firefox.TARGET_HOST
        and entry.get("kind") == 1
        and entry["unix_ns"] >= min(ready) * 1_000_000
        and entry.get("error") is None
        and entry.get("response_hex")
        and ("response_queued_ns" in entry or "response_drained_ns" in entry)
    ]
    if not answered:
        raise RuntimeError("no owned A response was sent after Firefox hooks attached")
    return {
        "post_attach_a_responses": len(answered),
        "https_query_count": sum(entry.get("kind") == 65 for entry in records),
    }


async def capture(executable: Path, record: dict) -> None:
    dns = NativeDnsServer(firefox.TARGET_HOST)
    primary = None
    cleanup = []
    browser = None
    browser_observed = False
    failed = None
    try:
        await dns.start()
        record["dns_address"] = dns.address
        record["nrpt"] = guard(record, "Install", "-OwnerPid", str(os.getpid()))
        browser = asyncio.create_task(
            firefox.run_once(
                SCENARIO,
                executable,
                headful=True,
                failure_path=OUTPUT / "firefox-failed.json",
            )
        )
        failed = asyncio.create_task(dns.failed.wait())
        done, _ = await asyncio.wait(
            (browser, failed), return_when=asyncio.FIRST_COMPLETED
        )
        if failed in done:
            raise RuntimeError(
                "native DNS peer failed during browser capture"
            ) from dns.failures[0]
        try:
            result, arguments = await browser
        finally:
            browser_observed = True
        write_json(OUTPUT / "hooks.json", result.reports)
        (OUTPUT / "parent.moz_log").write_text(result.moz_log_text, encoding="utf-8")
        write_json(
            OUTPUT / "origin.json",
            [asdict(connection) for connection in result.origins.connections],
        )
        record["launch_arguments"] = arguments
        record["hook_errors"] = result.errors
        record["timed_out"] = result.timed_out
        record["positive"] = validate_result(result, dns.records())
        (OUTPUT / "hooks.txt").write_text(
            "\n".join(firefox.render_run(0, result)) + "\n", encoding="utf-8"
        )
    except BaseException as error:
        primary = error
    finally:
        if browser is not None and not browser_observed:
            if not browser.done():
                browser.cancel()
            try:
                await browser
            except asyncio.CancelledError:
                pass  # Requested cancellation; run_once collects its owned browser first.
            except BaseException as error:
                cleanup.append(error)
        if failed is not None:
            failed.cancel()
            await asyncio.gather(failed, return_exceptions=True)
        try:
            await dns.close()
        except BaseException as error:
            cleanup.append(error)
        try:
            write_json(OUTPUT / "dns.json", dns.records())
        except BaseException as error:
            cleanup.append(error)
        record["dns_failures"] = [
            f"{type(error).__name__}: {error}" for error in dns.failures
        ]
        try:
            record["restoration"] = guard(record, "Verify")
        except BaseException as error:
            cleanup.append(error)
        record["cleanup_errors"] = [
            f"{type(error).__name__}: {error}" for error in cleanup
        ]
    raise_browser_failures(primary, tuple(cleanup))


def main() -> None:
    require_hosted()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    record = {
        "platform": platform.platform(),
        "runner": "windows-2025",
        "scope": "one native A lookup and complete HTTP body; not DNS cache/TTL policy",
        "interventions": {
            "exact_name_nrpt": firefox.TARGET_HOST,
            "network.trr.mode": 5,
            "network.proxy.type": 0,
            "lookup_rewrite": False,
        },
        "source_before": {path: file_digest(ROOT / path) for path in SOURCE_PATHS},
    }
    executable = None
    try:
        record["host"] = guard(record, "Preflight")
        executable = stage_browser(record)
        asyncio.run(capture(executable, record))
        record["browser_after"] = browser_identity(executable)
        record["signature_after"] = guard(
            record, "Identity", "-Executable", str(executable)
        )
        if record["signature_after"]["staged_processes"]:
            raise RuntimeError("staged Firefox processes remain after capture cleanup")
        if record["browser_after"] != record["browser_before"]:
            raise RuntimeError("Firefox identity changed during capture")
        record["source_after"] = {
            path: file_digest(ROOT / path) for path in SOURCE_PATHS
        }
        if record["source_before"] != record["source_after"]:
            raise RuntimeError("capture source changed during run")
        record["status"] = "complete"
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if executable is not None and "browser_after" not in record:
            record["browser_after_sha256"] = file_digest(executable)
        write_json(OUTPUT / "result.json", record)


if __name__ == "__main__":
    main()
