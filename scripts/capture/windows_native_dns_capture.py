"""Capture one native DNS lookup on a disposable hosted Windows 2025 runner."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import struct
import subprocess
import sys
import tempfile
from dataclasses import asdict, replace
from pathlib import Path

from scripts.capture import firefox_socket_hooks as firefox
from scripts.capture.browser_failures import raise_browser_failures
from scripts.capture.capture_report import file_digest
from scripts.capture.native_dns import NativeDnsServer, question, response

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
SCENARIOS = {
    "initial": SCENARIO,
    "drop-first-udp-a": replace(
        SCENARIO,
        name="native-dns-drop-first-udp-a",
        question="Does the native resolver recover after one unanswered UDP A query?",
    ),
    "two-server": replace(
        SCENARIO,
        name="native-dns-two-server",
        question="Are the silent primary and answering secondary both observed?",
    ),
    "address-order": replace(
        SCENARIO,
        name="native-dns-address-order",
        question="Which address is returned and selected from two healthy owned origins?",
    ),
}

ADDRESS_ORDER = ("127.0.0.2", "127.0.0.1")
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


def validate_recovery(records: list[dict], attached_ns: int) -> dict:
    dropped = [
        index
        for index, entry in enumerate(records)
        if entry.get("disposition") == "dropped-first-udp-a"
    ]
    if len(dropped) != 1:
        raise RuntimeError("recovery capture requires exactly one dropped UDP A query")
    index = dropped[0]
    query = records[index]
    if (
        query.get("name") != firefox.TARGET_HOST
        or type(query.get("kind")) is not int
        or query.get("kind") != 1
        or query.get("transport") != "udp"
        or query.get("error", "missing") is not None
        or "response_hex" not in query
        or query["response_hex"] is not None
        or "response_queued_ns" in query
        or "response_drained_ns" in query
        or type(query.get("unix_ns")) is not int
        or query["unix_ns"] < attached_ns
        or any(
            entry.get("name") == firefox.TARGET_HOST
            and entry.get("kind") == 1
            and entry.get("transport") == "udp"
            for entry in records[:index]
        )
    ):
        raise RuntimeError("dropped query is not the first post-attachment owned UDP A")
    answered = [
        entry
        for entry in records[index + 1 :]
        if entry.get("name") == firefox.TARGET_HOST
        and type(entry.get("kind")) is int
        and entry.get("kind") == 1
        and entry.get("transport") == "udp"
        and entry.get("error", "missing") is None
        and isinstance(entry.get("response_hex"), str)
        and entry["response_hex"]
        and type(entry.get("unix_ns")) is int
        and entry["unix_ns"] > query["unix_ns"]
        and type(entry.get("response_queued_ns")) is int
        and entry["response_queued_ns"] >= entry["unix_ns"]
    ]
    if not answered:
        raise RuntimeError(
            "dropped UDP A was not followed by a sent owned UDP A answer"
        )
    return {
        "dropped_udp_a_queries": 1,
        "post_drop_udp_a_responses": len(answered),
        "dropped_query_unix_ns": query["unix_ns"],
        "first_post_drop_query_unix_ns": answered[0]["unix_ns"],
        "first_post_drop_response_queued_ns": answered[0]["response_queued_ns"],
    }


def validate_result(
    result: firefox.RunResult, records: list[dict], *, scenario: str = "initial"
) -> dict:
    ready = [
        entry["time_ms"]
        for entry in result.reports
        if entry.get("kind") == "firefox-config" and type(entry.get("time_ms")) is int
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
    if scenario == "two-server":
        recovery = validate_two_server(records, min(ready) * 1_000_000)
    elif scenario == "drop-first-udp-a":
        recovery = validate_recovery(records, min(ready) * 1_000_000)
    elif scenario == "address-order":
        recovery = validate_address_order(result, records, min(ready) * 1_000_000)
    else:
        recovery = {}
    answered = [
        entry
        for entry in records
        if entry.get("name") == firefox.TARGET_HOST
        and entry.get("kind") == 1
        and type(entry.get("unix_ns")) is int
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
        **recovery,
    }


def address_answer(wire: bytes, answer: bytes) -> list[str]:
    """Read the fixed scene's two A records independently of the DNS producer."""
    parsed = question(wire)
    if len(answer) < 12:
        raise ValueError("two-A response has a short header")
    fields = struct.unpack("!6H", answer[:12])
    if (
        fields
        != (
            int.from_bytes(wire[:2], "big"),
            0x8400 | (int.from_bytes(wire[2:4], "big") & 0x0100),
            1,
            2,
            0,
            int(parsed.edns_size is not None),
        )
        or answer[12 : parsed.end] != wire[12 : parsed.end]
    ):
        raise ValueError("two-A response header or echoed question differs")
    addresses = []
    offset = parsed.end
    for _ in range(2):
        record = answer[offset : offset + 16]
        if len(record) != 16 or record[:12] != bytes.fromhex(
            "c00c00010001000000050004"
        ):
            raise ValueError("two-A response requires two IN/A records with TTL5")
        addresses.append(str(ipaddress.IPv4Address(record[12:])))
        offset += 16
    tail = (
        b"\x00" + struct.pack("!HHIH", 41, parsed.edns_size, 0, 0)
        if parsed.edns_size is not None
        else b""
    )
    if answer[offset:] != tail:
        raise ValueError("two-A response has unexpected trailing bytes")
    return addresses


def validate_address_order(
    result: firefox.RunResult, records: list[dict], attached_ns: int
) -> dict:
    answered = []
    for entry in records:
        if entry.get("name") != firefox.TARGET_HOST or entry.get("kind") != 1:
            continue
        try:
            wire = bytes.fromhex(entry["query_hex"])
            parsed = question(wire)
            addresses = address_answer(wire, bytes.fromhex(entry["response_hex"]))
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "address-order capture has an invalid A query or response"
            ) from error
        if (
            parsed.name != firefox.TARGET_HOST
            or parsed.kind != 1
            or entry.get("transport") != "udp"
            or entry.get("error", "missing") is not None
            or tuple(addresses) != ADDRESS_ORDER
            or type(entry.get("unix_ns")) is not int
            or entry["unix_ns"] < attached_ns
            or type(entry.get("response_queued_ns")) is not int
            or entry["response_queued_ns"] < entry["unix_ns"]
        ):
            raise RuntimeError(
                "address-order capture requires a queued post-hook two-A answer"
            )
        answered.append(addresses)
    if not answered:
        raise RuntimeError("address-order capture has no queued post-hook two-A answer")
    events = firefox.decode_events(result.reports, attached_ns // 1_000_000)
    resolutions = [
        event
        for event in events
        if event["kind"] == "resolve-return"
        and event["host"] == firefox.TARGET_HOST
        and event["function"] in ("getaddrinfo", "GetAddrInfoW", "GetAddrInfoExW")
    ]
    if not resolutions or not any(
        all(
            any(answer.startswith(address + ":") for answer in event["answers"])
            for address in ADDRESS_ORDER
        )
        for event in resolutions
        if event["result"] == 0 and event["t"] >= 0
    ):
        raise RuntimeError(
            "address-order capture did not retain both native returned addresses"
        )
    port = result.origins.port
    endpoints = tuple(f"{address}:{port}" for address in ADDRESS_ORDER)
    attempts = [
        event
        for event in events
        if event["kind"] == "connect"
        and event["t"] >= 0
        and event["address"].endswith(f":{port}")
    ]
    winners = [
        connection
        for connection in result.origins.connections
        if any(
            path == "/close?i=0" and stamp * 1_000_000 >= attached_ns
            for stamp, path in connection.requests
        )
    ]
    if not attempts or len(winners) != 1 or winners[0].local not in endpoints:
        raise RuntimeError(
            "address-order capture lacks a measured connect attempt and owned winner"
        )
    if not any(event["address"] == winners[0].local for event in attempts):
        raise RuntimeError(
            "address-order winner has no matching observed connect attempt"
        )
    return {
        "wire_addresses": answered[0],
        "native_resolutions": resolutions,
        "resolve_hints": [
            event
            for event in events
            if event["kind"] == "resolve-hints" and event["host"] == firefox.TARGET_HOST
        ],
        "connect_attempts": attempts,
        "connect_outcomes": [
            event
            for event in events
            if event["kind"] in ("connect-return", "socket-error")
            and event.get("socket") in {attempt["socket"] for attempt in attempts}
        ],
        "winner": winners[0].local,
    }


async def prepare_address_origins(origins: firefox.Origins) -> list[dict]:
    """Bind both measured endpoints and check their literal HTTP bodies before NRPT."""
    for address in ADDRESS_ORDER:
        listener = await asyncio.start_server(
            origins.accept_target, address, origins.port, limit=firefox.MAX_REQUEST_HEAD
        )
        origins.listeners.append(listener)
        origins.port = listener.sockets[0].getsockname()[1]
    controls = []
    for address in ADDRESS_ORDER:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, origins.port, limit=4096), 5
        )
        primary = None
        try:
            path = f"/close?literal-control={address}"
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {address}\r\n\r\n".encode("ascii")
            )
            await asyncio.wait_for(writer.drain(), 5)
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            body = await asyncio.wait_for(reader.readexactly(3), 5)
            extra = await asyncio.wait_for(reader.read(1), 5)
            if not head.startswith(b"HTTP/1.1 200 ") or body != b"ok\n" or extra:
                raise RuntimeError(
                    "literal address origin did not return the complete expected body"
                )
            raw = head + body
            controls.append(
                {
                    "address": address,
                    "port": origins.port,
                    "path": path,
                    "response_hex": raw.hex(),
                }
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            await firefox.close_writer(writer, primary)
    if origins.failures:
        raise origins.failures[0]
    return controls


def validate_two_server(records: list[dict], attached_ns: int) -> dict:
    """Require both owned peers without inferring resolver scheduling policy."""
    dropped = []
    answered = []
    for entry in records:
        if entry.get("server") not in ("127.0.0.53", "127.0.0.54"):
            raise RuntimeError("two-server DNS record has an unexpected server")
        expected_role = "primary" if entry["server"] == "127.0.0.53" else "secondary"
        if entry.get("role") != expected_role:
            raise RuntimeError("two-server DNS record has an unexpected role")
        try:
            wire = bytes.fromhex(entry["query_hex"])
            parsed = question(wire)
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "two-server DNS record has an invalid IN question"
            ) from error
        if (
            entry.get("name") != parsed.name
            or type(entry.get("kind")) is not int
            or entry["kind"] != parsed.kind
            or type(entry.get("unix_ns")) is not int
            or entry.get("error", "missing") is not None
        ):
            raise RuntimeError("two-server DNS record disagrees with its wire question")
        if parsed.name != firefox.TARGET_HOST:
            continue
        if entry.get("transport") != "udp":
            raise RuntimeError("two-server capture requires owned UDP questions")
        if expected_role == "primary":
            if (
                entry.get("disposition") != "dropped-owned-udp"
                or "response_hex" not in entry
                or entry["response_hex"] is not None
                or "response_queued_ns" in entry
                or "response_drained_ns" in entry
            ):
                raise RuntimeError(
                    "two-server primary did not leave its query unanswered"
                )
            if parsed.kind == 1 and entry["unix_ns"] >= attached_ns:
                dropped.append(entry)
        elif parsed.kind == 1 and entry["unix_ns"] >= attached_ns:
            if (
                entry.get("response_hex")
                != response(wire, parsed, firefox.TARGET_HOST, 5).hex()
                or type(entry.get("response_queued_ns")) is not int
                or entry["response_queued_ns"] < entry["unix_ns"]
                or "response_drained_ns" in entry
            ):
                raise RuntimeError(
                    "two-server secondary has no queued owned UDP A answer"
                )
            answered.append(entry)
    if not dropped:
        raise RuntimeError(
            "two-server capture did not observe a post-hook primary UDP A drop"
        )
    if not answered:
        raise RuntimeError(
            "two-server capture did not observe a post-hook secondary UDP A answer"
        )
    primary_ns = min(entry["unix_ns"] for entry in dropped)
    secondary = min(answered, key=lambda entry: entry["unix_ns"])
    delta = secondary["unix_ns"] - primary_ns
    return {
        "primary_dropped_udp_a_queries": len(dropped),
        "secondary_udp_a_responses": len(answered),
        "first_primary_query_unix_ns": primary_ns,
        "first_secondary_query_unix_ns": secondary["unix_ns"],
        "first_secondary_response_queued_ns": secondary["response_queued_ns"],
        "secondary_query_minus_primary_query_ns": delta,
        "secondary_answer_minus_primary_query_ns": secondary["response_queued_ns"]
        - primary_ns,
        "observed_order": "primary-first"
        if delta > 0
        else "secondary-first"
        if delta < 0
        else "same-timestamp",
    }


def dns_records(peers: list[NativeDnsServer]) -> list[dict]:
    if len(peers) == 1:
        return peers[0].records()
    records = [
        {**entry, "server": peer.address[0], "role": role, "peer_sequence": index}
        for role, peer in zip(("primary", "secondary"), peers, strict=True)
        for index, entry in enumerate(peer.records())
    ]
    # Retain per-peer sequence as well: equal wall-clock stamps imply no ordering.
    return sorted(records, key=lambda entry: entry["unix_ns"])


async def capture(executable: Path, record: dict, *, scenario: str = "initial") -> None:
    selected = SCENARIOS[scenario]
    if scenario == "two-server":
        peers = [
            NativeDnsServer(firefox.TARGET_HOST, "127.0.0.53", drop_owned_udp=True),
            NativeDnsServer(firefox.TARGET_HOST, "127.0.0.54"),
        ]
    else:
        options = {"ipv4_answers": ADDRESS_ORDER} if scenario == "address-order" else {}
        peers = [
            NativeDnsServer(
                firefox.TARGET_HOST,
                drop_first_udp_a=scenario == "drop-first-udp-a",
                **options,
            )
        ]
    primary = None
    cleanup = []
    browser = None
    browser_observed = False
    failed = []
    prepared = firefox._FirefoxRun(selected) if scenario == "address-order" else None

    async def close_prepared() -> None:
        if prepared is not None:
            raise_browser_failures(None, await prepared.finish(primary))

    try:
        if prepared is not None:
            record["literal_origin_controls"] = await prepare_address_origins(
                prepared.origins
            )
        for peer in peers:
            await peer.start()
        record["dns_address"] = peers[0].address
        if scenario == "two-server":
            record["dns_peers"] = [
                {"role": role, "address": peer.address}
                for role, peer in zip(("primary", "secondary"), peers, strict=True)
            ]
        extra = ("-DnsScene", "two-server") if scenario == "two-server" else ()
        record["nrpt"] = guard(record, "Install", "-OwnerPid", str(os.getpid()), *extra)
        options = {"prepared": prepared} if prepared is not None else {}
        browser = asyncio.create_task(
            firefox.run_once(
                selected,
                executable,
                headful=True,
                failure_path=OUTPUT / "firefox-failed.json",
                **options,
            )
        )
        failed = [asyncio.create_task(peer.failed.wait()) for peer in peers]
        done, _ = await asyncio.wait(
            (browser, *failed), return_when=asyncio.FIRST_COMPLETED
        )
        for peer, failure in zip(peers, failed, strict=True):
            if failure in done:
                raise RuntimeError(
                    "native DNS peer failed during browser capture"
                ) from peer.failures[0]
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
        record["positive"] = validate_result(
            result, dns_records(peers), scenario=scenario
        )
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
        for failure in failed:
            failure.cancel()
        try:
            await asyncio.gather(*failed, return_exceptions=True)
        except BaseException as error:
            cleanup.append(error)
        # DNS peers close in parallel under their existing per-peer bound.
        closing_work = [peer.close() for peer in peers]
        if prepared is not None:
            closing_work.append(close_prepared())
        closing = asyncio.gather(*closing_work, return_exceptions=True)
        while True:
            try:
                # Caller cancellation must not detach either bounded close owner
                # or skip NRPT restoration. Preserve it after collecting both.
                outcomes = await asyncio.shield(closing)
                cleanup.extend(
                    error for error in outcomes if isinstance(error, BaseException)
                )
                break
            except asyncio.CancelledError as error:
                cleanup.append(error)
            except BaseException as error:
                cleanup.append(error)
                break
        try:
            write_json(OUTPUT / "dns.json", dns_records(peers))
        except BaseException as error:
            cleanup.append(error)
        record["dns_failures"] = [
            f"{type(error).__name__}: {error}"
            for peer in peers
            for error in peer.failures
        ]
        if scenario == "two-server":
            record["dns_peer_failures"] = [
                {
                    "role": role,
                    "address": peer.address,
                    "failures": [
                        f"{type(error).__name__}: {error}" for error in peer.failures
                    ],
                }
                for role, peer in zip(("primary", "secondary"), peers, strict=True)
            ]
        try:
            record["restoration"] = guard(record, "Verify")
        except BaseException as error:
            cleanup.append(error)
        record["cleanup_errors"] = [
            f"{type(error).__name__}: {error}" for error in cleanup
        ]
    raise_browser_failures(primary, tuple(cleanup))


def report_guard_failure(record: dict) -> None:
    commands = []
    for entry in record.get("commands", []):
        argv = entry["argv"]
        if str(GUARD) not in argv or entry["exit"] == 0:
            continue
        command = {"action": argv[argv.index("-Action") + 1], "exit": entry["exit"]}
        for stream in ("stdout", "stderr"):
            text = entry.get(stream, "")
            command[stream] = text[:8192]
            command[f"{stream}_truncated"] = len(text) > 8192
        commands.append(command)
        if len(commands) == 4:
            break
    diagnostic = {"kind": "windows-native-dns-guard-failure", "commands": commands}
    try:
        with (OUTPUT / "nrpt-state.json.watch.stderr").open("rb") as watchdog:
            text = watchdog.read(8193)
        diagnostic["watchdog_stderr"] = text[:8192].decode("utf-8", "replace")
        diagnostic["watchdog_stderr_truncated"] = len(text) > 8192
    except FileNotFoundError:
        pass  # The watchdog may not have started before the failure.
    except OSError as error:
        diagnostic["watchdog_stderr_error"] = f"{type(error).__name__}: {error}"
    print(json.dumps(diagnostic), file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="initial")
    arguments = parser.parse_args(argv)
    require_hosted()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    record = {
        "platform": platform.platform(),
        "runner": "windows-2025",
        "scenario": arguments.scenario,
        "scope": "native A resolution and complete HTTP body; not DNS cache/TTL policy",
        "interventions": {
            "exact_name_nrpt": firefox.TARGET_HOST,
            "network.trr.mode": 5,
            "network.proxy.type": 0,
            "lookup_rewrite": False,
            "drop_first_udp_a": arguments.scenario == "drop-first-udp-a",
            "primary_drop_owned_udp": arguments.scenario == "two-server",
            "ipv4_answers": list(ADDRESS_ORDER)
            if arguments.scenario == "address-order"
            else ["127.0.0.1"],
            "nameservers": ["127.0.0.53", "127.0.0.54"]
            if arguments.scenario == "two-server"
            else ["127.0.0.53"],
        },
        "source_before": {path: file_digest(ROOT / path) for path in SOURCE_PATHS},
    }
    executable = None
    try:
        record["host"] = guard(record, "Preflight")
        executable = stage_browser(record)
        asyncio.run(capture(executable, record, scenario=arguments.scenario))
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
        report_guard_failure(record)
        raise
    finally:
        if executable is not None and "browser_after" not in record:
            record["browser_after_sha256"] = file_digest(executable)
        write_json(OUTPUT / "result.json", record)


if __name__ == "__main__":
    main()
