"""Run Phantom against a pinned Autobahn WebSocket fuzzing server."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from .docker_owner import remove_container, verified_container_id
    from .loopback_tls import generate_loopback_certificate
else:
    from docker_owner import remove_container, verified_container_id
    from loopback_tls import generate_loopback_certificate

IMAGE = (
    "crossbario/autobahn-testsuite:25.10.1@"
    "sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
)
SOURCE_REVISION = "6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c"
AGENT = "phantom-autobahn"
STRICT_STATUSES = frozenset({"OK", "INFORMATIONAL"})
WARNING_BEHAVIORS = frozenset({"NON-STRICT"})
WARNING_CLOSE_BEHAVIORS = frozenset({"NON-STRICT", "WRONG CODE", "FAILED BY CLIENT"})
MODE_TIMEOUT_SECONDS = {"smoke": 180, "compression": 1800, "full": 2400}
BUILD_TIMEOUT_SECONDS = 1800
EXPECTED_CASE_COUNTS = {"smoke": 8, "compression": 216, "full": 463}
CONTAINER_OWNER_LABEL = "io.byway.phantom.autobahn.owner"
CONTAINER_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ReportSummary:
    """Sanitized result classes from one Autobahn agent report."""

    case_count: int
    warnings: tuple[str, ...]
    failures: tuple[str, ...]
    cases: dict[str, dict[str, str]]

    def as_json(self) -> dict[str, object]:
        """Returns the bounded JSON representation retained by CI."""

        return {
            "case_count": self.case_count,
            "warning_count": len(self.warnings),
            "failure_count": len(self.failures),
            "warnings": list(self.warnings),
            "failures": list(self.failures),
            "cases": self.cases,
        }


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"duplicate JSON key {key!r}")
        mapping[key] = value
    return mapping


def load_json(path: Path) -> Any:
    """Loads JSON while rejecting duplicate object keys."""

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"could not load {path}: {error}") from error


def summarize_report(
    report: Any,
    agent: str,
    expected_case_ids: set[str] | None = None,
    expected_case_count: int | None = None,
) -> ReportSummary:
    """Validates an Autobahn index and classifies strict, warning, and failed cases."""

    if not isinstance(report, dict):
        raise ValueError("Autobahn index must be an object")
    agents = set(report)
    if agents != {agent}:
        raise ValueError(
            f"Autobahn index contained unexpected agents: {sorted(agents)!r}"
        )
    results = report[agent]
    if not isinstance(results, dict) or not results:
        raise ValueError("Autobahn index contained no case results")
    if any(not isinstance(case_id, str) for case_id in results):
        raise ValueError("Autobahn case identifiers must be strings")
    if expected_case_count is not None and len(results) != expected_case_count:
        raise ValueError(
            f"Autobahn returned {len(results)} cases; expected {expected_case_count}"
        )
    case_ids = set(results)
    if expected_case_ids is not None and case_ids != expected_case_ids:
        missing = sorted(expected_case_ids - case_ids)
        extra = sorted(case_ids - expected_case_ids)
        raise ValueError(
            f"Autobahn case set differed: missing={missing!r}, extra={extra!r}"
        )

    warnings: list[str] = []
    failures: list[str] = []
    cases: dict[str, dict[str, str]] = {}
    for case_id in sorted(results, key=_case_sort_key):
        result = results[case_id]
        if not isinstance(case_id, str) or not isinstance(result, dict):
            raise ValueError("Autobahn case results must be named objects")
        behavior = result.get("behavior")
        close = result.get("behaviorClose")
        if not isinstance(behavior, str) or not isinstance(close, str):
            raise ValueError(f"Autobahn case {case_id} omitted behavior fields")
        cases[case_id] = {"behavior": behavior, "behavior_close": close}

        if behavior in WARNING_BEHAVIORS:
            warnings.append(f"{case_id}: behavior={behavior}")
        elif behavior not in STRICT_STATUSES:
            failures.append(f"{case_id}: behavior={behavior}")
        if close in WARNING_CLOSE_BEHAVIORS:
            warnings.append(f"{case_id}: behaviorClose={close}")
        elif close not in STRICT_STATUSES:
            failures.append(f"{case_id}: behaviorClose={close}")

    return ReportSummary(len(results), tuple(warnings), tuple(failures), cases)


def _case_sort_key(case_id: str) -> tuple[tuple[int, str], ...]:
    return tuple(
        (0, f"{int(part):08d}") if part.isdigit() else (1, part)
        for part in case_id.split(".")
    )


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        cwd=cwd,
        text=True,
        timeout=timeout,
        capture_output=quiet,
    )


def _build_adapter(repository: Path) -> Path:
    # Compilation is intentionally separate from the protocol-suite deadline.
    target_directory = repository / "target"
    _run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--target-dir",
            str(target_directory),
            "-p",
            "phantom-http",
            "--example",
            "autobahn-client",
            "--features",
            "websocket-deflate",
        ],
        cwd=repository,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    executable = target_directory / "release" / "examples" / "autobahn-client"
    if os.name == "nt":
        executable = executable.with_suffix(".exe")
    if not executable.is_file():
        raise RuntimeError(
            f"Cargo did not produce the Autobahn adapter at {executable}"
        )
    return executable


def _wait_for_tls(port: int, container_name: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Readiness probe for the local test container's self-signed listener.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with socket.create_connection(
                ("127.0.0.1", port), timeout=min(1, remaining)
            ) as stream:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                stream.settimeout(min(1, remaining))
                with context.wrap_socket(stream, server_hostname="localhost"):
                    return
        except (OSError, ssl.SSLError) as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                status = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Running}}",
                        container_name,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired as inspection_error:
                raise TimeoutError(
                    "Autobahn server did not accept TLS within 30 seconds"
                ) from inspection_error
            if status.returncode == 0 and status.stdout.strip() != "true":
                raise RuntimeError(
                    "Autobahn container exited before accepting TLS"
                ) from error
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise TimeoutError("Autobahn server did not accept TLS within 30 seconds")


def _write_container_log(container_id: str, destination: Path) -> None:
    result = subprocess.run(
        ["docker", "logs", container_id],
        capture_output=True,
        text=True,
        check=False,
        timeout=CONTAINER_TIMEOUT_SECONDS,
    )
    try:
        destination.write_text(result.stdout + result.stderr, encoding="utf-8")
    except OSError as error:
        if result.returncode:
            raise RuntimeError(
                f"container log collection exited with status {result.returncode}: "
                f"{result.stderr.strip()}; container log retention: {error}"
            ) from error
        raise
    if result.returncode:
        raise RuntimeError(
            f"container log collection exited with status {result.returncode}: "
            f"{result.stderr.strip()}"
        )


def _cleanup_container(
    container_name: str, owner: str, run_directory: Path
) -> tuple[list[tuple[str, Exception | KeyboardInterrupt]], list[str]]:
    failures: list[tuple[str, Exception | KeyboardInterrupt]] = []
    notes: list[str] = []

    try:
        container_id = verified_container_id(
            container_name,
            CONTAINER_OWNER_LABEL,
            owner,
            timeout=CONTAINER_TIMEOUT_SECONDS,
        )
    except (Exception, KeyboardInterrupt) as error:
        failures.append(("container ownership inspection", error))
        return failures, notes

    if container_id is None:
        notes.append("container cleanup: named container not found")
        return failures, notes

    try:
        _write_container_log(container_id, run_directory / "container.log")
    except (Exception, KeyboardInterrupt) as error:
        failures.append(("container log collection", error))

    try:
        remove_container(container_id, timeout=CONTAINER_TIMEOUT_SECONDS)
    except (Exception, KeyboardInterrupt) as error:
        failures.append(("container removal", error))

    return failures, notes


def _failure_message(error: BaseException) -> str:
    message = str(error) or type(error).__name__
    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
        message += f": {error.stderr.strip()}"
    return message


def _copy_container_report(container_name: str, destination: Path) -> None:
    with destination.open("xb") as output:
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "cat",
                "/reports/clients/index.json",
            ],
            check=True,
            timeout=30,
            stdout=output,
        )


def _git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _expected_smoke_cases(config: Any) -> set[str] | None:
    if not isinstance(config, dict) or not isinstance(config.get("cases"), list):
        raise ValueError("Autobahn configuration must contain a case list")
    cases = config["cases"]
    if all(isinstance(case, str) and "*" not in case for case in cases):
        return set(cases)
    return None


def run(mode: str, repository: Path, report_root: Path) -> Path:
    """Runs one pinned Autobahn mode and returns its retained report directory."""

    source_config = repository / "scripts" / "conformance" / "autobahn" / f"{mode}.json"
    config = load_json(source_config)
    expected_cases = _expected_smoke_cases(config)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_directory = (report_root / f"{mode}-{timestamp}-{os.getpid()}").resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(source_config, run_directory / "case-config.json")
    owner = uuid.uuid4().hex
    container_name = f"phantom-autobahn-{owner}"
    metadata = {
        "agent": AGENT,
        "features": ["websocket-deflate"],
        "image": IMAGE,
        "mode": mode,
        "phantom_revision": _git_revision(repository),
        "platform": platform.platform(),
        "suite_source_revision": SOURCE_REVISION,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "container_name": container_name,
        "container_owner_label": CONTAINER_OWNER_LABEL,
        "container_owner": owner,
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    adapter_executable = _build_adapter(repository)
    launch_attempted = False
    primary_error: Exception | KeyboardInterrupt | None = None
    summary_document = ReportSummary(0, (), (), {}).as_json()
    cleanup_errors: list[tuple[str, Exception | KeyboardInterrupt]] = []
    cleanup_notes: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="phantom-autobahn-") as temporary:
            config_directory = Path(temporary).resolve()
            certificate = generate_loopback_certificate(config_directory)
            port = _available_port()
            runtime_config = dict(config)
            runtime_config["url"] = f"wss://127.0.0.1:{port}"
            (config_directory / "fuzzingserver.json").write_text(
                json.dumps(runtime_config, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            launch_attempted = True
            _run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    container_name,
                    "--label",
                    f"{CONTAINER_OWNER_LABEL}={owner}",
                    "--platform",
                    "linux/amd64",
                    "--publish",
                    f"127.0.0.1:{port}:{port}",
                    "--volume",
                    f"{config_directory}:/config:ro",
                    "--tmpfs",
                    "/reports:rw,nodev,noexec,nosuid,size=128m",
                    IMAGE,
                ],
                timeout=300,
                quiet=True,
            )
            _wait_for_tls(port, container_name)
            adapter_command = [
                str(adapter_executable),
                "--url",
                f"wss://127.0.0.1:{port}/",
                "--ca-der",
                str(certificate.root_der),
                "--agent",
                AGENT,
            ]
            if mode in {"compression", "full"}:
                adapter_command.append("--deflate")
            adapter = subprocess.run(
                adapter_command,
                check=False,
                text=True,
                timeout=MODE_TIMEOUT_SECONDS[mode],
            )
            retained_clients = run_directory / "clients"
            retained_clients.mkdir()
            report_path = retained_clients / "index.json"
            _copy_container_report(container_name, report_path)
            summary = summarize_report(
                load_json(report_path),
                AGENT,
                expected_cases,
                EXPECTED_CASE_COUNTS[mode],
            )
        summary_document = summary.as_json()
        adapter_failure = None
        if adapter.returncode != 0:
            adapter_failure = f"adapter exited with status {adapter.returncode}"
            summary_document["failure_count"] = len(summary.failures) + 1
            summary_document["failures"] = [*summary.failures, adapter_failure]
        failure_count = len(summary.failures) + int(adapter_failure is not None)
        if failure_count:
            raise RuntimeError("Autobahn reported conformance failures")
    except (Exception, KeyboardInterrupt) as error:
        primary_error = error
    finally:
        if launch_attempted:
            cleanup_errors, cleanup_notes = _cleanup_container(
                container_name, owner, run_directory
            )
    cleanup_failures = [
        f"{operation}: {_failure_message(error)}" for operation, error in cleanup_errors
    ]
    failures = list(summary_document["failures"])
    if primary_error is not None:
        failures.append(f"suite execution: {_failure_message(primary_error)}")
    failures.extend(cleanup_failures)
    summary_document["failures"] = failures
    summary_document["failure_count"] = len(failures)
    summary_document["cleanup"] = cleanup_notes
    try:
        (run_directory / "summary.json").write_text(
            json.dumps(summary_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        if primary_error is None and not cleanup_failures:
            raise
        cleanup_failures.append(f"summary retention: {_failure_message(error)}")
        cleanup_errors.append(("summary retention", error))
        failures.append(cleanup_failures[-1])
    print(
        f"Autobahn {mode}: {summary_document['case_count']} cases, "
        f"{summary_document['warning_count']} warnings, {len(failures)} failures"
    )
    for warning in summary_document["warnings"]:
        print(f"warning: {warning}")
    for failure in failures:
        print(f"failure: {failure}")
    for note in cleanup_notes:
        print(note)
    if cleanup_failures:
        if (
            primary_error is None
            and len(cleanup_errors) == 1
            and isinstance(cleanup_errors[0][1], KeyboardInterrupt)
        ):
            raise cleanup_errors[0][1]
        raise RuntimeError("; ".join(failures)) from (
            primary_error if primary_error is not None else cleanup_errors[0][1]
        )
    if primary_error is not None:
        raise primary_error
    return run_directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=sorted(MODE_TIMEOUT_SECONDS))
    parser.add_argument(
        "--report-root",
        type=Path,
        default=Path("target/autobahn"),
        help="parent directory for retained reports",
    )
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        directory = run(args.mode, repository, args.report_root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(_failure_message(error))
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
