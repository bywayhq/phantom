"""Run Phantom against a pinned TLS-Anvil client-test profile."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from .docker_owner import remove_container, verified_container_id
else:
    from docker_owner import remove_container, verified_container_id

IMAGE = "phantom-tls-anvil:local"
SUITE_IMAGE = (
    "ghcr.io/tls-attacker/tlsanvil@"
    "sha256:a8a4bb924b09453926ccb4721028c68051c7b61168829469a28f5af47df311d4"
)
SUITE_SOURCE_REVISION = "1a0f23ae611e4fed27abdad3e72559e28d80684b"
EXPECTED_TEST_IDS = frozenset({"5246-jsdAL1vDy5", "8446-jVohiUKi4u"})
FAILURE_STATUSES = frozenset(
    {"PARTIALLY_FAILED", "FULLY_FAILED", "DISABLED", "TEST_SUITE_ERROR"}
)
BUILD_TIMEOUT_SECONDS = 1200
RUN_TIMEOUT_SECONDS = 300
CONTAINER_TIMEOUT_SECONDS = 30
CONTAINER_OWNER_LABEL = "io.byway.phantom.tls-anvil.owner"
RETAINED_LOG_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class ReportSummary:
    """Validated, bounded result data retained by CI."""

    total_tests: int
    finished_tests: int
    strictly_succeeded_tests: int
    test_ids: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        """Returns the sanitized summary representation."""

        return {
            "finished_tests": self.finished_tests,
            "strictly_succeeded_tests": self.strictly_succeeded_tests,
            "test_ids": list(self.test_ids),
            "total_tests": self.total_tests,
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


def summarize_reports(report: Any, result_map: Any) -> ReportSummary:
    """Requires one complete strict success for every selected test."""

    if not isinstance(report, dict):
        raise ValueError("TLS-Anvil report must be an object")
    if report.get("Running") is not False:
        raise ValueError("TLS-Anvil report is incomplete")

    expected_count = len(EXPECTED_TEST_IDS)
    counts = {
        name: _required_nonnegative_int(report, name)
        for name in (
            "TotalTests",
            "FinishedTests",
            "StrictlySucceededTests",
            "ConceptuallySucceededTests",
            "DisabledTests",
            "PartiallyFailedTests",
            "FullyFailedTests",
            "TestSuiteErrorTests",
        )
    }
    if counts["TotalTests"] != expected_count:
        raise ValueError(
            f"TLS-Anvil selected {counts['TotalTests']} tests; expected {expected_count}"
        )
    if counts["FinishedTests"] != counts["TotalTests"]:
        raise ValueError("TLS-Anvil did not finish every selected test")
    if counts["StrictlySucceededTests"] != expected_count:
        raise ValueError("TLS-Anvil did not strictly pass every selected test")
    for name in (
        "ConceptuallySucceededTests",
        "DisabledTests",
        "PartiallyFailedTests",
        "FullyFailedTests",
        "TestSuiteErrorTests",
    ):
        if counts[name] != 0:
            raise ValueError(f"TLS-Anvil reported {name}={counts[name]}")

    if not isinstance(result_map, dict):
        raise ValueError("TLS-Anvil result map must be an object")
    observed: list[str] = []
    for status, test_ids in result_map.items():
        if not isinstance(status, str) or not isinstance(test_ids, list):
            raise ValueError("TLS-Anvil result-map entries must be named arrays")
        if any(not isinstance(test_id, str) for test_id in test_ids):
            raise ValueError(f"TLS-Anvil status {status} contains a non-string test ID")
        if status in FAILURE_STATUSES and test_ids:
            raise ValueError(f"TLS-Anvil status {status} was not empty")
        observed.extend(test_ids)

    if len(observed) != len(set(observed)):
        raise ValueError("TLS-Anvil result map contains duplicate test IDs")
    if set(observed) != EXPECTED_TEST_IDS:
        missing = sorted(EXPECTED_TEST_IDS - set(observed))
        extra = sorted(set(observed) - EXPECTED_TEST_IDS)
        raise ValueError(
            f"TLS-Anvil test set differed: missing={missing!r}, extra={extra!r}"
        )
    strict_ids = result_map.get("STRICTLY_SUCCEEDED")
    if not isinstance(strict_ids, list) or set(strict_ids) != EXPECTED_TEST_IDS:
        raise ValueError(
            "TLS-Anvil strict-success set differed from the selected profile"
        )

    return ReportSummary(
        total_tests=counts["TotalTests"],
        finished_tests=counts["FinishedTests"],
        strictly_succeeded_tests=counts["StrictlySucceededTests"],
        test_ids=tuple(sorted(observed)),
    )


def _required_nonnegative_int(report: dict[str, Any], name: str) -> int:
    value = report.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"TLS-Anvil report omitted non-negative integer {name}")
    return value


def _git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _bound_log(path: Path) -> None:
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        return
    if len(content) <= RETAINED_LOG_BYTES:
        return

    marker = b"[earlier TLS-Anvil output omitted]\n"
    path.write_bytes(marker + content[-RETAINED_LOG_BYTES:])


def _cleanup_container(
    name: str, owner: str
) -> tuple[list[tuple[str, Exception | KeyboardInterrupt]], list[str]]:
    try:
        container_id = verified_container_id(
            name, CONTAINER_OWNER_LABEL, owner, timeout=CONTAINER_TIMEOUT_SECONDS
        )
    except (Exception, KeyboardInterrupt) as error:
        return [("container ownership inspection", error)], []

    if container_id is None:
        return [], ["container cleanup: named container not found"]

    try:
        remove_container(container_id, timeout=CONTAINER_TIMEOUT_SECONDS)
    except (Exception, KeyboardInterrupt) as error:
        return [("container removal", error)], []

    return [], []


def _failure_message(error: BaseException) -> str:
    message = str(error) or type(error).__name__
    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
        message += f": {error.stderr.strip()}"
    return message


def run(repository: Path, report_root: Path) -> Path:
    """Builds the adapter image, runs the smoke profile, and validates reports."""

    owner = uuid.uuid4().hex
    container_name = f"phantom-tls-anvil-{owner}"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_directory = (report_root / f"smoke-{timestamp}-{os.getpid()}-{owner}").resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    config_directory = (repository / "scripts" / "conformance" / "tls-anvil").resolve()
    metadata = {
        "adapter_image": IMAGE,
        "features": ["tcp-tls", "client"],
        "mode": "smoke",
        "phantom_revision": _git_revision(repository),
        "platform": platform.platform(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "suite_image": SUITE_IMAGE,
        "suite_source_revision": SUITE_SOURCE_REVISION,
        "container_name": container_name,
        "container_owner_label": CONTAINER_OWNER_LABEL,
        "container_owner": owner,
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    container_log = run_directory / "container.log"
    command = [
        "docker",
        "run",
        "--name",
        container_name,
        "--label",
        f"{CONTAINER_OWNER_LABEL}={owner}",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--hostname",
        "tls-anvil",
        "--add-host",
        "tls-anvil:127.0.0.1",
        "--volume",
        f"{config_directory}:/config:ro",
        "--volume",
        f"{run_directory}:/output",
        IMAGE,
        "-tlsAnvilConfig",
        "/config/client.json",
    ]

    result: subprocess.CompletedProcess[str] | None = None
    launch_attempted = False
    primary_error: Exception | KeyboardInterrupt | None = None
    cleanup_errors: list[tuple[str, Exception | KeyboardInterrupt]] = []
    cleanup_notes: list[str] = []
    summary_document = ReportSummary(0, 0, 0, ()).as_json()
    summary_document["suite_report_validated"] = False

    try:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--file",
                str(config_directory / "Dockerfile"),
                "--tag",
                IMAGE,
                str(repository),
            ],
            check=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )

        with container_log.open("x", encoding="utf-8") as output:
            launch_attempted = True
            result = subprocess.run(
                command,
                check=False,
                text=True,
                timeout=RUN_TIMEOUT_SECONDS,
                stdout=output,
                stderr=subprocess.STDOUT,
            )

        suite_directory = run_directory / "suite"
        summary = summarize_reports(
            load_json(suite_directory / "report.json"),
            load_json(suite_directory / "result_map.json"),
        )
        summary_document = summary.as_json()
        summary_document["suite_report_validated"] = True

        result.check_returncode()
    except (Exception, KeyboardInterrupt) as error:
        primary_error = error
    finally:
        if launch_attempted:
            cleanup_errors, cleanup_notes = _cleanup_container(container_name, owner)

        for log in (container_log, run_directory / "adapter.log"):
            try:
                _bound_log(log)
            except (OSError, KeyboardInterrupt) as error:
                cleanup_errors.append((f"log retention of {log}", error))

    failures = []
    if primary_error is not None:
        failures.append(f"suite execution: {_failure_message(primary_error)}")

    if (
        result is not None
        and result.returncode
        and not summary_document["suite_report_validated"]
    ):
        failures.append(f"TLS-Anvil exited with status {result.returncode}")

    failures.extend(
        f"{operation}: {_failure_message(error)}" for operation, error in cleanup_errors
    )

    summary_document["runner_exit_status"] = (
        None if result is None else result.returncode
    )
    summary_document["failures"] = failures
    summary_document["cleanup"] = cleanup_notes

    try:
        (run_directory / "summary.json").write_text(
            json.dumps(summary_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, KeyboardInterrupt) as error:
        if primary_error is None and not cleanup_errors:
            raise
        cleanup_errors.append(("summary retention", error))
        failures.append(f"summary retention: {_failure_message(error)}")

    if cleanup_errors:
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

    print(
        f"TLS-Anvil smoke: {summary_document['strictly_succeeded_tests']}/"
        f"{summary_document['total_tests']} tests strictly succeeded"
    )
    return run_directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-root",
        type=Path,
        default=Path("target/tls-anvil"),
        help="parent directory for retained reports",
    )
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        directory = run(repository, args.report_root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
