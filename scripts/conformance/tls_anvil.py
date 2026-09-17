"""Run Phantom against a pinned TLS-Anvil client-test profile."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    except OSError:
        return
    if len(content) <= RETAINED_LOG_BYTES:
        return
    marker = b"[earlier TLS-Anvil output omitted]\n"
    path.write_bytes(marker + content[-RETAINED_LOG_BYTES:])


def run(repository: Path, report_root: Path) -> Path:
    """Builds the adapter image, runs the smoke profile, and validates reports."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_directory = (report_root / f"smoke-{timestamp}-{os.getpid()}").resolve()
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
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

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

    container_name = f"phantom-tls-anvil-{os.getpid()}-{int(time.time())}"
    container_log = run_directory / "container.log"
    command = [
        "docker",
        "run",
        "--name",
        container_name,
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
    try:
        with container_log.open("x", encoding="utf-8") as output:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                timeout=RUN_TIMEOUT_SECONDS,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        _bound_log(container_log)
        _bound_log(run_directory / "adapter.log")

    suite_directory = run_directory / "suite"
    summary = summarize_reports(
        load_json(suite_directory / "report.json"),
        load_json(suite_directory / "result_map.json"),
    )
    summary_document = summary.as_json()
    summary_document["runner_exit_status"] = result.returncode
    (run_directory / "summary.json").write_text(
        json.dumps(summary_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(f"TLS-Anvil exited with status {result.returncode}")
    print(
        f"TLS-Anvil smoke: {summary.strictly_succeeded_tests}/"
        f"{summary.total_tests} tests strictly succeeded"
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
