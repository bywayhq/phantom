"""Validate a retained Reaper-to-Phantom regression inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

COVERAGE_SCHEMA = "phantom-reaper-coverage/1"
SOURCE_SCHEMA = "reaper-public-clients/1"
SNAPSHOT_DATE = "2026-09-16"
SOURCE_MANIFEST_SHA256 = (
    "ad68dce4f8c34e794a7a90ffb06b538dda3af84d63c165ddb0290f2ea2164f3c"
)
EXPECTED_PROBE_IDS = (
    "h2-unknown-frame",
    "h2-control",
    "h2-hpack-zero",
    "h2-hpack-oscillation",
    "h2-redirect",
    "tls-alps-concurrency-gate",
    "tls-alps-hpack-last-wins",
    "h2-goaway-retry",
    "h2-flow-control",
    "h2-continuation",
    "h2-misdirected421",
    "tls-resumption",
    "h2-response-sequence",
    "h2-goaway-boundary",
    "tls-hello-retry",
    "tls-key-update",
    "tls-record-shape",
    "h1-chunk-extensions",
    "h1-trailers",
    "h1-segmentation",
    "h3-retry",
    "h3-redirect",
)

_TOP_LEVEL_KEYS = {"schema", "source", "probes"}
_SOURCE_KEYS = {"schema", "snapshot_date", "manifest_sha256"}
_PROBE_KEYS = {"id", "regressions"}
_REGRESSION_KEYS = {"file", "test"}
_RUST_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CoverageError(ValueError):
    """A deterministic coverage validation failure."""


def _mapping_with_keys(
    value: object, expected: set[str], description: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CoverageError(f"{description} has an invalid schema")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise CoverageError(f"{description} must be a non-empty string")
    return value


def _test_pattern(name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?m)^[ \t]*#\[(?:tokio::)?test(?:\([^\]\r\n]*\))?\][ \t]*\r?$"
        rf"(?:\n^[ \t]*#\[[^\]\r\n]+\][ \t]*\r?$)*"
        rf"\n^[ \t]*(?:async[ \t]+)?fn[ \t]+{re.escape(name)}[ \t]*\(",
    )


def _validate_regression(
    value: object, repo_root: Path, probe_id: str
) -> tuple[str, str]:
    regression = _mapping_with_keys(
        value, _REGRESSION_KEYS, f"regression for {probe_id}"
    )
    source_name = _string(regression["file"], f"source file for {probe_id}")
    test_name = _string(regression["test"], f"test name for {probe_id}")
    if not _RUST_IDENTIFIER.fullmatch(test_name):
        raise CoverageError(f"test name for {probe_id} is not a Rust identifier")

    relative_source = Path(source_name)
    if relative_source.is_absolute() or relative_source.suffix != ".rs":
        raise CoverageError(f"source file for {probe_id} must be a relative Rust file")
    root = repo_root.resolve()
    source = (root / relative_source).resolve()
    if not source.is_relative_to(root):
        raise CoverageError(f"source file for {probe_id} escapes the repository")
    if not source.is_file():
        raise CoverageError(f"source file for {probe_id} does not exist: {source_name}")

    contents = source.read_text(encoding="utf-8")
    if _test_pattern(test_name).search(contents) is None:
        raise CoverageError(
            f"annotated Rust test for {probe_id} does not exist: "
            f"{source_name}::{test_name}"
        )
    return source_name, test_name


def validate_coverage(document: object, repo_root: Path) -> int:
    """Validate one coverage document and return its regression count."""

    coverage = _mapping_with_keys(document, _TOP_LEVEL_KEYS, "coverage document")
    if coverage["schema"] != COVERAGE_SCHEMA:
        raise CoverageError("coverage schema is unsupported")

    source = _mapping_with_keys(coverage["source"], _SOURCE_KEYS, "source metadata")
    expected_source = {
        "schema": SOURCE_SCHEMA,
        "snapshot_date": SNAPSHOT_DATE,
        "manifest_sha256": SOURCE_MANIFEST_SHA256,
    }
    if source != expected_source:
        raise CoverageError("source metadata does not identify the retained snapshot")

    probes = coverage["probes"]
    if not isinstance(probes, list):
        raise CoverageError("probes must be a list")

    parsed: list[tuple[str, list[object]]] = []
    for index, value in enumerate(probes):
        probe = _mapping_with_keys(value, _PROBE_KEYS, f"probe at index {index}")
        probe_id = _string(probe["id"], f"probe ID at index {index}")
        regressions = probe["regressions"]
        if not isinstance(regressions, list) or not regressions:
            raise CoverageError(f"probe {probe_id} must have at least one regression")
        parsed.append((probe_id, regressions))

    probe_ids = [probe_id for probe_id, _ in parsed]
    duplicates = sorted(
        probe_id for probe_id in set(probe_ids) if probe_ids.count(probe_id) > 1
    )
    if duplicates:
        raise CoverageError(f"duplicate probe IDs: {', '.join(duplicates)}")
    if "passive" in probe_ids:
        raise CoverageError("passive is not an active adversarial probe")

    missing = sorted(set(EXPECTED_PROBE_IDS) - set(probe_ids))
    unknown = sorted(set(probe_ids) - set(EXPECTED_PROBE_IDS))
    if missing:
        raise CoverageError(f"missing probe IDs: {', '.join(missing)}")
    if unknown:
        raise CoverageError(f"unknown probe IDs: {', '.join(unknown)}")
    if tuple(probe_ids) != EXPECTED_PROBE_IDS:
        raise CoverageError("probe IDs do not follow the retained manifest order")

    regression_count = 0
    for probe_id, regressions in parsed:
        references = [
            _validate_regression(regression, repo_root, probe_id)
            for regression in regressions
        ]
        if len(references) != len(set(references)):
            raise CoverageError(f"probe {probe_id} has duplicate regression references")
        if references != sorted(references):
            raise CoverageError(
                f"regressions for {probe_id} are not in canonical order"
            )
        regression_count += len(references)
    return regression_count


def validate_source_manifest(payload: bytes, source_metadata: object) -> int:
    """Validate the exact Reaper manifest used by a coverage snapshot."""

    source = _mapping_with_keys(source_metadata, _SOURCE_KEYS, "source metadata")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != source["manifest_sha256"]:
        raise CoverageError(
            "Reaper source manifest digest differs from the retained snapshot"
        )

    try:
        manifest = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot parse Reaper source manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise CoverageError("Reaper source manifest must be an object")
    if manifest.get("schema") != source["schema"]:
        raise CoverageError("Reaper source manifest schema differs from the snapshot")
    if manifest.get("snapshot_date") != source["snapshot_date"]:
        raise CoverageError("Reaper source manifest date differs from the snapshot")

    probes = manifest.get("probes")
    if not isinstance(probes, list) or not all(
        isinstance(probe_id, str) and probe_id for probe_id in probes
    ):
        raise CoverageError("Reaper source manifest probes must be non-empty strings")
    if len(probes) != len(set(probes)):
        raise CoverageError("Reaper source manifest has duplicate probe IDs")
    if probes.count("passive") != 1:
        raise CoverageError("Reaper source manifest must contain one passive probe")

    active_probe_ids = tuple(probe_id for probe_id in probes if probe_id != "passive")
    missing = sorted(set(EXPECTED_PROBE_IDS) - set(active_probe_ids))
    added = sorted(set(active_probe_ids) - set(EXPECTED_PROBE_IDS))
    if missing:
        raise CoverageError(f"Reaper source removed probe IDs: {', '.join(missing)}")
    if added:
        raise CoverageError(f"Reaper source added probe IDs: {', '.join(added)}")
    if active_probe_ids != EXPECTED_PROBE_IDS:
        raise CoverageError("Reaper source probe order differs from the snapshot")
    return len(active_probe_ids)


def load_coverage(path: Path) -> object:
    """Read a UTF-8 JSON coverage document."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot read coverage document: {error}") from error


def load_source_manifest(path: Path) -> bytes:
    """Read a Reaper source manifest without normalizing its retained digest."""

    try:
        return path.read_bytes()
    except OSError as error:
        raise CoverageError(f"cannot read Reaper source manifest: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate a coverage snapshot")
    check.add_argument("coverage", type=Path)
    check.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    check.add_argument(
        "--source-manifest",
        type=Path,
        help="audit the exact Reaper manifest that produced the snapshot",
    )
    arguments = parser.parse_args(argv)

    try:
        coverage = load_coverage(arguments.coverage)
        regression_count = validate_coverage(coverage, arguments.repo_root)
        if arguments.source_manifest is not None:
            source = _mapping_with_keys(coverage, _TOP_LEVEL_KEYS, "coverage document")[
                "source"
            ]
            validate_source_manifest(
                load_source_manifest(arguments.source_manifest), source
            )
    except CoverageError as error:
        parser.exit(1, f"error: {error}\n")

    message = (
        f"Reaper coverage OK: {len(EXPECTED_PROBE_IDS)} probes, "
        f"{regression_count} regressions"
    )
    if arguments.source_manifest is not None:
        message += "; source manifest matches"
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
