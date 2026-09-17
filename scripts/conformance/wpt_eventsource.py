"""Run selected pinned WPT EventSource scenarios through Phantom's public API."""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import logging.handlers
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from .loopback_tls import LoopbackCertificate, generate_loopback_certificate
else:
    from loopback_tls import LoopbackCertificate, generate_loopback_certificate

WPT_REPOSITORY = "https://github.com/web-platform-tests/wpt.git"
WPT_REVISION = "7dbbcb8bcbf62683e6ac095da7d95a84b3672ab5"
MODE_TIMEOUT_SECONDS = {"smoke": 240, "full": 420}
SPARSE_PATHS = (
    "/eventsource/",
    "/tools/__init__.py",
    "/tools/localpaths.py",
    "/tools/wptserve/",
    "/tools/third_party/h2/",
    "/tools/third_party/hpack/",
    "/tools/third_party/hyperframe/",
    "/tools/third_party/pywebsocket3/",
    "/tools/third_party/six/",
)
MAX_LOG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CaseSummary:
    """Parsed case results emitted by the Rust adapter."""

    cases: dict[str, dict[str, str]]
    failures: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        """Returns the bounded result document retained by CI."""

        return {
            "case_count": len(self.cases),
            "failure_count": len(self.failures),
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


def load_case_ids(path: Path) -> tuple[str, ...]:
    """Loads one ordered case manifest with strict shape validation."""

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"could not load {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != {"cases", "revision"}:
        raise ValueError("WPT case manifest must contain revision and cases")
    if document["revision"] != WPT_REVISION:
        raise ValueError(
            f"WPT case manifest revision must be the pinned {WPT_REVISION}"
        )
    cases = document["cases"]
    if not isinstance(cases, list) or not cases:
        raise ValueError("WPT case manifest must contain a nonempty cases array")
    if any(not isinstance(case, str) or not case for case in cases):
        raise ValueError("WPT case identifiers must be nonempty strings")
    if len(set(cases)) != len(cases):
        raise ValueError("WPT case identifiers must be unique")
    return tuple(cases)


def parse_adapter_output(output: str, expected: tuple[str, ...]) -> CaseSummary:
    """Parses the adapter's bounded line protocol and checks its exact case set."""

    cases: dict[str, dict[str, str]] = {}
    summary: tuple[int, int] | None = None
    for line in output.splitlines():
        fields = line.split("\t", 3)
        if fields[0] == "CASE" and len(fields) in {3, 4}:
            _, status, case, *detail = fields
            if status not in {"PASS", "FAIL"}:
                raise ValueError(f"adapter emitted invalid status {status!r}")
            if case in cases:
                raise ValueError(f"adapter emitted duplicate case {case!r}")
            result = {"status": status.lower()}
            if detail:
                result["detail"] = detail[0]
            cases[case] = result
        elif fields[0] == "SUMMARY" and len(fields) == 3:
            if summary is not None:
                raise ValueError("adapter emitted more than one summary")
            try:
                summary = (int(fields[1]), int(fields[2]))
            except ValueError as error:
                raise ValueError("adapter summary counts must be integers") from error
        elif line:
            raise ValueError(f"adapter emitted an invalid line: {line[:120]!r}")

    if summary is None:
        raise ValueError("adapter omitted its summary")
    expected_set = set(expected)
    observed_set = set(cases)
    if observed_set != expected_set:
        missing = sorted(expected_set - observed_set)
        extra = sorted(observed_set - expected_set)
        raise ValueError(
            f"adapter case set differed: missing={missing!r}, extra={extra!r}"
        )
    failures = tuple(
        f"{case}: {result.get('detail', 'failed')}"
        for case, result in cases.items()
        if result["status"] == "fail"
    )
    if summary != (len(cases), len(failures)):
        raise ValueError(
            f"adapter summary was {summary!r}; observed {(len(cases), len(failures))!r}"
        )
    ordered = {case: cases[case] for case in expected}
    return CaseSummary(ordered, failures)


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 180) -> None:
    subprocess.run(
        command,
        cwd=cwd,
        check=True,
        timeout=timeout,
        capture_output=True,
        text=True,
    )


def _checkout_wpt(destination: Path) -> None:
    _run(["git", "init", "--quiet", str(destination)])
    _run(["git", "remote", "add", "origin", WPT_REPOSITORY], cwd=destination)
    _run(["git", "sparse-checkout", "init", "--no-cone"], cwd=destination)
    _run(
        ["git", "sparse-checkout", "set", "--no-cone", *SPARSE_PATHS],
        cwd=destination,
    )
    _run(
        [
            "git",
            "fetch",
            "--quiet",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            WPT_REVISION,
        ],
        cwd=destination,
        timeout=300,
    )
    _run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=destination)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=destination,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != WPT_REVISION:
        raise RuntimeError(
            f"WPT checkout resolved to {revision}, expected {WPT_REVISION}"
        )


def _verify_case_sources(source: Path, cases: tuple[str, ...]) -> None:
    missing = sorted(
        case for case in cases if not (source / case.split("#", 1)[0]).is_file()
    )
    if missing:
        raise ValueError(f"WPT case sources were missing: {missing!r}")


def _load_server_types(source: Path) -> tuple[type[Any], type[Any]]:
    tools = str(source / "tools")
    sys.path.insert(0, tools)
    importlib.import_module("localpaths")
    config_type = importlib.import_module("wptserve.config").Config
    server_type = importlib.import_module("wptserve.server").WebTestHttpd
    return config_type, server_type


def _start_server(source: Path, certificate: LoopbackCertificate) -> Any:
    config_type, server_type = _load_server_types(source)
    config = config_type(
        {
            "browser_host": "localhost",
            "all_domains": {"": {"": "localhost"}},
            "ports": {"https": []},
            "logging": {"suppress_handler_traceback": False},
        }
    )
    server = server_type(
        host="127.0.0.1",
        port=0,
        use_ssl=True,
        key_file=str(certificate.private_key_pem),
        certificate=str(certificate.certificate_pem),
        doc_root=str(source),
        config=config,
    )
    server.start()
    return server


def _git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _bounded_text(value: str) -> str:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= MAX_LOG_BYTES:
        return encoded.decode("utf-8")
    suffix = b"\n[log truncated]\n"
    return (encoded[: MAX_LOG_BYTES - len(suffix)] + suffix).decode("utf-8", "replace")


def run(mode: str, repository: Path, report_root: Path) -> Path:
    """Runs one pinned EventSource case set and returns its report directory."""

    source_manifest = (
        repository / "scripts" / "conformance" / "wpt-eventsource" / f"{mode}.json"
    )
    case_ids = load_case_ids(source_manifest)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_directory = (report_root / f"{mode}-{timestamp}-{os.getpid()}").resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    (run_directory / "case-manifest.json").write_text(
        source_manifest.read_text(encoding="utf-8"), encoding="utf-8"
    )
    metadata = {
        "features": ["sse"],
        "mode": mode,
        "phantom_revision": _git_revision(repository),
        "platform": platform.platform(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "suite_repository": WPT_REPOSITORY,
        "suite_source_revision": WPT_REVISION,
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    server = None
    handler = logging.handlers.RotatingFileHandler(
        run_directory / "server.log",
        maxBytes=MAX_LOG_BYTES,
        backupCount=1,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    try:
        with tempfile.TemporaryDirectory(
            prefix="phantom-wpt-eventsource-"
        ) as temporary:
            temporary_root = Path(temporary)
            source = temporary_root / "wpt"
            _checkout_wpt(source)
            _verify_case_sources(source, case_ids)
            certificate = generate_loopback_certificate(temporary_root)
            server = _start_server(source, certificate)
            command = [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "phantom",
                "--example",
                "wpt-eventsource-client",
                "--features",
                "sse",
                "--",
                "--url",
                f"https://localhost:{server.port}/",
                "--ca-der",
                str(certificate.root_der),
            ]
            for case in case_ids:
                command.extend(["--case", case])
            adapter = subprocess.run(
                command,
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
                timeout=MODE_TIMEOUT_SECONDS[mode],
            )
            (run_directory / "adapter.log").write_text(
                _bounded_text(adapter.stdout + adapter.stderr), encoding="utf-8"
            )
            summary = parse_adapter_output(adapter.stdout, case_ids)
            if (adapter.returncode == 0) != (not summary.failures):
                raise RuntimeError(
                    "adapter exit status disagreed with its case summary"
                )
            (run_directory / "summary.json").write_text(
                json.dumps(summary.as_json(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(
                f"WPT EventSource {mode}: {len(summary.cases)} cases, "
                f"{len(summary.failures)} failures"
            )
            for failure in summary.failures:
                print(f"failure: {failure}")
            if summary.failures:
                raise RuntimeError("WPT EventSource scenarios reported failures")
    except Exception as error:
        summary_path = run_directory / "summary.json"
        if not summary_path.exists():
            detail = " ".join(str(error).split())[:500]
            summary_path.write_text(
                json.dumps(
                    {
                        "case_count": 0,
                        "failure_count": 1,
                        "failures": [f"infrastructure: {detail}"],
                        "cases": {},
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        raise
    finally:
        try:
            if server is not None:
                server.stop()
        finally:
            root_logger.removeHandler(handler)
            handler.close()
            (run_directory / "server.log.1").unlink(missing_ok=True)
    return run_directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=sorted(MODE_TIMEOUT_SECONDS))
    parser.add_argument(
        "--report-root",
        type=Path,
        default=Path("target/wpt-eventsource"),
        help="parent directory for retained reports",
    )
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    try:
        directory = run(args.mode, repository, args.report_root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
