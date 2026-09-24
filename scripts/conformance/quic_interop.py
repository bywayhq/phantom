"""Run Phantom's client endpoint against the pinned QUIC Interop Runner."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUNNER_REPOSITORY = "https://github.com/quic-interop/quic-interop-runner.git"
RUNNER_REVISION = "740c05a10b61d65e8abd3ad38d60898004d335d9"
CLIENT_NAME = "phantom"
SUPPORTED_TEST = "http3"
DEFAULT_IMAGE = "phantom-quic-interop:local"
DEFAULT_SERVER = "quic-go"
DEFAULT_SERVER_IMAGE = (
    "martenseemann/quic-go-interop@"
    "sha256:ddff4e7b23d520513138e22b33bd17ece901fd0d1753ffa78f5f5c2270e92c46"
)
SIMULATOR_IMAGE = (
    "martenseemann/quic-network-simulator@"
    "sha256:c23d82a55caffe681b1bdae65d4d30d23e1283141a414a7f02ee56cf15f9c6b9"
)
CLEANUP_IMAGE = (
    "alpine:3.18@"
    "sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"
)
MAX_LOG_BYTES = 1024 * 1024
RUN_TIMEOUT_SECONDS = 20 * 60


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"duplicate JSON key {key!r}")
        mapping[key] = value
    return mapping


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"could not load {path}: {error}") from error


def verify_runner_checkout(runner: Path) -> None:
    """Requires the exact reviewed upstream runner revision."""

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=runner,
        check=True,
        capture_output=True,
        text=True,
    )
    revision = result.stdout.strip()
    if revision != RUNNER_REVISION:
        raise ValueError(
            f"runner checkout is {revision}, expected pinned {RUNNER_REVISION}"
        )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=runner,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise ValueError("runner checkout contains unreviewed changes")
    for relative in ["run.py", "implementations_quic.json", "docker-compose.yml"]:
        if not (runner / relative).is_file():
            raise ValueError(f"runner checkout is missing {relative}")


def register_client(path: Path, image: str) -> bytes:
    """Adds the local client to a fresh runner checkout and returns its original file."""

    original = path.read_bytes()
    document = _load_json(path)
    if not isinstance(document, dict):
        raise ValueError("runner implementation registry must be an object")
    if CLIENT_NAME in document:
        raise ValueError(f"runner registry already contains {CLIENT_NAME}")
    if not image or any(character.isspace() for character in image):
        raise ValueError("client image must be one nonempty argument")
    document[CLIENT_NAME] = {
        "image": image,
        "url": "https://github.com/bywayhq/phantom",
        "role": "client",
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return original


def validate_server(path: Path, server: str) -> None:
    """Requires one existing server-capable runner implementation."""

    if (
        not server
        or len(server) > 64
        or server in {".", ".."}
        or any(
            not (character.isascii() and (character.isalnum() or character in "._-"))
            for character in server
        )
    ):
        raise ValueError("server name contains unsupported characters")
    document = _load_json(path)
    if not isinstance(document, dict):
        raise ValueError("runner implementation registry must be an object")
    implementation = document.get(server)
    if not isinstance(implementation, dict) or implementation.get("role") not in {
        "server",
        "both",
    }:
        raise ValueError(f"runner registry has no server-capable {server!r}")


def pin_runner_images(path: Path, server: str, server_image: str) -> None:
    """Pins the selected server in the temporary upstream registry."""

    if not server_image or any(character.isspace() for character in server_image):
        raise ValueError("server image must be one nonempty argument")
    document = _load_json(path)
    implementation = document.get(server) if isinstance(document, dict) else None
    if not isinstance(implementation, dict):
        raise ValueError(f"runner registry does not contain {server!r}")
    implementation["image"] = server_image
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _replace_once(path: Path, before: str, after: str) -> bytes:
    original = path.read_bytes()
    text = original.decode("utf-8")
    if text.count(before) != 1:
        raise ValueError(f"{path.name} did not contain exactly one {before!r}")
    path.write_text(text.replace(before, after), encoding="utf-8")
    return original


def parse_result(path: Path, server: str) -> dict[str, str]:
    """Requires one successful HTTP/3 result for the selected pair."""

    document = _load_json(path)
    if not isinstance(document, dict):
        raise ValueError("runner result must be an object")
    if document.get("clients") != [CLIENT_NAME]:
        raise ValueError("runner result has an unexpected client set")
    if document.get("servers") != [server]:
        raise ValueError("runner result has an unexpected server set")

    tests = document.get("tests")
    if not isinstance(tests, dict) or len(tests) != 1:
        raise ValueError("runner result must describe exactly one test")
    ((abbreviation, description),) = tests.items()
    if (
        not isinstance(description, dict)
        or description.get("name") != SUPPORTED_TEST
        or not isinstance(abbreviation, str)
    ):
        raise ValueError("runner result does not describe the HTTP/3 test")

    results = document.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError("runner result must contain one client/server cell")
    cell = results[0]
    if not isinstance(cell, list) or len(cell) != 1 or not isinstance(cell[0], dict):
        raise ValueError("runner result cell has an unexpected shape")
    result = cell[0]
    if (
        result.get("abbr") != abbreviation
        or result.get("name") != SUPPORTED_TEST
        or result.get("result") != "succeeded"
    ):
        raise ValueError(f"QUIC interop HTTP/3 result was {result.get('result')!r}")
    return {
        "client": CLIENT_NAME,
        "server": server,
        "status": "succeeded",
        "test": SUPPORTED_TEST,
    }


def _bounded_text(value: str) -> str:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= MAX_LOG_BYTES:
        return encoded.decode("utf-8")
    suffix = b"\n[log truncated]\n"
    return (encoded[: MAX_LOG_BYTES - len(suffix)] + suffix).decode("utf-8", "replace")


def _git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def run(
    runner: Path,
    repository: Path,
    report_root: Path,
    image: str,
    server: str,
    server_image: str,
) -> Path:
    """Runs the pinned HTTP/3 client case and returns its report directory."""

    verify_runner_checkout(runner)
    registry_path = runner / "implementations_quic.json"
    validate_server(registry_path, server)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_directory = (
        report_root / f"http3-{server}-{timestamp}-{os.getpid()}"
    ).resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    result_path = run_directory / "result.json"
    summary_path = run_directory / "summary.json"
    metadata = {
        "client_image": image,
        "client_name": CLIENT_NAME,
        "phantom_revision": _git_revision(repository),
        "platform": platform.platform(),
        "runner_repository": RUNNER_REPOSITORY,
        "runner_revision": RUNNER_REVISION,
        "server": server,
        "server_image": server_image,
        "simulator_image": SIMULATOR_IMAGE,
        "cleanup_image": CLEANUP_IMAGE,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "test": SUPPORTED_TEST,
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    compose_path = runner / "docker-compose.yml"
    testcase_path = runner / "testcase.py"
    original_registry = registry_path.read_bytes()
    original_compose = compose_path.read_bytes()
    original_testcase = testcase_path.read_bytes()
    try:
        register_client(registry_path, image)
        pin_runner_images(registry_path, server, server_image)
        _replace_once(
            compose_path,
            "image: martenseemann/quic-network-simulator",
            f"image: {SIMULATOR_IMAGE}",
        )
        _replace_once(testcase_path, '"alpine:3.18"', f'"{CLEANUP_IMAGE}"')
        with tempfile.TemporaryDirectory(prefix="phantom-quic-interop-") as temporary:
            raw_logs = Path(temporary) / "logs"
            command = [
                sys.executable,
                "run.py",
                "--server",
                server,
                "--client",
                CLIENT_NAME,
                "--test",
                SUPPORTED_TEST,
                "--no-auto-unsupported",
                CLIENT_NAME,
                "--log-dir",
                str(raw_logs),
                "--json",
                str(result_path),
            ]
            completed = subprocess.run(
                command,
                cwd=runner,
                check=False,
                capture_output=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                timeout=RUN_TIMEOUT_SECONDS,
            )
            (run_directory / "runner.log").write_text(
                _bounded_text(completed.stdout + completed.stderr),
                encoding="utf-8",
            )
            summary = parse_result(result_path, server)
            if completed.returncode != 0:
                raise RuntimeError(
                    f"QUIC Interop Runner exited with {completed.returncode}"
                )
            summary_path.write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    except Exception as error:
        if not summary_path.exists():
            detail = " ".join(str(error).split())[:500]
            summary_path.write_text(
                json.dumps(
                    {
                        "client": CLIENT_NAME,
                        "server": server,
                        "status": "failed",
                        "test": SUPPORTED_TEST,
                        "detail": detail,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        raise
    finally:
        registry_path.write_bytes(original_registry)
        compose_path.write_bytes(original_compose)
        testcase_path.write_bytes(original_testcase)

    print(f"QUIC interop {SUPPORTED_TEST}: {CLIENT_NAME} -> {server}: succeeded")
    return run_directory


def checkout_runner(destination: Path) -> None:
    """Fetches only the pinned runner revision."""

    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", RUNNER_REPOSITORY],
        cwd=destination,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "fetch",
            "--quiet",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            RUNNER_REVISION,
        ],
        cwd=destination,
        check=True,
        timeout=300,
    )
    subprocess.run(
        ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        cwd=destination,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runner",
        type=Path,
        help="existing checkout of the exact pinned runner revision",
    )
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--server-image", default=DEFAULT_SERVER_IMAGE)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument(
        "--report-root",
        type=Path,
        default=Path("target/quic-interop"),
    )
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]

    temporary = None
    try:
        runner = args.runner
        if runner is None:
            temporary = tempfile.TemporaryDirectory(prefix="phantom-quic-runner-")
            runner = Path(temporary.name) / "runner"
            checkout_runner(runner)
        directory = run(
            runner.resolve(),
            repository,
            args.report_root,
            args.image,
            args.server,
            args.server_image,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        parser.error(str(error))
    finally:
        if temporary is not None:
            temporary.cleanup()
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
