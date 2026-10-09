"""Run Phantom's client endpoint against the pinned QUIC Interop Runner."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .docker_owner import remove_container, verified_container_id
except ImportError:
    from docker_owner import remove_container, verified_container_id

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
DOCKER_TIMEOUT_SECONDS = 30
PROCESS_EXIT_SECONDS = 5
OWNER_LABEL = "org.phantom.quic-interop.owner"
FIXED_CONTAINERS = ("sim", "server", "client")


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


def _require_shell_safe_image(image: str, role: str) -> None:
    # The pinned runner interpolates images into POSIX shell assignments.
    # Docker validates reference syntax; this boundary excludes shell syntax.
    if (
        not image
        or image.startswith("-")
        or any(
            not (
                character.isascii()
                and (character.isalnum() or character in "._:/@+[]-")
            )
            for character in image
        )
    ):
        raise ValueError(f"{role} image contains unsupported shell characters")


def register_client(path: Path, image: str) -> bytes:
    """Adds the local client to a fresh runner checkout and returns its original file."""

    original = path.read_bytes()
    document = _load_json(path)
    if not isinstance(document, dict):
        raise ValueError("runner implementation registry must be an object")
    if CLIENT_NAME in document:
        raise ValueError(f"runner registry already contains {CLIENT_NAME}")
    _require_shell_safe_image(image, "client")
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

    _require_shell_safe_image(server_image, "server")
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


def _docker(command: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        ["docker", *command],
        capture_output=True,
        text=True,
        check=False,
        timeout=DOCKER_TIMEOUT_SECONDS,
        env=environment,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Docker {' '.join(command[:2])} exited with {result.returncode}: "
            f"{_bounded_text(result.stderr).strip()}"
        )
    return result.stdout


def _refuse_fixed_containers(environment: dict[str, str]) -> None:
    # The pinned runner also discovers logs by these global names.
    for name in FIXED_CONTAINERS:
        result = subprocess.run(
            ["docker", "inspect", "--type", "container", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_TIMEOUT_SECONDS,
            env=environment,
        )
        if result.returncode == 0:
            raise RuntimeError(
                f"fixed container name {name!r} is occupied; left it untouched"
            )
        if result.returncode != 1 or result.stderr.strip() not in {
            f"Error: No such object: {name}",
            f"Error response from daemon: No such container: {name}",
        }:
            raise RuntimeError(
                f"could not establish that fixed container {name!r} is absent: "
                f"{_bounded_text(result.stderr).strip()}"
            )


def _owned_ids(command: list[str], environment: dict[str, str]) -> list[str]:
    output = _docker(
        [
            *command,
            "--no-trunc",
            "--filter",
            f"label={OWNER_LABEL}={environment['PHANTOM_QUIC_OWNER']}",
            "--format",
            "{{.ID}}",
        ],
        environment,
    )
    identities = output.split()
    if any(
        len(identity) != 64
        or any(character not in "0123456789abcdef" for character in identity)
        for identity in identities
    ):
        raise ValueError("owned Docker resource listing returned an invalid full ID")
    return sorted(set(identities))


def _remove_owned_resources(
    environment: dict[str, str],
) -> list[tuple[str, BaseException]]:
    failures: list[tuple[str, BaseException]] = []
    owner = environment["PHANTOM_QUIC_OWNER"]
    try:
        containers = _owned_ids(["ps", "--all"], environment)
    except Exception as error:
        failures.append(("container listing", error))
        containers = []
    for identity in containers:
        try:
            verified = verified_container_id(
                identity,
                OWNER_LABEL,
                owner,
                timeout=DOCKER_TIMEOUT_SECONDS,
                env=environment,
            )
            if verified is None:
                continue
            if verified != identity:
                raise RuntimeError("container inspection changed its immutable ID")
            remove_container(identity, timeout=DOCKER_TIMEOUT_SECONDS, env=environment)
        except Exception as error:
            failures.append((f"container cleanup {identity}", error))

    try:
        networks = _owned_ids(["network", "ls"], environment)
    except Exception as error:
        failures.append(("network listing", error))
        networks = []
    for identity in networks:
        try:
            document = json.loads(
                _docker(["network", "inspect", identity], environment)
            )
            if (
                not isinstance(document, list)
                or len(document) != 1
                or not isinstance(document[0], dict)
                or document[0].get("Id") != identity
                or not isinstance(document[0].get("Labels"), dict)
                or document[0]["Labels"].get(OWNER_LABEL) != owner
                or not isinstance(document[0].get("Containers"), dict)
            ):
                raise ValueError("network inspection did not prove its owned identity")
            if document[0]["Containers"]:
                raise RuntimeError(
                    "owned network still has attached containers; left it untouched"
                )
            _docker(["network", "rm", identity], environment)
        except Exception as error:
            failures.append((f"network cleanup {identity}", error))

    for command, name in [
        (["ps", "--all"], "containers"),
        (["network", "ls"], "networks"),
    ]:
        try:
            if _owned_ids(command, environment):
                raise RuntimeError(f"owned {name} remain after cleanup")
        except Exception as error:
            failures.append((f"{name} absence check", error))
    return failures


def _group_has_live_members(identity: int) -> bool:
    # A fresh Linux session owns this process group. Zombies cannot use files.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_bytes().rsplit(b")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if len(fields) < 4:
            raise RuntimeError("could not inspect a Linux process group member")
        if (
            fields[0] not in {b"Z", b"X"}
            and int(fields[2]) == identity
            and int(fields[3]) == identity
        ):
            return True
    return False


def _wait_group_exit(identity: int, deadline: float) -> None:
    while _group_has_live_members(identity):
        if time.monotonic() >= deadline:
            raise TimeoutError("owned runner process group did not exit")
        time.sleep(0.02)


def _reap_runner(process: subprocess.Popen[bytes]) -> None:
    for signum in [signal.SIGTERM, signal.SIGKILL]:
        deadline = time.monotonic() + PROCESS_EXIT_SECONDS
        if _group_has_live_members(process.pid):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signum)
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            _wait_group_exit(process.pid, deadline)
            return
        except (subprocess.TimeoutExpired, TimeoutError):
            if signum == signal.SIGKILL:
                raise


@contextlib.contextmanager
def _finish_without_sigint() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


@contextlib.contextmanager
def _defer_launch_sigint() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    interrupted = False

    def remember(signum, frame):
        nonlocal interrupted
        interrupted = True

    previous = signal.signal(signal.SIGINT, remember)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
    if interrupted:
        raise KeyboardInterrupt("interrupted while starting the owned runner")


class _RunnerFailure(RuntimeError):
    def __init__(
        self,
        failures: list[tuple[str, BaseException]],
        retained_paths: list[Path],
        retain_checkout: bool,
        report_directory: Path | None,
    ):
        super().__init__(_failure_detail(failures))
        self.failures = tuple(failures)
        self.retained_paths = tuple(retained_paths)
        self.retain_checkout = retain_checkout
        self.report_directory = report_directory


class _RunnerInterrupted(KeyboardInterrupt):
    def __init__(
        self,
        failures: list[tuple[str, BaseException]],
        retained_paths: list[Path],
        retain_checkout: bool,
        report_directory: Path | None,
    ):
        super().__init__(_failure_detail(failures))
        self.failures = tuple(failures)
        self.retained_paths = tuple(retained_paths)
        self.retain_checkout = retain_checkout
        self.report_directory = report_directory


def _failure_detail(failures: list[tuple[str, BaseException]]) -> str:
    return "; ".join(
        f"{phase}: {' '.join(str(error).split())[:500]}" for phase, error in failures
    )


def _report_failure(
    server: str,
    directory: Path,
    failures: list[tuple[str, BaseException]],
    retained_paths: list[Path],
    retain_checkout: bool,
) -> _RunnerFailure | _RunnerInterrupted:
    try:
        (directory / "summary.json").write_text(
            json.dumps(
                {
                    "client": CLIENT_NAME,
                    "server": server,
                    "status": "failed",
                    "test": SUPPORTED_TEST,
                    "detail": _failure_detail(failures),
                    "failures": [
                        {"phase": phase, "detail": " ".join(str(error).split())[:500]}
                        for phase, error in failures
                    ],
                    "retained_paths": [str(path) for path in retained_paths],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except Exception as error:
        failures.append(("failure report", error))
    failure_type = (
        _RunnerInterrupted
        if isinstance(failures[0][1], KeyboardInterrupt)
        else _RunnerFailure
    )
    return failure_type(failures, retained_paths, retain_checkout, directory)


class _RunnerOwner:
    def __init__(self, runner: Path):
        self.runner = runner
        self.originals = {
            runner / name: (runner / name).read_bytes()
            for name in [
                "implementations_quic.json",
                "docker-compose.yml",
                "testcase.py",
            ]
        }
        self.environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("COMPOSE_")
        }
        token = secrets.token_hex(16)
        self.environment.update(
            {
                "COMPOSE_PROJECT_NAME": f"phantom-quic-{token}",
                "PHANTOM_QUIC_OWNER": token,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        self.scratch: Path | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.reaped = True

    def prepare(self, image: str, server: str, server_image: str) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="phantom-quic-interop-"))
        backups = self.scratch / "originals"
        backups.mkdir()
        for path, original in self.originals.items():
            (backups / path.name).write_bytes(original)
        override = self.scratch / "owned-compose.json"
        labels = {OWNER_LABEL: self.environment["PHANTOM_QUIC_OWNER"]}
        override.write_text(
            json.dumps(
                {
                    "services": {name: {"labels": labels} for name in FIXED_CONTAINERS},
                    "networks": {
                        name: {"labels": labels} for name in ["leftnet", "rightnet"]
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        compose = self.runner / "docker-compose.yml"
        if any(os.pathsep in str(path) for path in [compose, override]):
            raise ValueError("runner paths contain the Compose file separator")
        self.environment["COMPOSE_FILE"] = os.pathsep.join(
            [str(compose), str(override)]
        )
        self.environment["COMPOSE_PATH_SEPARATOR"] = os.pathsep

        registry = self.runner / "implementations_quic.json"
        register_client(registry, image)
        pin_runner_images(registry, server, server_image)
        _replace_once(
            compose,
            "image: martenseemann/quic-network-simulator",
            f"image: {SIMULATOR_IMAGE}",
        )
        _replace_once(
            self.runner / "testcase.py",
            '                "alpine:3.18",',
            '                "--label",\n'
            f'                "{OWNER_LABEL}=" + os.environ["PHANTOM_QUIC_OWNER"],\n'
            f'                "{CLEANUP_IMAGE}",',
        )

    def finish(
        self, report_directory: Path
    ) -> tuple[list[tuple[str, BaseException]], list[Path]]:
        failures: list[tuple[str, BaseException]] = []
        if self.process is not None:
            try:
                _reap_runner(self.process)
            except Exception as error:
                self.reaped = False
                failures.append(("runner process reaping", error))
        if self.scratch is not None and (self.scratch / "runner-output.log").exists():
            try:
                with (self.scratch / "runner-output.log").open("rb") as output:
                    text = output.read(MAX_LOG_BYTES + 1).decode("utf-8", "replace")
                (report_directory / "runner.log").write_text(
                    _bounded_text(text), encoding="utf-8"
                )
            except Exception as error:
                failures.append(("runner log", error))
        if not self.reaped:
            return failures, [self.runner, *([self.scratch] if self.scratch else [])]

        resource_failures = (
            _remove_owned_resources(self.environment)
            if self.process is not None
            else []
        )
        failures.extend(resource_failures)
        for path, original in self.originals.items():
            try:
                path.write_bytes(original)
            except Exception as error:
                failures.append((f"restore {path.name}", error))
        retained = []
        if self.scratch is not None:
            if failures:
                retained.append(self.scratch)
            else:
                try:
                    shutil.rmtree(self.scratch)
                except Exception as error:
                    retained.append(self.scratch)
                    failures.append(("scratch cleanup", error))
        return failures, retained


def run(
    runner: Path,
    repository: Path,
    report_root: Path,
    image: str,
    server: str,
    server_image: str,
) -> Path:
    """Run the pinned HTTP/3 client case on Linux with one runner per daemon.

    Other platforms fail before mutation. A failed process reap retains scratch
    and checkout files for recovery; owned resources never use global removal.
    """

    if sys.platform != "linux":
        raise ValueError(
            "the full QUIC Interop Runner requires Linux process ownership"
        )
    runner = runner.resolve()
    verify_runner_checkout(runner)
    registry_path = runner / "implementations_quic.json"
    validate_server(registry_path, server)
    owner = _RunnerOwner(runner)
    _refuse_fixed_containers(owner.environment)
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
        "resource_owner": {
            "label": OWNER_LABEL,
            "value": owner.environment["PHANTOM_QUIC_OWNER"],
            "compose_project": owner.environment["COMPOSE_PROJECT_NAME"],
        },
        "started_at": datetime.now(timezone.utc).isoformat(),
        "test": SUPPORTED_TEST,
    }
    (run_directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    failures: list[tuple[str, BaseException]] = []
    summary = None
    try:
        owner.prepare(image, server, server_image)
        raw_output = owner.scratch / "runner-output.log"
        with raw_output.open("wb") as output:
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
                str(owner.scratch / "logs"),
                "--json",
                str(result_path),
            ]
            with _defer_launch_sigint():
                owner.process = subprocess.Popen(
                    command,
                    cwd=runner,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    env=owner.environment,
                    start_new_session=True,
                )
            returncode = owner.process.wait(timeout=RUN_TIMEOUT_SECONDS)
            summary = parse_result(result_path, server)
            if returncode != 0:
                raise RuntimeError(f"QUIC Interop Runner exited with {returncode}")
    except BaseException as error:
        failures.append(("runner", error))
    with _finish_without_sigint():
        cleanup_failures, retained = owner.finish(run_directory)
        failures.extend(cleanup_failures)
        if failures:
            failure = _report_failure(
                server, run_directory, failures, retained, not owner.reaped
            )
            raise failure from failures[0][1]
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

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
    if sys.platform != "linux":
        parser.error("the full QUIC Interop Runner requires Linux process ownership")

    temporary: Path | None = None
    directory = None
    failure = None
    try:
        runner = args.runner
        if runner is None:
            temporary = Path(tempfile.mkdtemp(prefix="phantom-quic-runner-"))
            runner = temporary / "runner"
            checkout_runner(runner)
        directory = run(
            runner.resolve(),
            repository,
            args.report_root,
            args.image,
            args.server,
            args.server_image,
        )
    except BaseException as error:
        failure = error
    with _finish_without_sigint():
        if temporary is not None:
            if getattr(failure, "retain_checkout", False):
                print(f"retained runner checkout: {temporary}", file=sys.stderr)
            else:
                try:
                    shutil.rmtree(temporary)
                except Exception as error:
                    failures = list(getattr(failure, "failures", []))
                    if failure is not None and not failures:
                        failures.append(("runner", failure))
                    failures.append(("temporary checkout cleanup", error))
                    report = directory or getattr(failure, "report_directory", None)
                    if report is not None:
                        failure = _report_failure(
                            args.server, report, failures, [temporary], False
                        )
                    else:
                        failure = _RunnerFailure(failures, [temporary], False, None)
                    failure.__cause__ = failures[0][1]
        if failure is not None:
            if isinstance(
                failure, (OSError, ValueError, RuntimeError, subprocess.SubprocessError)
            ):
                parser.error(str(failure))
            raise failure
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
