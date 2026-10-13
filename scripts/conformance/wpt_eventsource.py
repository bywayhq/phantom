"""Run selected pinned WPT EventSource scenarios through Phantom's public API."""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import logging
import logging.handlers
import multiprocessing
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
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
SERVER_START_SECONDS = 10
SERVER_STOP_SECONDS = 10
SERVER_REAP_SECONDS = 5


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


def _construct_server(source: Path, certificate: LoopbackCertificate) -> Any:
    config_type, server_type = _load_server_types(source)
    config = config_type(
        {
            "browser_host": "localhost",
            "all_domains": {"": {"": "localhost"}},
            "ports": {"https": []},
            "logging": {"suppress_handler_traceback": False},
        }
    )
    return server_type(
        host="127.0.0.1",
        port=0,
        use_ssl=True,
        key_file=str(certificate.private_key_pem),
        certificate=str(certificate.certificate_pem),
        doc_root=str(source),
        config=config,
    )


def _failure_detail(error: Exception | KeyboardInterrupt) -> str:
    detail = " ".join(str(error).split())[:500]
    return f"{type(error).__name__}: {detail}" if detail else type(error).__name__


def _server_process(
    source: Path, certificate: LoopbackCertificate, log_path: Path, connection: Any
) -> None:
    server = None
    handler = None
    logger = logging.getLogger()
    failures = []
    operation = "server logging"
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=MAX_LOG_BYTES, backupCount=1, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        logger.addHandler(handler)

        operation = "server construction"
        server = _construct_server(source, certificate)
        operation = "server startup"
        server.start()
        connection.send(("ready", server.port))

        operation = "server control"
        if connection.recv() != "stop":
            raise RuntimeError("unexpected server control message")
    except (Exception, KeyboardInterrupt) as error:
        failures.append(f"{operation}: {_failure_detail(error)}")
    finally:
        if server is not None:
            try:
                if server.started:
                    server.stop()
            except (Exception, KeyboardInterrupt) as error:
                failures.append(f"server stop: {_failure_detail(error)}")
            finally:
                # The pinned stop can fail before closing its acquired socket.
                httpd = server.httpd
                if httpd is not None:
                    try:
                        httpd.server_close()
                    except (Exception, KeyboardInterrupt) as error:
                        failures.append(
                            f"server socket close: {_failure_detail(error)}"
                        )
        if handler is not None:
            try:
                logger.removeHandler(handler)
            except (Exception, KeyboardInterrupt) as error:
                failures.append(f"server log detach: {_failure_detail(error)}")
            try:
                handler.close()
            except (Exception, KeyboardInterrupt) as error:
                failures.append(f"server log close: {_failure_detail(error)}")
        try:
            connection.send(("stopped", failures))
        finally:
            connection.close()


class _ServerFailure(RuntimeError):
    def __init__(self, failures: list[str], *, unreaped: bool = False):
        super().__init__("; ".join(failures))
        self.failures = failures
        self.unreaped = unreaped


class _ServerProcess(multiprocessing.context.SpawnProcess):
    """Retain the native constructor if CPython spawn raises after acquisition."""

    def __init__(self, *, target, args):
        super().__init__(target=target, args=args)
        self._native_constructor = None
        self.acquisition_uncertain = False

    def __getstate__(self):
        state = self.__dict__.copy()
        # The native constructor and finalizer belong only to the parent.
        state["_native_constructor"] = None
        return state

    @staticmethod
    def _Popen(process):
        if sys.platform == "win32":
            from multiprocessing.popen_spawn_win32 import Popen
        else:
            from multiprocessing.popen_spawn_posix import Popen

        native = Popen.__new__(Popen)
        process._native_constructor = native
        Popen.__init__(native, process)
        return native

    def recover_start_failure(self):
        if self._popen is not None or self._native_constructor is None:
            return

        native = self._native_constructor
        fields = ("pid", "sentinel", "returncode", "finalizer")
        if sys.platform == "win32":
            fields += ("_handle",)
        # CPython 3.10: Windows installs these before serialization. POSIX
        # installs them and its finalizer before a post-spawn write can escape.
        # BaseProcess.start otherwise loses the constructor on that exception.
        if (
            all(hasattr(native, field) for field in fields)
            and native.finalizer is not None
        ):
            self._popen = native
            self._sentinel = native.sentinel
        else:
            self.acquisition_uncertain = True


class _ServerOwner:
    """Own one spawned WPT server until its exit has been observed."""

    def __init__(self, source: Path, certificate: LoopbackCertificate, log_path: Path):
        context = multiprocessing.get_context("spawn")
        self.connection, child_connection = context.Pipe()
        try:
            self.process = _ServerProcess(
                target=_server_process,
                args=(source, certificate, log_path, child_connection),
            )
        except (Exception, KeyboardInterrupt) as primary:
            failures = [f"server process construction: {_failure_detail(primary)}"]
            interrupt = primary if isinstance(primary, KeyboardInterrupt) else None
            for connection in (child_connection, self.connection):
                try:
                    connection.close()
                except (Exception, KeyboardInterrupt) as error:
                    failures.append(f"server control close: {_failure_detail(error)}")
                    if isinstance(error, KeyboardInterrupt) and interrupt is None:
                        interrupt = error
            if interrupt is not None:
                interrupt.shutdown_failures = failures
                if interrupt is primary:
                    raise
                raise interrupt from primary
            if len(failures) > 1:
                raise _ServerFailure(failures) from primary
            raise
        self.port = None
        self.started = False
        self.final_status = None
        self.child_connection = child_connection

    def start(self) -> None:
        primary = None
        failures = []
        with _start_signals() as interrupts:
            try:
                self.process.start()
            except (Exception, KeyboardInterrupt) as error:
                primary = error
                failures.append(f"server process start: {_failure_detail(error)}")
                self.process.recover_start_failure()
            finally:
                self.started = self.process.pid is not None
                try:
                    self.child_connection.close()
                except (Exception, KeyboardInterrupt) as error:
                    if primary is None or (
                        isinstance(error, KeyboardInterrupt)
                        and not isinstance(primary, KeyboardInterrupt)
                    ):
                        primary = error
                    failures.append(
                        f"server child control close: {_failure_detail(error)}"
                    )

        if interrupts:
            handler, signum, frame = interrupts[0]
            try:
                handler(signum, frame)
            except KeyboardInterrupt as interrupt:
                if isinstance(primary, KeyboardInterrupt):
                    failures.append(f"server acquisition: {_failure_detail(interrupt)}")
                    primary.shutdown_failures = failures
                    raise primary from interrupt
                interrupt.shutdown_failures = failures
                raise
        if primary is not None:
            if isinstance(primary, KeyboardInterrupt):
                primary.shutdown_failures = failures
                raise primary
            if len(failures) > 1:
                raise _ServerFailure(failures) from primary
            raise primary

    def wait_ready(self) -> None:
        if not self.connection.poll(SERVER_START_SECONDS):
            raise TimeoutError("server startup exceeded 10 seconds")
        status, value = self.connection.recv()
        if status == "stopped" and _valid_failures(value):
            self.final_status = value
            raise _ServerFailure(value or ["server exited before reporting ready"])
        if status != "ready" or type(value) is not int or not 1 <= value <= 65535:
            raise RuntimeError("server reported invalid readiness")
        self.port = value

    def stop(self) -> None:
        with _shutdown_signals() as interrupts:
            self._stop(interrupts)

    def _stop(self, interrupts: list[KeyboardInterrupt]) -> None:
        failures = []
        interrupt = None
        forced = False
        deadline = time.monotonic() + SERVER_STOP_SECONDS
        try:
            if self.started and self.final_status is None:
                self.connection.send("stop")
                if not self.connection.poll(max(0, deadline - time.monotonic())):
                    raise TimeoutError("server shutdown exceeded 10 seconds")
                status, value = self.connection.recv()
                if status == "ready" and type(value) is int and 1 <= value <= 65535:
                    # Start can be interrupted before the parent consumes readiness.
                    if not self.connection.poll(max(0, deadline - time.monotonic())):
                        raise TimeoutError("server shutdown exceeded 10 seconds")
                    status, value = self.connection.recv()
                if status != "stopped" or not _valid_failures(value):
                    raise RuntimeError("server omitted its final shutdown status")
                self.final_status = value
            if self.final_status is not None:
                failures.extend(self.final_status)
            if self.started:
                self.process.join(max(0, deadline - time.monotonic()))
                if self.process.is_alive():
                    raise TimeoutError("server did not exit after shutdown status")
        except (Exception, KeyboardInterrupt) as error:
            failures.append(f"server shutdown: {_failure_detail(error)}")
            if isinstance(error, KeyboardInterrupt):
                interrupt = error
        finally:
            for operation in ("terminate", "kill"):
                if not self.started or not self.process.is_alive():
                    break
                forced = True
                try:
                    getattr(self.process, operation)()
                    self.process.join(SERVER_REAP_SECONDS)
                except (Exception, KeyboardInterrupt) as error:
                    failures.append(f"server {operation}: {_failure_detail(error)}")
                    if isinstance(error, KeyboardInterrupt) and interrupt is None:
                        interrupt = error

            unreaped = self.process.acquisition_uncertain or (
                self.started and self.process.is_alive()
            )
            if self.process.acquisition_uncertain:
                failures.append(
                    "server acquisition left an incomplete native handle; child exit is unobserved"
                )
            elif unreaped:
                failures.append("server process remains alive after terminate and kill")
            elif self.started and self.process.exitcode != 0:
                context = " after forced shutdown" if forced else ""
                failures.append(
                    f"server process exited with status {self.process.exitcode}{context}"
                )
            try:
                self.connection.close()
            except (Exception, KeyboardInterrupt) as error:
                failures.append(f"server control close: {_failure_detail(error)}")
                if isinstance(error, KeyboardInterrupt) and interrupt is None:
                    interrupt = error
            if not unreaped:
                try:
                    self.process.close()
                except (Exception, KeyboardInterrupt) as error:
                    failures.append(f"server process close: {_failure_detail(error)}")
                    if isinstance(error, KeyboardInterrupt) and interrupt is None:
                        interrupt = error

        if interrupts:
            if interrupt is None:
                interrupt = interrupts[0]
            failures.append(f"server shutdown: {_failure_detail(interrupts[0])}")
        if interrupt is not None:
            # Preserve the interrupt while exposing any accompanying cleanup errors.
            interrupt.shutdown_failures = failures
            interrupt.unreaped = unreaped
            raise interrupt
        if failures:
            raise _ServerFailure(failures, unreaped=unreaped)


def _valid_failures(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


@contextlib.contextmanager
def _start_signals():
    """Delay SIGINT until native acquisition has installed its owned handle."""
    interrupts = []
    if threading.current_thread() is not threading.main_thread():
        yield interrupts
        return

    previous = signal.getsignal(signal.SIGINT)
    if not callable(previous):
        yield interrupts
        return

    def interrupted(signum, frame):
        if not interrupts:
            interrupts.append((previous, signum, frame))

    signal.signal(signal.SIGINT, interrupted)
    try:
        yield interrupts
    finally:
        signal.signal(signal.SIGINT, previous)


@contextlib.contextmanager
def _shutdown_signals():
    """Defer further SIGINT until acquired owners have been shut down."""
    interrupts = []
    if threading.current_thread() is not threading.main_thread():
        yield interrupts
        return

    def interrupted(signum, frame):
        if not interrupts:
            interrupts.append(KeyboardInterrupt("interrupted during shutdown"))

    previous = signal.signal(signal.SIGINT, interrupted)
    try:
        yield interrupts
    finally:
        signal.signal(signal.SIGINT, previous)


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
    """Runs cases and reaps the server before removing its temporary files.

    Summary case counts describe observations only. Infrastructure errors
    appear in infrastructure_failures and make run_failed true.
    """

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
    temporary_root = None
    summary = CaseSummary({}, ())
    primary = None
    infrastructure_failures = []
    retain_temporary = False
    operation = "temporary server files"
    try:
        temporary_root = Path(
            tempfile.mkdtemp(prefix="phantom-wpt-eventsource-")
        ).resolve()
        temporary_root.relative_to(Path(tempfile.gettempdir()).resolve())
        source = temporary_root / "wpt"
        operation = "WPT checkout"
        _checkout_wpt(source)
        _verify_case_sources(source, case_ids)
        operation = "server certificate"
        certificate = generate_loopback_certificate(temporary_root)
        operation = "server startup"
        server = _ServerOwner(source, certificate, run_directory / "server.log")
        server.start()
        server.wait_ready()
        command = [
            "cargo",
            "run",
            "--quiet",
            "--locked",
            "-p",
            "phantom-http",
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
        operation = "adapter run"
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
        operation = "adapter results"
        summary = parse_adapter_output(adapter.stdout, case_ids)
        if (adapter.returncode == 0) != (not summary.failures):
            raise RuntimeError("adapter exit status disagreed with its case summary")
    except (Exception, KeyboardInterrupt) as error:
        primary = error
        if isinstance(error, _ServerFailure):
            infrastructure_failures.extend(error.failures)
        else:
            infrastructure_failures.append(f"{operation}: {_failure_detail(error)}")
        infrastructure_failures.extend(getattr(error, "shutdown_failures", []))
        retain_temporary = getattr(error, "unreaped", False)
    finally:
        with _shutdown_signals() as interrupts:
            if server is not None:
                try:
                    server.stop()
                except (Exception, KeyboardInterrupt) as error:
                    repeated_status = (
                        isinstance(primary, _ServerFailure)
                        and isinstance(error, _ServerFailure)
                        and primary.failures == error.failures
                    )
                    if primary is None or (
                        isinstance(error, KeyboardInterrupt)
                        and not isinstance(primary, KeyboardInterrupt)
                    ):
                        primary = error
                    failures = getattr(
                        error,
                        "shutdown_failures",
                        getattr(
                            error,
                            "failures",
                            [f"server cleanup: {_failure_detail(error)}"],
                        ),
                    )
                    # A startup failure and stop can observe the same final child status.
                    if not repeated_status:
                        infrastructure_failures.extend(failures)
                    retain_temporary = getattr(error, "unreaped", False)
            if temporary_root is not None:
                if retain_temporary:
                    infrastructure_failures.append(
                        f"server files retained at {temporary_root}"
                    )
                else:
                    try:
                        temporary_root.relative_to(
                            Path(tempfile.gettempdir()).resolve()
                        )
                        shutil.rmtree(temporary_root)
                    except (Exception, KeyboardInterrupt) as error:
                        if primary is None or (
                            isinstance(error, KeyboardInterrupt)
                            and not isinstance(primary, KeyboardInterrupt)
                        ):
                            primary = error
                        infrastructure_failures.append(
                            f"temporary server files: {_failure_detail(error)}"
                        )
            if not retain_temporary:
                try:
                    (run_directory / "server.log.1").unlink(missing_ok=True)
                except (Exception, KeyboardInterrupt) as error:
                    if primary is None or (
                        isinstance(error, KeyboardInterrupt)
                        and not isinstance(primary, KeyboardInterrupt)
                    ):
                        primary = error
                    infrastructure_failures.append(
                        f"rotated server log: {_failure_detail(error)}"
                    )
        if interrupts:
            infrastructure_failures.append(
                f"run cleanup: {_failure_detail(interrupts[0])}"
            )
            if not isinstance(primary, KeyboardInterrupt):
                primary = interrupts[0]

    document = summary.as_json()
    document["infrastructure_failures"] = infrastructure_failures
    document["run_failed"] = bool(summary.failures or infrastructure_failures)
    publication_interrupted = False
    with _shutdown_signals() as interrupts:
        try:
            summary_path = run_directory / "summary.json"
            summary_path.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            if interrupts:
                publication_interrupted = True
                infrastructure_failures.append(
                    f"summary publication: {_failure_detail(interrupts[0])}"
                )
                if not isinstance(primary, KeyboardInterrupt):
                    primary = interrupts[0]
                document["run_failed"] = True
                summary_path.write_text(
                    json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
        except (Exception, KeyboardInterrupt) as error:
            infrastructure_failures.append(
                f"summary publication: {_failure_detail(error)}"
            )
            if primary is None or (
                isinstance(error, KeyboardInterrupt)
                and not isinstance(primary, KeyboardInterrupt)
            ):
                primary = error
            if interrupts and not publication_interrupted:
                infrastructure_failures.append(
                    f"summary publication: {_failure_detail(interrupts[0])}"
                )
                if not isinstance(primary, KeyboardInterrupt):
                    primary = interrupts[0]

    if isinstance(primary, KeyboardInterrupt):
        primary.shutdown_failures = infrastructure_failures
        raise primary
    if document["run_failed"] or primary is not None:
        failures = []
        if summary.failures:
            failures.append("WPT EventSource scenarios reported failures")
        failures.extend(infrastructure_failures)
        raise _ServerFailure(failures) from primary

    print(f"WPT EventSource {mode}: {len(summary.cases)} cases, 0 failures")
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
    except KeyboardInterrupt as error:
        for failure in getattr(error, "shutdown_failures", []):
            print(f"failure: {failure}", file=sys.stderr)
        raise
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f"retained report: {directory}")


if __name__ == "__main__":
    main()
