"""Run a manifest of desktop browser captures in parallel, unattended.

A manifest lists capture tools, browsers, scenarios, and repeat counts. The
runner expands it into jobs, one tool invocation per (tool, browser,
scenario), and runs them as subprocesses of this interpreter. Each tool still
writes its own fixture, so fixture bytes are what the tool alone would write.

Every job gets its own temporary directory, which becomes the process's
TEMP, so its browser profiles and certificate files never share a path with
another job. A job whose tool needs machine-wide state runs alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .browser_launch import FIREFOX_START_LIMIT_SECONDS, LAUNCH_LOCK_DIRECTORY
from .fixture_file import write_atomically
from .process_container import ProcessContainer, popen_options, stop_processes_naming

# Shared by every runner on the host, so launches take turns across runners
# too. Each job's TEMP points elsewhere, so the path is fixed here.
LOCK_DIRECTORY = Path(tempfile.gettempdir()) / "phantom-capture-locks"
DESKTOP_CHROMIUM = ("chrome", "edge", "brave", "opera")
DESKTOP_BROWSERS = (*DESKTOP_CHROMIUM, "firefox")
# A run the tool gave up on is written into the fixture rather than failing
# the tool; no retained fixture holds one.
TIMED_OUT_RUN = re.compile(r"^run_\d+_timed_out=true$", re.MULTILINE)
# Arguments the runner derives from the manifest; a capture's `args` cannot
# repeat them.
RUNNER_ARGUMENTS = frozenset(
    (
        "--browser",
        "--browser-path",
        "--client-version",
        "--operating-system",
        "--repeat",
        "--scenario",
        "--layer",
        "--output",
        "--output-dir",
        "--netlog-dir",
    )
)


class ManifestError(ValueError):
    """The manifest cannot be expanded into jobs."""


@dataclass(frozen=True)
class Tool:
    """How the runner drives one capture tool's command line.

    `outputs` returns the file names a job writes into its output directory,
    given the scenario, repeat count, and the capture's extra arguments.
    """

    name: str
    module: str
    browsers: tuple[str, ...]
    outputs: Callable[[str | None, int, Sequence[str]], tuple[str, ...]]
    # The flag that selects a scenario, or None for a tool without scenarios.
    scenario_flag: str | None = "--scenario"
    # Scenario names; None reads `SCENARIOS` from the module for "all".
    scenarios: tuple[str, ...] | None = None
    # "dir" passes --output-dir; "file" passes --output with the single output.
    output_flag: str = "dir"
    takes_repeat: bool = True
    # A job writes Chromium NetLogs to its own directory.
    netlog_dir: bool = False
    # Budget for one run, used for the job timeout and to order long jobs first.
    run_seconds: float = 30.0
    # Machine-wide state the tool uses; such a tool always runs alone.
    global_state: str | None = None
    # Why load would skew the tool's evidence; such a tool runs alone unless a
    # capture sets `"exclusive": false`.
    timing: str | None = None


def scenario_file(pattern: str) -> Callable[[str | None, int, Sequence[str]], tuple]:
    return lambda scenario, _repeat, _args: (pattern.format(scenario=scenario),)


def quic_resumption_outputs(
    scenario: str | None, _repeat: int, args: Sequence[str]
) -> tuple[str, ...]:
    prefix = option_value(args, "--fixture-prefix") or "resumption"
    return (f"{prefix}-{scenario}.txt",)


def startup_outputs(
    layer: str | None, repeat: int, _args: Sequence[str]
) -> tuple[str, ...]:
    names = {
        "tls": ("client-hello",),
        "http2": ("client-startup",),
        "http3": ("client-startup", "quic-client-hello"),
    }[layer or ""]
    return tuple(f"{name}-{run}.txt" for run in range(1, repeat + 1) for name in names)


def ech_outputs(
    scenario: str | None, _repeat: int, args: Sequence[str]
) -> tuple[str, ...]:
    quic = "quic-" if "--quic" in args else ""
    return (f"ech-{quic}{scenario}.txt",)


TOOLS = {
    tool.name: tool
    for tool in (
        Tool(
            "client_hints",
            "scripts.capture.client_hints",
            DESKTOP_BROWSERS,
            lambda _scenario, _repeat, _args: ("navigation.txt",),
            scenario_flag=None,
            output_flag="file",
            run_seconds=5,
        ),
        Tool(
            "tls_resumption",
            "scripts.capture.tls_resumption",
            DESKTOP_BROWSERS,
            scenario_file("resumption-{scenario}.txt"),
            run_seconds=8,
            timing="its fixtures keep connection counts, ticket order, and "
            "which requests arrive in early data",
        ),
        Tool(
            "quic_resumption",
            "scripts.capture.quic_resumption",
            DESKTOP_BROWSERS,
            quic_resumption_outputs,
            run_seconds=8,
            timing="its fixtures keep connection counts and which requests "
            "travel in 0-RTT",
        ),
        Tool(
            "cookie_crumbs",
            "scripts.capture.cookie_crumbs",
            DESKTOP_BROWSERS,
            scenario_file("crumbs-{scenario}.txt"),
            run_seconds=5,
            timing="its fixtures keep connections and the order of QPACK "
            "encoder-stream inserts",
        ),
        Tool(
            "http2_websocket",
            "scripts.capture.http2_websocket",
            DESKTOP_BROWSERS,
            scenario_file("{scenario}.txt"),
            run_seconds=8,
            timing="its fixtures keep retries, connection counts, and frame order",
        ),
        Tool(
            "proxy_route",
            "scripts.capture.proxy_route",
            DESKTOP_BROWSERS,
            scenario_file("{scenario}.txt"),
            run_seconds=8,
            timing="its fixtures keep connection and tunnel counts, and browsers "
            "retry failed tunnels",
        ),
        Tool(
            "sse_reconnect",
            "scripts.capture.sse_reconnect",
            DESKTOP_BROWSERS,
            scenario_file("{scenario}.txt"),
            run_seconds=120,
            timing="its fixtures keep reconnect delays",
        ),
        Tool(
            "alt_svc_race",
            "scripts.capture.alt_svc_race",
            ("chrome", "edge"),
            scenario_file("{scenario}.txt"),
            netlog_dir=True,
            run_seconds=60,
            global_state="it binds UDP and TCP ports drawn from the fixed range "
            "20000-39999, and its fixtures keep race delays",
        ),
        Tool(
            "startup_capture",
            "scripts.capture.startup_capture",
            DESKTOP_CHROMIUM,
            startup_outputs,
            scenario_flag="--layer",
            scenarios=("tls", "http2", "http3"),
            run_seconds=60,
        ),
        Tool(
            "chrome_ech",
            "scripts.capture.chrome_ech",
            DESKTOP_CHROMIUM,
            ech_outputs,
            scenarios=("accept", "reject"),
            output_flag="file",
            takes_repeat=False,
            run_seconds=60,
            global_state="its origin listens on the fixed port 127.0.0.1:443, "
            "and --dns-from-policy needs a machine-wide Edge policy",
        ),
    )
}


def option_value(args: Sequence[str], name: str) -> str | None:
    for index, argument in enumerate(args):
        if argument == name and index + 1 < len(args):
            return args[index + 1]
        if argument.startswith(name + "="):
            return argument.split("=", 1)[1]
    return None


def tool_scenarios(tool: Tool) -> tuple[str, ...]:
    if tool.scenarios is not None:
        return tool.scenarios
    import importlib

    return tuple(importlib.import_module(tool.module).SCENARIOS)


@dataclass(frozen=True)
class Browser:
    name: str
    path: str
    version: str


@dataclass(frozen=True)
class Job:
    """One tool invocation that writes one or more fixture files."""

    id: str
    tool: Tool
    browser: Browser
    scenario: str | None
    repeat: int
    output_dir: Path
    outputs: tuple[Path, ...]
    arguments: tuple[str, ...]
    exclusive: bool
    timeout: float

    @property
    def estimate(self) -> float:
        return self.tool.run_seconds * self.repeat

    def command(self, python: str, netlog_dir: Path | None = None) -> list[str]:
        arguments = [
            python,
            "-m",
            self.tool.module,
            "--browser",
            self.browser.name,
            "--browser-path",
            self.browser.path,
            "--client-version",
            self.browser.version,
        ]
        arguments += self.arguments
        if self.tool.takes_repeat:
            arguments += ["--repeat", str(self.repeat)]
        if self.tool.scenario_flag is not None:
            arguments += [self.tool.scenario_flag, str(self.scenario)]
        if self.tool.output_flag == "file":
            arguments += ["--output", str(self.outputs[0])]
        else:
            arguments += ["--output-dir", str(self.output_dir)]
        if netlog_dir is not None:
            arguments += ["--netlog-dir", str(netlog_dir)]
        return arguments


def expand_manifest(
    manifest: Mapping[str, object],
    *,
    base: Path,
    tools: Mapping[str, Tool] = TOOLS,
) -> list[Job]:
    """Expand a parsed manifest into jobs, rejecting anything ambiguous."""
    if not isinstance(manifest, Mapping):
        raise ManifestError("the manifest must be a JSON object")
    unknown = set(manifest) - {"operating_system", "repeat", "browsers", "captures"}
    if unknown:
        raise ManifestError(f"unknown manifest keys: {', '.join(sorted(unknown))}")
    operating_system = manifest.get("operating_system")
    if not isinstance(operating_system, str) or not operating_system:
        raise ManifestError("operating_system must be a non-empty string")
    default_repeat = positive(manifest.get("repeat", 3), "repeat")
    browsers = parse_browsers(manifest.get("browsers"))
    captures = manifest.get("captures")
    if not isinstance(captures, list) or not captures:
        raise ManifestError("captures must be a non-empty list")
    jobs: list[Job] = []
    for index, capture in enumerate(captures):
        jobs.extend(
            expand_capture(
                capture,
                index,
                browsers=browsers,
                operating_system=operating_system,
                default_repeat=default_repeat,
                base=base,
                tools=tools,
            )
        )
    ids: set[str] = set()
    seen: dict[Path, str] = {}
    for job in jobs:
        if job.id in ids:
            raise ManifestError(f"job {job.id} appears twice")
        ids.add(job.id)
        for output in job.outputs:
            key = Path(os.path.normcase(output.resolve()))
            if key in seen:
                raise ManifestError(
                    f"jobs {seen[key]} and {job.id} both write {output}"
                )
            seen[key] = job.id
    return jobs


def positive(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ManifestError(f"{name} must be a positive integer")
    return value


def parse_browsers(value: object) -> dict[str, Browser]:
    if not isinstance(value, Mapping) or not value:
        raise ManifestError("browsers must be a non-empty object")
    browsers = {}
    for name, entry in value.items():
        if name not in DESKTOP_BROWSERS:
            raise ManifestError(
                f"browser {name!r} is not one of {', '.join(DESKTOP_BROWSERS)}"
            )
        if not isinstance(entry, Mapping) or set(entry) != {"path", "version"}:
            raise ManifestError(f"browser {name} needs exactly path and version")
        path, version = entry["path"], entry["version"]
        if not isinstance(path, str) or not isinstance(version, str) or not version:
            raise ManifestError(f"browser {name} path and version must be strings")
        browsers[name] = Browser(name, os.path.expandvars(path), version)
    return browsers


CAPTURE_KEYS = frozenset(
    (
        "tool",
        "browsers",
        "scenarios",
        "repeat",
        "output_dir",
        "args",
        "exclusive",
        "timeout",
    )
)


def expand_capture(
    capture: object,
    index: int,
    *,
    browsers: Mapping[str, Browser],
    operating_system: str,
    default_repeat: int,
    base: Path,
    tools: Mapping[str, Tool],
) -> list[Job]:
    where = f"captures[{index}]"
    if not isinstance(capture, Mapping):
        raise ManifestError(f"{where} must be an object")
    unknown = set(capture) - CAPTURE_KEYS
    if unknown:
        raise ManifestError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
    tool = tools.get(capture.get("tool"))  # type: ignore[arg-type]
    if tool is None:
        raise ManifestError(f"{where}.tool must be one of {', '.join(sorted(tools))}")
    names = capture.get("browsers")
    if not isinstance(names, list) or not names:
        raise ManifestError(f"{where}.browsers must be a non-empty list")
    for name in names:
        if name not in browsers:
            raise ManifestError(f"{where} names undeclared browser {name!r}")
        if name not in tool.browsers:
            raise ManifestError(f"{tool.name} does not support {name}")
    scenarios = capture_scenarios(tool, capture.get("scenarios"), where)
    repeat = positive(capture.get("repeat", default_repeat), f"{where}.repeat")
    if not tool.takes_repeat and repeat != 1:
        raise ManifestError(f"{tool.name} writes one run per job; set repeat to 1")
    template = capture.get("output_dir")
    if not isinstance(template, str) or not template:
        raise ManifestError(f"{where}.output_dir must be a non-empty string")
    extra = capture.get("args", [])
    if not isinstance(extra, list) or not all(isinstance(item, str) for item in extra):
        raise ManifestError(f"{where}.args must be a list of strings")
    for argument in extra:
        if argument.split("=", 1)[0] in RUNNER_ARGUMENTS:
            raise ManifestError(f"{where}.args cannot set {argument.split('=')[0]}")
    exclusive = capture.get(
        "exclusive", tool.global_state is not None or tool.timing is not None
    )
    if not isinstance(exclusive, bool):
        raise ManifestError(f"{where}.exclusive must be true or false")
    if tool.global_state is not None and not exclusive:
        raise ManifestError(f"{tool.name} must run alone: {tool.global_state}")
    timeout = capture.get("timeout")
    if timeout is None:
        timeout = tool.run_seconds * repeat * 2 + 60
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ManifestError(f"{where}.timeout must be a positive number of seconds")
    arguments = ("--operating-system", operating_system, *extra)
    jobs = []
    for name in names:
        browser = browsers[name]
        for scenario in scenarios:
            fields = {
                "tool": tool.name,
                "browser": browser.name,
                "version": browser.version,
                "scenario": scenario or "",
            }
            try:
                output_dir = base / template.format(**fields)
            except (KeyError, IndexError) as error:
                raise ManifestError(
                    f"{where}.output_dir: unknown field {error}"
                ) from None
            outputs = tuple(
                output_dir / output for output in tool.outputs(scenario, repeat, extra)
            )
            job_id = "/".join(
                part for part in (tool.name, browser.name, scenario) if part
            )
            if option_value(extra, "--fixture-prefix"):
                job_id += "/" + str(option_value(extra, "--fixture-prefix"))
            jobs.append(
                Job(
                    id=job_id,
                    tool=tool,
                    browser=browser,
                    scenario=scenario,
                    repeat=repeat,
                    output_dir=output_dir,
                    outputs=outputs,
                    arguments=arguments,
                    exclusive=exclusive,
                    timeout=float(timeout),
                )
            )
    return jobs


def capture_scenarios(tool: Tool, value: object, where: str) -> tuple[str | None, ...]:
    if tool.scenario_flag is None:
        if value is not None:
            raise ManifestError(f"{tool.name} has no scenarios")
        return (None,)
    known = tool_scenarios(tool)
    if value == "all":
        return known
    if not isinstance(value, list) or not value:
        raise ManifestError(f'{where}.scenarios must be a non-empty list or "all"')
    unknown = [name for name in value if name not in known]
    if unknown:
        raise ManifestError(
            f"{tool.name} has no scenario {', '.join(map(str, unknown))}"
        )
    if len(set(value)) != len(value):
        raise ManifestError(f"{where}.scenarios repeats a scenario")
    return tuple(value)


# -- Completion ---------------------------------------------------------------


def output_problem(job: Job, *, since: float | None = None) -> str | None:
    """Why the job's outputs are not a complete capture, or None if they are.

    `since` rejects a file older than the attempt, so a failed attempt never
    passes on an earlier run's fixture.
    """
    for output in job.outputs:
        try:
            status = output.stat()
        except FileNotFoundError:
            return f"missing {output}"
        if since is not None and status.st_mtime < since:
            return f"not rewritten: {output}"
        data = output.read_bytes()
        if not data.endswith(b"\n"):
            return f"incomplete: {output}"
        if TIMED_OUT_RUN.search(data.decode("ascii", errors="replace")):
            return f"a run timed out: {output}"
    return None


def job_parameters(job: Job) -> dict[str, object]:
    """Everything the manifest decides about what a job's fixtures contain."""
    return {
        "tool": job.tool.name,
        "module": job.tool.module,
        "browser": job.browser.name,
        "browser_path": job.browser.path,
        "client_version": job.browser.version,
        "scenario": job.scenario,
        "repeat": job.repeat,
        "arguments": list(job.arguments),
        "outputs": [str(output) for output in job.outputs],
    }


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CompletionRecords:
    """The jobs a work directory saw pass, with their parameters and outputs.

    A job is skipped only when its record matches its parameters and every
    output still has the recorded digest. The record is removed before a job
    runs and written only when an attempt passes, so a fixture from a failed
    attempt, from other parameters, or written by hand never counts.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def path(self, job: Job) -> Path:
        return self.directory / f"{slug(job.id)}.json"

    def mismatch(self, job: Job) -> str | None:
        """Why `job` must run, or None when its record still holds."""
        try:
            record = json.loads(self.path(job).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "no completion record"
        if not isinstance(record, dict):
            return "no completion record"
        if record.get("parameters") != job_parameters(job):
            return "parameters differ from the completion record"
        digests = record.get("outputs")
        if not isinstance(digests, dict):
            return "no completion record"
        for output in job.outputs:
            try:
                digest = file_digest(output)
            except OSError:
                return f"missing {output}"
            if digests.get(str(output)) != digest:
                return f"changed after the completion record: {output}"
        return None

    def forget(self, job: Job) -> None:
        self.path(job).unlink(missing_ok=True)

    def remember(self, job: Job, *, shared_host: bool, concurrency: int) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {
            "job": job.id,
            "parameters": job_parameters(job),
            "shared_host": shared_host,
            "concurrency": concurrency,
            "outputs": {str(output): file_digest(output) for output in job.outputs},
        }
        write_atomically(
            self.path(job), json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )


# -- Execution ----------------------------------------------------------------


@dataclass
class Attempt:
    ok: bool
    seconds: float
    detail: str = ""
    log: str = ""


@dataclass
class JobResult:
    job: Job
    # "ok", "failed", "skipped", "stopped" (interrupted while it ran), or
    # "not-run" (interrupted before it started).
    status: str
    attempts: list[Attempt] = field(default_factory=list)
    # Whether other jobs could run beside it.
    shared_host: bool = False

    @property
    def seconds(self) -> float:
        return sum(attempt.seconds for attempt in self.attempts)


def slug(job_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", job_id)


def end_attempt(container: ProcessContainer, temporary: Path) -> None:
    container.close()
    # A browser outside the container still names the attempt's directory.
    stop_processes_naming(temporary)


class Attempts:
    """The attempts running now, so a stop can end every one of them."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running: dict[str, tuple[ProcessContainer, Path]] = {}
        self.stopped = threading.Event()

    def add(self, name: str, container: ProcessContainer, temporary: Path) -> bool:
        """Track an attempt; False once a stop has begun."""
        with self.lock:
            if self.stopped.is_set():
                return False
            self.running[name] = (container, temporary)
            return True

    def remove(self, name: str) -> None:
        with self.lock:
            self.running.pop(name, None)

    def stop(self) -> None:
        """Start no more attempts and end every running attempt's processes."""
        with self.lock:
            self.stopped.set()
            running = list(self.running.values())
        for container, temporary in running:
            end_attempt(container, temporary)


def attempt_timeout(job: Job, *, shared_host: bool, limit: int) -> float:
    """The job's timeout, plus the longest its Firefox launches can wait.

    Each launch that takes turns can wait for every other running job's
    launch and then its own, each up to the Firefox start limit.
    """
    if not shared_host or job.browser.name != "firefox":
        return job.timeout
    return job.timeout + job.repeat * limit * FIREFOX_START_LIMIT_SECONDS


def run_attempt(
    job: Job,
    attempt: int,
    work_dir: Path,
    *,
    shared_host: bool,
    limit: int,
    attempts: Attempts,
) -> Attempt:
    """Run one attempt of `job` as a subprocess and check its outputs."""
    name = f"{slug(job.id)}.{attempt}"
    temporary = work_dir / "tmp" / name
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True)
    log = work_dir / "logs" / f"{name}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    netlog = None
    if job.tool.netlog_dir:
        netlog = work_dir / "netlog" / name
        netlog.mkdir(parents=True, exist_ok=True)
    job.output_dir.mkdir(parents=True, exist_ok=True)
    environment = {
        **os.environ,
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "TMPDIR": str(temporary),
    }
    # Launches take turns only while other jobs can launch at the same time.
    environment.pop(LAUNCH_LOCK_DIRECTORY, None)
    if shared_host:
        environment[LAUNCH_LOCK_DIRECTORY] = str(LOCK_DIRECTORY)
    timeout = attempt_timeout(job, shared_host=shared_host, limit=limit)
    started = time.time()
    begin = time.perf_counter()
    detail = ""
    with log.open("wb") as output:
        process = subprocess.Popen(
            job.command(sys.executable, netlog),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=environment,
            **popen_options(),
        )
        container = ProcessContainer(process)
        if not attempts.add(name, container, temporary):
            end_attempt(container, temporary)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            code = None
            detail = f"timed out after {timeout:g}s"
        finally:
            attempts.remove(name)
            end_attempt(container, temporary)
    seconds = time.perf_counter() - begin
    shutil.rmtree(temporary, ignore_errors=True)
    if not container.contained:
        with log.open("ab") as output:
            output.write(b"run_matrix: Windows refused the job object\n")
    if code != 0 and attempts.stopped.is_set():
        detail = "stopped"
    elif code is not None and code != 0:
        detail = f"exit status {code}"
    if not detail:
        detail = output_problem(job, since=started) or ""
    return Attempt(ok=not detail, seconds=seconds, detail=detail, log=str(log))


def run_with_retry(
    job: Job,
    attempt: Callable[[Job, int], Attempt],
    retries: int,
    stopped: threading.Event | None = None,
) -> JobResult:
    stopped = stopped or threading.Event()
    result = JobResult(job, "failed")
    for number in range(1, retries + 2):
        if stopped.is_set():
            result.status = "stopped" if result.attempts else "not-run"
            break
        outcome = attempt(job, number)
        result.attempts.append(outcome)
        if outcome.ok:
            result.status = "ok"
            break
        if stopped.is_set():
            result.status = "stopped"
            break
    return result


def order_jobs(jobs: Iterable[Job]) -> list[Job]:
    """Shared jobs, longest first, then exclusive jobs in manifest order."""
    jobs = list(jobs)
    shared = sorted(
        (job for job in jobs if not job.exclusive), key=lambda j: -j.estimate
    )
    return [*shared, *(job for job in jobs if job.exclusive)]


def schedule(
    jobs: Sequence[Job],
    run: Callable[[Job], JobResult],
    *,
    limit: int,
    report: Callable[[JobResult], None] = lambda _result: None,
    stopped: threading.Event | None = None,
    on_interrupt: Callable[[], None] = lambda: None,
) -> list[JobResult]:
    """Run `jobs` in order, at most `limit` at once, each exclusive job alone.

    Jobs start in the given order: a job waits for a free slot, and an
    exclusive job also waits until nothing else runs and holds every slot.
    Once `stopped` is set no job starts; Ctrl+C calls `on_interrupt`, which
    should set it and end the running attempts. Jobs that never started are
    reported as "not-run".
    """
    if limit < 1:
        raise ValueError("the concurrency limit must be positive")
    stopped = stopped or threading.Event()
    condition = threading.Condition()
    running = 0
    exclusive_running = False
    results: dict[int, JobResult] = {}
    threads: list[threading.Thread] = []

    def worker(index: int, job: Job) -> None:
        nonlocal running, exclusive_running
        try:
            result = run(job)
        except Exception as error:  # noqa: BLE001 - reported as a failed job
            result = JobResult(job, "failed", [Attempt(False, 0.0, repr(error))])
        with condition:
            results[index] = result
            running -= 1
            if job.exclusive:
                exclusive_running = False
            report(result)
            condition.notify_all()

    def dispatch() -> None:
        nonlocal running, exclusive_running
        for index, job in enumerate(jobs):
            with condition:
                # Short waits keep Ctrl+C deliverable on Windows.
                while not stopped.is_set() and (
                    exclusive_running
                    or running >= limit
                    or (job.exclusive and running > 0)
                ):
                    condition.wait(0.2)
                if stopped.is_set():
                    return
                running += 1
                exclusive_running = job.exclusive
            thread = threading.Thread(target=worker, args=(index, job), daemon=True)
            # Listed first, so a Ctrl+C right after the start still joins it.
            threads.append(thread)
            thread.start()

    def join() -> None:
        # Dispatch has ended, so a thread not started yet never will be; its
        # job is reported as not run.
        for thread in threads:
            while thread.ident is not None and thread.is_alive():
                thread.join(0.2)

    try:
        dispatch()
        join()
    except KeyboardInterrupt:
        on_interrupt()
        join()
    return [
        results.get(index, JobResult(job, "not-run")) for index, job in enumerate(jobs)
    ]


# -- Reporting ----------------------------------------------------------------

STATUSES = ("ok", "failed", "skipped", "stopped", "not-run")


def summary_table(results: Sequence[JobResult], wall: float) -> str:
    width = max([len("job"), *(len(result.job.id) for result in results)])
    lines = [f"{'job':<{width}}  {'status':<7}  attempts  seconds  detail"]
    for result in results:
        last = result.attempts[-1].detail if result.attempts else ""
        lines.append(
            f"{result.job.id:<{width}}  {result.status:<7}  "
            f"{len(result.attempts):>8}  {result.seconds:>7.1f}  {last}"
        )
    counts = ", ".join(
        f"{sum(result.status == status for result in results)} {status}"
        for status in STATUSES
    )
    retried = sum(len(result.attempts) > 1 for result in results)
    job_seconds = sum(result.seconds for result in results)
    lines.append(
        f"{counts}, {retried} retried; job time {job_seconds:.1f}s, "
        f"wall clock {wall:.1f}s"
    )
    return "\n".join(lines)


def results_document(
    results: Sequence[JobResult],
    *,
    manifest: Path,
    limit: int,
    wall: float,
    interrupted: bool = False,
) -> dict[str, object]:
    return {
        "manifest": str(manifest),
        "concurrency": limit,
        "interrupted": interrupted,
        "wall_seconds": round(wall, 3),
        "jobs": [
            {
                "id": result.job.id,
                "tool": result.job.tool.name,
                "browser": result.job.browser.name,
                "browser_version": result.job.browser.version,
                "scenario": result.job.scenario,
                "repeat": result.job.repeat,
                "exclusive": result.job.exclusive,
                "shared_host": result.shared_host,
                "status": result.status,
                "seconds": round(result.seconds, 3),
                "outputs": [str(output) for output in result.job.outputs],
                "attempts": [
                    {
                        "ok": attempt.ok,
                        "seconds": round(attempt.seconds, 3),
                        "detail": attempt.detail,
                        "log": attempt.log,
                    }
                    for attempt in result.attempts
                ],
            }
            for result in results
        ],
    }


def default_concurrency() -> int:
    # On the 32-thread capture host, 8 jobs at once made each job about 25%
    # slower and 16 about 70%; README.md has the measurements.
    return max(1, min(8, (os.cpu_count() or 4) // 4))


def run_manifest(
    jobs: Sequence[Job],
    *,
    work_dir: Path,
    limit: int,
    retries: int,
    force: bool,
    attempt: Callable[[Job, int], Attempt] | None = None,
    attempts: Attempts | None = None,
    log: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
) -> tuple[list[JobResult], float]:
    """Skip jobs whose records hold unless `force`, run the rest, and time it.

    `attempts.stop()`, or Ctrl+C, ends the running attempts and starts no more;
    the results then hold "stopped" and "not-run" jobs.
    """
    attempts = attempts or Attempts()
    records = CompletionRecords(work_dir / "completed")

    def shared(job: Job) -> bool:
        return limit > 1 and not job.exclusive

    attempt = attempt or (
        lambda job, number: run_attempt(
            job,
            number,
            work_dir,
            shared_host=shared(job),
            limit=limit,
            attempts=attempts,
        )
    )
    begin = time.perf_counter()
    skipped = []
    pending = []
    for job in jobs:
        if not force and records.mismatch(job) is None:
            skipped.append(JobResult(job, "skipped"))
        else:
            pending.append(job)
    done = 0

    def report(result: JobResult) -> None:
        nonlocal done
        done += 1
        detail = result.attempts[-1].detail if result.attempts else ""
        retried = " after a retry" if len(result.attempts) > 1 else ""
        log(
            f"[{done}/{len(pending)}] {result.status}{retried} {result.job.id} "
            f"{result.seconds:.1f}s {detail}".rstrip()
        )

    def run_job(job: Job) -> JobResult:
        records.forget(job)
        result = run_with_retry(job, attempt, retries, attempts.stopped)
        result.shared_host = shared(job)
        if result.status == "ok":
            records.remember(job, shared_host=result.shared_host, concurrency=limit)
        return result

    ran = schedule(
        order_jobs(pending),
        run_job,
        limit=limit,
        report=report,
        stopped=attempts.stopped,
        on_interrupt=attempts.stop,
    )
    wall = time.perf_counter() - begin
    by_id = {result.job.id: result for result in [*skipped, *ran]}
    return [by_id[job.id] for job in jobs], wall


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--jobs", type=int, default=default_concurrency(), help="concurrency limit"
    )
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument(
        "--force", action="store_true", help="rerun jobs whose outputs are complete"
    )
    parser.add_argument(
        "--only", action="append", default=[], help="run job ids with this prefix"
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument(
        "--dry-run", action="store_true", help="print each job's command and exit"
    )
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        jobs = expand_manifest(manifest, base=Path.cwd())
    except (OSError, json.JSONDecodeError, ManifestError) as error:
        parser.error(f"{args.manifest}: {error}")
    if args.only:
        jobs = [job for job in jobs if any(job.id.startswith(p) for p in args.only)]
    if args.dry_run:
        for job in order_jobs(jobs):
            mode = "exclusive" if job.exclusive else "shared"
            netlog = (
                Path("<work-dir>") / "netlog" / slug(job.id)
                if job.tool.netlog_dir
                else None
            )
            print(f"{job.id} ({mode}): {shlex.join(job.command('python', netlog))}")
        return 0
    work_dir = args.work_dir or Path(tempfile.gettempdir()) / (
        "phantom-run-matrix-" + args.manifest.stem
    )
    work_dir = work_dir.resolve()
    if "'" in str(work_dir):
        # Stopping a hung attempt names this path in a PowerShell string.
        parser.error("the work directory path cannot contain a single quote")
    print(
        f"{len(jobs)} jobs, concurrency {args.jobs}, work directory {work_dir}",
        file=sys.stderr,
        flush=True,
    )
    attempts = Attempts()
    results, wall = run_manifest(
        jobs,
        work_dir=work_dir,
        limit=args.jobs,
        retries=args.retries,
        force=args.force,
        attempts=attempts,
    )
    interrupted = attempts.stopped.is_set()
    print(summary_table(results, wall))
    results_path = args.results or work_dir / "results.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    write_atomically(
        results_path,
        json.dumps(
            results_document(
                results,
                manifest=args.manifest,
                limit=args.jobs,
                wall=wall,
                interrupted=interrupted,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"results: {results_path}", file=sys.stderr)
    if interrupted:
        return 130
    return 0 if all(result.status != "failed" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
