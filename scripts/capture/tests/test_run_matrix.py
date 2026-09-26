import _thread
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.capture.browser_launch import FIREFOX_START_LIMIT_SECONDS
from scripts.capture.run_matrix import (
    LOCK_DIRECTORY,
    TOOLS,
    Attempt,
    Attempts,
    Browser,
    CompletionRecords,
    Job,
    JobResult,
    ManifestError,
    Tool,
    attempt_timeout,
    expand_manifest,
    main,
    order_jobs,
    output_problem,
    results_document,
    run_manifest,
    run_with_retry,
    scenario_file,
    schedule,
    summary_table,
)

FAKE = Tool(
    "fake",
    "scripts.capture.tests.fake_capture_tool",
    ("chrome", "firefox"),
    scenario_file("resumption-{scenario}.txt"),
    run_seconds=1,
)
# Writes the same file names as FAKE, so two captures can collide.
FAKE_COPY = Tool(
    "fake-copy",
    FAKE.module,
    FAKE.browsers,
    FAKE.outputs,
    scenarios=("ok",),
)
FAKE_TOOLS = {**TOOLS, "fake": FAKE, "fake-copy": FAKE_COPY}
BROWSERS = {
    "chrome": {"path": "C:/chrome.exe", "version": "154.0.8037.58"},
    "firefox": {"path": "C:/firefox.exe", "version": "156.0"},
}


def manifest(*captures, **top):
    return {
        "operating_system": "Test OS",
        "browsers": BROWSERS,
        "captures": list(captures),
        **top,
    }


def fake_capture(**fields):
    return {
        "tool": "fake",
        "browsers": ["chrome"],
        "scenarios": ["ok"],
        "output_dir": "out/{browser}/{version}",
        **fields,
    }


class ManifestTests(unittest.TestCase):
    def test_each_browser_and_scenario_becomes_one_job(self) -> None:
        jobs = expand_manifest(
            manifest(
                {
                    "tool": "tls_resumption",
                    "browsers": ["chrome", "firefox"],
                    "scenarios": ["sequential", "methods"],
                    "repeat": 5,
                    "output_dir": "fixtures/tls/{browser}/{version}/windows",
                }
            ),
            base=Path("/repo"),
        )

        self.assertEqual(
            [job.id for job in jobs],
            [
                "tls_resumption/chrome/sequential",
                "tls_resumption/chrome/methods",
                "tls_resumption/firefox/sequential",
                "tls_resumption/firefox/methods",
            ],
        )
        first = jobs[0]
        self.assertEqual(
            first.outputs,
            (
                Path(
                    "/repo/fixtures/tls/chrome/154.0.8037.58/windows/"
                    "resumption-sequential.txt"
                ),
            ),
        )
        self.assertEqual(
            first.command("python"),
            [
                "python",
                "-m",
                "scripts.capture.tls_resumption",
                "--browser",
                "chrome",
                "--browser-path",
                "C:/chrome.exe",
                "--client-version",
                "154.0.8037.58",
                "--operating-system",
                "Test OS",
                "--repeat",
                "5",
                "--scenario",
                "sequential",
                "--output-dir",
                str(Path("/repo/fixtures/tls/chrome/154.0.8037.58/windows")),
            ],
        )
        # Its evidence includes connection counts, so it runs alone.
        self.assertTrue(first.exclusive)

    def test_manifest_repeat_is_the_default_for_captures(self) -> None:
        jobs = expand_manifest(
            manifest(
                fake_capture(), fake_capture(scenarios=["slow"], repeat=2), repeat=4
            ),
            base=Path("/repo"),
            tools=FAKE_TOOLS,
        )

        self.assertEqual([job.repeat for job in jobs], [4, 2])

    def test_single_file_tool_gets_output_and_no_scenario(self) -> None:
        (job,) = expand_manifest(
            manifest(
                {
                    "tool": "client_hints",
                    "browsers": ["firefox"],
                    "output_dir": "fixtures/client-hints/{browser}/{version}/w",
                }
            ),
            base=Path("/repo"),
        )

        command = job.command("python")
        self.assertEqual(job.id, "client_hints/firefox")
        self.assertNotIn("--scenario", command)
        self.assertEqual(
            command[-2:],
            [
                "--output",
                str(Path("/repo/fixtures/client-hints/firefox/156.0/w/navigation.txt")),
            ],
        )

    def test_startup_layers_name_every_run_file(self) -> None:
        (job,) = expand_manifest(
            manifest(
                {
                    "tool": "startup_capture",
                    "browsers": ["chrome"],
                    "scenarios": ["http3"],
                    "repeat": 2,
                    "output_dir": "out",
                }
            ),
            base=Path("/repo"),
        )

        self.assertEqual(
            [path.name for path in job.outputs],
            [
                "client-startup-1.txt",
                "quic-client-hello-1.txt",
                "client-startup-2.txt",
                "quic-client-hello-2.txt",
            ],
        )
        self.assertIn("--layer", job.command("python"))

    def test_quic_resumption_prefix_names_the_fixture(self) -> None:
        (job,) = expand_manifest(
            manifest(
                {
                    "tool": "quic_resumption",
                    "browsers": ["chrome"],
                    "scenarios": ["accept"],
                    "args": ["--fixture-prefix", "resumption-streams"],
                    "output_dir": "out",
                }
            ),
            base=Path("/repo"),
        )

        self.assertEqual(job.outputs[0].name, "resumption-streams-accept.txt")

    def test_all_scenarios_come_from_the_tool(self) -> None:
        jobs = expand_manifest(
            manifest(fake_capture(scenarios="all")),
            base=Path("/repo"),
            tools=FAKE_TOOLS,
        )

        self.assertEqual(
            [job.scenario for job in jobs],
            ["ok", "slow", "fail-once", "fail", "hang", "timed-out"],
        )

    def test_browser_paths_expand_environment_variables(self) -> None:
        os.environ["PHANTOM_TEST_BROWSER_ROOT"] = "C:/Browsers"
        browsers = {
            "chrome": {"path": "$PHANTOM_TEST_BROWSER_ROOT/c.exe", "version": "1"}
        }
        (job,) = expand_manifest(
            manifest(fake_capture(), browsers=browsers),
            base=Path("/repo"),
            tools=FAKE_TOOLS,
        )

        self.assertEqual(job.browser.path, "C:/Browsers/c.exe")

    def test_timing_tools_run_alone_unless_the_capture_says_otherwise(self) -> None:
        capture = {
            "tool": "sse_reconnect",
            "browsers": ["chrome"],
            "scenarios": ["reconnect-204"],
            "output_dir": "out/{scenario}",
        }
        (alone,) = expand_manifest(manifest(capture), base=Path("/repo"))
        (shared,) = expand_manifest(
            manifest({**capture, "exclusive": False}), base=Path("/repo")
        )

        self.assertTrue(alone.exclusive)
        self.assertFalse(shared.exclusive)

    def test_tools_whose_evidence_depends_on_timing_run_alone(self) -> None:
        def exclusive(tool: str, scenario: str | None, **fields) -> bool:
            capture = {"tool": tool, "browsers": ["chrome"], "output_dir": "out"}
            if scenario is not None:
                capture["scenarios"] = [scenario]
            (item,) = expand_manifest(
                manifest({**capture, **fields}), base=Path("/repo")
            )
            return item.exclusive

        for tool, scenario in (
            ("tls_resumption", "sequential"),
            ("quic_resumption", "accept"),
            ("cookie_crumbs", "h2"),
            ("proxy_route", "direct-loopback"),
            ("http2_websocket", "accept"),
            ("sse_reconnect", "reconnect-204"),
        ):
            with self.subTest(tool):
                self.assertTrue(exclusive(tool, scenario))
                self.assertFalse(exclusive(tool, scenario, exclusive=False))
        self.assertFalse(exclusive("client_hints", None))
        self.assertFalse(exclusive("startup_capture", "http3"))

    def test_alt_svc_race_always_runs_alone(self) -> None:
        capture = {
            "tool": "alt_svc_race",
            "browsers": ["chrome"],
            "scenarios": ["udp-blackhole"],
            "output_dir": "out",
        }
        (item,) = expand_manifest(manifest(capture), base=Path("/repo"))

        self.assertTrue(item.exclusive)
        with self.assertRaisesRegex(ManifestError, "20000-39999"):
            expand_manifest(
                manifest({**capture, "exclusive": False}), base=Path("/repo")
            )

    def test_machine_wide_tools_always_run_alone(self) -> None:
        capture = {
            "tool": "chrome_ech",
            "browsers": ["chrome"],
            "scenarios": ["accept"],
            "repeat": 1,
            "args": ["--capture-binary", "ech.exe"],
            "output_dir": "out",
        }
        (job,) = expand_manifest(manifest(capture), base=Path("/repo"))

        self.assertTrue(job.exclusive)
        self.assertNotIn("--repeat", job.command("python"))
        with self.assertRaisesRegex(ManifestError, "must run alone"):
            expand_manifest(
                manifest({**capture, "exclusive": False}), base=Path("/repo")
            )

    def test_invalid_manifests_are_refused(self) -> None:
        cases = {
            "unknown manifest keys": manifest(fake_capture(), extra=1),
            "operating_system": {**manifest(fake_capture()), "operating_system": ""},
            "tool must be one of": manifest(fake_capture(tool="nope")),
            "undeclared browser": manifest(fake_capture(browsers=["edge"])),
            "does not support": manifest(
                {
                    "tool": "alt_svc_race",
                    "browsers": ["firefox"],
                    "scenarios": ["udp-blackhole"],
                    "output_dir": "out",
                }
            ),
            "no scenario": manifest(fake_capture(scenarios=["missing"])),
            "repeats a scenario": manifest(fake_capture(scenarios=["ok", "ok"])),
            "cannot set --repeat": manifest(fake_capture(args=["--repeat", "2"])),
            "cannot set --output-dir": manifest(fake_capture(args=["--output-dir=x"])),
            "repeat must be a positive": manifest(fake_capture(repeat=0)),
            "unknown keys": manifest(fake_capture(output="x")),
            "unknown field": manifest(fake_capture(output_dir="out/{os}")),
            "appears twice": manifest(fake_capture(), fake_capture(output_dir="x")),
            "both write": manifest(fake_capture(), fake_capture(tool="fake-copy")),
            "has no scenarios": manifest(
                {
                    "tool": "client_hints",
                    "browsers": ["chrome"],
                    "scenarios": ["x"],
                    "output_dir": "out",
                }
            ),
            "writes one run per job": manifest(
                {
                    "tool": "chrome_ech",
                    "browsers": ["chrome"],
                    "scenarios": ["accept"],
                    "output_dir": "out",
                }
            ),
            "is not one of": {
                **manifest(fake_capture()),
                "browsers": {"safari": {"path": "s", "version": "1"}},
            },
        }
        for message, document in cases.items():
            with self.subTest(message), self.assertRaisesRegex(ManifestError, message):
                expand_manifest(document, base=Path("/repo"), tools=FAKE_TOOLS)


def job(name: str, *, exclusive: bool = False, estimate: int = 1) -> Job:
    return Job(
        id=name,
        tool=FAKE,
        browser=Browser("chrome", "chrome.exe", "1"),
        scenario=name,
        repeat=estimate,
        output_dir=Path("out"),
        outputs=(Path("out") / f"{name}.txt",),
        arguments=(),
        exclusive=exclusive,
        timeout=30,
    )


class ConcurrencyProbe:
    """Record how many fake jobs run at once, and which ran beside which."""

    def __init__(self, seconds: float = 0.05) -> None:
        self.seconds = seconds
        self.lock = threading.Lock()
        self.running: set[str] = set()
        self.peak = 0
        self.overlaps: dict[str, set[str]] = {}
        self.started: list[str] = []

    def run(self, item: Job) -> JobResult:
        with self.lock:
            self.started.append(item.id)
            for other in self.running:
                self.overlaps.setdefault(item.id, set()).add(other)
                self.overlaps.setdefault(other, set()).add(item.id)
            self.running.add(item.id)
            self.peak = max(self.peak, len(self.running))
        time.sleep(self.seconds)
        with self.lock:
            self.running.discard(item.id)
        return JobResult(item, "ok", [Attempt(True, self.seconds)])


class ScheduleTests(unittest.TestCase):
    def test_no_more_than_the_limit_run_at_once(self) -> None:
        probe = ConcurrencyProbe()
        jobs = [job(f"j{index}") for index in range(10)]

        results = schedule(jobs, probe.run, limit=3)

        self.assertEqual(probe.peak, 3)
        self.assertEqual([result.job.id for result in results], [j.id for j in jobs])

    def test_exclusive_jobs_run_alone(self) -> None:
        probe = ConcurrencyProbe()
        jobs = [
            job("a"),
            job("b"),
            job("alone-1", exclusive=True),
            job("c"),
            job("alone-2", exclusive=True),
            job("d"),
        ]

        schedule(jobs, probe.run, limit=4)

        self.assertNotIn("alone-1", probe.overlaps)
        self.assertNotIn("alone-2", probe.overlaps)
        self.assertEqual(probe.overlaps["a"], {"b"})

    def test_a_raising_job_is_reported_as_failed(self) -> None:
        def run(item: Job) -> JobResult:
            raise RuntimeError("boom")

        (result,) = schedule([job("x")], run, limit=2)

        self.assertEqual(result.status, "failed")
        self.assertIn("boom", result.attempts[0].detail)

    def test_ctrl_c_stops_the_batch_and_reports_unstarted_jobs(self) -> None:
        stopped = threading.Event()
        started = threading.Event()
        interrupted = []

        def run(item: Job) -> JobResult:
            started.set()
            stopped.wait(30)
            return JobResult(item, "stopped", [Attempt(False, 0.1, "stopped")])

        def interrupt() -> None:
            interrupted.append(True)
            stopped.set()

        def press_ctrl_c() -> None:
            started.wait(30)
            _thread.interrupt_main()

        threading.Thread(target=press_ctrl_c, daemon=True).start()
        results = schedule(
            [job("running"), job("waiting")],
            run,
            limit=1,
            stopped=stopped,
            on_interrupt=interrupt,
        )

        self.assertEqual(interrupted, [True])
        self.assertEqual([r.status for r in results], ["stopped", "not-run"])

    def test_long_shared_jobs_start_first_and_exclusive_jobs_last(self) -> None:
        jobs = [
            job("short", estimate=1),
            job("alone", exclusive=True, estimate=50),
            job("long", estimate=9),
        ]

        self.assertEqual([j.id for j in order_jobs(jobs)], ["long", "short", "alone"])


class RetryTests(unittest.TestCase):
    def test_a_failed_attempt_is_retried_once(self) -> None:
        outcomes = iter([Attempt(False, 1.0, "exit status 1"), Attempt(True, 2.0)])

        result = run_with_retry(job("x"), lambda _job, _n: next(outcomes), retries=1)

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(result.seconds, 3.0)

    def test_a_job_failing_every_attempt_fails(self) -> None:
        numbers = []

        def attempt(_job: Job, number: int) -> Attempt:
            numbers.append(number)
            return Attempt(False, 0.5, "exit status 1")

        result = run_with_retry(job("x"), attempt, retries=1)

        self.assertEqual(result.status, "failed")
        self.assertEqual(numbers, [1, 2])

    def test_a_passing_job_is_not_retried(self) -> None:
        result = run_with_retry(job("x"), lambda _j, _n: Attempt(True, 1.0), retries=3)

        self.assertEqual(len(result.attempts), 1)


class ResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def jobs(self, *captures):
        return expand_manifest(manifest(*captures), base=self.root, tools=FAKE_TOOLS)

    def test_output_problems_name_the_reason(self) -> None:
        (item,) = self.jobs(fake_capture())
        path = item.outputs[0]

        self.assertRegex(output_problem(item), "missing")
        path.parent.mkdir(parents=True)
        path.write_bytes(b"format=fake")
        self.assertRegex(output_problem(item), "incomplete")
        path.write_bytes(b"format=fake\nrun_0_timed_out=false\nrun_1_timed_out=true\n")
        self.assertRegex(output_problem(item), "timed out")
        path.write_bytes(b"format=fake\nrun_0_timed_out=false\n")
        self.assertIsNone(output_problem(item))
        self.assertRegex(output_problem(item, since=time.time() + 60), "not rewritten")

    def complete(self, item: Job, text: bytes = b"format=fake\n") -> None:
        item.outputs[0].parent.mkdir(parents=True, exist_ok=True)
        item.outputs[0].write_bytes(text)
        CompletionRecords(self.root / "work" / "completed").remember(
            item, shared_host=True, concurrency=2
        )

    def resume(self, *items: Job, force: bool = False):
        ran = []

        def attempt(item: Job, _number: int) -> Attempt:
            ran.append(item.id)
            item.outputs[0].parent.mkdir(parents=True, exist_ok=True)
            item.outputs[0].write_bytes(b"format=fake\n")
            return Attempt(True, 0.1)

        results, _wall = run_manifest(
            list(items),
            work_dir=self.root / "work",
            limit=2,
            retries=1,
            force=force,
            attempt=attempt,
            log=lambda _line: None,
        )
        return ran, [result.status for result in results]

    def test_recorded_jobs_are_skipped_and_the_rest_run(self) -> None:
        done, pending = self.jobs(fake_capture(scenarios=["ok", "slow"]))
        self.complete(done)

        ran, statuses = self.resume(done, pending)

        self.assertEqual(ran, [pending.id])
        self.assertEqual(statuses, ["skipped", "ok"])

    def test_a_passing_job_is_recorded_for_the_next_run(self) -> None:
        (item,) = self.jobs(fake_capture())

        self.assertEqual(self.resume(item), ([item.id], ["ok"]))
        self.assertEqual(self.resume(item), ([], ["skipped"]))

    def test_a_fixture_without_a_record_runs_again(self) -> None:
        # Written by hand, or by an attempt that failed.
        (item,) = self.jobs(fake_capture())
        item.outputs[0].parent.mkdir(parents=True)
        item.outputs[0].write_bytes(b"format=fake\n")

        self.assertEqual(self.resume(item), ([item.id], ["ok"]))

    def test_changed_parameters_run_the_job_again(self) -> None:
        other = {"chrome": {"path": "C:/other.exe", "version": "154.0.8037.58"}}
        changes = {
            "client version": {
                "browsers": {"chrome": {**BROWSERS["chrome"], "version": "155.0"}}
            },
            "operating system": {"operating_system": "Other OS"},
            "run count": {"repeat": 5},
            "browser path": {"browsers": other},
        }
        for change, top in changes.items():
            with self.subTest(change):
                (recorded,) = self.jobs(fake_capture(output_dir="out/fixed"))
                self.complete(recorded)
                (changed,) = expand_manifest(
                    {**manifest(fake_capture(output_dir="out/fixed")), **top},
                    base=self.root,
                    tools=FAKE_TOOLS,
                )

                self.assertEqual(self.resume(changed), ([changed.id], ["ok"]))

    def test_changed_arguments_run_the_job_again(self) -> None:
        (recorded,) = self.jobs(fake_capture())
        self.complete(recorded)
        (changed,) = self.jobs(fake_capture(args=["--sleep", "0"]))

        self.assertEqual(self.resume(changed), ([changed.id], ["ok"]))

    def test_an_edited_or_missing_fixture_runs_again(self) -> None:
        (item,) = self.jobs(fake_capture())
        self.complete(item)
        item.outputs[0].write_bytes(b"format=edited\n")
        self.assertRegex(
            CompletionRecords(self.root / "work" / "completed").mismatch(item),
            "changed after",
        )
        self.assertEqual(self.resume(item), ([item.id], ["ok"]))

        item.outputs[0].unlink()
        self.assertEqual(self.resume(item), ([item.id], ["ok"]))

    def test_a_failed_attempt_removes_the_record(self) -> None:
        (item,) = self.jobs(fake_capture())
        self.complete(item)
        records = CompletionRecords(self.root / "work" / "completed")

        run_manifest(
            [item],
            work_dir=self.root / "work",
            limit=1,
            retries=0,
            force=True,
            attempt=lambda _job, _n: Attempt(False, 0.1, "exit status 1"),
            log=lambda _line: None,
        )

        self.assertEqual(records.mismatch(item), "no completion record")

    def test_force_reruns_recorded_jobs(self) -> None:
        (item,) = self.jobs(fake_capture())
        self.complete(item)

        self.assertEqual(self.resume(item, force=True), ([item.id], ["ok"]))


def process_alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0) != 0
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_for_file(path: Path, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"{path} never appeared")
        time.sleep(0.05)


class SubprocessTests(unittest.TestCase):
    """Drive the fake tool through real subprocesses, as a capture would run."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_jobs(self, *captures, limit=2, retries=1):
        jobs = expand_manifest(manifest(*captures), base=self.root, tools=FAKE_TOOLS)
        return run_manifest(
            jobs,
            work_dir=self.root / "work",
            limit=limit,
            retries=retries,
            force=False,
            log=lambda _line: None,
        )

    def test_the_tool_writes_the_fixture_in_its_own_temporary_directory(self) -> None:
        (result,), _wall = self.run_jobs(fake_capture(repeat=2))

        self.assertEqual(result.status, "ok")
        self.assertEqual(
            result.job.outputs[0].read_bytes(),
            b"format=fake\nclient_version=154.0.8037.58\noperating_system=Test OS\n"
            b"run_0_timed_out=false\nrun_1_timed_out=false\n",
        )
        log = Path(result.attempts[0].log).read_text()
        temporary = self.root / "work" / "tmp" / "fake-chrome-ok.1"
        self.assertIn(f"temp={temporary}", log)
        self.assertIn(f"lock_dir={LOCK_DIRECTORY}", log)
        self.assertFalse(temporary.exists())

    def test_launches_take_turns_only_beside_other_jobs(self) -> None:
        def lock_dir(*captures, limit):
            results, _wall = self.run_jobs(*captures, limit=limit)
            text = Path(results[0].attempts[0].log).read_text()
            return text.split("lock_dir=", 1)[1].splitlines()[0]

        self.assertEqual(lock_dir(fake_capture(), limit=1), "")
        self.assertEqual(
            lock_dir(fake_capture(scenarios=["slow"], exclusive=True), limit=4), ""
        )

    def test_a_failed_attempt_is_retried_and_reported(self) -> None:
        (result,), _wall = self.run_jobs(fake_capture(scenarios=["fail-once"]))

        self.assertEqual(result.status, "ok")
        self.assertEqual(
            [attempt.detail for attempt in result.attempts], ["exit status 1", ""]
        )

    def test_a_timed_out_run_in_the_fixture_fails_the_job(self) -> None:
        (result,), _wall = self.run_jobs(
            fake_capture(scenarios=["timed-out"]), retries=0
        )

        self.assertEqual(result.status, "failed")
        self.assertRegex(result.attempts[0].detail, "a run timed out")

    def test_a_hung_tool_is_stopped_at_the_job_timeout(self) -> None:
        begin = time.perf_counter()
        (result,), _wall = self.run_jobs(
            fake_capture(scenarios=["hang"], timeout=1), retries=0
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.attempts[0].detail, "timed out after 1s")
        self.assertLess(time.perf_counter() - begin, 60)
        pid = int((result.job.output_dir / "grandchild.pid").read_text())
        self.assertFalse(process_alive(pid))

    def test_a_stop_ends_running_attempts_and_starts_nothing_more(self) -> None:
        jobs = expand_manifest(
            manifest(fake_capture(scenarios=["hang", "ok"])),
            base=self.root,
            tools=FAKE_TOOLS,
        )
        attempts = Attempts()
        outcome = []
        runner = threading.Thread(
            target=lambda: outcome.append(
                run_manifest(
                    jobs,
                    work_dir=self.root / "work",
                    limit=1,
                    retries=1,
                    force=False,
                    attempts=attempts,
                    log=lambda _line: None,
                )
            )
        )
        runner.start()
        pid_file = jobs[0].output_dir / "grandchild.pid"
        wait_for_file(pid_file)
        pid = int(pid_file.read_text())

        attempts.stop()
        runner.join(60)

        self.assertFalse(runner.is_alive())
        (hung, later), _wall = outcome[0]
        self.assertEqual(hung.status, "stopped")
        self.assertEqual([a.detail for a in hung.attempts], ["stopped"])
        self.assertEqual(later.status, "not-run")
        self.assertFalse(process_alive(pid))

    def test_summary_and_results_count_each_outcome(self) -> None:
        results, wall = self.run_jobs(
            fake_capture(scenarios=["ok", "fail", "fail-once"]), limit=3
        )
        table = summary_table(results, wall)
        document = results_document(
            results, manifest=Path("m.json"), limit=3, wall=wall
        )

        self.assertIn(
            "2 ok, 1 failed, 0 skipped, 0 stopped, 0 not-run, 2 retried", table
        )
        self.assertEqual(
            [
                (entry["id"], entry["status"], len(entry["attempts"]))
                for entry in document["jobs"]
            ],
            [
                ("fake/chrome/ok", "ok", 1),
                ("fake/chrome/fail", "failed", 2),
                ("fake/chrome/fail-once", "ok", 2),
            ],
        )


class TimeoutTests(unittest.TestCase):
    def test_shared_firefox_jobs_get_time_to_wait_for_launch_turns(self) -> None:
        chrome, firefox = expand_manifest(
            manifest(
                fake_capture(browsers=["chrome", "firefox"], repeat=3, timeout=100)
            ),
            base=Path("/repo"),
            tools=FAKE_TOOLS,
        )

        self.assertEqual(attempt_timeout(chrome, shared_host=True, limit=8), 100)
        self.assertEqual(attempt_timeout(firefox, shared_host=False, limit=8), 100)
        self.assertEqual(
            attempt_timeout(firefox, shared_host=True, limit=8),
            100 + 3 * 8 * FIREFOX_START_LIMIT_SECONDS,
        )


class DryRunTests(unittest.TestCase):
    def test_a_netlog_tool_prints_a_placeholder_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "m.json"
            path.write_text(
                json.dumps(
                    manifest(
                        {
                            "tool": "alt_svc_race",
                            "browsers": ["chrome"],
                            "scenarios": ["udp-blackhole"],
                            "output_dir": "out",
                        }
                    )
                )
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([str(path), "--dry-run"]), 0)

        self.assertIn(
            "--netlog-dir '<work-dir>/netlog/alt_svc_race-chrome-udp-blackhole'",
            output.getvalue().replace("\\", "/"),
        )


if __name__ == "__main__":
    unittest.main()
