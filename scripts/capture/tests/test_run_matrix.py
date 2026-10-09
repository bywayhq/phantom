import _thread
import contextlib
import io
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import run_matrix
from scripts.capture.browser_launch import FIREFOX_START_LIMIT_SECONDS
from scripts.capture.process_container import ProcessContainer
from scripts.capture.run_matrix import (
    LOCK_DIRECTORY,
    PROFILE_PATH_LIMIT,
    TOOLS,
    Attempt,
    Attempts,
    Browser,
    CompletionRecords,
    Job,
    JobResult,
    ManifestError,
    Tool,
    attempt_directory,
    attempt_timeout,
    expand_manifest,
    longest_profile_path,
    main,
    order_jobs,
    output_problem,
    profile_path_problem,
    results_document,
    run_manifest,
    run_with_retry,
    scenario_file,
    schedule,
    slug,
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

    def test_snapshot_names_one_file_per_run_and_takes_no_scenario(self) -> None:
        (job,) = expand_manifest(
            manifest(
                {
                    "tool": "snapshot",
                    "browsers": ["chrome"],
                    "repeat": 2,
                    "output_dir": "out",
                }
            ),
            base=Path("/repo"),
        )

        self.assertEqual(
            [path.name for path in job.outputs], ["snapshot-1.txt", "snapshot-2.txt"]
        )
        command = job.command("python")
        self.assertNotIn("--scenario", command)
        self.assertEqual(command[command.index("--repeat") + 1], "2")
        self.assertIn("--output-dir", command)
        self.assertFalse(job.exclusive)

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
    """Record how many fake jobs run at once, and which ran beside which.

    Each job waits until `together` jobs have run at once, or 30 seconds pass,
    so an overlap the scheduler allows does not depend on how quickly a busy
    host starts threads.
    """

    def __init__(self, seconds: float = 0.05, together: int = 1) -> None:
        self.seconds = seconds
        self.together = together
        self.lock = threading.Condition()
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
            self.lock.notify_all()
            self.lock.wait_for(lambda: self.peak >= self.together, timeout=30)
        time.sleep(self.seconds)
        with self.lock:
            self.running.discard(item.id)
        return JobResult(item, "ok", [Attempt(True, self.seconds)])


class ScheduleTests(unittest.TestCase):
    def test_no_more_than_the_limit_run_at_once(self) -> None:
        probe = ConcurrencyProbe(together=3)
        jobs = [job(f"j{index}") for index in range(10)]

        results = schedule(jobs, probe.run, limit=3)

        self.assertEqual(probe.peak, 3)
        self.assertEqual([result.job.id for result in results], [j.id for j in jobs])

    def test_exclusive_jobs_run_alone(self) -> None:
        probe = ConcurrencyProbe(together=2)
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


class CleanupFailureTests(unittest.TestCase):
    def test_stop_cleans_every_attempt_after_one_cleanup_failure(self) -> None:
        for operation in ["close", "sweep"]:
            with self.subTest(operation=operation):
                attempts = Attempts()
                first, second = mock.Mock(), mock.Mock()
                attempts.add("first", first, Path("owned-first"))
                attempts.add("second", second, Path("owned-second"))
                if operation == "close":
                    first.close.side_effect = OSError("job close failed")
                sweep_error = OSError("profile discovery failed")
                with (
                    mock.patch.object(
                        run_matrix,
                        "stop_processes_naming",
                        side_effect=[sweep_error, None]
                        if operation == "sweep"
                        else None,
                    ) as sweep,
                    self.assertRaises(Exception) as raised,
                ):
                    attempts.stop()

                self.assertTrue(attempts.stopped.is_set())
                self.assertEqual(first.close.call_count, 1)
                self.assertEqual(second.close.call_count, 1)
                self.assertEqual(
                    [call.args[0] for call in sweep.call_args_list],
                    [Path("owned-first"), Path("owned-second")],
                )
                self.assertIn("first", str(raised.exception))
                self.assertIn(
                    "job close failed"
                    if operation == "close"
                    else "profile discovery failed",
                    str(raised.exception),
                )

    def test_close_and_sweep_failures_both_keep_their_original_causes(self) -> None:
        container = mock.Mock()
        close_error = OSError("job close failed")
        sweep_error = OSError("profile discovery failed")
        container.close.side_effect = close_error
        with (
            mock.patch.object(
                run_matrix, "stop_processes_naming", side_effect=sweep_error
            ) as sweep,
            self.assertRaises(run_matrix.CleanupError) as raised,
        ):
            run_matrix.end_attempt(container, Path("owned"))

        sweep.assert_called_once_with(Path("owned"))
        self.assertIs(raised.exception.__cause__, close_error)
        self.assertEqual(
            [error for _operation, error in raised.exception.failures],
            [close_error, sweep_error],
        )
        self.assertIn(
            "close process container: job close failed", str(raised.exception)
        )
        self.assertIn(
            "sweep profile processes: profile discovery failed", str(raised.exception)
        )

    def test_normal_attempt_cleanup_failure_is_reported_and_invalidates_resume(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (item,) = expand_manifest(
                manifest(fake_capture()), base=root, tools=FAKE_TOOLS
            )
            process = mock.Mock()
            process.wait.return_value = 0
            container = mock.Mock(process=process)
            item.outputs[0].parent.mkdir(parents=True, exist_ok=True)
            item.outputs[0].write_bytes(b"format=fake\n")
            records = CompletionRecords(root / "work" / "completed")
            records.remember(item, shared_host=False, concurrency=1)

            with (
                mock.patch.object(
                    run_matrix, "ProcessContainer", return_value=container
                ),
                mock.patch.object(
                    run_matrix,
                    "stop_processes_naming",
                    side_effect=OSError("profile discovery failed"),
                ),
            ):
                (result,), _wall = run_manifest(
                    [item],
                    work_dir=root / "work",
                    limit=1,
                    retries=0,
                    force=True,
                    log=lambda _line: None,
                )

            container.close.assert_called_once()
            self.assertEqual(result.status, "failed")
            self.assertIn("cleanup", result.attempts[0].detail)
            self.assertIn("profile discovery failed", result.attempts[0].detail)
            self.assertEqual(records.mismatch(item), "no completion record")

    def test_interrupt_cleanup_failure_still_joins_workers_and_returns_results(
        self,
    ) -> None:
        release = threading.Event()
        finished = threading.Event()
        stopped = threading.Event()
        join = threading.Thread.join
        interrupted = False
        joins = []
        owned_threads = []

        def run(item: Job) -> JobResult:
            release.wait(10)
            finished.set()
            return JobResult(item, "stopped", [Attempt(False, 0.1, "stopped")])

        def interrupt_join(thread, *args, **kwargs):
            nonlocal interrupted
            owned_threads.append(thread)
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            joins.append(thread)
            return join(thread, *args, **kwargs)

        def cleanup() -> None:
            stopped.set()
            release.set()
            raise OSError("profile discovery failed")

        try:
            with mock.patch.object(threading.Thread, "join", interrupt_join):
                results = schedule(
                    [job("running")],
                    run,
                    limit=1,
                    stopped=stopped,
                    on_interrupt=cleanup,
                )
        finally:
            release.set()
            for thread in owned_threads:
                join(thread, 10)

        self.assertTrue(finished.is_set())
        self.assertTrue(joins)
        self.assertEqual(results[0].status, "failed")
        self.assertIn("cleanup", results[0].attempts[-1].detail)
        self.assertIn("profile discovery failed", results[0].attempts[-1].detail)

    def test_main_writes_summary_and_results_after_interrupt_cleanup_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_text("{}")
            output_path = root / "results.json"
            release = threading.Event()
            join = threading.Thread.join
            interrupted = False
            joins = []
            owned_threads = []
            attempts = Attempts()
            finished = threading.Event()
            registered = threading.Event()
            container = mock.Mock()
            container.close.side_effect = release.set
            (item,) = expand_manifest(
                manifest(fake_capture()), base=root, tools=FAKE_TOOLS
            )

            def attempt(_job, _number, _work, **kwargs):
                attempts.add(slug(item.id) + ".1", container, root / "owned")
                registered.set()
                release.wait(10)
                finished.set()
                return Attempt(False, 0.1, "stopped")

            def interrupt_join(thread, *args, **kwargs):
                nonlocal interrupted
                owned_threads.append(thread)
                if not interrupted:
                    # The worker registers ownership before this checkpoint.
                    self.assertTrue(registered.wait(10))
                    interrupted = True
                    raise KeyboardInterrupt
                joins.append(thread)
                return join(thread, *args, **kwargs)

            output = io.StringIO()
            try:
                with (
                    mock.patch.object(
                        run_matrix, "expand_manifest", return_value=[item]
                    ),
                    mock.patch.object(run_matrix, "Attempts", return_value=attempts),
                    mock.patch.object(run_matrix, "run_attempt", side_effect=attempt),
                    mock.patch.object(
                        run_matrix,
                        "stop_processes_naming",
                        side_effect=OSError("profile discovery failed"),
                    ),
                    mock.patch.object(threading.Thread, "join", interrupt_join),
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    status = main(
                        [
                            str(manifest_path),
                            "--work-dir",
                            str(root / "work"),
                            "--results",
                            str(output_path),
                        ]
                    )
            finally:
                release.set()
                for thread in owned_threads:
                    join(thread, 10)

            self.assertEqual(status, 130)
            self.assertTrue(finished.is_set())
            self.assertTrue(joins)
            self.assertIn("failed", output.getvalue())
            document = json.loads(output_path.read_text())
            self.assertTrue(document["interrupted"])
            self.assertEqual(document["jobs"][0]["status"], "failed")
            detail = document["jobs"][0]["attempts"][-1]["detail"]
            self.assertIn("cleanup", detail)
            self.assertIn("profile discovery failed", detail)

    def test_named_cleanup_failure_does_not_fail_another_interrupted_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            items = expand_manifest(
                manifest(
                    fake_capture(
                        args=["--fixture-prefix", "foo"], output_dir="out/short"
                    ),
                    fake_capture(
                        args=["--fixture-prefix", "foo.1"], output_dir="out/long"
                    ),
                ),
                base=root,
                tools=FAKE_TOOLS,
            )
            releases = {item.id: threading.Event() for item in items}
            registered = {item.id: threading.Event() for item in items}
            attempts = Attempts()
            join = threading.Thread.join
            interrupted = False
            owned_threads = []

            def attempt(item, _number):
                container = mock.Mock()
                container.close.side_effect = releases[item.id].set
                attempts.add(slug(item.id) + ".1", container, root / slug(item.id))
                registered[item.id].set()
                releases[item.id].wait(10)
                return Attempt(False, 0.2, "stopped")

            def sweep(directory):
                if directory == root / slug(items[1].id):
                    raise OSError("long owner's discovery failed")

            def interrupt_join(thread, *args, **kwargs):
                nonlocal interrupted
                owned_threads.append(thread)
                if not interrupted:
                    for event in registered.values():
                        self.assertTrue(event.wait(10))
                    interrupted = True
                    raise KeyboardInterrupt
                return join(thread, *args, **kwargs)

            try:
                with (
                    mock.patch.object(threading.Thread, "join", interrupt_join),
                    mock.patch.object(
                        run_matrix, "stop_processes_naming", side_effect=sweep
                    ),
                ):
                    results, _wall = run_manifest(
                        items,
                        work_dir=root / "work",
                        limit=2,
                        retries=0,
                        force=False,
                        attempt=attempt,
                        attempts=attempts,
                        log=lambda _line: None,
                    )
            finally:
                for release in releases.values():
                    release.set()
                for thread in owned_threads:
                    join(thread, 10)

            self.assertEqual(
                [result.status for result in results], ["stopped", "failed"]
            )
            self.assertIn(
                "long owner's discovery failed", results[1].attempts[0].detail
            )
            self.assertEqual(results[0].attempts[0].detail, "stopped")
            self.assertEqual([len(result.attempts) for result in results], [1, 1])

    def test_second_interrupt_during_cleanup_still_ends_every_owner(self) -> None:
        releases = [threading.Event(), threading.Event()]
        registered = [threading.Event(), threading.Event()]
        attempts = Attempts()
        items = [job("first"), job("second")]
        containers = [mock.Mock(), mock.Mock()]
        join = threading.Thread.join
        owned_threads = []
        interrupted = False
        repeated = []
        old_handler = signal.signal(signal.SIGINT, signal.default_int_handler)

        def close_first() -> None:
            releases[0].set()
            signal.raise_signal(signal.SIGINT)
            repeated.append(True)

        containers[0].close.side_effect = close_first
        containers[1].close.side_effect = releases[1].set

        def run(item: Job) -> JobResult:
            index = items.index(item)
            attempts.add(slug(item.id) + ".1", containers[index], Path(item.id))
            registered[index].set()
            releases[index].wait(10)
            return JobResult(item, "stopped", [Attempt(False, 0.1, "stopped")])

        def interrupt_join(thread, *args, **kwargs):
            nonlocal interrupted
            owned_threads.append(thread)
            if not interrupted:
                for event in registered:
                    self.assertTrue(event.wait(10))
                interrupted = True
                raise KeyboardInterrupt
            return join(thread, *args, **kwargs)

        try:
            with (
                mock.patch.object(threading.Thread, "join", interrupt_join),
                mock.patch.object(run_matrix, "stop_processes_naming") as sweep,
            ):
                results = schedule(
                    items,
                    run,
                    limit=2,
                    stopped=attempts.stopped,
                    on_interrupt=attempts.stop,
                )
        finally:
            for release in releases:
                release.set()
            for thread in owned_threads:
                join(thread, 10)
            signal.signal(signal.SIGINT, old_handler)

        self.assertEqual(repeated, [True])
        self.assertEqual(
            [container.close.call_count for container in containers], [1, 1]
        )
        self.assertEqual(sweep.call_count, 2)
        self.assertEqual([result.status for result in results], ["stopped", "stopped"])

    def test_second_interrupt_during_join_still_returns_results(self) -> None:
        release, finish, registered = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        stopped = threading.Event()
        join = threading.Thread.join
        owned_threads = []
        join_count = 0
        repeated = []
        old_handler = signal.signal(signal.SIGINT, signal.default_int_handler)

        def run(item: Job) -> JobResult:
            registered.set()
            release.wait(10)
            finish.wait(10)
            return JobResult(item, "stopped", [Attempt(False, 0.1, "stopped")])

        def interrupt_join(thread, *args, **kwargs):
            nonlocal join_count
            owned_threads.append(thread)
            join_count += 1
            if join_count == 1:
                self.assertTrue(registered.wait(10))
                raise KeyboardInterrupt
            if join_count == 2:
                signal.raise_signal(signal.SIGINT)
                repeated.append(True)
                finish.set()
            return join(thread, *args, **kwargs)

        try:
            with mock.patch.object(threading.Thread, "join", interrupt_join):
                results = schedule(
                    [job("running")],
                    run,
                    limit=1,
                    stopped=stopped,
                    on_interrupt=release.set,
                )
                handler_after_schedule = signal.getsignal(signal.SIGINT)
        finally:
            release.set()
            finish.set()
            for thread in owned_threads:
                join(thread, 10)
            signal.signal(signal.SIGINT, old_handler)

        self.assertEqual(repeated, [True])
        self.assertEqual(results[0].status, "stopped")
        self.assertTrue(stopped.is_set())
        self.assertIs(handler_after_schedule, signal.default_int_handler)

    def test_interrupt_cleanup_failure_removes_a_racing_completion_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (item,) = expand_manifest(
                manifest(fake_capture()), base=root, tools=FAKE_TOOLS
            )
            release, registered = threading.Event(), threading.Event()
            attempts = Attempts()
            container = mock.Mock()
            container.close.side_effect = release.set
            join = threading.Thread.join
            interrupted = False
            owned_threads = []

            def attempt(_job, _number):
                attempts.add(slug(item.id) + ".1", container, root / "owned")
                registered.set()
                release.wait(10)
                item.outputs[0].parent.mkdir(parents=True, exist_ok=True)
                item.outputs[0].write_bytes(b"format=fake\n")
                return Attempt(True, 2.0)

            def interrupt_join(thread, *args, **kwargs):
                nonlocal interrupted
                owned_threads.append(thread)
                if not interrupted:
                    self.assertTrue(registered.wait(10))
                    interrupted = True
                    raise KeyboardInterrupt
                return join(thread, *args, **kwargs)

            try:
                with (
                    mock.patch.object(threading.Thread, "join", interrupt_join),
                    mock.patch.object(
                        run_matrix,
                        "stop_processes_naming",
                        side_effect=OSError("profile discovery failed"),
                    ),
                ):
                    (result,), _wall = run_manifest(
                        [item],
                        work_dir=root / "work",
                        limit=1,
                        retries=0,
                        force=False,
                        attempt=attempt,
                        attempts=attempts,
                        log=lambda _line: None,
                    )
            finally:
                release.set()
                for thread in owned_threads:
                    join(thread, 10)

            self.assertEqual(result.status, "failed")
            self.assertEqual(len(result.attempts), 1)
            self.assertEqual(result.seconds, 2.0)
            self.assertFalse(result.attempts[0].ok)
            self.assertIn("profile discovery failed", result.attempts[0].detail)
            records = CompletionRecords(root / "work" / "completed")
            self.assertEqual(records.mismatch(item), "no completion record")


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


def wait_for_file(path: Path, seconds: float = 60) -> None:
    deadline = time.monotonic() + seconds
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"{path} never appeared")
        time.sleep(0.05)


def ended_within(pid: int, seconds: float = 30) -> bool:
    """Whether `pid` ends within `seconds`.

    A kill returns before the process is gone: Windows terminates a job's
    processes asynchronously, and a killed POSIX process lingers until reaped.
    """
    deadline = time.monotonic() + seconds
    while process_alive(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


def container_awaiting(path: Path, seconds: float = 60) -> type[ProcessContainer]:
    """A container that starts the attempt's timeout once `path` exists.

    The tool joins the container first, as in a real attempt. A busy host can
    take longer than a short job timeout to start the fake tool's interpreter
    and its child, and a timeout before then would prove nothing about the
    child. The wait ends early if the tool exits, and never raises, so the
    runner still ends the attempt.
    """

    class Awaiting(ProcessContainer):
        def start(self) -> bool:
            started = super().start()
            if not started:
                return False
            deadline = time.monotonic() + seconds
            while (
                not path.exists()
                and self.process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            return True

    return Awaiting


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
        temporary = self.root / "work" / "tmp" / attempt_directory(result.job.id, 1)
        self.assertIn(f"temp={temporary}", log)
        self.assertIn(f"lock_dir={LOCK_DIRECTORY}", log)
        self.assertFalse(temporary.exists())

    def test_an_attempt_reports_the_job_object_it_got(self) -> None:
        (result,), _wall = self.run_jobs(fake_capture())

        self.assertEqual(result.status, "ok")
        log = Path(result.attempts[0].log).read_text()
        self.assertNotIn("refused the job object", log)

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
        capture = fake_capture(scenarios=["hang"], timeout=1)
        (item,) = expand_manifest(manifest(capture), base=self.root, tools=FAKE_TOOLS)
        pid_file = item.output_dir / "grandchild.pid"
        begin = time.perf_counter()
        with mock.patch(
            "scripts.capture.run_matrix.ProcessContainer", container_awaiting(pid_file)
        ):
            (result,), _wall = self.run_jobs(capture, retries=0)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.attempts[0].detail, "timed out after 1s")
        self.assertLess(time.perf_counter() - begin, 120)
        pid = int(pid_file.read_text())
        self.assertTrue(ended_within(pid), f"grandchild {pid} outlived the timeout")

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
        self.assertTrue(ended_within(pid), f"grandchild {pid} outlived the stop")

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


class WorkDirectoryTests(unittest.TestCase):
    LONGEST_ID = "proxy_route/firefox/https-proxy-auth-remembered-hostname"

    def test_a_quoted_work_directory_is_passed_as_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "m.json"
            path.write_text(
                json.dumps(
                    manifest(
                        {
                            "tool": "snapshot",
                            "browsers": ["chrome"],
                            "output_dir": "out",
                        }
                    )
                )
            )
            work = Path(directory) / "O'Brien work"
            with (
                mock.patch(
                    "scripts.capture.run_matrix.run_manifest", return_value=([], 0.0)
                ) as run,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main([str(path), "--work-dir", str(work)]), 0)
            self.assertEqual(run.call_args.kwargs["work_dir"], work.resolve())

    def test_attempt_directories_are_short_and_distinct(self) -> None:
        names = {
            attempt_directory(job_id, attempt)
            for job_id in (self.LONGEST_ID, "sse_reconnect/firefox/retry-0")
            for attempt in (1, 2)
        }
        self.assertEqual(len(names), 4)
        self.assertTrue(all(len(name) <= 10 for name in names), names)

    def test_profile_paths_leave_room_in_a_deep_work_directory(self) -> None:
        # About as deep as the scratch directory where a Firefox 157 matrix
        # lost two jobs to the limit.
        work_dir = Path("C:/") / ("w" * 120)
        self.assertLessEqual(longest_profile_path(work_dir, 2), PROFILE_PATH_LIMIT)

    def test_jobs_sharing_a_temporary_directory_name_are_refused(self) -> None:
        captures = manifest(fake_capture(scenarios=["ok", "fail"]))
        with (
            mock.patch(
                "scripts.capture.run_matrix.attempt_directory",
                lambda _job_id, attempt: f"00000000.{attempt}",
            ),
            self.assertRaisesRegex(ManifestError, "share the temporary directory"),
        ):
            expand_manifest(captures, base=Path("."), tools=FAKE_TOOLS)

    def test_a_work_directory_too_deep_for_a_browser_profile_is_refused(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "m.json"
            path.write_text(
                json.dumps(
                    manifest(
                        {
                            "tool": "snapshot",
                            "browsers": ["firefox"],
                            "output_dir": "out",
                        }
                    )
                )
            )
            deep = Path(directory) / ("w" * PROFILE_PATH_LIMIT)
            errors = io.StringIO()
            with (
                mock.patch.object(sys, "platform", "win32"),
                contextlib.redirect_stderr(errors),
                self.assertRaises(SystemExit),
            ):
                main([str(path), "--work-dir", str(deep)])

        self.assertIn("work directory path is too long", errors.getvalue())

    def test_only_firefox_jobs_on_windows_hold_the_work_directory_to_the_limit(
        self,
    ) -> None:
        def jobs(browser: str) -> list[Job]:
            capture = fake_capture(browsers=[browser])
            return expand_manifest(manifest(capture), base=Path("."), tools=FAKE_TOOLS)

        deep = Path("C:/") / ("w" * PROFILE_PATH_LIMIT)
        shallow = Path("C:/") / "work"

        self.assertRegex(
            profile_path_problem(jobs("firefox"), deep, 2, "win32") or "",
            "a Firefox profile in it could take",
        )
        self.assertIsNone(profile_path_problem(jobs("firefox"), shallow, 2, "win32"))
        self.assertIsNone(profile_path_problem(jobs("chrome"), deep, 2, "win32"))
        self.assertIsNone(profile_path_problem(jobs("firefox"), deep, 2, "darwin"))


if __name__ == "__main__":
    unittest.main()
