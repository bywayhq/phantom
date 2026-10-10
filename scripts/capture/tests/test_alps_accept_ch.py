import argparse
import json
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.capture import alps_accept_ch
from scripts.capture.alps_accept_ch import field_name, load_netlog, netlog_lines

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/alps-accept-ch.txt"
)
CONSTANTS = {
    "logEventTypes": {
        "HTTP2_SESSION_RECV_ACCEPT_CH": 1,
        "URL_REQUEST_START_JOB": 2,
        "URL_REQUEST_DELEGATE_CONNECTED": 3,
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS": 4,
    },
    "logSourceType": {"HTTP2_SESSION": 1, "URL_REQUEST": 2},
    "logEventPhase": {"PHASE_BEGIN": 1, "PHASE_END": 2, "PHASE_NONE": 0},
}
CONTROL_TIMEOUT = 5
CAPTURE_ORIGIN = "https://server.phantom.test:5"
REAL_THREAD = threading.Thread
CHILD_SOURCE = """
import sys
print('armed', file=sys.stderr, flush=True)
command = sys.stdin.readline().strip()
if command == 'listen':
    print('listening on 127.0.0.1:5', file=sys.stderr, flush=True)
    print('request=/', flush=True)
"""


def event(kind: int, source: tuple[int, int], **params) -> dict:
    return {
        "type": kind,
        "source": {"type": source[0], "id": source[1]},
        "params": params,
    }


class NetLogTests(unittest.TestCase):
    def test_a_restarted_navigation_shows_an_aborted_request_then_a_sent_one(
        self,
    ) -> None:
        url = "https://server.phantom.test:5/"
        data = {
            "constants": CONSTANTS,
            "events": [
                event(
                    1,
                    (1, 9),
                    accept_ch="Sec-CH-UA-Arch",
                    origin="https://server.phantom.test:5",
                ),
                event(
                    1,
                    (1, 10),
                    accept_ch="Sec-CH-UA-Model",
                    origin="https://www.example",
                ),
                event(2, (2, 20), url=url),
                event(3, (2, 20), net_error=-3),
                event(2, (2, 21), url=url),
                event(
                    4,
                    (2, 21),
                    headers=[":method: GET", "accept: */*", 'sec-ch-ua-arch: "x86"'],
                ),
                event(2, (2, 22), url="https://other.test/"),
            ],
        }

        self.assertEqual(
            netlog_lines(data, CAPTURE_ORIGIN),
            [
                'accept_ch_frame="Sec-CH-UA-Arch"',
                "url_request_0=path:/,delegate_connected_error:-3,sent_headers:false,fields:none",
                "url_request_1=path:/,delegate_connected_error:none,sent_headers:true,"
                "fields::method|accept|sec-ch-ua-arch",
            ],
        )

    def test_a_cut_off_netlog_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "netlog.json"
            path.write_text(
                json.dumps({"constants": CONSTANTS, "events": []})[:-2] + ",\n",
                encoding="utf-8",
            )
            self.assertEqual(load_netlog(path)["events"], [])

    def test_field_names_keep_the_pseudo_header_colon(self) -> None:
        self.assertEqual(field_name(":path: /"), ":path")
        self.assertEqual(field_name("accept: */*"), "accept")


class RetainedFixtureTests(unittest.TestCase):
    def test_the_navigation_restarts_once_with_the_hints_after_accept(self) -> None:
        lines = dict(
            line.split("=", 1)
            for line in FIXTURE.read_text(encoding="ascii").splitlines()
        )
        self.assertIn(
            "delegate_connected_error:-3,sent_headers:false",
            lines["netlog_url_request_0"],
        )
        fields = lines["netlog_url_request_1"].split("fields:", 1)[1].split("|")
        accept = fields.index("accept")
        self.assertEqual(
            fields[accept + 1 : accept + 4],
            ["sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-fetch-site"],
        )
        self.assertNotIn("sec-ch-ua-arch", lines["netlog_url_request_2"])


class OriginAttributionTests(unittest.TestCase):
    def test_the_literal_https_target_keeps_its_frame_and_request(self) -> None:
        self.assertEqual(
            self.lines("https://server.phantom.test:5"),
            [
                'accept_ch_frame="Sec-CH-UA-Arch"',
                "url_request_0=path:/probe,delegate_connected_error:none,"
                "sent_headers:false,fields:none",
            ],
        )

    def test_a_lookalike_hostname_is_not_the_capture_origin(self) -> None:
        self.assert_origin_omitted("https://server.phantom.test.other:5")

    def test_a_foreign_path_or_query_does_not_name_the_capture_origin(self) -> None:
        for origin in (
            "https://other.test:5/server.phantom.test",
            "https://other.test:5/?next=server.phantom.test",
        ):
            with self.subTest(origin=origin):
                self.assert_origin_omitted(origin)

    def test_http_is_not_the_https_capture_origin(self) -> None:
        self.assert_origin_omitted("http://server.phantom.test:5")

    def test_a_different_port_is_not_the_capture_origin(self) -> None:
        self.assert_origin_omitted("https://server.phantom.test:6")

    def assert_origin_omitted(self, origin: str) -> None:
        for observed in (
            event(1, (1, 9), origin=origin, accept_ch="Sec-CH-UA-Arch"),
            event(2, (2, 20), url=f"{origin}/probe"),
        ):
            with self.subTest(event=observed["type"]):
                self.assertEqual(
                    netlog_lines(
                        {"constants": CONSTANTS, "events": [observed]}, CAPTURE_ORIGIN
                    ),
                    [],
                )

    @staticmethod
    def lines(origin: str) -> list[str]:
        return netlog_lines(
            {
                "constants": CONSTANTS,
                "events": [
                    event(1, (1, 9), origin=origin, accept_ch="Sec-CH-UA-Arch"),
                    event(2, (2, 20), url=f"{origin}/probe"),
                ],
            },
            CAPTURE_ORIGIN,
        )


class ObservedStderr:
    def __init__(self, stream, action: str) -> None:
        self.stream = stream
        self.action = action
        self.read_started = threading.Event()
        self.listening_seen = threading.Event()
        self.failure_raised = threading.Event()
        self.failure = PermissionError("controlled ALPS stderr read failure")
        self.close_failed = threading.Event()
        self.close_failure = PermissionError("controlled ALPS stderr close failure")

    def readline(self, *args):
        self.read_started.set()
        line = self.stream.readline(*args)
        if self.action == "fail_after_ready" and self.listening_seen.is_set():
            self.failure_raised.set()
            raise self.failure

        if line.startswith("listening on 127.0.0.1:5"):
            self.listening_seen.set()

        return line

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration

        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def close(self):
        if self.action == "close_fail" and not self.close_failed.is_set():
            self.close_failed.set()
            raise self.close_failure

        return self.stream.close()


class ControlledStdout:
    def __init__(self, stream, action: str) -> None:
        self.stream = stream
        self.action = action
        self.read_completed = threading.Event()
        self.failure_raised = threading.Event()
        self.release = threading.Event()
        self.closed_before_release = threading.Event()
        self.text = None
        self.failure = PermissionError("controlled ALPS stdout read failure")

    def read(self, *args):
        self.text = self.stream.read(*args)
        self.read_completed.set()
        if self.action == "fail":
            self.failure_raised.set()
            raise self.failure

        if self.action == "hold" and not self.release.wait(CONTROL_TIMEOUT):
            raise TimeoutError("controlled stdout gate was not released")

        return self.text

    def close(self):
        if self.action == "hold" and not self.release.is_set():
            self.closed_before_release.set()
            raise PermissionError("controlled close while stdout reader is held")

        return self.stream.close()

    def __getattr__(self, name):
        return getattr(self.stream, name)


class CaptureControlCleanupError(RuntimeError):
    def __init__(
        self, failures: list[BaseException], primary: BaseException | None
    ) -> None:
        self.failures = failures
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        super().__init__("ALPS control cleanup failed")


class InterruptedReaderThread:
    def __init__(self, thread, control, mode: str) -> None:
        self.thread = thread
        self.control = control
        self.mode = mode
        self.joins = 0
        self.reported_stopped = False
        self.failure = KeyboardInterrupt("controlled ALPS reader interruption")

    @property
    def ident(self):
        if self.mode == "start_unreported":
            return None

        return self.thread.ident

    def start(self):
        self.thread.start()
        if self.mode == "start_unreported":
            if not self.control.stdout.read_completed.wait(CONTROL_TIMEOUT):
                raise TimeoutError("controlled stdout read was not observed")

            self.reported_stopped = True
            raise self.failure

    def join(self, timeout=None):
        self.joins += 1
        if self.mode == "join_stopped" and self.joins == 1:
            if not self.control.stdout.read_completed.wait(CONTROL_TIMEOUT):
                raise TimeoutError("controlled stdout read was not observed")

            self.reported_stopped = True
            raise self.failure

        if self.mode == "cleanup_interrupt" and self.joins == 2:
            raise self.failure

        return self.thread.join(timeout)

    def is_alive(self):
        return not self.reported_stopped and self.thread.is_alive()


class CaptureControl:
    def __init__(
        self,
        server,
        netlog: Path,
        stdout_action: str,
        stderr_action: str,
        browser_error,
        thread_mode: str,
    ) -> None:
        self.server = server
        self.stderr = ObservedStderr(server.stderr, stderr_action)
        self.stdout = ControlledStdout(server.stdout, stdout_action)
        server.stderr = self.stderr
        server.stdout = self.stdout
        self.done = threading.Event()
        self.browser_entered = threading.Event()
        self.threads = []
        self.thread_errors = []
        self.result = None
        self.error = None
        self.browser_error = browser_error
        self.thread_mode = thread_mode
        self.interrupted_reader = None
        self.netlog = netlog
        self.worker = REAL_THREAD(target=self.run)

    def run(self) -> None:
        try:
            self.result = alps_accept_ch.capture(
                argparse.Namespace(
                    capture_binary=Path("controlled-child"),
                    accept_ch="Sec-CH-UA-Arch",
                    browser="chrome",
                    browser_path=Path("unused-fake-browser"),
                    headful=False,
                    netlog=self.netlog,
                    client_version="controlled",
                    operating_system="controlled",
                )
            )
        except BaseException as error:
            self.error = error
        finally:
            self.done.set()

    def fake_browser(self, _plan, _url):
        # This writes a NetLog for pipe controls; it launches no real browser.
        control = self

        class Browser:
            def __enter__(self):
                control.browser_entered.set()
                control.netlog.write_text(
                    json.dumps({"constants": CONSTANTS, "events": []}),
                    encoding="utf-8",
                )
                if control.browser_error is not None:
                    if not control.stderr.failure_raised.wait(CONTROL_TIMEOUT):
                        raise TimeoutError("controlled stderr failure was not observed")

                    if not control.stdout.read_completed.wait(CONTROL_TIMEOUT):
                        raise TimeoutError(
                            "controlled stdout completion was not observed"
                        )

                    raise control.browser_error

                return self

            def __exit__(self, *_details):
                return False

        return Browser()

    def observe_thread_error(self, args) -> None:
        self.thread_errors.append(args.exc_value)

    def new_thread(self, *args, **kwargs):
        thread = REAL_THREAD(*args, **kwargs)
        self.threads.append(thread)
        if self.thread_mode != "normal" and self.interrupted_reader is None:
            self.interrupted_reader = InterruptedReaderThread(
                thread, self, self.thread_mode
            )
            return self.interrupted_reader

        return thread


@contextmanager
def capture_control(
    *,
    listen: bool,
    stdout_action: str = "normal",
    stderr_action: str = "normal",
    browser_error=None,
    thread_mode: str = "normal",
):
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", CHILD_SOURCE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    threads = []
    primary = None
    control = None
    with ExitStack() as stack:
        try:
            armed = queue.Queue()

            def read_armed():
                try:
                    armed.put(server.stderr.readline())
                except BaseException as error:
                    armed.put(error)

            handshake = REAL_THREAD(target=read_armed)
            threads.append(handshake)
            handshake.start()
            line = armed.get(timeout=CONTROL_TIMEOUT)
            if isinstance(line, BaseException):
                raise line

            if line != "armed\n":
                raise RuntimeError(f"unexpected child startup: {line!r}")

            directory = stack.enter_context(tempfile.TemporaryDirectory())
            control = CaptureControl(
                server,
                Path(directory) / "netlog.json",
                stdout_action,
                stderr_action,
                browser_error,
                thread_mode,
            )
            threads.append(control.worker)
            if listen:
                server.stdin.write("listen\n")
                server.stdin.flush()

            for replacement in (
                patch.object(alps_accept_ch.subprocess, "Popen", return_value=server),
                patch.object(alps_accept_ch, "LaunchedBrowser", control.fake_browser),
                patch.object(alps_accept_ch, "RUN_TIMEOUT_SECONDS", 0.1),
                patch.object(alps_accept_ch, "PIPE_TIMEOUT_SECONDS", 0.1),
                patch.object(alps_accept_ch.threading, "Thread", control.new_thread),
                patch.object(threading, "excepthook", control.observe_thread_error),
            ):
                stack.enter_context(replacement)
            control.worker.start()
            yield control
        except BaseException as error:
            primary = error
            raise
        finally:
            stop_capture_control(server, threads, control, primary)


def stop_capture_control(server, threads, control, primary):
    failures = []
    if control is not None:
        control.stdout.release.set()

    try:
        if server.poll() is None:
            server.kill()
        server.wait(timeout=CONTROL_TIMEOUT)
    except BaseException as error:
        failures.append(error)

    for group in (threads, control.threads if control is not None else ()):
        for thread in group:
            if thread.ident is None:
                continue
            try:
                thread.join(timeout=CONTROL_TIMEOUT)
                if thread.is_alive():
                    failures.append(TimeoutError("ALPS control thread did not stop"))
            except BaseException as error:
                failures.append(error)

    for stream in (server.stdin, server.stdout, server.stderr):
        try:
            stream.close()
        except BaseException as error:
            failures.append(error)

    if failures:
        cleanup = CaptureControlCleanupError(failures, primary)
        if primary is not None:
            raise primary from cleanup
        raise cleanup from failures[0]


class CapturePipeTests(unittest.TestCase):
    def test_silent_startup_finishes_before_the_control_releases_the_child(
        self,
    ) -> None:
        with capture_control(listen=False) as control:
            self.assertTrue(control.stderr.read_started.wait(CONTROL_TIMEOUT))
            finished_before_release = control.done.wait(1)

        self.assertTrue(
            finished_before_release, "capture startup exceeded its own bound"
        )
        self.assertIsNotNone(control.error)
        self.assertFalse(control.browser_entered.is_set())

    def test_a_completed_child_with_complete_stdout_produces_a_fixture(self) -> None:
        with capture_control(listen=True) as control:
            self.assertTrue(control.done.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")

        self.assertIsNone(control.error)
        self.assertEqual(control.thread_errors, [])
        self.assertTrue(control.browser_entered.is_set())
        self.assertIn("server_0=request=/\n", control.result)

    def test_a_live_stdout_reader_cannot_publish_a_partial_fixture(self) -> None:
        with capture_control(listen=True, stdout_action="hold") as control:
            self.assertTrue(control.stdout.read_completed.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")
            finished_before_release = control.done.wait(1)
            published_before_release = control.result
            error_before_release = control.error

        self.assertEqual(control.thread_errors, [])
        self.assertTrue(control.browser_entered.is_set())
        self.assertTrue(
            finished_before_release, "capture did not bound its reader wait"
        )
        self.assertIsNone(published_before_release)
        self.assertIsNotNone(error_before_release)

    def test_a_failed_stdout_reader_retains_its_actual_controlled_error(self) -> None:
        with capture_control(listen=True, stdout_action="fail") as control:
            self.assertTrue(control.stdout.failure_raised.wait(CONTROL_TIMEOUT))
            self.assertTrue(control.done.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")

        self.assertIsNotNone(
            control.error, "capture accepted its actual reader failure"
        )
        error = control.error
        visited = set()
        while (
            error is not None
            and error is not control.stdout.failure
            and id(error) not in visited
        ):
            visited.add(id(error))
            error = error.__cause__ or error.__context__
        self.assertIs(error, control.stdout.failure)

    def test_a_failed_stderr_reader_retains_its_actual_controlled_error(self) -> None:
        with capture_control(listen=True, stderr_action="fail_after_ready") as control:
            self.assertTrue(control.stderr.failure_raised.wait(CONTROL_TIMEOUT))
            self.assertTrue(control.done.wait(CONTROL_TIMEOUT))
            self.assertTrue(control.stderr.listening_seen.is_set())
            self.assertEqual(control.stdout.text, "request=/\n")

        self.assertIs(control.error, control.stderr.failure)
        self.assertIsNone(control.result)

    def test_a_primary_browser_error_retains_the_completed_stderr_failure(self) -> None:
        primary = RuntimeError("controlled browser context failure")
        with capture_control(
            listen=True, stderr_action="fail_after_ready", browser_error=primary
        ) as control:
            self.assertTrue(control.done.wait(CONTROL_TIMEOUT))
            self.assertTrue(control.browser_entered.is_set())
            self.assertTrue(control.stderr.listening_seen.is_set())
            self.assertTrue(control.stderr.failure_raised.is_set())
            self.assertEqual(control.stdout.text, "request=/\n")

        self.assertIs(control.error, primary)
        self.assertIsNone(control.result)
        cleanup = primary.__cause__
        self.assertIsNotNone(cleanup)
        self.assertTrue(
            any(
                error is control.stderr.failure
                for _operation, error in cleanup.failures
            )
        )

    def test_interrupted_join_cannot_close_a_live_reader_pipe(self) -> None:
        with capture_control(
            listen=True, stdout_action="hold", thread_mode="join_stopped"
        ) as control:
            self.assertTrue(control.stdout.read_completed.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")
            self.assertTrue(control.done.wait(1))
            closed_before_release = control.stdout.closed_before_release.is_set()
            error_before_release = control.error
            published_before_release = control.result

        self.assertFalse(closed_before_release, "capture closed a still-used pipe")
        self.assertIs(error_before_release, control.interrupted_reader.failure)
        self.assertIsNone(published_before_release)

    def test_interrupted_start_cannot_close_an_unreported_live_reader_pipe(self) -> None:
        with capture_control(
            listen=True, stdout_action="hold", thread_mode="start_unreported"
        ) as control:
            self.assertTrue(control.stdout.read_completed.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")
            self.assertTrue(control.done.wait(1))
            closed_before_release = control.stdout.closed_before_release.is_set()
            error_before_release = control.error
            published_before_release = control.result

        self.assertFalse(closed_before_release, "capture closed an uncertain reader")
        self.assertIs(error_before_release, control.interrupted_reader.failure)
        self.assertIsNone(published_before_release)

    def test_first_cleanup_interruption_keeps_its_original_identity(self) -> None:
        with capture_control(
            listen=True, stderr_action="close_fail", thread_mode="cleanup_interrupt"
        ) as control:
            self.assertTrue(control.done.wait(CONTROL_TIMEOUT))
            self.assertEqual(control.stdout.text, "request=/\n")

        self.assertIs(control.error, control.interrupted_reader.failure)
        self.assertIsNone(control.result)
        self.assertTrue(control.stderr.close_failed.is_set())
        self.assertTrue(
            any(
                error is control.stderr.close_failure
                for _operation, error in control.error.__cause__.failures
            )
        )


if __name__ == "__main__":
    unittest.main()
