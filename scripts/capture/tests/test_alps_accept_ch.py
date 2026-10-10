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
            netlog_lines(data),
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

    def assert_origin_omitted(self, origin: str) -> None:
        for observed in (
            event(1, (1, 9), origin=origin, accept_ch="Sec-CH-UA-Arch"),
            event(2, (2, 20), url=f"{origin}/probe"),
        ):
            with self.subTest(event=observed["type"]):
                self.assertEqual(
                    netlog_lines({"constants": CONSTANTS, "events": [observed]}),
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
            }
        )


class ObservedStderr:
    def __init__(self, stream) -> None:
        self.stream = stream
        self.read_started = threading.Event()

    def readline(self, *args):
        self.read_started.set()
        return self.stream.readline(*args)

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration

        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class ControlledStdout:
    def __init__(self, stream, action: str) -> None:
        self.stream = stream
        self.action = action
        self.read_completed = threading.Event()
        self.failure_raised = threading.Event()
        self.release = threading.Event()
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


class CaptureControl:
    def __init__(self, server, netlog: Path, stdout_action: str) -> None:
        self.server = server
        self.stderr = ObservedStderr(server.stderr)
        self.stdout = ControlledStdout(server.stdout, stdout_action)
        server.stderr = self.stderr
        server.stdout = self.stdout
        self.done = threading.Event()
        self.browser_entered = threading.Event()
        self.threads = []
        self.thread_errors = []
        self.result = None
        self.error = None
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
                return self

            def __exit__(self, *_details):
                return False

        return Browser()

    def observe_thread_error(self, args) -> None:
        self.thread_errors.append(args.exc_value)

    def new_thread(self, *args, **kwargs):
        thread = REAL_THREAD(*args, **kwargs)
        self.threads.append(thread)
        return thread


@contextmanager
def capture_control(*, listen: bool, stdout_action: str = "normal"):
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
                server, Path(directory) / "netlog.json", stdout_action
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

        self.assertEqual(control.thread_errors, [])
        self.assertTrue(control.browser_entered.is_set())
        self.assertTrue(
            not finished_before_release or published_before_release is None,
            "capture published while its actual stdout reader was still held",
        )

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


if __name__ == "__main__":
    unittest.main()
