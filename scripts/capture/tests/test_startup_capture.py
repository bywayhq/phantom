import argparse
import errno
import io
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.capture import startup_capture
from scripts.capture.browser_failures import BrowserLaunchFailures
from scripts.capture.process_container import (
    ProcessCleanupError,
    ProcessContainerStopped,
)
from scripts.capture.startup_capture import (
    REMOTE_FLAG,
    START_URL,
    CaptureListener,
    launch_arguments,
    launch_mode,
    main,
    recorded_arguments,
    wait_until_listening,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


def fixture_field(path: str, field: str) -> str:
    prefix = f"{field}="
    for line in (FIXTURES / path).read_text(encoding="ascii").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].rstrip("\r")
    raise AssertionError(f"{path} has no {field}")


def fixture_port(path: str) -> int:
    return int(fixture_field(path, "listen_address").rsplit(":", 1)[1])


class RecordedArgumentTests(unittest.TestCase):
    """The tool records exactly what the retained startup fixtures hold."""

    def assert_reproduces(
        self, path: str, layer: str, *, port: int = 0, platform: str = "win32"
    ) -> None:
        devtools = fixture_field(path, "launch_mode") == "devtools-navigate"
        self.assertEqual(
            recorded_arguments(layer, port=port, devtools=devtools, platform=platform),
            fixture_field(path, "launch_arguments"),
        )

    def test_command_line_tls_and_http2_fixtures(self) -> None:
        for path, layer in (
            ("tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt", "tls"),
            ("tls/brave/154.1.96.59/windows-11-26200/client-hello.txt", "tls"),
            ("tls/opera/136.0.6008.52/windows-11-26200/client-hello.txt", "tls"),
            ("http2/chrome/154.0.8037.58/windows-11-26200/client-startup.txt", "http2"),
            ("http2/brave/154.1.96.59/windows-11-26200/client-startup.txt", "http2"),
        ):
            with self.subTest(path):
                self.assertEqual(fixture_field(path, "launch_mode"), "command-line")
                self.assert_reproduces(path, layer)

    def test_devtools_http2_fixture(self) -> None:
        path = "http2/opera/136.0.6008.52/windows-11-26200/client-startup.txt"
        self.assertEqual(fixture_field(path, "launch_mode"), "devtools-navigate")
        self.assert_reproduces(path, "http2")

    def test_http3_fixtures_in_both_modes(self) -> None:
        for path in (
            "http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt",
            "http3/brave/154.1.96.59/windows-11-26200/client-startup.txt",
            "http3/brave/154.1.96.59/windows-11-26200/launch-mode/"
            "client-startup-devtools.txt",
            "http3/opera/136.0.6008.52/windows-11-26200/client-startup.txt",
            "http3/opera/136.0.6008.52/windows-11-26200/quic-client-hello-2.txt",
        ):
            with self.subTest(path):
                self.assert_reproduces(path, "http3", port=fixture_port(path))

    def test_macos_http3_fixtures(self) -> None:
        for path in (
            "http3/chrome/154.0.8037.95/macos-15.5-arm64/client-startup.txt",
            "http3/edge/154.0.4258.48/macos-15.5-arm64/client-startup.txt",
            "http3/opera/136.0.6008.52/macos-15.5-arm64/client-startup.txt",
        ):
            with self.subTest(path):
                self.assert_reproduces(
                    path, "http3", port=fixture_port(path), platform="darwin"
                )


class LaunchArgumentTests(unittest.TestCase):
    def test_devtools_mode_starts_blank_with_a_remote_port(self) -> None:
        arguments = launch_arguments("http2", "profile", devtools=True)

        self.assertEqual(arguments[-2:], [REMOTE_FLAG, START_URL])
        self.assertNotIn("--dump-dom", arguments)
        self.assertEqual(launch_mode(True), "devtools-navigate")

    def test_command_line_mode_leaves_the_url_to_the_caller(self) -> None:
        arguments = launch_arguments("tls", "profile", devtools=False)

        self.assertEqual(arguments[-1], "--dump-dom")
        self.assertNotIn(REMOTE_FLAG, arguments)
        self.assertEqual(arguments[1], "--user-data-dir=profile")
        self.assertEqual(launch_mode(False), "command-line")

    def test_macos_launch_keeps_the_profile_off_the_login_keychain(self) -> None:
        macos = launch_arguments("tls", "profile", devtools=False, platform="darwin")
        windows = launch_arguments("tls", "profile", devtools=False, platform="win32")

        self.assertIn("--use-mock-keychain", macos)
        self.assertNotIn("--use-mock-keychain", windows)
        self.assertEqual([a for a in macos if a != "--use-mock-keychain"], windows)


if __name__ == "__main__":
    unittest.main()


class AndroidBrowserRefusalTests(unittest.TestCase):
    def test_android_browsers_are_refused(self) -> None:
        for browser in ("chrome-android", "brave-android", "edge-android"):
            with (
                self.subTest(browser=browser),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                main(
                    [
                        "--browser",
                        browser,
                        "--browser-path",
                        "adb",
                        "--client-version",
                        "1",
                        "--layer",
                        "tls",
                        "--output-dir",
                        "out",
                    ]
                )


def server(script: str) -> CaptureListener:
    """A stand-in for chrome_http3.py that runs `script`."""
    process = CaptureListener([sys.executable, "-c", script])
    try:
        process.start()
    except BaseException as primary:
        try:
            process.close()
        except BaseException as cleanup:
            raise primary from cleanup
        raise
    return process


class ListeningWaitTests(unittest.TestCase):
    def test_a_late_listening_line_ends_the_wait_and_keeps_later_output(
        self,
    ) -> None:
        process = server(
            "import sys, time; "
            "print('warming up', file=sys.stderr, flush=True); "
            "time.sleep(0.5); "
            "sys.stderr.write('listening on 127.0.0.1:1\\nafter\\n'); "
            "sys.stderr.flush(); "
            "time.sleep(0.2); "
            "print('later', file=sys.stderr, flush=True)"
        )
        self.addCleanup(process.close)

        listening = wait_until_listening(process, 30)
        self.assertEqual(process.wait(30), 0)
        process.close()

        self.assertTrue(listening.reported)
        self.assertEqual(
            listening.line.replace(b"\r\n", b"\n"), b"listening on 127.0.0.1:1\n"
        )
        # The line after the listening line arrives in the same read.
        output = process.stderr.partition(listening.line)[2].replace(b"\r\n", b"\n")
        self.assertEqual(output, b"after\nlater\n")

    def test_a_server_that_exits_without_the_line_ends_the_wait_early(self) -> None:
        process = server("import sys; print('no', file=sys.stderr); sys.exit(3)")
        self.addCleanup(process.close)
        begin = time.monotonic()

        listening = wait_until_listening(process, 30)

        self.assertLess(time.monotonic() - begin, 20)
        self.assertFalse(listening.reported)
        self.assertEqual(listening.stderr.replace(b"\r\n", b"\n"), b"no\n")
        self.assertEqual(process.wait(30), 3)

    def test_a_silent_server_is_stopped_at_the_limit(self) -> None:
        process = server("import time; time.sleep(60)")
        self.addCleanup(process.close)

        self.assertFalse(wait_until_listening(process, 0.5).reported)

        process.close()
        self.assertIsNone(process.directory)
        with self.assertRaises(ProcessContainerStopped):
            process.process.poll()


class StartupOwnershipTests(unittest.TestCase):
    def args(self, directory: Path, *, layer: str = "tls") -> argparse.Namespace:
        return argparse.Namespace(
            navigate="command-line",
            capture_binary=Path("unused"),
            layer=layer,
            client="Chrome",
            client_version="1",
            operating_system="test",
            browser_path=Path(sys.executable),
            server_start=10.0,
            settle=0.0,
            repeat=1,
            timeout=10.0,
            output_dir=directory,
        )

    def listener_factory(self, owners: list[CaptureListener]):
        def create(_command):
            listener = CaptureListener(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys,time; s=socket.socket(); "
                    "s.bind(('127.0.0.1',0)); s.listen(); "
                    "print('listening on 127.0.0.1:%s' % s.getsockname()[1], "
                    "file=sys.stderr,flush=True); time.sleep(60)",
                ]
            )
            owners.append(listener)
            self.addCleanup(listener.close)
            return listener

        return create

    def assert_listener_closed(self, listener: CaptureListener) -> None:
        self.assertIsNone(listener.directory)
        port = int(listener.stderr.split(b":", 1)[1].splitlines()[0])
        with socket.socket() as replacement:
            replacement.bind(("127.0.0.1", port))

    def test_browser_constructor_failure_closes_original_listener(self) -> None:
        primary = LookupError("profile allocation failed")
        owners = []
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.txt"
            with (
                mock.patch.object(
                    startup_capture,
                    "CaptureListener",
                    side_effect=self.listener_factory(owners),
                ),
                mock.patch.object(startup_capture, "Browser", side_effect=primary),
                self.assertRaises(LookupError) as caught,
            ):
                startup_capture.tcp_run(self.args(Path(directory)), output, 10)

            self.assertIs(caught.exception, primary)
            self.assertEqual(len(owners), 1)
            self.assert_listener_closed(owners[0])
            self.assertFalse(output.exists())

    def test_successful_tcp_capture_keeps_fixture_bytes_after_owned_shutdown(
        self,
    ) -> None:
        owners = []
        browsers = []
        original_browser = startup_capture.Browser

        def create_listener(_command):
            listener = CaptureListener(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys; s=socket.socket(); "
                    "s.bind(('127.0.0.1',0)); s.listen(); "
                    "print('listening on 127.0.0.1:%s' % s.getsockname()[1], "
                    "file=sys.stderr,flush=True); c,_=s.accept(); "
                    "assert c.recv(1)==b'x'; "
                    "sys.stdout.buffer.write(b'format=positive-startup\\nbytes=00ff\\n'); "
                    "sys.stdout.buffer.flush()",
                ]
            )
            owners.append(listener)
            self.addCleanup(listener.close)
            return listener

        def create_browser(executable, _arguments):
            browser = original_browser(
                executable,
                [
                    "-c",
                    "import socket,sys,urllib.parse; "
                    "u=urllib.parse.urlsplit(sys.argv[1]); "
                    "c=socket.create_connection(('127.0.0.1',u.port),timeout=5); "
                    "c.sendall(b'x')",
                ],
            )
            browsers.append(browser)
            self.addCleanup(browser.stop)
            return browser

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.txt"
            with (
                mock.patch.object(
                    startup_capture, "CaptureListener", side_effect=create_listener
                ),
                mock.patch.object(
                    startup_capture, "Browser", side_effect=create_browser
                ),
            ):
                self.assertTrue(
                    startup_capture.tcp_run(self.args(Path(directory)), output, 10)
                )

            self.assertEqual(
                output.read_bytes(), b"format=positive-startup\nbytes=00ff\n"
            )
            self.assertIsNone(owners[0].directory)
            self.assertFalse(browsers[0].profile.exists())

    def test_original_listener_exit_survives_output_directory_cleanup_failure(
        self,
    ) -> None:
        owners = []
        cleanup = PermissionError(errno.EACCES, "output directory removal failed")
        original_remove = startup_capture._remove_directory

        def create_listener(_command):
            listener = CaptureListener(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('listening on 127.0.0.1:1', "
                    "file=sys.stderr,flush=True); sys.exit(3)",
                ]
            )
            owners.append(listener)
            self.addCleanup(listener.close)
            return listener

        def remove(directory):
            if owners and directory == owners[0].directory:
                raise cleanup
            original_remove(directory)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.txt"
            with (
                mock.patch.object(
                    startup_capture, "CaptureListener", side_effect=create_listener
                ),
                mock.patch.object(startup_capture, "open_page"),
                mock.patch.object(
                    startup_capture, "_remove_directory", side_effect=remove
                ),
                self.assertRaises(BrowserLaunchFailures) as caught,
            ):
                startup_capture.tcp_run(self.args(Path(directory)), output, 10)

            self.assertIsInstance(
                caught.exception.primary, subprocess.CalledProcessError
            )
            self.assertEqual(caught.exception.primary.returncode, 3)
            self.assertEqual(caught.exception.primary.cmd, owners[0].command)
            (failure,) = caught.exception.cleanup
            self.assertIs(failure.listener, owners[0])
            self.assertIs(failure.failures[0][1], cleanup)
            self.assertTrue(owners[0].directory.is_dir())
            self.assertFalse(output.exists())
            owners[0].close()

    def test_navigation_and_profile_removal_failures_remain_independent(self) -> None:
        primary = LookupError("navigation failed")
        cleanup = PermissionError(errno.EACCES, "profile removal failed")
        owners = []
        browsers = []
        original_browser = startup_capture.Browser
        original_remove = startup_capture._remove_directory

        def create_browser(executable, _arguments):
            browser = original_browser(
                executable, ["-c", "import time; time.sleep(60)"]
            )
            browsers.append(browser)
            return browser

        def open_page(browser, *_arguments):
            browser.start(None)
            raise primary

        def remove(directory):
            if browsers and directory == browsers[0].profile:
                raise cleanup
            original_remove(directory)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.txt"
            try:
                with (
                    mock.patch.object(
                        startup_capture,
                        "CaptureListener",
                        side_effect=self.listener_factory(owners),
                    ),
                    mock.patch.object(
                        startup_capture, "Browser", side_effect=create_browser
                    ),
                    mock.patch.object(
                        startup_capture, "open_page", side_effect=open_page
                    ),
                    mock.patch.object(
                        startup_capture, "_remove_directory", side_effect=remove
                    ),
                    self.assertRaises(BrowserLaunchFailures) as caught,
                ):
                    startup_capture.tcp_run(self.args(Path(directory)), output, 10)

                self.assertIs(caught.exception.primary, primary)
                self.assertEqual(caught.exception.cleanup, (cleanup,))
                self.assert_listener_closed(owners[0])
                self.assertTrue(browsers[0].profile.is_dir())
                with self.assertRaises(ProcessContainerStopped):
                    browsers[0].process.poll()
                self.assertFalse(output.exists())
            finally:
                for browser in browsers:
                    browser.stop()

    def test_certificate_write_failure_removes_partially_written_material(self) -> None:
        primary = OSError(errno.EIO, "certificate key write failed")
        material = []
        original_mkdtemp = tempfile.mkdtemp
        original_write = Path.write_bytes

        def allocate(*arguments, **keywords):
            name = original_mkdtemp(*arguments, **keywords)
            material.append(Path(name))
            return name

        def write(path, value):
            if path.name == "key.pem":
                raise primary
            return original_write(path, value)

        certificate = SimpleNamespace(
            certificate_pem=b"certificate", private_key_pem=b"key"
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch(
                    "scripts.capture.http2_session.generate_certificate",
                    return_value=certificate,
                ),
                mock.patch.object(tempfile, "mkdtemp", side_effect=allocate),
                mock.patch.object(Path, "write_bytes", write),
                mock.patch.object(startup_capture, "CaptureListener") as launch,
                self.assertRaises(OSError) as caught,
            ):
                startup_capture.quic_run(
                    self.args(Path(directory), layer="http3"),
                    Path(directory) / "startup",
                    Path(directory) / "hello",
                    10,
                )

            self.assertIs(caught.exception, primary)
            self.assertEqual(len(material), 1)
            self.assertFalse(material[0].exists())
            launch.assert_not_called()

    def test_readiness_limit_and_original_file_error_stop_owned_listener(self) -> None:
        process = server(
            "import sys,time; sys.stderr.write('x' * 65537); sys.stderr.flush(); time.sleep(60)"
        )
        self.addCleanup(process.close)
        with self.assertRaisesRegex(ValueError, "stderr exceeds"):
            wait_until_listening(process, 5)
        process.close()
        self.assertIsNone(process.directory)
        self.assertLessEqual(len(process.stderr), 65536)

        process = server("import time; time.sleep(60)")
        self.addCleanup(process.close)
        primary = OSError(errno.EIO, "original readiness file read failed")
        reader = mock.Mock(wraps=process.diagnostics_reader)
        reader.read.side_effect = primary
        process.diagnostics_reader = reader
        with self.assertRaises(OSError) as caught:
            wait_until_listening(process, 5)
        self.assertIs(caught.exception, primary)
        process.close()
        self.assertIsNone(process.directory)

    def test_failed_exit_and_read_error_survive_independent_cleanup_before_publication(
        self,
    ) -> None:
        primary = OSError(errno.EIO, "original failed listener read")
        cleanup = PermissionError(errno.EACCES, "original output directory removal")
        owners = []
        original_remove = startup_capture._remove_directory

        def create_listener(_command):
            listener = CaptureListener(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.exit(3)",
                ]
            )
            original_start = listener.start

            def start():
                original_start()
                self.assertEqual(listener.process.wait(timeout=30), 3)
                reader = mock.Mock(wraps=listener.diagnostics_reader)
                reader.read.side_effect = primary
                listener.diagnostics_reader = reader

            listener.start = start
            owners.append(listener)
            self.addCleanup(listener.close)
            return listener

        def remove(directory):
            if owners and directory == owners[0].directory:
                raise cleanup
            original_remove(directory)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.txt"
            with (
                mock.patch.object(
                    startup_capture, "CaptureListener", side_effect=create_listener
                ),
                mock.patch.object(
                    startup_capture, "_remove_directory", side_effect=remove
                ),
                mock.patch.object(startup_capture, "Browser") as browser,
                self.assertRaises(BrowserLaunchFailures) as caught,
            ):
                startup_capture.tcp_run(self.args(Path(directory)), output, 10)

            (listener,) = owners
            observation = caught.exception.primary
            self.assertIs(observation, listener.output_error)
            self.assertIs(observation.primary, primary)
            self.assertEqual(observation.cleanup, (listener.exit_failure,))
            self.assertEqual(listener.exit_failure.returncode, 3)
            self.assertEqual(listener.exit_failure.cmd, listener.command)
            (failure,) = caught.exception.cleanup
            self.assertIs(failure.listener, listener)
            self.assertIs(failure.failures[0][1], cleanup)
            with self.assertRaises(BrowserLaunchFailures) as repeated:
                listener.observe()
            self.assertIs(repeated.exception, observation)
            browser.assert_not_called()
            self.assertFalse(output.exists())
            self.assertTrue(listener.directory.is_dir())
            listener.close()

    def test_failed_exit_survives_original_wait_output_limit(self) -> None:
        listener = server(
            "import sys; sys.stderr.buffer.write(b'x' * 65537); "
            "sys.stderr.buffer.flush(); sys.exit(3)"
        )
        self.addCleanup(listener.close)
        self.assertEqual(listener.process.wait(timeout=30), 3)

        with self.assertRaises(BrowserLaunchFailures) as caught:
            listener.wait(30)

        observation = caught.exception
        self.assertIs(observation, listener.output_error)
        self.assertIsInstance(observation.primary, ValueError)
        self.assertIn("stderr exceeds", str(observation.primary))
        self.assertEqual(observation.cleanup, (listener.exit_failure,))
        self.assertEqual(listener.exit_failure.returncode, 3)
        self.assertEqual(listener.exit_failure.cmd, listener.command)
        with self.assertRaises(BrowserLaunchFailures) as repeated:
            listener.observe()
        self.assertIs(repeated.exception, observation)
        listener.close()
        self.assertIsNone(listener.directory)

    def test_partial_file_close_retry_keeps_final_snapshot_and_original_file_owner(
        self,
    ) -> None:
        listener = server(
            "import sys; sys.stdout.buffer.write(b'fixture\\n'); "
            "sys.stderr.buffer.write(b'final diagnostics\\n')"
        )
        self.addCleanup(listener.close)
        self.assertEqual(listener.wait(30), 0)
        original = listener.files[0]
        cleanup = OSError(errno.EIO, "original output file close failed")
        attempts = []
        retained = SimpleNamespace(closed=False)

        def close():
            attempts.append(None)
            if len(attempts) == 1:
                raise cleanup
            original.close()
            retained.closed = original.closed

        retained.close = close
        listener.files[0] = retained
        self.addCleanup(original.close)

        with self.assertRaises(ProcessCleanupError) as caught:
            listener.close()

        self.assertIs(caught.exception.listener, listener)
        self.assertEqual(
            caught.exception.failures, (("close startup output file", cleanup),)
        )
        self.assertEqual(listener.files, [retained])
        self.assertFalse(original.closed)
        self.assertIsNone(listener.output_reader)
        self.assertIsNone(listener.diagnostics_reader)
        self.assertTrue(listener.final_snapshot)
        self.assertIsNone(listener.output_error)
        self.assertEqual(listener.stdout, b"fixture\n")
        self.assertEqual(listener.stderr, b"final diagnostics\n")
        self.assertTrue(listener.directory.is_dir())

        listener.close()

        self.assertTrue(original.closed)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(listener.files, [])
        self.assertIsNone(listener.directory)
        self.assertIsNone(listener.output_error)
        self.assertEqual(listener.stdout, b"fixture\n")
        self.assertEqual(listener.stderr, b"final diagnostics\n")

    def test_exited_parent_with_stderr_holding_descendant_is_retired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "address"
            child = (
                "import socket,pathlib; s=socket.socket(); "
                "s.bind(('127.0.0.1',0)); s.listen(); "
                f"p=pathlib.Path({str(marker)!r}); "
                "p.with_suffix('.tmp').write_text(str(s.getsockname()[1])); "
                "p.with_suffix('.tmp').replace(p); "
                "c,_=s.accept(); c.sendall(b'held'); c.recv(1)"
            )
            parent = (
                "import pathlib,subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
                f"p=pathlib.Path({str(marker)!r}); "
                "end=time.monotonic()+10\n"
                "while not p.exists() and time.monotonic()<end: time.sleep(.01)\n"
                "sys.exit(3)"
            )
            process = server(parent)
            self.addCleanup(process.close)
            begin = time.monotonic()
            self.assertFalse(wait_until_listening(process, 30).reported)
            self.assertLess(time.monotonic() - begin, 20)
            self.assertEqual(process.wait(30), 3)
            port = int(marker.read_text())
            with socket.create_connection(("127.0.0.1", port), timeout=5) as accepted:
                self.assertEqual(accepted.recv(4), b"held")
                process.close()
                try:
                    self.assertEqual(accepted.recv(1), b"")
                except OSError as error:
                    self.assertIn(
                        error.errno, (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE)
                    )
                self.assertIsNone(process.directory)

    def test_invalid_bounds_are_rejected_before_output_or_process_acquisition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            for option, value in (
                ("--timeout", "nan"),
                ("--server-start", "inf"),
                ("--settle", "-1"),
                ("--repeat", "0"),
            ):
                with (
                    self.subTest(option=option),
                    redirect_stderr(io.StringIO()),
                    mock.patch.object(startup_capture, "CaptureListener") as launch,
                    mock.patch.object(tempfile, "mkdtemp") as allocate,
                    self.assertRaises(SystemExit),
                ):
                    main(
                        [
                            "--browser",
                            "chrome",
                            "--browser-path",
                            sys.executable,
                            "--client-version",
                            "1",
                            "--layer",
                            "tls",
                            "--output-dir",
                            str(output),
                            option,
                            value,
                        ]
                    )
                self.assertFalse(output.exists())
                launch.assert_not_called()
                allocate.assert_not_called()
