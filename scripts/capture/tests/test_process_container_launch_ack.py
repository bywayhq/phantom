"""Confirm real Windows tool creation without releasing job ownership."""

import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import process_container
from scripts.capture.process_container import ProcessCleanupError, ProcessContainer

STATUS_BOOTSTRAP = """import sys
if sys.stdin.buffer.read(1) != b'G':
    raise SystemExit(125)
sys.stdin.close()
from multiprocessing.connection import PipeConnection
status = PipeConnection(int(sys.argv[1]), readable=False)
"""


@unittest.skipUnless(sys.platform == "win32", "Windows launch acknowledgement")
class ProcessLaunchAcknowledgementTests(unittest.TestCase):
    def test_real_creation_preserves_command_environment_and_exit_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="launch-ack-争-") as directory:
            marker = Path(directory) / "argument with spaces.txt"
            source = (
                "import os,sys; from pathlib import Path; "
                "Path(sys.argv[1]).write_text(os.environ['CAPTURE_ACK_VALUE']+':'+str(os.getpid())); "
                "raise SystemExit(-1073741502)"
            )
            container = ProcessContainer(
                [process_container._windows_interpreter(), "-c", source, str(marker)],
                env=dict(os.environ, CAPTURE_ACK_VALUE="owned command"),
                confirm_start=True,
            )
            try:
                self.assertFalse(marker.exists())
                bootstrap_pid = container.pid
                self.assertIsNone(container.tool_pid)
                self.assertTrue(container.start())
                self.assertTrue(container.start())
                self.assertEqual(container.wait(timeout=10), 0xC0000142)
                value, pid = marker.read_text(encoding="utf-8").split(":")
                self.assertEqual(value, "owned command")
                self.assertEqual(container.tool_pid, int(pid))
                self.assertNotEqual(container.tool_pid, bootstrap_pid)
                self.assertEqual(container.pid, bootstrap_pid)
                self.assertIsNone(container._launch_reader)
                self.assertIsNone(container._launch_writer)
            finally:
                container.close()
            self.assertFalse(container.start())

    def test_real_createprocess_errors_keep_exact_native_error_and_filename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="launch-ack-errors-") as directory:
            root = Path(directory)
            invalid = root / "invalid.exe"
            invalid.write_bytes(b"not an executable")
            commands = [root / "missing.exe", invalid, root]
            observed = set()
            for executable in commands:
                with self.subTest(executable=executable.name):
                    with self.assertRaises(OSError) as direct:
                        subprocess.Popen([str(executable)])
                    container = ProcessContainer([str(executable)], confirm_start=True)
                    try:
                        with self.assertRaises(OSError) as confirmed:
                            container.start()
                        expected = direct.exception
                        actual = confirmed.exception
                        observed.add(actual.winerror)
                        self.assertIs(type(actual), type(expected))
                        self.assertEqual(actual.errno, expected.errno)
                        self.assertEqual(actual.winerror, expected.winerror)
                        self.assertEqual(actual.filename, expected.filename)
                        self.assertIs(actual.container, container)
                        self.assertTrue(container._cleanup_complete)
                        self.assertIsNone(container._launch_reader)
                        self.assertIsNone(container._launch_writer)
                        self.assertFalse(container.start())
                    finally:
                        container.close()
            self.assertIn(observed, ({2, 5, 193}, {2, 5, 216}))

    def test_default_release_does_not_add_synchronous_creation_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="launch-ack-default-") as directory:
            container = ProcessContainer(
                [str(Path(directory) / "missing.exe")], stderr=subprocess.DEVNULL
            )
            try:
                self.assertIsNone(container._launch_reader)
                bootstrap_pid = container.pid
                self.assertTrue(container.start())
                self.assertIsNone(container.tool_pid)
                self.assertEqual(container.pid, bootstrap_pid)
                self.assertNotEqual(container.wait(timeout=10), 0)
            finally:
                container.close()

    def test_status_writer_is_not_inherited_by_the_running_tool(self) -> None:
        readers = []
        close_pipe = ProcessContainer._close_launch_pipe

        def retain_reader(container, attribute):
            if attribute == "_launch_reader" and container._launch_reader is not None:
                readers.append(container._launch_reader)
                container._launch_reader = None
            else:
                close_pipe(container, attribute)

        source = (
            "import socket,sys; "
            "peer=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=10); "
            "peer.settimeout(None); peer.sendall(b'R'); peer.recv(1)"
        )
        with contextlib.ExitStack() as cleanup:
            listener = cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            container = ProcessContainer(
                [sys.executable, "-c", source, str(listener.getsockname()[1])],
                confirm_start=True,
            )
            cleanup.callback(container.close)
            with mock.patch.object(
                ProcessContainer, "_close_launch_pipe", retain_reader
            ):
                self.assertTrue(container.start())
            self.assertEqual(len(readers), 1)
            cleanup.callback(readers[0].close)
            peer, _ = listener.accept()
            cleanup.enter_context(peer)
            peer.settimeout(10)
            self.assertEqual(peer.recv(1), b"R")
            self.assertIsNone(container.poll())
            try:
                ready = readers[0].poll(10)
            except BrokenPipeError as error:
                self.assertEqual(error.winerror, 109)
            else:
                self.assertTrue(ready, "bootstrap left a status writer open")
                with self.assertRaises(EOFError):
                    readers[0].recv_bytes(9)
            self.assertIsNone(container.poll(), "tool exited before EOF was checked")
            peer.sendall(b"X")
            self.assertEqual(container.wait(timeout=10), 0)

    def test_missing_malformed_and_oversized_status_fail_closed(self) -> None:
        frames = [
            b"",
            b"G",
            b"G" + bytes(4),
            b"Gtrailing",
            b"?",
            b"E" + bytes(8),
            b"G" * 10,
        ]
        for frame in [None, *frames]:
            with self.subTest(frame=frame):
                publish = "" if frame is None else f"status.send_bytes({frame!r})\n"
                bootstrap = STATUS_BOOTSTRAP + publish + "status.close()\n"
                with mock.patch.object(
                    process_container, "_CONFIRMED_BOOTSTRAP", bootstrap
                ):
                    container = ProcessContainer(["unused-tool"], confirm_start=True)
                try:
                    with self.assertRaises(OSError) as observed:
                        container.start()
                    self.assertIs(observed.exception.container, container)
                    self.assertTrue(container._cleanup_complete)
                    self.assertIsNone(container._launch_reader)
                    self.assertIsNone(container._launch_writer)
                finally:
                    container.close()

    def test_missing_acknowledgement_times_out_and_stops_the_bootstrap(self) -> None:
        bootstrap = STATUS_BOOTSTRAP + "import time\ntime.sleep(60)\n"
        with mock.patch.object(process_container, "_CONFIRMED_BOOTSTRAP", bootstrap):
            container = ProcessContainer(["unused-tool"], confirm_start=True)
        try:
            with (
                mock.patch.object(process_container, "WINDOWS_START_SECONDS", 0.05),
                self.assertRaises(TimeoutError) as observed,
            ):
                container.start()
            self.assertIs(observed.exception.container, container)
            self.assertTrue(container._cleanup_complete)
            self.assertIsNotNone(container._process.poll())
            self.assertIsNone(container._launch_reader)
            self.assertIsNone(container._launch_writer)
        finally:
            container.close()

    def test_constructor_failure_closes_both_status_handles(self) -> None:
        primary = OSError("controlled bootstrap creation failure")
        with (
            mock.patch.object(
                process_container.subprocess, "Popen", side_effect=primary
            ),
            self.assertRaises(OSError) as observed,
        ):
            ProcessContainer(["unused-tool"], confirm_start=True)
        self.assertIs(observed.exception, primary)
        container = primary.container
        self.assertTrue(container._cleanup_complete)
        self.assertIsNone(container._launch_reader)
        self.assertIsNone(container._launch_writer)
        container.close()

    def test_status_failure_retains_failed_cleanup_owner_for_retry(self) -> None:
        container = ProcessContainer([sys.executable, "-c", "pass"], confirm_start=True)
        primary = OSError("controlled status read failure")
        secondary = OSError("controlled pipe close failure")
        reader = container._launch_reader
        try:
            with (
                mock.patch.object(container, "_confirm_launch", side_effect=primary),
                mock.patch.object(reader, "close", side_effect=secondary),
                self.assertRaises(OSError) as observed,
            ):
                container.start()
            self.assertIs(observed.exception, primary)
            self.assertIs(primary.container, container)
            self.assertIsInstance(primary.__cause__, ProcessCleanupError)
            cleanup = primary.__cause__.failures[0][1]
            self.assertIn(secondary, [error for _operation, error in cleanup.failures])
            # Connection.close failures can lose handle identity. Keep the
            # failure visible rather than claiming a later retry repaired it.
            self.assertFalse(container._cleanup_complete)
            self.assertTrue(container._lost_failures)
        finally:
            reader.close()
            # Keep failed-operation evidence visible after disposing of
            # this test's still-owned mock-close handle explicitly.
            with self.assertRaises(ProcessCleanupError):
                container.close()


if __name__ == "__main__":
    unittest.main()
