"""Linux process-tree control; never invokes Docker or the real upstream runner."""

import contextlib
import io
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts.conformance import docker_owner, quic_interop
from scripts.conformance.tests.test_quic_interop_lifecycle import ControlledRunner


@unittest.skipUnless(
    sys.platform == "linux"
    and hasattr(os, "pidfd_open")
    and hasattr(signal, "pidfd_send_signal"),
    "requires Linux held process identities",
)
class QuicInteropProcessTests(unittest.TestCase):
    def test_outer_timeout_reaps_actual_descendant_before_restoration(self):
        with tempfile.TemporaryDirectory(prefix="quic-owned-process-") as temporary:
            root = Path(temporary)
            control = ControlledRunner(root, "timeout")
            child_pid_path = root / "child.pid"
            child_exit_path = root / "child.exited"
            child_program = (
                "import os,signal,sys,time\n"
                "from pathlib import Path\n"
                "signal.signal(signal.SIGTERM,lambda signum,frame: sys.exit(0))\n"
                "Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                "deadline=time.monotonic()+15\n"
                "try:\n"
                "    while time.monotonic()<deadline: time.sleep(0.05)\n"
                "finally:\n"
                "    Path(sys.argv[2]).write_text('exited')\n"
            )
            (control.runner / "run.py").write_text(
                "import subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable,'-c',{child_program!r},{str(child_pid_path)!r},{str(child_exit_path)!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "while True: time.sleep(0.05)\n",
                encoding="utf-8",
            )
            held = []
            collector_errors = []
            restored_with_live_child = []
            launched = []
            real_run = subprocess.run
            real_popen = subprocess.Popen
            real_write = Path.write_bytes

            def collect_child():
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        try:
                            identity = int(child_pid_path.read_text())
                        except (FileNotFoundError, ValueError):
                            identity = None
                        if identity is not None:
                            held.append(os.pidfd_open(identity))
                            return
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "controlled child did not announce its identity"
                            )
                        time.sleep(0.005)
                except BaseException as error:
                    collector_errors.append(error)

            def observe_restore(path, content):
                if (
                    path.parent == control.runner
                    and content == control.original.get(path.name)
                    and held
                    and not select.select(held, [], [], 0)[0]
                ):
                    restored_with_live_child.append(path.name)
                return real_write(path, content)

            def command_run(command, **options):
                if len(command) > 1 and command[1] == "run.py":
                    control.begin(command, options)
                    return real_run(command, **options)
                return control.run_command(command, **options)

            def command_popen(command, **options):
                control.begin(command, options)
                process = real_popen(command, **options)
                launched.append(process)
                return process

            commands = types.SimpleNamespace(
                run=command_run,
                Popen=command_popen,
                SubprocessError=subprocess.SubprocessError,
                CalledProcessError=subprocess.CalledProcessError,
                TimeoutExpired=subprocess.TimeoutExpired,
                PIPE=subprocess.PIPE,
                STDOUT=subprocess.STDOUT,
                DEVNULL=subprocess.DEVNULL,
            )
            collector = threading.Thread(target=collect_child, daemon=True)
            collector.start()
            error = None
            try:
                with (
                    mock.patch.object(quic_interop, "subprocess", commands),
                    mock.patch.object(docker_owner, "subprocess", commands),
                    mock.patch.object(quic_interop, "RUN_TIMEOUT_SECONDS", 3),
                    mock.patch.object(Path, "write_bytes", observe_restore),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    try:
                        quic_interop.run(
                            control.runner,
                            root,
                            root / "reports",
                            "controlled-client:literal",
                            "controlled",
                            "controlled-server:literal",
                        )
                    except BaseException as caught:
                        error = caught
                collector.join(timeout=10)

                self.assertFalse(collector.is_alive())
                self.assertEqual(collector_errors, [])
                self.assertEqual(len(held), 1)
                self.assertEqual(control.launches, 1)
                self.assertIsNotNone(error)
                self.assertTrue(
                    select.select(held, [], [], 0)[0], "owned descendant is still alive"
                )
                self.assertEqual(restored_with_live_child, [])
            finally:
                collector.join(timeout=10)
                for descriptor in held:
                    try:
                        if not select.select([descriptor], [], [], 0)[0]:
                            with contextlib.suppress(ProcessLookupError):
                                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                            if not select.select([descriptor], [], [], 5)[0]:
                                with contextlib.suppress(ProcessLookupError):
                                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                                if not select.select([descriptor], [], [], 5)[0]:
                                    raise TimeoutError(
                                        "controlled descendant did not exit"
                                    )
                    finally:
                        os.close(descriptor)
                if not held and child_pid_path.exists():
                    deadline = time.monotonic() + 18
                    while not child_exit_path.exists():
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "controlled child's self-exit was not observed"
                            )
                        time.sleep(0.005)
                for process in launched:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
