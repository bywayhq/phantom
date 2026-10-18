import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.capture.tests import test_android_browser_async_lifecycle as lifecycle


class AndroidBrowserProgressMonitorTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_failure_wakes_the_waiting_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command = lifecycle.HostCommand(Path(directory), ())
            monitor = lifecycle.ProgressMonitor(asyncio.get_running_loop(), command)
            with patch.object(lifecycle, "READY_SECONDS", 0.03):
                monitor.start()
                try:
                    await asyncio.wait_for(monitor.observed.wait(), 2)
                    self.assertIsInstance(monitor.failure, TimeoutError)
                finally:
                    with self.assertRaisesRegex(TimeoutError, "did not become ready"):
                        monitor.finish()

    async def test_invalid_startup_receipt_wakes_the_waiting_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command = lifecycle.HostCommand(Path(directory), ())
            command.ready.write_text("not JSON")
            monitor = lifecycle.ProgressMonitor(asyncio.get_running_loop(), command)
            monitor.start()
            try:
                await asyncio.wait_for(monitor.observed.wait(), 2)
                self.assertIsInstance(monitor.failure, ValueError)
            finally:
                with self.assertRaises(ValueError):
                    monitor.finish()

    async def test_delayed_startup_still_checks_loop_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command = lifecycle.HostCommand(Path(directory), ())
            command.process = Mock(pid=42)
            command.process.poll.return_value = None
            monitor = lifecycle.ProgressMonitor(asyncio.get_running_loop(), command)
            with patch.object(lifecycle, "READY_SECONDS", 2):
                monitor.start()
                try:
                    await asyncio.sleep(0.05)
                    pending = command.ready.with_suffix(".tmp")
                    pending.write_text(json.dumps({"pid": 42, "arguments": []}))
                    pending.replace(command.ready)
                    await asyncio.wait_for(monitor.observed.wait(), 3)
                    self.assertIsNone(monitor.failure)
                    self.assertTrue(monitor.progress_before_release)
                    self.assertTrue(monitor.child_alive_before_release)
                    self.assertTrue(monitor.gate_closed_before_release)
                finally:
                    monitor.finish()

    async def test_blocked_loop_is_detected_after_successful_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command = lifecycle.HostCommand(Path(directory), ())
            command.process = Mock(pid=42)
            command.process.poll.return_value = None
            command.ready.write_text(json.dumps({"pid": 42, "arguments": []}))
            monitor = lifecycle.ProgressMonitor(asyncio.get_running_loop(), command)
            with patch.object(lifecycle, "PROGRESS_SECONDS", 0.03):
                monitor.start()
                try:
                    # Deliberately block this loop while the independent observer waits.
                    self.assertTrue(monitor.done.wait(2))
                    await asyncio.wait_for(monitor.observed.wait(), 2)
                    self.assertFalse(monitor.progress_before_release)
                finally:
                    monitor.finish()
