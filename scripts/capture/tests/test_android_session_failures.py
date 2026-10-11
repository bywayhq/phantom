import asyncio
import unittest

from scripts.capture.android_device import ANDROID_BROWSERS, AndroidLaunch
from scripts.capture.browser_launch import BrowserLaunchFailures
from scripts.capture.tests.test_android_device_lifecycle import (
    CLEANUP_COMMANDS,
    CLEAR_DEBUG,
    OPEN,
    PACKAGE,
    REMOVE_FIRST,
    REMOVE_SECOND,
    URL,
    ObservedSession,
    OfflineDevice,
    failure_from,
)


class AndroidSessionFailureTests(unittest.TestCase):
    def device(self) -> OfflineDevice:
        device = OfflineDevice()
        self.addCleanup(device.backup)
        return device

    def session(self, device: OfflineDevice) -> ObservedSession:
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=1,
            reverse=(9451,),
        )
        return ObservedSession(device, launch)

    def test_entry_primary_retains_ordered_independent_cleanup_failures(self) -> None:
        device = self.device()
        session = self.session(device)
        primary = OSError("controlled entry failure")
        first = OSError("controlled stop cleanup failure")
        second = OSError("controlled first reverse cleanup failure")
        previous_cause = RuntimeError("pre-existing entry cause")
        previous_context = RuntimeError("pre-existing entry context")
        primary.__cause__ = previous_cause
        primary.__context__ = previous_context
        device.faults[OPEN] = primary
        device.stop_after_open_failure = first
        device.faults[REMOVE_FIRST] = second

        failure = failure_from(session.__enter__)

        self.assertFalse(device.backup_started)
        self.assertIs(session.original_entry_failure, primary)
        self.assertGreaterEqual(len(device.raised), 2)
        self.assertIs(device.raised[0], primary)
        self.assertIs(device.raised[1], first)
        self.assertIs(getattr(failure, "primary", None), primary)
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertEqual(len(failure.cleanup), 2)
        self.assertIs(failure.cleanup[0], first)
        self.assertIs(failure.cleanup[1], second)
        self.assertIs(failure.previous_cause, previous_cause)
        self.assertIs(failure.previous_context, previous_context)

        self.assertEqual(len(device.raised), 3)
        self.assertIs(device.raised[2], second)
        opened = device.commands.index(OPEN)
        self.assertEqual(device.commands[opened + 1 :], CLEANUP_COMMANDS)

    def test_direct_body_primary_retains_its_cleanup_failure(self) -> None:
        device = self.device()
        session = self.session(device)
        primary = OSError("controlled body failure")
        cleanup = OSError("controlled debug cleanup failure")
        previous_cause = RuntimeError("pre-existing body cause")
        previous_context = RuntimeError("pre-existing body context")
        primary.__cause__ = previous_cause
        primary.__context__ = previous_context
        entered = []

        def body() -> None:
            with session:
                entered.append(len(device.commands))
                device.faults[CLEAR_DEBUG] = cleanup
                raise primary

        failure = failure_from(body)

        self.assertFalse(device.backup_started)
        self.assertEqual(len(entered), 1)
        self.assertIsNone(session.original_entry_failure)
        self.assertEqual(len(device.raised), 1)
        self.assertIs(device.raised[0], cleanup)
        self.assertIs(getattr(failure, "primary", None), primary)
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertEqual(len(failure.cleanup), 1)
        self.assertIs(failure.cleanup[0], cleanup)
        self.assertIs(failure.previous_cause, previous_cause)
        self.assertIs(failure.previous_context, previous_context)

        self.assertEqual(device.commands[entered[0] :], CLEANUP_COMMANDS)

    def test_cleanup_only_retains_both_original_reverse_failures(self) -> None:
        device = self.device()
        session = self.session(device)
        self.assertIs(session.__enter__(), session)
        checkpoint = len(device.commands)
        first = OSError("controlled first reverse cleanup failure")
        second = OSError("controlled second reverse cleanup failure")
        device.faults[REMOVE_FIRST] = first
        device.faults[REMOVE_SECOND] = second

        failure = failure_from(session.__exit__)

        self.assertFalse(device.backup_started)
        self.assertGreaterEqual(len(device.raised), 1)
        self.assertIs(device.raised[0], first)
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertIsNone(failure.primary)
        self.assertEqual(len(failure.cleanup), 2)
        self.assertIs(failure.cleanup[0], first)
        self.assertIs(failure.cleanup[1], second)
        self.assertEqual(len(device.raised), 2)
        self.assertIs(device.raised[1], second)

        self.assertEqual(device.commands[checkpoint:], CLEANUP_COMMANDS)
        self.assertEqual(device.ports, {"tcp:9450", "tcp:9451"})
        self.assertEqual(device.files, {})
        self.assertIsNone(device.debug_app)
        self.assertFalse(device.running)

    def test_entry_interruption_keeps_original_object_and_cleanup_details(self) -> None:
        device = self.device()
        session = self.session(device)
        primary = asyncio.CancelledError("controlled synchronous entry interruption")
        cleanup = OSError("controlled debug cleanup failure")
        previous_cause = RuntimeError("pre-existing interruption cause")
        previous_context = RuntimeError("pre-existing interruption context")
        primary.__cause__ = previous_cause
        primary.__context__ = previous_context
        device.faults[OPEN] = primary
        device.faults[CLEAR_DEBUG] = cleanup

        failure = failure_from(session.__enter__)

        self.assertFalse(device.backup_started)
        self.assertIs(session.original_entry_failure, primary)
        self.assertEqual(len(device.raised), 2)
        self.assertIs(device.raised[0], primary)
        self.assertIs(device.raised[1], cleanup)
        self.assertIs(failure, primary)
        aggregate = failure.__cause__
        self.assertIsInstance(aggregate, BrowserLaunchFailures)
        self.assertIs(aggregate.primary, primary)
        self.assertEqual(len(aggregate.cleanup), 1)
        self.assertIs(aggregate.cleanup[0], cleanup)
        self.assertIs(aggregate.previous_cause, previous_cause)
        self.assertIs(aggregate.previous_context, previous_context)
        self.assertIs(aggregate.interruption_cause, previous_cause)
        self.assertIs(aggregate.interruption_context, previous_context)

        opened = device.commands.index(OPEN)
        self.assertEqual(device.commands[opened + 1 :], CLEANUP_COMMANDS)

    def test_second_healthy_exit_does_not_repeat_released_device_actions(self) -> None:
        device = self.device()
        session = self.session(device)
        self.assertIs(session.__enter__(), session)
        checkpoint = len(device.commands)

        self.assertIsNone(failure_from(session.__exit__))

        self.assertFalse(device.backup_started)
        self.assertEqual(device.commands[checkpoint:], CLEANUP_COMMANDS)
        self.assertEqual(device.files, {})
        self.assertEqual(device.ports, set())
        self.assertIsNone(device.debug_app)
        self.assertFalse(device.running)
        checkpoint = len(device.commands)

        failure = failure_from(session.__exit__)

        self.assertIsNone(failure)
        self.assertEqual(device.commands[checkpoint:], [])
        self.assertFalse(device.backup_started)

    def test_failed_debug_cleanup_retries_only_its_unreleased_action(self) -> None:
        device = self.device()
        session = self.session(device)
        self.assertIs(session.__enter__(), session)
        checkpoint = len(device.commands)
        cleanup = OSError("controlled debug cleanup failure")
        device.faults[CLEAR_DEBUG] = cleanup

        failure = failure_from(session.__exit__)

        self.assertFalse(device.backup_started)
        self.assertIs(failure, cleanup)
        self.assertEqual(len(device.raised), 1)
        self.assertIs(device.raised[0], cleanup)
        self.assertEqual(device.commands[checkpoint:], CLEANUP_COMMANDS)
        self.assertEqual(device.files, {})
        self.assertEqual(device.ports, set())
        self.assertFalse(device.running)
        self.assertEqual(device.debug_app, PACKAGE)
        checkpoint = len(device.commands)

        retried = failure_from(session.__exit__)

        self.assertIsNone(retried)
        self.assertEqual(device.commands[checkpoint:], [CLEAR_DEBUG])
        self.assertIsNone(device.debug_app)
        self.assertFalse(device.backup_started)
        checkpoint = len(device.commands)

        self.assertIsNone(failure_from(session.__exit__))

        self.assertEqual(device.commands[checkpoint:], [])
        self.assertFalse(device.backup_started)
