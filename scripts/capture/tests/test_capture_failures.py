import asyncio
import unittest
from functools import partial
from types import SimpleNamespace

from scripts.capture.browser_failures import (
    BrowserLaunchFailures,
    raise_browser_failures,
)
from scripts.capture.client_hints import HintFailures, _raise_hint_failures
from scripts.capture.http2_preface_ping import PrefaceFailures, _raise_preface_failures


class CaptureFailureTests(unittest.TestCase):
    def paths(self):
        owner = SimpleNamespace()
        return (
            ("browser", raise_browser_failures, BrowserLaunchFailures, None),
            ("hints", partial(_raise_hint_failures, server=owner), HintFailures, owner),
            (
                "preface",
                partial(_raise_preface_failures, owner=owner),
                PrefaceFailures,
                owner,
            ),
        )

    def observe(self, operation, primary, cleanup):
        try:
            operation(primary, cleanup)
        except BaseException as error:
            return error
        return None

    def assert_owner(self, failure, name, owner):
        if owner is not None:
            self.assertIs(
                getattr(failure, "server" if name == "hints" else "owner"), owner
            )

    def test_no_cleanup_preserves_the_original_error_and_its_chain(self):
        for name, operation, _kind, _owner in self.paths():
            with self.subTest(path=name):
                self.assertIsNone(self.observe(operation, None, ()))
                primary = OSError("capture failed")
                previous = RuntimeError("earlier cause")
                context = RuntimeError("earlier context")
                primary.__cause__, primary.__context__ = previous, context
                self.assertIs(self.observe(operation, primary, ()), primary)
                self.assertIs(primary.__cause__, previous)
                self.assertIs(primary.__context__, context)

    def test_single_cleanup_keeps_each_tools_existing_aggregate_policy(self):
        for name, operation, kind, owner in self.paths():
            with self.subTest(path=name):
                cleanup = OSError("cleanup failed")
                observed = self.observe(operation, None, (cleanup,))
                if name == "browser":
                    self.assertIs(observed, cleanup)
                else:
                    self.assertIs(type(observed), kind)
                    self.assertIs(observed.__cause__, cleanup)
                    self.assertEqual(observed.cleanup, (cleanup,))
                    self.assert_owner(observed, name, owner)

    def test_primary_and_cleanup_keep_each_tools_existing_raise_policy(self):
        for name, operation, kind, owner in self.paths():
            with self.subTest(path=name):
                primary = OSError("capture failed")
                previous = RuntimeError("earlier cause")
                context = RuntimeError("earlier context")
                primary.__cause__, primary.__context__ = previous, context
                cleanup = OSError("cleanup failed")
                observed = self.observe(operation, primary, (cleanup,))
                aggregate = observed if name == "browser" else observed.__cause__
                self.assertIs(type(aggregate), kind)
                self.assertIs(aggregate.primary, primary)
                self.assertEqual(aggregate.cleanup, (cleanup,))
                self.assertIs(aggregate.previous_cause, previous)
                self.assertIs(aggregate.previous_context, context)
                self.assertIsNone(aggregate.interruption_cause)
                self.assertIsNone(aggregate.interruption_context)
                self.assert_owner(aggregate, name, owner)
                if name == "browser":
                    self.assertIs(aggregate.__cause__, primary)
                else:
                    self.assertIs(observed, primary)

    def test_interruptions_keep_identity_chain_and_retained_owner(self):
        for name, operation, kind, owner in self.paths():
            for interruption_type in (
                asyncio.CancelledError,
                KeyboardInterrupt,
                SystemExit,
            ):
                for source in ("primary", "cleanup"):
                    with self.subTest(
                        path=name, interruption=interruption_type, source=source
                    ):
                        interruption = interruption_type("interrupted")
                        previous = RuntimeError("interruption cause")
                        context = RuntimeError("interruption context")
                        interruption.__cause__, interruption.__context__ = (
                            previous,
                            context,
                        )
                        primary = (
                            interruption
                            if source == "primary"
                            else OSError("capture failed")
                        )
                        cleanup = (
                            (OSError("cleanup failed"), interruption)
                            if source == "cleanup"
                            else (OSError("cleanup failed"),)
                        )
                        observed = self.observe(operation, primary, cleanup)
                        self.assertIs(observed, interruption)
                        aggregate = observed.__cause__
                        self.assertIs(type(aggregate), kind)
                        self.assertIs(aggregate.primary, primary)
                        self.assertEqual(aggregate.cleanup, cleanup)
                        self.assertIs(aggregate.interruption_cause, previous)
                        self.assertIs(aggregate.interruption_context, context)
                        self.assert_owner(aggregate, name, owner)

    def test_unknown_base_exception_keeps_the_existing_non_interruption_policy(self):
        class OtherControlFlow(BaseException):
            pass

        for name, operation, kind, _owner in self.paths():
            with self.subTest(path=name):
                primary = OSError("capture failed")
                cleanup = OtherControlFlow("custom control flow")
                observed = self.observe(operation, primary, (cleanup,))
                aggregate = observed if name == "browser" else observed.__cause__
                self.assertIs(type(aggregate), kind)
                self.assertEqual(aggregate.cleanup, (cleanup,))
                self.assertIsNone(aggregate.interruption_cause)
                self.assertIsNone(aggregate.interruption_context)

    def test_primary_interruption_precedes_a_cleanup_interruption(self):
        for name, operation, kind, _owner in self.paths():
            with self.subTest(path=name):
                primary = KeyboardInterrupt("primary")
                cleanup = SystemExit("cleanup")
                observed = self.observe(operation, primary, (cleanup,))
                self.assertIs(observed, primary)
                self.assertIs(type(observed.__cause__), kind)
                self.assertEqual(observed.__cause__.cleanup, (cleanup,))

    def test_duplicate_primary_keeps_each_tools_existing_filter_policy(self):
        for name, operation, kind, _owner in self.paths():
            with self.subTest(path=name):
                primary = OSError("capture failed")
                observed = self.observe(operation, primary, (primary,))
                if name == "browser":
                    self.assertIs(type(observed), kind)
                    self.assertEqual(observed.cleanup, (primary,))
                else:
                    self.assertIs(observed, primary)
                    self.assertIsNone(observed.__cause__)
