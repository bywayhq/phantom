"""Loop-global handler scopes retain caller state across overlapping lifetimes."""

import asyncio
import unittest
from unittest.mock import patch

from scripts.capture import alt_svc_race as race


class HandlerOverlapTests(unittest.IsolatedAsyncioTestCase):
    async def dispatch_failure(self, loop, error):
        dispatched = []
        fired = asyncio.Event()
        actual_dispatch = loop.call_exception_handler

        def observe_dispatch(context):
            dispatched.append(context)
            actual_dispatch(context)

        def raise_callback():
            try:
                raise error
            finally:
                fired.set()

        with patch.object(loop, "call_exception_handler", observe_dispatch):
            handle = loop.call_soon(raise_callback)
            try:
                await asyncio.wait_for(fired.wait(), 5)
            finally:
                handle.cancel()

        self.assertEqual(len(dispatched), 1, "actual Handle context was not dispatched")
        context = dispatched[0]
        self.assertIs(context["exception"], error)
        self.assertIs(context["handle"], handle)
        return context

    def assert_forwarded(self, loop, reports, context):
        matching = [entry for entry in reports if entry[1] is context]
        self.assertEqual(len(matching), 1, "caller did not receive the exact context")
        self.assertIs(matching[0][0], loop)

    async def test_out_of_order_scope_exit_restores_the_original_caller_handler(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        reports = []

        def H(active_loop, context):
            reports.append((active_loop, context))

        active = []
        loop.set_exception_handler(H)
        try:
            scope_a = race.capture_exception_handler()
            scope_a.__enter__()
            active.append(scope_a)
            scope_b = race.capture_exception_handler()
            scope_b.__enter__()
            active.append(scope_b)

            scope_a.__exit__(None, None, None)
            active.remove(scope_a)
            failure = RuntimeError(
                "unrelated callback while later scope remains active"
            )
            context = await self.dispatch_failure(loop, failure)
            forwarded_before_backup = list(reports)

            scope_b.__exit__(None, None, None)
            active.remove(scope_b)
            restored_before_backup = loop.get_exception_handler()

            self.assert_forwarded(loop, forwarded_before_backup, context)
            self.assertIs(
                restored_before_backup,
                H,
                "out-of-order scopes discarded the original caller handler",
            )
        finally:
            try:
                for scope in reversed(active):
                    scope.__exit__(None, None, None)
            finally:
                loop.set_exception_handler(original)

    async def test_nested_lifo_scopes_restore_each_active_handler_then_the_caller(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        reports = []

        def H(active_loop, context):
            reports.append((active_loop, context))

        loop.set_exception_handler(H)
        try:
            with race.capture_exception_handler():
                handler_a = loop.get_exception_handler()
                with race.capture_exception_handler():
                    handler_b = loop.get_exception_handler()
                    context_b = await self.dispatch_failure(
                        loop, RuntimeError("unrelated callback in inner scope")
                    )
                restored_a = loop.get_exception_handler()
                context_a = await self.dispatch_failure(
                    loop, RuntimeError("unrelated callback in outer scope")
                )
            restored_before_backup = loop.get_exception_handler()
            forwarded_before_backup = list(reports)

            self.assertIsNot(handler_a, H)
            self.assertIsNot(handler_b, handler_a)
            self.assertIs(restored_a, handler_a)
            self.assert_forwarded(loop, forwarded_before_backup, context_b)
            self.assert_forwarded(loop, forwarded_before_backup, context_a)
            self.assertIs(restored_before_backup, H)
        finally:
            loop.set_exception_handler(original)

    async def test_later_active_scope_keeps_filtering_after_earlier_scope_exits(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        reports = []

        def H(active_loop, context):
            reports.append((active_loop, context))

        active = []
        loop.set_exception_handler(H)
        try:
            scope_a = race.capture_exception_handler()
            scope_a.__enter__()
            active.append(scope_a)
            scope_b = race.capture_exception_handler()
            scope_b.__enter__()
            active.append(scope_b)

            scope_a.__exit__(None, None, None)
            active.remove(scope_a)
            reset = ConnectionResetError("controlled reset in later active scope")
            reset_context = await self.dispatch_failure(loop, reset)
            forwarded_before_backup = list(reports)

            scope_b.__exit__(None, None, None)
            active.remove(scope_b)
            restored_before_backup = loop.get_exception_handler()

            self.assertFalse(
                any(entry[1] is reset_context for entry in forwarded_before_backup),
                "earlier scope exit removed the later active reset filter",
            )
            self.assertIs(restored_before_backup, H)
        finally:
            try:
                for scope in reversed(active):
                    scope.__exit__(None, None, None)
            finally:
                loop.set_exception_handler(original)

    async def test_active_scope_filters_resets_and_forwards_unrelated_context(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        reports = []

        def H(active_loop, context):
            reports.append((active_loop, context))

        loop.set_exception_handler(H)
        try:
            with race.capture_exception_handler():
                active_handler = loop.get_exception_handler()
                failure = RuntimeError("unrelated callback in one active scope")
                context = await self.dispatch_failure(loop, failure)
                reset = ConnectionResetError("controlled active peer reset")
                reset_context = await self.dispatch_failure(loop, reset)
                forwarded_before_backup = list(reports)
            restored_before_backup = loop.get_exception_handler()

            self.assertIsNot(active_handler, H)
            self.assert_forwarded(loop, forwarded_before_backup, context)
            self.assertFalse(
                any(entry[1] is reset_context for entry in forwarded_before_backup)
            )
            self.assertIs(restored_before_backup, H)
        finally:
            loop.set_exception_handler(original)
