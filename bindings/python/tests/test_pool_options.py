"""Pool options preserve defaults and affect real admission and retention."""

import asyncio
import dataclasses
import math
import sys
import types
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class PoolFacadeTests(unittest.TestCase):
    def test_explicit_fields_are_frozen_and_only_present_pool_is_forwarded(self):
        options = FACADE.PoolOptions
        settings = options(
            max_retained_http1_connections=1,
            max_concurrent_http1_requests_per_origin=2,
            max_pending_http1_requests_per_origin=3,
            max_retained_http2_connections=4,
            max_concurrent_http2_requests_per_origin=5,
            max_pending_http2_requests_per_origin=6,
            max_http2_connections_per_origin=7,
            max_retained_http3_connections=8,
            max_concurrent_http3_requests_per_origin=9,
            max_pending_http3_requests_per_origin=10,
            max_http3_connections_per_origin=8,
            negotiated_setup_wait_limit=0.125,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            settings.max_http2_connections_per_origin = 1
        calls = []

        def native(*args, **kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(cookies=object())

        with patch.object(FACADE._native, "NativeClient", native, create=True):
            FACADE.AsyncClient(profile="exact", protocol="h1")
            FACADE.AsyncClient(profile="exact", protocol="h1", pool=options())
            FACADE.AsyncClient(profile="exact", protocol="h1", pool=settings)
        self.assertNotIn("pool", calls[0])
        self.assertEqual(calls[1]["pool"], options())
        self.assertIs(calls[2]["pool"], settings)
        self.assertEqual(
            options(negotiated_setup_wait_limit=0).negotiated_setup_wait_limit, 0
        )
        options(max_retained_http1_connections=sys.maxsize * 2 + 1)

    def test_exact_numeric_validation_and_revalidation_precede_native_work(self):
        class Coerce:
            def __index__(self):
                raise AssertionError("private")

            def __float__(self):
                raise AssertionError("private")

        class Integer(int):
            pass

        options = FACADE.PoolOptions
        for field in dataclasses.fields(options):
            values = (True, "private", Coerce(), Integer(1))
            invalid_numbers = (-1, math.inf, math.nan, 10**1000)
            if field.name != "negotiated_setup_wait_limit":
                values += (1.0,)
                invalid_numbers = (0, -1, sys.maxsize * 2 + 2)
            for value in values + invalid_numbers:
                with self.subTest(field=field.name, value=type(value)):
                    with self.assertRaises((TypeError, ValueError)) as caught:
                        options(**{field.name: value})
                    self.assertNotIn("private", str(caught.exception))
        with patch.object(FACADE._native, "NativeClient", create=True) as native:
            with self.assertRaises(TypeError):
                FACADE.AsyncClient(profile="exact", protocol="h1", pool={})
            value = options()
            object.__setattr__(value, "max_pending_http3_requests_per_origin", True)
            with self.assertRaises(TypeError):
                FACADE.AsyncClient(profile="exact", protocol="h1", pool=value)
            native.assert_not_called()


class PoolPublicTests(unittest.TestCase):
    def test_retained_entry_limit_changes_reuse_and_survives_fork_and_restore(self):
        from phantom_http import Client, PoolOptions
        from test_settings_transport import PROFILE, peer

        for maximum in (1, 2):
            with (
                self.subTest(maximum=maximum),
                peer() as first,
                peer() as other,
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    timeout_ms=5000,
                    pool=PoolOptions(max_retained_http1_connections=maximum),
                ) as source,
            ):
                snapshot = source.export_session(b"x" * 32)
                with (
                    source.fork() as fork,
                    source.restore_session(snapshot, b"x" * 32) as restored,
                ):
                    for owner in (source, fork, restored):
                        start = len(first.requests)
                        for url in (first.url, other.url, first.url):
                            with owner.request("GET", url) as response:
                                self.assertEqual(response.read(max_bytes=5), b"hello")
                        addresses = [request[1] for request in first.requests[start:]]
                        self.assertEqual(len(addresses), 2)
                        self.assertEqual(addresses[0] == addresses[1], maximum == 2)

    def test_native_boundary_and_core_policy_bounds_remain_recoverable(self):
        from phantom_http import Client, Error, PoolOptions, _native
        from test_settings_transport import PROFILE

        for name, value in (
            ("max_retained_http1_connections", True),
            ("max_retained_http1_connections", 0),
            ("max_retained_http1_connections", 1.0),
            ("max_retained_http1_connections", 1 << 128),
            ("negotiated_setup_wait_limit", True),
        ):
            settings = PoolOptions()
            object.__setattr__(settings, name, value)
            with self.subTest(name=name, value=value):
                with self.assertRaises(_native.NativeError) as caught:
                    _native.NativeClient(PROFILE, "h1", pool=settings)
                self.assertEqual(caught.exception.args[0], "input")
        for settings in (
            PoolOptions(max_http3_connections_per_origin=9),
            PoolOptions(max_pending_http2_requests_per_origin=sys.maxsize),
            PoolOptions(negotiated_setup_wait_limit=1e300),
        ):
            with self.subTest(settings=settings), self.assertRaises(Error) as caught:
                Client(profile=PROFILE, protocol="h1", pool=settings)
            self.assertEqual(caught.exception.category, "input")
        # HTTP/2 has no invented eight-connection cap; an explicit zero wait is valid.
        with Client(
            profile=PROFILE,
            protocol="h2",
            pool=PoolOptions(
                max_http2_connections_per_origin=9,
                negotiated_setup_wait_limit=0,
            ),
        ):
            pass


class AsyncPoolPublicTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_body_holds_pool_slot_pending_limit_and_cancel_release_it(
        self,
    ):
        from phantom_http import (
            AsyncClient,
            Error,
            PoolOptions,
            RequestDiagnostics,
            TimeoutOverrides,
        )
        from test_settings_transport import PROFILE, peer

        with peer() as origin:
            async with AsyncClient(
                profile=PROFILE,
                protocol="h1",
                timeout_ms=5000,
                pool=PoolOptions(
                    max_concurrent_http1_requests_per_origin=1,
                    max_pending_http1_requests_per_origin=1,
                ),
            ) as client:
                response = await client.request(
                    "GET",
                    origin.url + "/live",
                    timeouts=TimeoutOverrides(total=None, connect=5, response_head=5),
                )
                pending = None
                try:
                    self.assertTrue(await asyncio.to_thread(origin.entered.wait, 5))
                    observer = RequestDiagnostics()
                    pending = asyncio.create_task(
                        client.request("GET", origin.url, diagnostics=observer)
                    )

                    async def wait_for_pool_admission():
                        while True:
                            timeline = observer.snapshot()
                            if timeline is not None and any(
                                event.phase == "pool_admission"
                                and event.outcome == "pending"
                                for event in timeline.events
                            ):
                                return
                            await asyncio.sleep(0.001)

                    await asyncio.wait_for(wait_for_pool_admission(), 2)

                    # The diagnostic phase begins before the pending guard is acquired.
                    async def require_pending_capacity():
                        while True:
                            try:
                                unexpected = await client.request(
                                    "GET",
                                    origin.url,
                                    timeouts=TimeoutOverrides(pool_admission=0),
                                )
                            except Error as failure:
                                if failure.kind == "capacity":
                                    return
                                self.assertEqual(failure.kind, "timeout")
                                self.assertEqual(
                                    failure.timeout_phase, "pool_admission"
                                )
                            else:
                                await unexpected.aclose()
                                self.fail("overflow request reached the peer")
                            await asyncio.sleep(0)

                    await asyncio.wait_for(require_pending_capacity(), 2)
                    self.assertEqual(len(origin.requests), 1)
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                    pending = None
                    self.assertEqual(await response.read_chunk(1), b"a")
                    await response.aclose()
                    origin.release.set()
                    async with await client.request("GET", origin.url) as healthy:
                        self.assertEqual(await healthy.read(max_bytes=5), b"hello")
                    self.assertEqual(len(origin.requests), 2)
                finally:
                    if pending is not None:
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
                    await response.aclose()
                    origin.release.set()
