"""Caller retry policies use native eligibility, scheduling and request budgets."""

import asyncio
import dataclasses
import http.server
import math
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    AttemptBudget,
    AttemptBudgetExhausted,
    Client,
    ConnectionRetry,
    RedirectPolicy,
    RetryPolicy,
    StatusRetry,
    TimeoutOverrides,
)
from test_client import OPTIONS
from test_settings_transport import peer


class RetryFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_policy_is_owned_and_forwarded_with_whole_replacement(self):
        maximum = 2 * sys.maxsize + 1
        policy = RetryPolicy(
            connection_failures=ConnectionRetry(
                maximum=maximum, delay=0, maximum_delay=2, full_jitter=True
            ),
            reused_connection_replay=True,
            unprocessed_replays=maximum,
            status_retry=StatusRetry(
                statuses=(503, 429, 503),
                maximum=maximum,
                delay=0.25,
                maximum_delay=4,
                full_jitter=True,
                retry_after_limit=8,
            ),
            maximum_retries=0,
            http2_fallback=True,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.maximum_retries = 3
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.connection_failures.maximum = 3
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.status_retry.statuses = ()
        constructors, requests = [], []

        class Native:
            cookies = object()

            def __init__(self, *arguments):
                constructors.append(arguments)

            async def request(self, *arguments):
                requests.append(arguments)
                return types.SimpleNamespace(status=200, protocol="h1", headers=[])

        with patch.object(phantom_http._native, "NativeClient", Native):
            client = AsyncClient(**OPTIONS, retry_policy=policy)
            self.assertIs(constructors[0][-1], policy)
            for replacement in (None, RetryPolicy.none(), policy):
                await client.request(
                    "GET", "http://origin.invalid", retry_policy=replacement
                )
                self.assertIs(requests[-1][-1], replacement)
            with self.assertRaises(TypeError):
                AsyncClient(**OPTIONS, retry_policy={})
            with self.assertRaises(TypeError):
                await client.request("GET", "http://origin.invalid", retry_policy={})
            self.assertEqual((len(constructors), len(requests)), (1, 3))

    async def test_invalid_counts_durations_flags_and_statuses_are_redacted(self):
        for value in (0, -1, 2 * sys.maxsize + 2, True, 1.5, "private"):
            for make in (
                lambda value=value: ConnectionRetry(maximum=value, delay=0),
                lambda value=value: StatusRetry(
                    statuses=(503,), maximum=value, delay=0
                ),
                lambda value=value: RetryPolicy(unprocessed_replays=value),
            ):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    make()
                self.assertNotIn("private", str(caught.exception))
        for value in (-1, math.inf, math.nan, 10**1000, True, "private"):
            for make in (
                lambda value=value: ConnectionRetry(maximum=1, delay=value),
                lambda value=value: StatusRetry(
                    statuses=(503,), maximum=1, delay=value
                ),
                lambda value=value: StatusRetry(
                    statuses=(503,), maximum=1, delay=0, retry_after_limit=value
                ),
            ):
                with self.assertRaises((TypeError, ValueError)):
                    make()
        for options in (
            {"statuses": ()},
            {"statuses": (421,)},
            {"statuses": (200,)},
            {"statuses": [503]},
            {"statuses": (True,)},
            {"statuses": (503,), "maximum_delay": 0.5},
            {"statuses": (503,), "full_jitter": 1},
        ):
            with self.assertRaises((TypeError, ValueError)):
                StatusRetry(maximum=1, delay=1, **options)
        for options in (
            {"connection_failures": {}},
            {"status_retry": {}},
            {"maximum_retries": -1},
            {"maximum_retries": True},
            {"reused_connection_replay": 1},
            {"http2_fallback": 1},
        ):
            with self.assertRaises((TypeError, ValueError)):
                RetryPolicy(**options)
        with self.assertRaises(ValueError):
            ConnectionRetry(maximum=1, delay=1, maximum_delay=0)
        self.assertEqual(RetryPolicy.none(), RetryPolicy())


class RetryHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def do_PUT(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append(
            (self.command, self.path, body, self.client_address)
        )
        count = sum(row[1] == self.path for row in self.server.requests)
        if self.path == "/reused" and count == 1:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        status = (
            503
            if self.path in ("/always", "/wait", "/after", "/malformed")
            or count == 1
            and self.path == "/once"
            else 200
        )
        if self.path in ("/redirect", "/final-retry"):
            status = 503 if count == 1 else 302 if self.path == "/redirect" else 200
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/final-retry")
        if self.path == "/after":
            self.send_header("Retry-After", "120")
        elif self.path == "/malformed":
            self.send_header("Retry-After", "not-a-delay")
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")
        self.wfile.flush()
        if self.path == "/wait":
            self.server.entered.set()


def status_policy(**options):
    return RetryPolicy(
        status_retry=StatusRetry(statuses=(503,), maximum=2, delay=0, **options)
    )


class SyncRetryTests(unittest.TestCase):
    def test_default_inherit_disable_shared_cap_and_fork_use_actual_attempts(self):
        with peer() as server:
            server.RequestHandlerClass = RetryHandler
            with Client(
                **OPTIONS, retry_policy=status_policy(maximum_delay=1, full_jitter=True)
            ) as client:
                for override, expected in (
                    (RetryPolicy.none(), 1),
                    (None, 3),
                    (
                        RetryPolicy(
                            maximum_retries=1,
                            status_retry=StatusRetry(
                                statuses=(503,), maximum=2, delay=0
                            ),
                        ),
                        2,
                    ),
                    (
                        RetryPolicy(
                            maximum_retries=0,
                            status_retry=StatusRetry(
                                statuses=(503,), maximum=2, delay=0
                            ),
                        ),
                        1,
                    ),
                ):
                    before = len(server.requests)
                    with client.request(
                        "GET", server.url + "/always", retry_policy=override
                    ) as response:
                        self.assertEqual(response.status, 503)
                        self.assertEqual(response.connection_setup_retries, 0)
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(len(server.requests) - before, expected)
                with client.fork() as fork:
                    before = len(server.requests)
                    with fork.request("GET", server.url + "/always") as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(len(server.requests) - before, 3)
            before = len(server.requests)
            with (
                Client(**OPTIONS) as client,
                client.request("GET", server.url + "/always") as response,
            ):
                self.assertEqual(response.status, 503)
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(len(server.requests), before + 1)

    def test_retry_cap_spans_redirects_and_success_still_reports_actual_metadata(self):
        with peer() as server:
            server.RequestHandlerClass = RetryHandler
            with Client(
                **OPTIONS,
                retry_policy=RetryPolicy(
                    status_retry=StatusRetry(statuses=(503,), maximum=3, delay=0),
                    maximum_retries=1,
                ),
                redirect_policy=RedirectPolicy.limited(1),
            ) as client:
                with client.request("GET", server.url + "/redirect") as response:
                    self.assertEqual(response.status, 503)
                    self.assertEqual(response.redirects_followed, 1)
                    self.assertEqual(response.connection_setup_retries, 0)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                self.assertEqual(
                    [row[1] for row in server.requests],
                    ["/redirect", "/redirect", "/final-retry"],
                )
                with client.request("GET", server.url + "/once") as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                self.assertEqual(
                    [row[1] for row in server.requests[-2:]], ["/once", "/once"]
                )

    def test_status_replay_requires_idempotence_and_replayable_body(self):
        with peer() as server, tempfile.TemporaryDirectory() as directory:
            server.RequestHandlerClass = RetryHandler
            with Client(**OPTIONS, retry_policy=status_policy()) as client:
                for method, expected in (("PUT", 3), ("POST", 1)):
                    before = len(server.requests)
                    with client.request(
                        method, server.url + "/always", body=b"payload"
                    ) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(len(server.requests) - before, expected)
                    self.assertTrue(
                        all(row[2] == b"payload" for row in server.requests[before:])
                    )
                path = Path(directory) / "body.bin"
                path.write_bytes(b"one-shot")
                before = len(server.requests)
                with client.request(
                    "PUT", server.url + "/always", upload=path
                ) as response:
                    self.assertEqual(response.status, 503)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                self.assertEqual(len(server.requests), before + 1)
                self.assertEqual(server.requests[-1][2], b"one-shot")

    def test_reused_connection_replay_keeps_route_and_uses_a_fresh_connection(self):
        with peer() as server:
            server.RequestHandlerClass = RetryHandler
            with Client(
                **OPTIONS, retry_policy=RetryPolicy(reused_connection_replay=True)
            ) as client:
                with client.request("GET", server.url + "/warmup") as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                with client.request("GET", server.url + "/reused") as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(
                [row[1] for row in server.requests], ["/warmup", "/reused", "/reused"]
            )
            self.assertEqual(server.requests[0][3], server.requests[1][3])
            self.assertNotEqual(server.requests[1][3], server.requests[2][3])


class AsyncRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_after_limit_malformed_fallback_and_total_deadline(self):
        with peer() as server:
            server.RequestHandlerClass = RetryHandler
            async with AsyncClient(**OPTIONS) as client:
                for path, policy, expected, timeouts in (
                    ("/after", status_policy(retry_after_limit=30), 1, None),
                    ("/malformed", status_policy(retry_after_limit=30), 3, None),
                    (
                        "/always",
                        RetryPolicy(
                            status_retry=StatusRetry(
                                statuses=(503,), maximum=2, delay=30
                            )
                        ),
                        1,
                        TimeoutOverrides(total=1),
                    ),
                ):
                    before = len(server.requests)
                    async with await client.request(
                        "GET", server.url + path, retry_policy=policy, timeouts=timeouts
                    ) as response:
                        self.assertEqual(response.status, 503)
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(len(server.requests) - before, expected)

    async def test_shared_attempt_budget_and_cancelled_delay_stop_another_send(self):
        with peer() as server:
            server.RequestHandlerClass = RetryHandler
            async with AsyncClient(**OPTIONS) as client:
                with self.assertRaises(AttemptBudgetExhausted):
                    await client.request(
                        "GET",
                        server.url + "/always",
                        retry_policy=status_policy(),
                        budget=AttemptBudget(1),
                    )
                self.assertEqual(len(server.requests), 1)
                server.entered.clear()
                pending = asyncio.create_task(
                    client.request(
                        "GET",
                        server.url + "/wait",
                        timeouts=TimeoutOverrides(total=None),
                        retry_policy=RetryPolicy(
                            status_retry=StatusRetry(
                                statuses=(503,), maximum=1, delay=30
                            )
                        ),
                    )
                )
                try:
                    self.assertTrue(await asyncio.to_thread(server.entered.wait, 5))
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                    async with await client.request(
                        "GET", server.url + "/healthy"
                    ) as response:
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(
                        [row[1] for row in server.requests],
                        ["/always", "/wait", "/healthy"],
                    )
                finally:
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
