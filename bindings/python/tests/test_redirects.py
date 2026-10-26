"""Core redirects preserve method, replay, credentials and bounded history."""

import asyncio
import dataclasses
import http.server
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    AsyncResponse,
    AttemptBudget,
    AttemptBudgetExhausted,
    Client,
    Error,
    RedirectHistory,
    RedirectPolicy,
    Response,
)
from test_client import OPTIONS
from test_settings_transport import peer


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append(
            (self.command, self.path, body, list(self.headers.raw_items()))
        )
        status, location = {
            "/start?private=%2F": (302, "middle?encoded=%2F"),
            "/middle?encoded=%2F": (302, "final"),
            "/change": (303, "/final"),
            "/preserve": (307, "/final"),
            "/permanent": (308, "/final"),
            "/loop": (302, "/loop"),
            "/external": (302, getattr(self.server, "destination", "/final")),
            "/back": (302, getattr(self.server, "destination", "/final")),
            "/duplicate": (302, "/final"),
        }.get(self.path, (200, None))
        if self.path == "/held":
            self.server.entered.set()
            if not self.server.release.wait(5):
                raise AssertionError("redirect destination was not released")
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
            if self.path == "/duplicate":
                self.send_header("Location", "/other")
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")
        self.wfile.flush()


class RedirectFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_typed_policies_inherit_disable_and_history_are_owned_and_redacted(
        self,
    ):
        self.assertEqual(RedirectPolicy.none().maximum_hops, 0)
        self.assertEqual(
            RedirectPolicy.limited(2 * sys.maxsize + 1).maximum_hops,
            2 * sys.maxsize + 1,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RedirectPolicy.limited(1).maximum_hops = 2
        for value in (True, "private", None, 1.5):
            with self.assertRaises(TypeError):
                RedirectPolicy.limited(value)
        for value in (-1, 0, 2 * sys.maxsize + 2):
            with self.assertRaises(ValueError):
                RedirectPolicy.limited(value)
        constructors, requests = [], []

        class Native:
            cookies = object()

            def __init__(self, *arguments):
                constructors.append(arguments)

            async def request(self, *arguments):
                requests.append(arguments)
                return types.SimpleNamespace(
                    status=200, protocol="h1", headers=[], redirect_history=None
                )

        with patch.object(phantom_http._native, "NativeClient", Native):
            source = AsyncClient(**OPTIONS, redirect_policy=RedirectPolicy.limited(2))
            self.assertEqual(constructors[0][-2], 2)
            for policy, expected in (
                (None, None),
                (RedirectPolicy.none(), 0),
                (RedirectPolicy.limited(3), 3),
            ):
                await source.request(
                    "GET",
                    "http://origin.invalid",
                    redirect_policy=policy,
                    redirect_history_limit=1,
                )
                self.assertEqual(requests[-1][-3:-1], (expected, 1))
            for value in (0, -1, True, 1.5, 2 * sys.maxsize + 2):
                with self.assertRaises((TypeError, ValueError)):
                    await source.request(
                        "GET", "http://origin.invalid", redirect_history_limit=value
                    )
            with self.assertRaises(TypeError):
                await source.request("GET", "http://origin.invalid", redirect_policy={})
            self.assertEqual(len(requests), 3)
        native = types.SimpleNamespace(
            status=200,
            protocol="h1",
            headers=[],
            redirect_history=(
                [
                    (
                        "https://private.invalid/start",
                        "https://private.invalid/final",
                        "POST",
                        "GET",
                        303,
                    )
                ],
                1,
            ),
        )
        asynchronous = AsyncResponse(native)
        for response in (asynchronous, Response(None, asynchronous)):
            retained = response.redirect_history
            self.assertIsInstance(retained, RedirectHistory)
            self.assertEqual(retained.omitted_hops, 1)
            self.assertEqual(
                retained.entries[0].from_url, "https://private.invalid/start"
            )
            self.assertNotIn("private", repr(retained))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                retained.entries[0].status = 200
            with self.assertRaises(AttributeError):
                response.redirect_history = None


class SyncRedirectTests(unittest.TestCase):
    def test_client_policy_request_override_and_bounded_relative_history(self):
        with peer() as server:
            server.RequestHandlerClass = RedirectHandler
            with Client(**OPTIONS, redirect_policy=RedirectPolicy.limited(2)) as client:
                start = server.url + "/start?private=%2F"
                with client.request("GET", start, redirect_history_limit=1) as response:
                    self.assertEqual(response.url, server.url + "/final")
                    self.assertEqual(response.redirects_followed, 2)
                    retained = response.redirect_history
                    self.assertEqual(len(retained.entries), 1)
                    self.assertEqual(retained.omitted_hops, 1)
                    hop = retained.entries[0]
                    self.assertEqual(
                        (hop.from_url, hop.to_url),
                        (start, server.url + "/middle?encoded=%2F"),
                    )
                    self.assertEqual(
                        (hop.status, hop.method, hop.next_method), (302, "GET", "GET")
                    )
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(response.redirect_history, retained)
                    self.assertNotIn("private", repr(retained))
                with client.request(
                    "GET",
                    start,
                    redirect_policy=RedirectPolicy.none(),
                    redirect_history_limit=1,
                ) as response:
                    self.assertEqual(response.status, 302)
                    self.assertEqual(response.redirects_followed, 0)
                    self.assertEqual(response.redirect_history, RedirectHistory((), 0))
                with client.request("GET", server.url + "/final") as response:
                    self.assertIsNone(response.redirect_history)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                with client.fork() as fork, fork.request("GET", start) as response:
                    self.assertEqual(response.redirects_followed, 2)
                    self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(
                [row[1] for row in server.requests],
                [
                    "/start?private=%2F",
                    "/middle?encoded=%2F",
                    "/final",
                    "/start?private=%2F",
                    "/final",
                    "/start?private=%2F",
                    "/middle?encoded=%2F",
                    "/final",
                ],
            )

    def test_303_changes_method_307_replays_bytes_and_one_shot_file_is_not_replayed(
        self,
    ):
        with peer() as server, tempfile.TemporaryDirectory() as directory:
            server.RequestHandlerClass = RedirectHandler
            with Client(**OPTIONS) as client:
                for path, final_method, final_body in (
                    ("/change", "GET", b""),
                    ("/preserve", "POST", b"payload"),
                    ("/permanent", "POST", b"payload"),
                ):
                    with client.request(
                        "POST",
                        server.url + path,
                        body=b"payload",
                        redirect_policy=RedirectPolicy.limited(1),
                        redirect_history_limit=1,
                    ) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                        hop = response.redirect_history.entries[0]
                        self.assertEqual(
                            (hop.method, hop.next_method), ("POST", final_method)
                        )
                    self.assertEqual(
                        server.requests[-1][:3], (final_method, "/final", final_body)
                    )
                path = Path(directory) / "body.bin"
                path.write_bytes(b"one-shot")
                before = len(server.requests)
                with self.assertRaises(Error) as caught:
                    client.request(
                        "POST",
                        server.url + "/preserve",
                        upload=path,
                        redirect_policy=RedirectPolicy.limited(1),
                    )
                self.assertEqual(caught.exception.kind, "request_body")
                self.assertEqual(len(server.requests), before + 1)
                self.assertEqual(
                    server.requests[-1][:3], ("POST", "/preserve", b"one-shot")
                )


class AsyncRedirectTests(unittest.IsolatedAsyncioTestCase):
    async def test_limits_invalid_locations_and_shared_attempt_budget_prevent_extra_hops(
        self,
    ):
        with peer() as server:
            server.RequestHandlerClass = RedirectHandler
            async with AsyncClient(**OPTIONS) as client:
                for path in ("/loop", "/duplicate"):
                    before = len(server.requests)
                    with self.assertRaises(Error) as caught:
                        await client.request(
                            "GET",
                            server.url + path,
                            redirect_policy=RedirectPolicy.limited(1),
                        )
                    self.assertEqual(caught.exception.kind, "redirect")
                    self.assertEqual(
                        len(server.requests) - before, 2 if path == "/loop" else 1
                    )
                before = len(server.requests)
                with self.assertRaises(AttemptBudgetExhausted):
                    await client.request(
                        "GET",
                        server.url + "/start?private=%2F",
                        redirect_policy=RedirectPolicy.limited(2),
                        budget=AttemptBudget(1),
                    )
                self.assertEqual(len(server.requests), before + 1)
                async with await client.request(
                    "GET", server.url + "/final", redirect_history_limit=1
                ) as response:
                    self.assertEqual(response.redirect_history, RedirectHistory((), 0))
                    self.assertEqual(await response.read(max_bytes=5), b"hello")

    async def test_cross_origin_credentials_stay_stripped_on_return_and_cancelled_hop_stops(
        self,
    ):
        with peer() as source, peer() as destination:
            source.RequestHandlerClass = destination.RequestHandlerClass = (
                RedirectHandler
            )
            source.destination = destination.url + "/back"
            destination.destination = source.url + "/final"
            async with AsyncClient(**OPTIONS) as client:
                async with await client.request(
                    "GET",
                    source.url + "/external",
                    headers=[
                        ("Authorization", "secret"),
                        ("Cookie", "private=yes"),
                        ("X-Api-Key", "custom-secret"),
                    ],
                    redirect_policy=RedirectPolicy.limited(
                        2, credential_headers=("x-api-key",)
                    ),
                    redirect_history_limit=2,
                ) as response:
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(response.redirects_followed, 2)
                self.assertEqual(dict(source.requests[0][3])["Authorization"], "secret")
                self.assertEqual(
                    dict(source.requests[0][3])["X-Api-Key"], "custom-secret"
                )
                for request in (destination.requests[0], source.requests[1]):
                    fields = {name.lower(): value for name, value in request[3]}
                    self.assertNotIn("authorization", fields)
                    self.assertNotIn("cookie", fields)
                    self.assertNotIn("x-api-key", fields)
                destination.destination = source.url + "/held"
                pending = asyncio.create_task(
                    client.request(
                        "GET",
                        destination.url + "/back",
                        redirect_policy=RedirectPolicy.limited(1),
                    )
                )
                try:
                    self.assertTrue(await asyncio.to_thread(source.entered.wait, 5))
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                finally:
                    source.release.set()
