"""Selected live state is shared while pools, loops and shutdown stay independent."""

import asyncio
import dataclasses
import threading
import unittest
from unittest.mock import patch

import phantom_http
from phantom_http import (
    AsyncClient,
    Client,
    Error,
    SessionSharing,
    TimeoutError,
    Timeouts,
    Trust,
)
from test_client import OPTIONS, PROFILE, Handler, server
from test_settings_transport import ROOT, peer


class SharingHandler(Handler):
    def reply(self, body, *, status=200):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        learned = {
            "/base/source": "learned=source; Path=/",
            "/base/fork": "learned=fork; Path=/",
        }.get(self.path)
        if learned is not None:
            self.send_header("Set-Cookie", learned)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


class SharingFacadeTests(unittest.TestCase):
    def test_sharing_is_frozen_boolean_configuration(self):
        selection = SessionSharing()
        self.assertEqual(dataclasses.astuple(selection), (False,) * 5)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            selection.cookies = True
        for name in ("cookies", "dns", "client_hints", "discovery", "tickets"):
            for value in (0, 1, None, "secret"):
                with self.subTest(name=name, value=value), self.assertRaises(TypeError):
                    SessionSharing(**{name: value})

    def test_native_fork_is_wrapped_without_rebuilding_config_and_has_own_loop(self):
        constructions = []
        selections = []

        class Native:
            cookies = object()

            def __init__(self, *arguments):
                constructions.append(arguments)
                self.is_closed = False

            def fork(self, *flags):
                selections.append(flags)
                child = object.__new__(Native)
                child.is_closed = False
                return child

            async def shutdown(self, _):
                self.is_closed = True

        sharing = SessionSharing(cookies=True, dns=True, tickets=True)
        with patch.object(phantom_http._native, "NativeClient", Native):
            source = Client(**OPTIONS)
            child = source.fork(sharing=sharing)
            try:
                self.assertEqual(len(constructions), 1)
                self.assertEqual(selections, [(True, True, False, False, True)])
                self.assertIsNot(source._loop, child._loop)
                source.close()
                self.assertFalse(child.is_closed)
                reopened = source.fork()
                try:
                    self.assertFalse(reopened.is_closed)
                    self.assertEqual(selections[-1], (False,) * 5)
                finally:
                    reopened.close()
                failures = []

                def wrong_thread():
                    try:
                        source.fork()
                    except RuntimeError as error:
                        failures.append(str(error))

                thread = threading.Thread(target=wrong_thread)
                thread.start()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(failures), 1)
                self.assertIn("creating thread", failures[0])
                with self.assertRaises(TypeError):
                    source.fork(sharing={})
                self.assertEqual(len(selections), 2)
            finally:
                source.close()
                child.close()
            self.assertTrue(child._loop.is_closed())

    def test_sync_fork_rejects_a_running_event_loop(self):
        source = object.__new__(Client)
        source._thread = threading.get_ident()

        async def check():
            with self.assertRaisesRegex(RuntimeError, "AsyncClient"):
                source.fork()

        asyncio.run(check())


class SyncSharingTests(unittest.TestCase):
    def test_live_cookies_independent_pools_and_retained_template_base_url(self):
        with server() as (origin, url):
            origin.RequestHandlerClass = SharingHandler
            with Client(**OPTIONS, base_url=url + "/base/", context="fetch") as source:
                with source.request("GET", "source") as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                with (
                    source.fork(sharing=SessionSharing(cookies=True)) as shared,
                    source.fork() as isolated,
                ):
                    self.assertEqual(shared.cookies.for_url(url), "learned=source")
                    self.assertIsNone(isolated.cookies.for_url(url))
                    with shared.request("GET", "fork") as response:
                        self.assertEqual(response.url, url + "/base/fork")
                        self.assertEqual(response.protocol, "h1")
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(source.cookies.for_url(url), "learned=fork")
                    with source.request("GET", "source") as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    self.assertEqual(shared.cookies.for_url(url), "learned=source")
                    shared.cookies.clear()
                    self.assertIsNone(source.cookies.for_url(url))
                    self.assertIsNone(shared.cookies.for_url(url))
                    with isolated.request("GET", "isolated") as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    shared.close()
                    with source.request("GET", "after-child-close") as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                source.close()
                with source.fork() as reopened:
                    self.assertFalse(reopened.is_closed)
                    with reopened.request("GET", "reopened") as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
            requests = origin.requests
            self.assertEqual(requests[0][1], requests[2][1])
            self.assertEqual(requests[0][1], requests[4][1])
            self.assertEqual(len({request[1] for request in requests}), 4)
            self.assertNotIn("Cookie", dict(requests[3][2]))
            for _, _, headers in requests:
                self.assertEqual(dict(headers).get("Sec-Fetch-Mode"), "cors")

    def test_disabled_cookies_stay_disabled_even_when_selected_for_sharing(self):
        with (
            server() as (_, url),
            Client(**{**OPTIONS, "cookies": False}) as source,
            source.fork(sharing=SessionSharing(cookies=True)) as child,
        ):
            with child.request("GET", url) as response:
                self.assertEqual(response.read(max_bytes=5), b"hello")
            for client in (source, child):
                with self.assertRaises(Error) as caught:
                    client.cookies.for_url(url)
                self.assertEqual(caught.exception.kind, "cookies_disabled")


class AsyncSharingTests(unittest.IsolatedAsyncioTestCase):
    async def test_fork_survives_source_close_and_closed_source_can_fork(self):
        with server() as (_, url):
            async with AsyncClient(**OPTIONS) as source:
                async with source.fork(sharing=SessionSharing(cookies=True)) as child:
                    await source.close()
                    self.assertFalse(child.is_closed)
                    async with await child.request("GET", url) as response:
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(source.cookies.for_url(url), "seen=yes")
                async with source.fork() as reopened:
                    self.assertFalse(reopened.is_closed)
                    self.assertIsNone(reopened.cookies.for_url(url))
                    async with await reopened.request("GET", url) as response:
                        self.assertEqual(await response.read(max_bytes=5), b"hello")

    async def test_fork_retains_tls_roots_and_phase_timeout(self):
        with peer(tls=True) as origin:
            origin.release.clear()
            async with (
                AsyncClient(
                    profile=PROFILE,
                    protocol="h1",
                    base_url=origin.url + "/",
                    trust=Trust(roots=(ROOT,)),
                    timeouts=Timeouts(response_head=0.05, total=5),
                ) as source,
                source.fork() as child,
            ):
                async with await child.request("GET", "ready") as response:
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
                with self.assertRaises(TimeoutError) as caught:
                    await child.request("GET", "head")
                self.assertEqual(caught.exception.timeout_phase, "response_head")
                self.assertTrue(origin.entered.is_set())
                origin.release.set()
