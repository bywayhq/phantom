"""Per-opening routes against independent CONNECT and WebSocket peers."""

import asyncio
import select
import socket
import unittest
from contextlib import AsyncExitStack
from urllib.parse import urlsplit

from phantom_http import INHERIT, AsyncClient, Client, Proxy, _native
from test_settings_transport import SettingsHandler
from test_settings_transport import peer as proxy_peer
from test_websocket import PROFILE, peer, stalled_handshake


class ConnectHandler(SettingsHandler):
    def do_CONNECT(self):
        self.server.requests.append(
            (self.path, self.client_address, list(self.headers.raw_items()), None)
        )
        if (
            self.server.basic_auth
            and self.headers.get("Proxy-Authorization") != "Basic dXNlcjpwYXNz"
        ):
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="loopback"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        target = urlsplit("//" + self.path)
        if target.hostname != "127.0.0.1" or target.port is None:
            raise AssertionError("CONNECT target must be the loopback WebSocket peer")

        self.close_connection = True
        with socket.create_connection(
            (target.hostname, target.port), timeout=5
        ) as origin:
            self.send_response_only(200)
            self.end_headers()
            self.wfile.flush()
            endpoints = (self.connection, origin)
            while True:
                readable, _, _ = select.select(endpoints, [], [], 5)
                if not readable:
                    raise AssertionError("CONNECT tunnel did not finish")
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = (
                        origin if source is self.connection else self.connection
                    )
                    destination.sendall(data)


def echo(connection):
    for message in connection:
        connection.send(message)


class SynchronousRouteTests(unittest.TestCase):
    def test_inherit_direct_and_authenticated_override_keep_the_client_route(self):
        openings = []

        def observe(_, request):
            openings.append(request.headers.get("Proxy-Authorization"))

        with (
            proxy_peer() as default,
            proxy_peer(basic_auth=True) as override,
            peer(echo, process_request=observe) as (url, _),
        ):
            default.RequestHandlerClass = ConnectHandler
            override.RequestHandlerClass = ConnectHandler
            with Client(profile=PROFILE, context="raw", proxy=default.url) as client:
                for route in (
                    INHERIT,
                    None,
                    Proxy(override.url, username="user", password="pass"),
                    INHERIT,
                ):
                    with client.websocket(url, proxy=route) as stream:
                        stream.send("routed")
                        self.assertEqual(stream.recv(), "routed")

            authority = urlsplit(url).netloc
            self.assertEqual([row[0] for row in default.requests], [authority] * 2)
            self.assertEqual([row[0] for row in override.requests], [authority])
            self.assertEqual(
                [dict(row[2]).get("Proxy-Authorization") for row in override.requests],
                ["Basic dXNlcjpwYXNz"],
            )
            self.assertTrue(
                all(
                    "Proxy-Authorization" not in dict(row[2])
                    for row in default.requests
                )
            )
            self.assertEqual(openings, [None] * 4)


class AsynchronousRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_routes_and_cancelled_setup_preserve_other_sockets(self):
        with (
            proxy_peer() as default,
            proxy_peer() as override,
            peer(echo) as (url, _),
        ):
            default.RequestHandlerClass = ConnectHandler
            override.RequestHandlerClass = ConnectHandler
            async with (
                AsyncClient(
                    profile=PROFILE, context="raw", proxy=default.url
                ) as client,
                AsyncExitStack() as owners,
            ):

                async def open_route(route):
                    return await owners.enter_async_context(
                        client.websocket(url, proxy=route)
                    )

                results = await asyncio.gather(
                    open_route(INHERIT),
                    open_route(None),
                    open_route(override.url),
                    return_exceptions=True,
                )
                streams = []
                for result in results:
                    if isinstance(result, BaseException):
                        raise result
                    streams.append(result)

                with stalled_handshake() as (stalled, started, disconnected):
                    opening = asyncio.ensure_future(
                        client.websocket(
                            url,
                            proxy=stalled.replace("ws://", "http://"),
                            handshake_timeout_ms=None,
                        )
                    )
                    try:
                        self.assertTrue(await asyncio.to_thread(started.wait, 5))
                        opening.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await opening
                        self.assertTrue(await asyncio.to_thread(disconnected.wait, 5))
                    finally:
                        if not opening.done():
                            opening.cancel()
                            await asyncio.gather(opening, return_exceptions=True)

                async with client.websocket(url) as later:
                    streams.append(later)
                    for index, stream in enumerate(streams):
                        await stream.send(str(index))
                        self.assertEqual(await stream.recv(), str(index))

            authority = urlsplit(url).netloc
            self.assertEqual([row[0] for row in default.requests], [authority] * 2)
            self.assertEqual([row[0] for row in override.requests], [authority])

    async def test_invalid_native_routes_reject_before_contacting_the_origin(self):
        openings = []

        def observe(_, request):
            openings.append(request.path)

        with peer(echo, process_request=observe) as (url, _):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                for options, kind in (
                    ({"proxy": "http://secret.invalid"}, "invalid_websocket_proxy"),
                    (
                        {"inherit_proxy": False, "proxy_username": "secret"},
                        "proxy_credentials_pair",
                    ),
                    (
                        {
                            "inherit_proxy": False,
                            "proxy_username": "user",
                            "proxy_password": "secret",
                        },
                        "proxy_credentials_without_route",
                    ),
                    (
                        {"inherit_proxy": False, "proxy": "invalid://secret"},
                        "invalid_proxy_scheme",
                    ),
                ):
                    with (
                        self.subTest(kind=kind),
                        self.assertRaises(_native.NativeError) as caught,
                    ):
                        client._native.websocket(
                            url,
                            "h1",
                            [],
                            1024,
                            4096,
                            16,
                            True,
                            None,
                            None,
                            0,
                            **options,
                        )
                    self.assertEqual(caught.exception.args[:2], ("input", kind))
                    self.assertNotIn("secret", str(caught.exception))
                self.assertEqual(openings, [])
                async with client.websocket(url, proxy=None) as stream:
                    await stream.send("still usable")
                    self.assertEqual(await stream.recv(), "still usable")
            self.assertEqual(len(openings), 1)
