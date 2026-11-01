"""Encrypted DNS against independent TLS and HTTP/2 loopback peers."""

import asyncio
import base64
import contextlib
import json
import socket
import ssl
import struct
import unittest
from urllib.parse import parse_qs, urlsplit

import h2.config
import h2.connection
import h2.events
from phantom_http import (
    INHERIT,
    AsyncClient,
    Client,
    DnsOverHttps,
    DnsOverTls,
    Error,
    HostOverride,
    NetworkOptions,
    Profile,
    SessionSharing,
    TimeoutError,
)
from test_settings_transport import FIXTURES, ROOT, peer

PROFILE = "chrome-154-windows"


def answer(query, ttl):
    """Decode a plain question and encode an independent bounded A/AAAA reply."""
    identity, flags, questions, _, _, _ = struct.unpack_from("!6H", query)
    if flags & 0x8000 or questions != 1:
        raise AssertionError("expected one DNS question")
    position = 12
    labels = []
    while query[position]:
        length = query[position]
        if length > 63:
            raise AssertionError("unexpected compressed question")
        position += 1
        labels.append(query[position : position + length].decode("ascii"))
        position += length
    position += 1
    kind, family = struct.unpack_from("!2H", query, position)
    if family != 1 or kind not in (1, 28):
        raise AssertionError("expected an IN address question")
    question = query[12 : position + 4]
    name = ".".join(labels)
    if name == "missing.invalid":
        response = struct.pack("!6H", identity, 0x8183, 1, 0, 0, 0) + question
    else:
        data = socket.inet_pton(
            socket.AF_INET if kind == 1 else socket.AF_INET6,
            "127.0.0.1" if kind == 1 else "::1",
        )
        record = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data
        response = struct.pack("!6H", identity, 0x8180, 1, 1, 0, 0) + question + record
    return name, kind, identity, response


class DnsPeer:
    def __init__(self, transport):
        self.transport = transport
        self.queries = []
        self.connections = 0
        self.tasks = set()
        self.writers = set()
        self.failures = []
        self.held = asyncio.Event()
        self.reset = asyncio.Event()
        self.status = 200
        self.ttl = 60

    async def __aenter__(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES / "certificate.pem", FIXTURES / "key.pem")
        context.set_alpn_protocols(["h2" if self.transport == "https" else "dot"])
        self.server = await asyncio.start_server(
            self.serve, "127.0.0.1", 0, ssl=context, ssl_handshake_timeout=5
        )
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_):
        self.server.close()
        for writer in tuple(self.writers):
            writer.close()
        await asyncio.wait_for(
            asyncio.gather(self.server.wait_closed(), *self.tasks), 5
        )
        if self.failures:
            raise AssertionError(self.failures)

    def configuration(self, **changes):
        values = {
            "timeout": 2,
            "max_concurrent": 8,
            "roots": (ROOT,),
            "families": "ipv4",
        }
        values.update(changes)
        if self.transport == "https":
            return DnsOverHttps(
                endpoint=f"https://localhost:{self.port}/dns-query",
                bootstrap=("127.0.0.1",),
                **values,
            )
        return DnsOverTls(
            server_name="localhost", bootstrap=(f"127.0.0.1:{self.port}",), **values
        )

    async def serve(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        try:
            selected = writer.get_extra_info("ssl_object").selected_alpn_protocol()
            if selected != ("h2" if self.transport == "https" else "dot"):
                raise AssertionError("encrypted DNS selected the wrong ALPN")
            if self.transport == "https":
                await self.https(reader, writer)
            else:
                await self.tls(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            # Cancellation and client shutdown may terminate an admitted query.
            pass
        except Exception as failure:
            self.failures.append(failure)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()
            self.writers.discard(writer)
            self.tasks.discard(task)

    def record(self, query, method=None, headers=()):
        name, kind, identity, response = answer(query, self.ttl)
        self.queries.append((name, kind, identity, len(query), method, headers))
        if name == "held.invalid":
            self.held.set()
            return None
        return response

    async def tls(self, reader, writer):
        while True:
            length = struct.unpack("!H", await reader.readexactly(2))[0]
            response = self.record(await reader.readexactly(length))
            if response is not None:
                writer.write(struct.pack("!H", len(response)) + response)
                await writer.drain()

    async def https(self, reader, writer):
        connection = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="ascii")
        )
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        streams = {}
        while data := await reader.read(65536):
            for event in connection.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = (event.headers, bytearray())
                elif isinstance(event, h2.events.DataReceived):
                    streams[event.stream_id][1].extend(event.data)
                    connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    headers, body = streams[event.stream_id]
                    fields = dict(headers)
                    method = fields[":method"]
                    if method == "GET":
                        encoded = parse_qs(urlsplit(fields[":path"]).query)["dns"][0]
                        query = base64.urlsafe_b64decode(
                            encoded + "=" * (-len(encoded) % 4)
                        )
                    elif method == "POST":
                        if fields["content-type"] != "application/dns-message":
                            raise AssertionError("wrong DoH request content type")
                        query = bytes(body)
                    else:
                        raise AssertionError("unexpected DoH method")
                    response = self.record(query, method, headers)
                    if response is not None:
                        connection.send_headers(
                            event.stream_id,
                            [
                                (":status", str(self.status)),
                                ("content-type", "application/dns-message"),
                            ],
                        )
                        connection.send_data(event.stream_id, response, end_stream=True)
                elif isinstance(event, h2.events.StreamReset):
                    self.reset.set()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            writer.write(connection.data_to_send())
            await writer.drain()


class DnsPeerCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_exit_closes_a_held_tls_connection_and_collects_its_handler(self):
        resolver = await DnsPeer("tls").__aenter__()
        context = ssl.create_default_context(cafile=FIXTURES / "certificate.pem")
        context.set_alpn_protocols(["dot"])
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", resolver.port, ssl=context, server_hostname="localhost"
                ),
                2,
            )
            query = (
                struct.pack("!6H", 42, 0x0100, 1, 0, 0, 0)
                + b"\x04held\x07invalid\x00"
                + struct.pack("!2H", 1, 1)
            )
            writer.write(struct.pack("!H", len(query)) + query)
            await writer.drain()
            await asyncio.wait_for(resolver.held.wait(), 2)
            self.assertEqual(len(resolver.tasks), 1)
            self.assertEqual(len(resolver.writers), 1)
            await asyncio.wait_for(resolver.__aexit__(None, None, None), 2)
            self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
            self.assertEqual(resolver.tasks, set())
            self.assertEqual(resolver.writers, set())
            self.assertEqual(resolver.failures, [])
        finally:
            if writer is not None:
                writer.close()
            resolver.server.close()
            cleanup = [resolver.server.wait_closed(), *resolver.tasks]
            if writer is not None:
                cleanup.append(writer.wait_closed())
            await asyncio.wait_for(asyncio.gather(*cleanup), 5)


class EncryptedDnsTests(unittest.IsolatedAsyncioTestCase):
    def test_invalid_settings_and_missing_h2_fail_before_network_io(self):
        for configuration, kind in (
            (
                DnsOverHttps(
                    endpoint="http://private.invalid/query",
                    bootstrap=("127.0.0.1",),
                    timeout=1,
                    max_concurrent=1,
                ),
                "invalid_dns_endpoint",
            ),
            (
                DnsOverHttps(
                    endpoint="https://localhost/query",
                    bootstrap=("0.0.0.0",),
                    timeout=1,
                    max_concurrent=1,
                ),
                "invalid_dns_bootstrap",
            ),
            (
                DnsOverHttps(
                    endpoint="https://localhost/query",
                    bootstrap=("127.0.0.1",),
                    timeout=1,
                    max_concurrent=1,
                    roots=(b"private",),
                ),
                "invalid_dns_roots",
            ),
            (
                DnsOverTls(
                    server_name="private.invalid",
                    bootstrap=("127.0.0.1:0",),
                    timeout=1,
                    max_concurrent=1,
                ),
                "invalid_dns_tls",
            ),
        ):
            with self.subTest(kind=kind), self.assertRaises(Error) as caught:
                AsyncClient(profile=PROFILE, network=NetworkOptions(dns=configuration))
            self.assertEqual(caught.exception.kind, kind)
            self.assertNotIn("private", str(caught.exception))
        document = Profile.from_catalog(PROFILE).describe()
        document["profile"]["http2"] = None
        document["profile"]["http3"] = None
        profile = Profile.import_json(json.dumps(document).encode())
        configuration = DnsOverHttps(
            endpoint="https://localhost/query",
            bootstrap=("127.0.0.1",),
            timeout=1,
            max_concurrent=1,
        )
        with self.assertRaises(Error) as caught:
            AsyncClient(
                profile=profile,
                context="raw",
                network=NetworkOptions(dns=configuration),
            )
        self.assertEqual(caught.exception.kind, "dns_missing_http2")

    async def request(self, client, origin, host="answer.invalid"):
        async with await client.get(f"http://{host}:{origin.server_port}/") as response:
            self.assertEqual(await response.read(max_bytes=5), b"hello")
        await client.refresh_connections()

    async def test_doh_get_post_and_dot_resolve_without_changing_authority(self):
        for transport, method in (("https", "get"), ("https", "post"), ("tls", None)):
            with self.subTest(transport=transport, method=method), peer() as origin:
                async with DnsPeer(transport) as resolver:
                    options = (
                        {} if method is None else {"method": method, "query_id": 42}
                    )
                    network = NetworkOptions(
                        dns=resolver.configuration(**options),
                        dns_cache=None,
                        local_addresses=("127.0.0.1",),
                    )
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        timeout_ms=5000,
                        network=network,
                    ) as client:
                        await self.request(client, origin)
                        await self.request(client, origin)
                    self.assertEqual(
                        [query[0] for query in resolver.queries], ["answer.invalid"] * 2
                    )
                    self.assertEqual(resolver.connections, 1)
                    if method is not None:
                        self.assertTrue(
                            all(
                                query[2] == 42 and query[4] == method.upper()
                                for query in resolver.queries
                            )
                        )
                self.assertTrue(
                    all(
                        dict(row[2])["Host"] == f"answer.invalid:{origin.server_port}"
                        for row in origin.requests
                    )
                )

    async def test_wire_defaults_and_explicit_padding_override(self):
        for padding, padded in ((INHERIT, True), (None, False), (64, True)):
            with self.subTest(padding=padding), peer() as origin:
                async with DnsPeer("https") as resolver:
                    network = NetworkOptions(
                        dns=resolver.configuration(
                            wire="chromium154", padding_block=padding, query_id=27
                        ),
                        dns_cache=None,
                    )
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        network=network,
                        timeout_ms=5000,
                    ) as client:
                        await self.request(client, origin)
                    query = resolver.queries[0]
                    self.assertEqual(query[2], 27)
                    self.assertEqual(dict(query[5])["user-agent"], "Chrome")
                    if padded:
                        self.assertEqual(query[3] % (64 if padding == 64 else 128), 0)
                    else:
                        self.assertLess(query[3], 64)

    async def test_proxy_hostname_uses_dns_but_proxy_resolved_target_does_not(self):
        for transport in ("https", "tls"):
            with self.subTest(transport=transport), peer() as proxy:
                async with DnsPeer(transport) as resolver:
                    async with (
                        AsyncClient(
                            profile=PROFILE,
                            protocol="h1",
                            context="raw",
                            timeout_ms=5000,
                            proxy=f"http://proxy.invalid:{proxy.server_port}",
                            network=NetworkOptions(dns=resolver.configuration()),
                        ) as client,
                        await client.get(
                            "http://target.invalid/through-proxy"
                        ) as response,
                    ):
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                    self.assertEqual(
                        [query[0] for query in resolver.queries], ["proxy.invalid"]
                    )
                    self.assertEqual(len(proxy.requests), 1)
                    self.assertEqual(
                        dict(proxy.requests[0][2])["Host"], "target.invalid"
                    )

    async def test_endpoint_identity_and_trust_fail_without_origin_send_or_fallback(
        self,
    ):
        for transport in ("https", "tls"):
            for trusted, identity in ((False, "localhost"), (True, "wrong.invalid")):
                with (
                    self.subTest(
                        transport=transport, trusted=trusted, identity=identity
                    ),
                    peer() as origin,
                ):
                    async with DnsPeer(transport) as resolver:
                        configuration = resolver.configuration(
                            roots=(ROOT,) if trusted else ()
                        )
                        if transport == "https":
                            configuration = DnsOverHttps(
                                endpoint=f"https://{identity}:{resolver.port}/dns-query",
                                bootstrap=("127.0.0.1",),
                                timeout=1,
                                max_concurrent=2,
                                roots=(ROOT,) if trusted else (),
                                families="ipv4",
                            )
                        else:
                            configuration = DnsOverTls(
                                server_name=identity,
                                bootstrap=(f"127.0.0.1:{resolver.port}",),
                                timeout=1,
                                max_concurrent=2,
                                roots=(ROOT,) if trusted else (),
                                families="ipv4",
                            )
                        async with AsyncClient(
                            profile=PROFILE,
                            protocol="h1",
                            context="raw",
                            timeout_ms=3000,
                            network=NetworkOptions(dns=configuration),
                        ) as client:
                            with self.assertRaises(Error) as caught:
                                await client.get(
                                    f"http://localhost:{origin.server_port}/"
                                )
                            self.assertEqual(caught.exception.kind, "connect")
                        self.assertEqual(resolver.queries, [])
                    self.assertEqual(origin.requests, [])

    async def test_cancellation_releases_admission_and_preserves_shared_resolver(self):
        for transport in ("https", "tls"):
            with self.subTest(transport=transport), peer() as origin:
                async with DnsPeer(transport) as resolver:
                    network = NetworkOptions(
                        dns=resolver.configuration(max_concurrent=1), dns_cache=None
                    )
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        timeout_ms=5000,
                        network=network,
                    ) as client:
                        held = asyncio.create_task(
                            client.get(f"http://held.invalid:{origin.server_port}/")
                        )
                        await asyncio.wait_for(resolver.held.wait(), 2)
                        with self.assertRaises(Error):
                            await client.get(
                                f"http://answer.invalid:{origin.server_port}/"
                            )
                        held.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await held
                        if transport == "https":
                            await asyncio.wait_for(resolver.reset.wait(), 2)
                        await self.request(client, origin)
                    self.assertEqual(resolver.connections, 1)
                    self.assertEqual(
                        [query[0] for query in resolver.queries],
                        ["held.invalid", "answer.invalid"],
                    )

    async def test_cache_forks_hard_ttl_and_host_override_remain_explicit(self):
        for transport in ("https", "tls"):
            with self.subTest(transport=transport), peer() as origin:
                async with DnsPeer(transport) as resolver:
                    network = NetworkOptions(
                        dns=resolver.configuration(),
                        host_overrides=(
                            HostOverride("overridden.invalid", ("127.0.0.1",)),
                        ),
                    )
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        network=network,
                        timeout_ms=5000,
                    ) as client:
                        await self.request(client, origin)
                        await self.request(client, origin)
                        self.assertEqual(len(resolver.queries), 1)
                        async with client.fork(
                            sharing=SessionSharing(dns=True)
                        ) as shared:
                            await self.request(shared, origin)
                        self.assertEqual(len(resolver.queries), 1)
                        async with client.fork() as independent:
                            await self.request(independent, origin)
                        self.assertEqual(len(resolver.queries), 2)
                        await self.request(client, origin, "overridden.invalid")
                        self.assertEqual(len(resolver.queries), 2)
                        resolver.ttl = 0
                        client.clear_dns_cache()
                        await self.request(client, origin)
                        await self.request(client, origin)
                        self.assertEqual(len(resolver.queries), 4)
                        with self.assertRaises(Error):
                            await client.get(
                                f"http://missing.invalid:{origin.server_port}/"
                            )
                    self.assertEqual(len(origin.requests), 7)

    async def test_cancelled_dns_setup_preserves_a_live_body_and_lookup_sibling(self):
        for transport in ("https", "tls"):
            with self.subTest(transport=transport), peer() as origin:
                async with DnsPeer(transport) as resolver:
                    async with AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        timeout_ms=5000,
                        network=NetworkOptions(
                            dns=resolver.configuration(), dns_cache=None
                        ),
                    ) as client:
                        held = asyncio.create_task(
                            client.get(f"http://held.invalid:{origin.server_port}/")
                        )
                        try:
                            await asyncio.wait_for(resolver.held.wait(), 2)
                            response = await client.get(
                                f"http://answer.invalid:{origin.server_port}/live"
                            )
                            async with response:
                                self.assertEqual(await response.read_chunk(1), b"a")
                                held.cancel()
                                with self.assertRaises(asyncio.CancelledError):
                                    await held
                                origin.release.set()
                                self.assertEqual(await response.read(max_bytes=1), b"b")
                            await self.request(client, origin)
                        finally:
                            held.cancel()
                            with contextlib.suppress(asyncio.CancelledError, Error):
                                await held
                    self.assertEqual(resolver.connections, 1)

    async def test_graceful_setup_timeout_can_be_followed_by_explicit_abort(self):
        for transport in ("https", "tls"):
            with self.subTest(transport=transport), peer() as origin:
                async with DnsPeer(transport) as resolver:
                    client = AsyncClient(
                        profile=PROFILE,
                        protocol="h1",
                        context="raw",
                        timeout_ms=5000,
                        network=NetworkOptions(
                            dns=resolver.configuration(), dns_cache=None
                        ),
                    )
                    held = asyncio.create_task(
                        client.get(f"http://held.invalid:{origin.server_port}/")
                    )
                    try:
                        await asyncio.wait_for(resolver.held.wait(), 2)
                        with self.assertRaises(TimeoutError):
                            await client.close(timeout_ms=20)
                        self.assertFalse(held.done())
                        await client.abort()
                        with self.assertRaises(Error) as caught:
                            await held
                        self.assertEqual(caught.exception.kind, "client_closed")
                        await client.close()
                        self.assertEqual(origin.requests, [])
                    finally:
                        held.cancel()
                        with contextlib.suppress(asyncio.CancelledError, Error):
                            await held
                        await client.abort()

    async def test_sync_client_uses_the_same_native_resolver(self):
        with peer() as origin:
            async with DnsPeer("tls") as resolver:
                configuration = resolver.configuration()

                def run():
                    with (
                        Client(
                            profile=PROFILE,
                            protocol="h1",
                            context="raw",
                            network=NetworkOptions(dns=configuration),
                            timeout_ms=5000,
                        ) as client,
                        client.get(
                            f"http://answer.invalid:{origin.server_port}/"
                        ) as response,
                    ):
                        self.assertEqual(response.read(max_bytes=5), b"hello")

                await asyncio.to_thread(run)
                self.assertEqual(len(resolver.queries), 1)
