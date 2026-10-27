"""Bounded network settings and verified public routing controls."""

import dataclasses
import ssl
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_upload_errors import FACADE


class LyingString(str):
    def __len__(self):
        return 0


class ThrowingString(str):
    def __len__(self):
        raise ValueError("private")


class NetworkFacadeTests(unittest.TestCase):
    def test_immutable_options_preserve_order_empty_answers_and_default_omission(self):
        override = FACADE.HostOverride("Secret.Invalid", ("127.0.0.2", "127.0.0.1"))
        network = FACADE.NetworkOptions(
            host_overrides=(override, FACADE.HostOverride("Secret.Invalid")),
            local_addresses=("::1", "127.0.0.1"),
            interface="Secret-Interface",
        )
        self.assertEqual(
            network.host_overrides, (override, FACADE.HostOverride("Secret.Invalid"))
        )
        self.assertEqual(network.local_addresses, ("::1", "127.0.0.1"))
        self.assertEqual(network.interface, "Secret-Interface")
        for value in (override, network):
            self.assertNotIn("Secret", repr(value))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            network.interface = "other"
        calls = []

        def native(*args, **kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(cookies=object())

        with patch.object(FACADE._native, "NativeClient", native, create=True):
            FACADE.AsyncClient(profile="exact", protocol="h1")
            FACADE.AsyncClient(profile="exact", protocol="h1", network=network)
            FACADE.AsyncClient(
                profile="exact", protocol="h1", network=FACADE.NetworkOptions()
            )
        self.assertNotIn("network", calls[0])
        self.assertIs(calls[1]["network"], network)
        self.assertEqual(calls[2]["network"], FACADE.NetworkOptions())

    def test_aggregate_utf8_and_combined_entry_boundaries_are_checked(self):
        options = FACADE.NetworkOptions
        override = FACADE.HostOverride
        options(host_overrides=(override("a" * 32768),), interface="é" * 16384)
        with self.assertRaises(ValueError):
            options(host_overrides=(override("a" * 32768),), interface="é" * 16385)
        options(host_overrides=(override("", ("",) * 1023),))
        with self.assertRaises(ValueError):
            options(host_overrides=(override("", ("",) * 1023),), local_addresses=("",))
        options(host_overrides=(override(""),) * 1024)
        with self.assertRaises(ValueError):
            options(host_overrides=(override(""),) * 1025)
        options(local_addresses=("",) * 1024)
        with self.assertRaises(ValueError):
            options(local_addresses=("",) * 1025)

    def test_invalid_shapes_and_utf8_are_redacted_before_native_construction(self):
        options = FACADE.NetworkOptions
        override = FACADE.HostOverride
        for build in (
            lambda: override("private", ["private"]),
            lambda: override(123),
            lambda: override("private", (True,)),
            lambda: options(host_overrides=[override("private")]),
            lambda: options(host_overrides=("private",)),
            lambda: options(local_addresses=["private"]),
            lambda: options(interface=123),
            lambda: options(interface="private\ud800"),
            lambda: options(interface=LyingString("private")),
            lambda: options(local_addresses=(ThrowingString("private"),)),
        ):
            with (
                self.subTest(build=build),
                self.assertRaises((TypeError, ValueError)) as caught,
            ):
                build()
            self.assertNotIn("private", str(caught.exception))
        with patch.object(FACADE._native, "NativeClient", create=True) as native:
            with self.assertRaises(TypeError):
                FACADE.AsyncClient(profile="exact", protocol="h1", network={})
            value = options()
            object.__setattr__(value, "local_addresses", ("",) * 1025)
            with self.assertRaises(ValueError):
                FACADE.AsyncClient(profile="exact", protocol="h1", network=value)
            native.assert_not_called()

    def test_unix_path_is_owned_frozen_redacted_and_shares_the_byte_bound(self):
        options = FACADE.NetworkOptions
        network = options(unix_socket="/private/é.sock")
        self.assertEqual(network.unix_socket, "/private/é.sock")
        self.assertNotIn("private", repr(network))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            network.unix_socket = "/other"
        options(interface="x", unix_socket="é" * 32767 + "x")
        with self.assertRaises(ValueError):
            options(interface="x", unix_socket="é" * 32768)
        for path in (
            "",
            "private\x00path",
            "private\ud800",
            123,
            LyingString("private"),
        ):
            with (
                self.subTest(kind=type(path)),
                self.assertRaises((TypeError, ValueError)) as caught,
            ):
                options(unix_socket=path)
            self.assertNotIn("private", str(caught.exception))
        calls = []

        def native(*args, **kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(cookies=object())

        with patch.object(FACADE._native, "NativeClient", native, create=True):
            FACADE.AsyncClient(profile="exact", protocol="h1", network=network)
            self.assertIs(calls[0]["network"], network)
            object.__setattr__(network, "unix_socket", "private\x00path")
            with self.assertRaises(ValueError):
                FACADE.AsyncClient(profile="exact", protocol="h1", network=network)
            self.assertEqual(len(calls), 1)


class CredentialFacadeTests(unittest.IsolatedAsyncioTestCase):
    def test_credential_names_are_immutable_bounded_and_forwarded(self):
        policy = FACADE.RedirectPolicy.limited(2, credential_headers=("x-api-key",))
        for names in (["x"], (1,), ("x",) * 257, ("x" * 65537,)):
            with self.assertRaises((TypeError, ValueError)):
                FACADE.RedirectPolicy.limited(1, credential_headers=names)
        with patch.object(FACADE._native, "NativeClient", create=True) as native:
            FACADE.AsyncClient(profile="exact", protocol="h1", redirect_policy=policy)
            self.assertEqual(
                native.call_args.kwargs["redirect_credential_headers"], ("x-api-key",)
            )
        self.assertNotIn("x-api-key", repr(policy))

    async def test_request_override_forwards_custom_credentials(self):
        calls = []

        class Native:
            cookies = object()

            async def request(self, *arguments, **fields):
                calls.append(fields)
                return types.SimpleNamespace(status=204, protocol="h1", headers=[])

        with patch.object(
            FACADE._native, "NativeClient", return_value=Native(), create=True
        ):
            client = FACADE.AsyncClient(profile="exact", protocol="h1")
            await client.request(
                "GET",
                "http://example.test/",
                redirect_policy=FACADE.RedirectPolicy.limited(
                    1, credential_headers=("x-api-key",)
                ),
            )
        self.assertEqual(calls[0]["redirect_credential_headers"], ("x-api-key",))

    def test_public_only_named_setting_and_boolean_validation(self):
        network = FACADE.NetworkOptions(public_only=True)
        self.assertTrue(network.public_only)
        self.assertIsNone(network.unix_socket)
        for value in (1, "true", None):
            with self.assertRaises(TypeError):
                FACADE.NetworkOptions(public_only=value)


class NetworkPublicTests(unittest.TestCase):
    def test_public_only_denies_literal_and_overridden_loopback(self):
        from phantom_http import Client, Error, HostOverride, NetworkOptions
        from test_settings_transport import PROFILE, peer

        with peer() as origin:
            with Client(
                profile=PROFILE,
                protocol="h1",
                timeout_ms=5000,
                network=NetworkOptions(
                    public_only=True,
                    host_overrides=(HostOverride("network.invalid", ("127.0.0.1",)),),
                ),
            ) as client:
                for host in ("127.0.0.1", "network.invalid"):
                    with self.assertRaises(Error) as caught:
                        client.request("GET", f"http://{host}:{origin.server_port}/")
                    self.assertEqual(caught.exception.kind, "destination_denied")
            self.assertEqual(origin.requests, [])

    def test_verified_tls_keeps_logical_host_and_source_across_fork_and_restore(self):
        from phantom_http import Client, HostOverride, NetworkOptions, Trust
        from test_settings_transport import FIXTURES, PROFILE, ROOT, peer

        with tempfile.TemporaryDirectory(prefix="phantom-network-") as temporary:
            directory = Path(temporary)
            config = directory / "leaf.cnf"
            config.write_text(
                "[server]\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:network.invalid\n",
                encoding="ascii",
            )
            for arguments in (
                [
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    "/CN=network.invalid",
                    "-keyout",
                    str(directory / "key.pem"),
                    "-out",
                    str(directory / "leaf.csr"),
                ],
                [
                    "x509",
                    "-req",
                    "-in",
                    str(directory / "leaf.csr"),
                    "-CA",
                    str(FIXTURES / "certificate.pem"),
                    "-CAkey",
                    str(FIXTURES / "key.pem"),
                    "-set_serial",
                    "42",
                    "-days",
                    "1",
                    "-extfile",
                    str(config),
                    "-extensions",
                    "server",
                    "-out",
                    str(directory / "leaf.pem"),
                ],
            ):
                subprocess.run(
                    ["openssl", *arguments], capture_output=True, check=True, timeout=10
                )
            names = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory / "leaf.pem", directory / "key.pem")
            context.set_servername_callback(
                lambda _socket, name, _context: names.append(name)
            )
            with peer(tls_context=context) as origin:
                network = NetworkOptions(
                    host_overrides=(
                        HostOverride("NETWORK.INVALID", ("127.0.0.2",)),
                        HostOverride("network.invalid", ("127.0.0.1",)),
                    ),
                    local_addresses=("127.0.0.2", "127.0.0.1"),
                )
                url = f"https://network.invalid:{origin.server_port}/"
                with Client(
                    profile=PROFILE,
                    protocol="h1",
                    context="raw",
                    timeout_ms=5000,
                    trust=Trust(roots=(ROOT,)),
                    network=network,
                ) as client:
                    with client.request("GET", url) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    key = b"x" * 32
                    snapshot = client.export_session(key)
                    with client.fork() as fork, fork.request("GET", url) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                    with (
                        client.restore_session(snapshot, key) as restored,
                        restored.request("GET", url) as response,
                    ):
                        self.assertEqual(response.read(max_bytes=5), b"hello")
                self.assertEqual(names, ["network.invalid"] * 3)
                self.assertEqual(len(origin.requests), 3)
                for _, address, headers, _ in origin.requests:
                    self.assertEqual(address[0], "127.0.0.1")
                    self.assertEqual(
                        dict(headers)["Host"], f"network.invalid:{origin.server_port}"
                    )

    def test_empty_override_and_incompatible_source_fail_without_connecting(self):
        from phantom_http import Client, Error, HostOverride, NetworkOptions
        from test_settings_transport import PROFILE, peer

        for network in (
            NetworkOptions(
                host_overrides=(
                    HostOverride("network.invalid", ("127.0.0.1",)),
                    HostOverride("NETWORK.INVALID", ()),
                )
            ),
            NetworkOptions(
                host_overrides=(HostOverride("network.invalid", ("127.0.0.1",)),),
                local_addresses=("::1",),
            ),
        ):
            with self.subTest(network=network), peer() as origin:
                with Client(
                    profile=PROFILE, protocol="h1", timeout_ms=5000, network=network
                ) as client:
                    with self.assertRaises(Error) as caught:
                        client.request(
                            "GET", f"http://network.invalid:{origin.server_port}/"
                        )
                    self.assertEqual(caught.exception.kind, "connect")
                self.assertEqual(origin.requests, [])

    def test_native_boundary_and_core_policy_validation_are_redacted(self):
        from phantom_http import Client, Error, HostOverride, NetworkOptions, _native
        from test_settings_transport import PROFILE

        for network in (
            NetworkOptions(host_overrides=(HostOverride("127.0.0.1"),)),
            NetworkOptions(local_addresses=("0.0.0.0",)),
            NetworkOptions(interface=""),
            NetworkOptions(interface="private\x00interface"),
            NetworkOptions(host_overrides=(HostOverride("private", ("private",)),)),
        ):
            with self.subTest(network=network), self.assertRaises(Error) as caught:
                Client(profile=PROFILE, protocol="h1", network=network)
            self.assertEqual(caught.exception.category, "input")
            self.assertNotIn("private", str(caught.exception))
        for invalid in (
            {"local_addresses": ("",) * 1025},
            {"interface": "é" * 32769},
            {"host_overrides": []},
            {"interface": LyingString("private")},
            {
                "host_overrides": (
                    types.SimpleNamespace(
                        host="host", addresses=(LyingString("127.0.0.1"),)
                    ),
                )
            },
            {
                "host_overrides": (
                    types.SimpleNamespace(host=ThrowingString("private"), addresses=()),
                )
            },
            {"local_addresses": (ThrowingString("127.0.0.1"),)},
        ):
            fields = types.SimpleNamespace(
                host_overrides=(),
                local_addresses=(),
                interface=None,
                unix_socket=None,
                public_only=False,
            )
            fields.__dict__.update(invalid)
            with self.assertRaises(_native.NativeError) as caught:
                _native.NativeClient(PROFILE, "h1", network=fields)
            self.assertNotIn("private", str(caught.exception))
