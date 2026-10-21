"""Verified client authentication and core-owned origin selection."""

import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from phantom_http import (
    AsyncClient,
    Client,
    ClientCertificate,
    Error,
    SessionSnapshotError,
    Trust,
)
from test_http2 import H2Peer
from test_settings_transport import PROFILE, ROOT, peer

KEY = b"checkpoint-test-key-not-a-secret"


class ClientIdentities:
    """Two independently issued clientAuth leaves with separate trusted CAs."""

    def __init__(self):
        if shutil.which("openssl") is None:
            raise RuntimeError("OpenSSL is required for client-certificate controls")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="phantom-client-identities-"
        )
        self.directory = Path(self.temporary.name)
        try:
            config = self.directory / "request.cnf"
            config.write_text(
                "[req]\n"
                "distinguished_name=subject\n"
                "[subject]\n"
                "[ca]\n"
                "basicConstraints=critical,CA:TRUE,pathlen:0\n"
                "keyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\n"
                "[client]\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=clientAuth\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n",
                encoding="ascii",
            )
            for name in ("a", "b"):
                for arguments in (
                    [
                        "req",
                        "-config",
                        str(config),
                        "-sha256",
                        "-x509",
                        "-newkey",
                        "ec",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-nodes",
                        "-keyout",
                        str(self.directory / f"{name}-ca.key"),
                        "-out",
                        self.ca_path(name),
                        "-subj",
                        f"/CN=client-{name}-ca",
                        "-days",
                        "1",
                        "-extensions",
                        "ca",
                    ],
                    [
                        "req",
                        "-config",
                        str(config),
                        "-sha256",
                        "-new",
                        "-newkey",
                        "ec",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-nodes",
                        "-keyout",
                        str(self.directory / f"{name}.key"),
                        "-out",
                        str(self.directory / f"{name}.csr"),
                        "-subj",
                        f"/CN=client-{name}",
                    ],
                    [
                        "x509",
                        "-req",
                        "-in",
                        str(self.directory / f"{name}.csr"),
                        "-CA",
                        self.ca_path(name),
                        "-CAkey",
                        str(self.directory / f"{name}-ca.key"),
                        "-set_serial",
                        "1",
                        "-sha256",
                        "-days",
                        "1",
                        "-extfile",
                        str(config),
                        "-extensions",
                        "client",
                        "-out",
                        str(self.directory / f"{name}.pem"),
                    ],
                ):
                    subprocess.run(
                        ["openssl", *arguments],
                        capture_output=True,
                        check=True,
                        timeout=10,
                    )
        except BaseException:
            self.close()
            raise

    def ca_path(self, name):
        return str(self.directory / f"{name}-ca.pem")

    def pem(self, name):
        return (self.directory / f"{name}.pem").read_bytes()

    def key(self, name):
        return (self.directory / f"{name}.key").read_bytes()

    def der(self, name):
        return ssl.PEM_cert_to_DER_cert(self.pem(name).decode("ascii"))

    def der_key(self, name):
        return subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.directory / f"{name}.key"),
                "-outform",
                "DER",
            ],
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout

    def close(self):
        self.temporary.cleanup()


class ClientCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identities = ClientIdentities()

    @classmethod
    def tearDownClass(cls):
        cls.identities.close()

    def test_parse_failures_are_typed_redacted_and_do_not_export_key(self):
        identities = self.identities
        for chain, key, kind in (
            (b"private supplied input", identities.key("a"), "certificate"),
            (identities.pem("a"), b"private supplied input", "private_key"),
            (identities.pem("a"), identities.key("b"), "key_mismatch"),
        ):
            with self.subTest(kind=kind), self.assertRaises(Error) as caught:
                ClientCertificate.from_pem(chain, key)
            self.assertEqual(caught.exception.category, "client_certificate")
            self.assertEqual(caught.exception.kind, kind)
            self.assertNotIn("supplied", repr(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
        certificate = ClientCertificate.from_der(
            (identities.der("a"),), identities.der_key("a")
        )
        self.assertEqual(repr(certificate), "ClientCertificate()")
        self.assertFalse(hasattr(certificate, "private_key"))

    def test_ordered_last_mapping_survives_fork_shutdown_and_snapshot_restore(self):
        identities = self.identities
        a = ClientCertificate.from_pem(identities.pem("a"), identities.key("a"))
        b = ClientCertificate.from_der((identities.der("b"),), identities.der_key("b"))
        with peer(tls=True, client_ca=identities.ca_path("b")) as server:
            with Client(
                profile=PROFILE,
                protocol="h1",
                timeout_ms=5000,
                trust=Trust(roots=(ROOT,)),
                client_certificate=a,
                client_certificates_for=((server.url + "/", a), (server.url, b)),
            ) as source:
                with source.request("GET", server.url + "/source") as response:
                    self.assertEqual(response.read(max_bytes=5), b"hello")
                child = source.fork()
                snapshot = source.export_session(KEY)
                restored = source.restore_session(snapshot, KEY)
            with child, restored:
                for owner, path in ((child, "/fork"), (restored, "/restore")):
                    with owner.request("GET", server.url + path) as response:
                        self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(server.client_certificates, [identities.der("b")] * 3)
            self.assertEqual(
                [request[0] for request in server.requests],
                ["/source", "/fork", "/restore"],
            )

    def test_missing_wrong_or_unmapped_certificate_cannot_authenticate(self):
        identities = self.identities
        wrong = ClientCertificate.from_pem(identities.pem("a"), identities.key("a"))
        right = ClientCertificate.from_pem(identities.pem("b"), identities.key("b"))
        for options in (
            {},
            {"client_certificate": wrong},
            {"client_certificates_for": (("https://not-this-origin.invalid", right),)},
        ):
            with (
                self.subTest(options=tuple(options)),
                peer(tls=True, client_ca=identities.ca_path("b")) as server,
            ):
                # TLS 1.3 rejection may arrive after the response-head future.
                with (
                    Client(
                        profile=PROFILE,
                        protocol="h1",
                        timeout_ms=5000,
                        trust=Trust(roots=(ROOT,)),
                        **options,
                    ) as client,
                    self.assertRaises(Error),
                    client.request("GET", server.url + "/rejected") as response,
                ):
                    response.read(max_bytes=5)
                self.assertEqual(server.requests, [])
                self.assertEqual(server.client_certificates, [])

    def test_certificate_policy_is_transactionally_bound_even_without_tickets(self):
        identities = self.identities
        a = ClientCertificate.from_pem(identities.pem("a"), identities.key("a"))
        same = ClientCertificate.from_der(
            (identities.der("a"),), identities.der_key("a")
        )
        b = ClientCertificate.from_pem(identities.pem("b"), identities.key("b"))
        options = {"profile": PROFILE, "protocol": "h1", "timeout_ms": 5000}
        with Client(**options, client_certificate=a) as source:
            snapshot = source.export_session(KEY)
        with Client(**options, client_certificate=same) as receiver:
            with receiver.restore_session(snapshot, KEY) as restored:
                self.assertFalse(restored.is_closed)
            self.assertFalse(receiver.is_closed)
        for certificate in (None, b):
            with Client(**options, client_certificate=certificate) as receiver:
                with self.assertRaises(SessionSnapshotError) as caught:
                    receiver.restore_session(snapshot, KEY)
                self.assertEqual(caught.exception.kind, "incompatible")
                self.assertFalse(receiver.is_closed)

    def test_client_identity_does_not_bypass_server_verification(self):
        identities = self.identities
        certificate = ClientCertificate.from_pem(
            identities.pem("a"), identities.key("a")
        )
        with peer(tls=True, client_ca=identities.ca_path("a")) as server:
            with (
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    timeout_ms=5000,
                    client_certificate=certificate,
                ) as client,
                self.assertRaises(Error) as caught,
                client.request("GET", server.url + "/untrusted") as response,
            ):
                response.read(max_bytes=5)
            self.assertEqual(caught.exception.kind, "tls")
            self.assertEqual(server.requests, [])

    def test_invalid_origin_rejected_without_connecting(self):
        identities = self.identities
        certificate = ClientCertificate.from_pem(
            identities.pem("a"), identities.key("a")
        )
        for origin in (
            "http://127.0.0.1",
            "https://example.com/path",
            "https://user:private@example.com",
        ):
            with self.subTest(origin=origin), self.assertRaises(Error) as caught:
                Client(
                    profile=PROFILE,
                    protocol="h1",
                    client_certificates_for=((origin, certificate),),
                )
            self.assertEqual(caught.exception.kind, "invalid_client_configuration")
            self.assertNotIn("private", str(caught.exception))


class AsyncClientCertificateTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_der_identity_preserves_verified_h2_pool(self):
        identities = ClientIdentities()
        try:
            certificate = ClientCertificate.from_der(
                (identities.der("a"),), identities.der_key("a")
            )
            with H2Peer(tls=True, client_ca=identities.ca_path("a")) as server:
                async with AsyncClient(
                    profile=PROFILE,
                    protocol="h2",
                    timeout_ms=5000,
                    trust=Trust(roots=(ROOT,)),
                    client_certificate=certificate,
                ) as client:
                    for path in ("/first", "/second", "/third"):
                        response = await client.request("GET", server.url + path)
                        self.assertEqual(response.protocol, "h2")
                        self.assertEqual(await response.read(max_bytes=5), b"hello")
                self.assertEqual(server.client_certificate, identities.der("a"))
                self.assertEqual(len(server.requests), 3)
            self.assertFalse(server.premature_close)
        finally:
            identities.close()
