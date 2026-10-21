"""Certificate owners and call-shape controls without a native extension."""

import dataclasses
import unittest
from unittest.mock import patch

from test_upload_errors import FACADE


class CertificateFacadeTests(unittest.TestCase):
    def test_native_parsing_is_explicit_bounded_and_errors_are_redacted(self):
        calls = []

        class NativeCertificate:
            @staticmethod
            def from_pem(chain, key):
                calls.append((chain, key))
                if chain == b"bad":
                    raise FACADE._native.NativeError(
                        "client_certificate", "certificate", None, None
                    )
                return object()

            from_der = from_pem

        with patch.object(
            FACADE._native, "NativeClientCertificate", NativeCertificate, create=True
        ):
            first = FACADE.ClientCertificate.from_pem(b"chain", b"private")
            second = FACADE.ClientCertificate.from_der((b"DER",), b"private")
            self.assertNotEqual(first, second)
            self.assertNotIn("private", repr(first))
            self.assertEqual(calls, [(b"chain", b"private"), ((b"DER",), b"private")])
            with self.assertRaises(dataclasses.FrozenInstanceError):
                first._native = object()
            for chain, key in (
                (bytearray(b"chain"), b"private"),
                (b"chain", "private"),
            ):
                with self.assertRaises(TypeError):
                    FACADE.ClientCertificate.from_pem(chain, key)
            for chain in ((), (b"DER",) * 257):
                with self.assertRaises(FACADE.Error) as caught:
                    FACADE.ClientCertificate.from_der(chain, b"private")
                self.assertEqual(caught.exception.kind, "invalid_chain_count")
            with self.assertRaises(FACADE.Error) as caught:
                FACADE.ClientCertificate.from_pem(b"x" * (16 * 1024 * 1024), b"private")
            self.assertEqual(caught.exception.kind, "too_large")
            with self.assertRaises(FACADE.Error) as caught:
                FACADE.ClientCertificate.from_pem(b"bad", b"private")
            self.assertEqual(caught.exception.category, "client_certificate")
            self.assertEqual(caught.exception.kind, "certificate")
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn("private", str(caught.exception))

    def test_ordered_native_owners_are_forwarded_without_changing_absent_call_shape(
        self,
    ):
        calls = []

        class Native:
            cookies = object()

            def __init__(self, *args, **kwargs):
                calls.append((args, kwargs))

            async def shutdown(self, _):
                pass

        a, b = (FACADE.ClientCertificate._wrap(object()) for _ in range(2))
        ordered = (("https://EXAMPLE.com", a), ("https://example.com:443/", b))
        with patch.object(FACADE._native, "NativeClient", Native, create=True):
            for owner in (FACADE.Client, FACADE.AsyncClient):
                for options, expected in (
                    ({}, {}),
                    ({"client_certificate": a}, {"client_certificate": a._native}),
                    (
                        {"client_certificate": a, "client_certificates_for": ordered},
                        {
                            "client_certificate": a._native,
                            "client_certificates_for": tuple(
                                (url, cert._native) for url, cert in ordered
                            ),
                        },
                    ),
                ):
                    client = owner(profile="exact", protocol="h1", **options)
                    self.assertEqual(len(calls[-1][0]), 14)
                    self.assertEqual(calls[-1][1], expected)
                    if isinstance(client, FACADE.Client):
                        client.close()
            for options, error in (
                ({"client_certificate": b"private"}, TypeError),
                ({"client_certificates_for": list(ordered)}, TypeError),
                ({"client_certificates_for": (("private", object()),)}, TypeError),
                ({"client_certificates_for": ordered * 129}, FACADE.Error),
                ({"client_certificates_for": (("private" * 65536, a),)}, FACADE.Error),
                ({"client_certificates_for": (("private\ud800", a),)}, FACADE.Error),
            ):
                before = len(calls)
                with self.assertRaises(error) as caught:
                    FACADE.AsyncClient(profile="exact", protocol="h1", **options)
                self.assertNotIn("private", str(caught.exception))
                self.assertEqual(len(calls), before)
