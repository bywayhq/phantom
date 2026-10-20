"""Runtime signatures and forwarding remain aligned with the typed facade."""

import inspect
import types
import unittest
from unittest.mock import patch

from phantom_http import AsyncClient, Client


class SignatureTests(unittest.TestCase):
    def test_sync_options_and_defaults_match_async_signatures(self):
        self.assertEqual(inspect.signature(Client), inspect.signature(AsyncClient))
        sync = inspect.signature(Client.request)
        asynchronous = inspect.signature(AsyncClient.request)
        self.assertEqual(
            sync.replace(return_annotation=inspect.Signature.empty),
            asynchronous.replace(return_annotation=inspect.Signature.empty),
        )
        for signature in (inspect.signature(Client), sync):
            self.assertFalse(
                any(
                    parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in signature.parameters.values()
                )
            )

    def test_sync_forwards_explicit_options_and_defaults_without_transforming(self):
        constructors = []
        requests = []
        shutdown = []

        class FakeAsyncClient:
            cookies = object()
            is_closed = False

            def __init__(self, **options):
                constructors.append(options)

            async def request(self, method, url, **options):
                requests.append((method, url, options))
                return types.SimpleNamespace(status=200, protocol="h1", headers=[])

            async def close(self, **options):
                shutdown.append(options)

        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                constructors.clear()
                requests.clear()
                shutdown.clear()

                defaults = {
                    "profile": "exact-profile",
                    "protocol": "h1",
                    "context": None,
                    "proxy": None,
                    "cookies": True,
                    "timeout_ms": None,
                }
                inputs = {
                    "profile": "exact-profile",
                    "protocol": "h2",
                    "context": "fetch",
                    "proxy": "http://proxy.invalid",
                    "cookies": False,
                    "timeout_ms": 1234,
                }
                fields = iter([("X-Duplicate", b"a"), ("X-Duplicate", "b")])
                budget = object()
                request = {
                    "headers": fields,
                    "body": b"bytes",
                    "upload": None,
                    "budget": budget,
                    "timeout_ms": 42,
                }
                with patch("phantom_http.AsyncClient", FakeAsyncClient):
                    client = Client(
                        **(
                            inputs
                            if explicit
                            else {"profile": "exact-profile", "protocol": "h1"}
                        )
                    )
                    try:
                        response = client.request(
                            "POST",
                            "http://origin.invalid",
                            **(request if explicit else {}),
                        )
                        self.assertEqual(response.status, 200)
                        self.assertEqual(
                            constructors, [inputs if explicit else defaults]
                        )
                        method, url, forwarded = requests[0]
                        self.assertEqual(
                            (method, url), ("POST", "http://origin.invalid")
                        )
                        expected = (
                            request
                            if explicit
                            else {
                                "headers": (),
                                "body": None,
                                "upload": None,
                                "budget": None,
                                "timeout_ms": None,
                            }
                        )
                        self.assertEqual(forwarded, expected)
                        if explicit:
                            self.assertIs(forwarded["headers"], fields)
                            self.assertIs(forwarded["budget"], budget)
                    finally:
                        client.close()
                self.assertEqual(shutdown, [{"timeout_ms": 5000}])
