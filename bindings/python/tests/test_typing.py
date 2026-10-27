"""Runtime signatures and forwarding remain aligned with the typed facade."""

import inspect
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from importlib import resources
from pathlib import Path
from typing import get_type_hints
from unittest.mock import patch

import phantom_http
from phantom_http import AsyncClient, AsyncResponse, Client, Response


class InstalledTypingTests(unittest.TestCase):
    def test_type_payload_and_external_consumer_checks(self):
        package = resources.files(phantom_http)
        for name in (
            "py.typed",
            "_native.pyi",
            "_bodies.py",
            "_certificates.py",
            "_client.py",
            "_convenience.py",
            "_errors.py",
            "_profile.py",
            "_request.py",
            "_response.py",
            "_session.py",
            "_sync.py",
        ):
            self.assertTrue(package.joinpath(name).is_file(), name)
        with tempfile.TemporaryDirectory(
            prefix="phantom-typing-consumer-"
        ) as temporary:
            directory = Path(temporary).resolve()
            fixtures = Path(__file__).with_name("typing")
            shutil.copytree(fixtures, directory / "typing")
            environment = os.environ.copy()
            for name in ("MYPYPATH", "PYTHONPATH"):
                environment.pop(name, None)
            command = [
                sys.executable,
                "-I",
                "-m",
                "mypy",
                "--strict",
                "--python-version",
                "3.10",
                "--no-incremental",
                "--cache-dir",
                str(directory / "cache"),
                "--disallow-any-expr",
            ]
            positive = subprocess.run(
                [*command, "typing/client_usage.py"],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
            invalid = directory / "typing/invalid_usage.py"
            expected = [
                (number, line.split("# E: ", 1)[1].strip())
                for number, line in enumerate(
                    invalid.read_text(encoding="utf-8").splitlines(), 1
                )
                if "# E: " in line
            ]
            self.assertTrue(expected)
            negative = subprocess.run(
                [*command, "--output=json", str(invalid)],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(negative.returncode, 1, negative.stdout + negative.stderr)
            errors = [
                entry
                for line in negative.stdout.splitlines()
                if (entry := json.loads(line))["severity"] == "error"
            ]
            self.assertTrue(
                all(
                    (directory / entry["file"]).resolve() == invalid for entry in errors
                )
            )
            self.assertEqual(
                [(entry["line"], entry["code"]) for entry in errors], expected
            )


class SignatureTests(unittest.TestCase):
    def test_public_class_field_annotations_resolve_in_the_preserved_module(self):
        for owner in (
            phantom_http.Profile,
            phantom_http.ResponseTrailers,
            phantom_http.StreamingMultipartBody,
        ):
            with self.subTest(owner=owner.__name__):
                self.assertEqual(owner.__module__, phantom_http.__name__)
                get_type_hints(owner)

    def test_response_owner_and_status_error_annotations_resolve_at_runtime(self):
        response = get_type_hints(Response.__init__)
        self.assertIs(response["client"], Client)
        self.assertIs(response["response"], AsyncResponse)
        status_error = get_type_hints(phantom_http.HTTPStatusError.__init__)
        self.assertEqual(status_error["response"], Response | AsyncResponse)

    def test_public_value_types_keep_their_import_and_serialization_identity(self):
        values = (
            phantom_http.ResponseHeader("X-Duplicate", b"value", True),
            phantom_http.ResponseTrailers("complete", ()),
            phantom_http.RedirectHop(
                "https://a.invalid", "https://b.invalid", "GET", "GET", 302
            ),
            phantom_http.MultipartPart("field", b"value"),
        )
        for value in values:
            with self.subTest(type=type(value).__name__):
                owner = type(value)
                self.assertEqual(owner.__module__, phantom_http.__name__)
                self.assertIs(getattr(phantom_http, owner.__name__), owner)
                restored = pickle.loads(pickle.dumps(value))
                self.assertIs(type(restored), owner)
                self.assertEqual(restored, value)

    def test_sync_and_async_response_reader_options_match(self):
        for name in ("read", "text", "json", "raise_for_status"):
            with self.subTest(name=name):
                self.assertEqual(
                    inspect.signature(getattr(Response, name)),
                    inspect.signature(getattr(AsyncResponse, name)),
                )

    def test_sync_options_and_defaults_match_async_signatures(self):
        self.assertEqual(inspect.signature(Client), inspect.signature(AsyncClient))
        self.assertIs(
            inspect.signature(Client.fork).parameters["sharing"].default,
            inspect.signature(AsyncClient.fork).parameters["sharing"].default,
        )
        sync = inspect.signature(Client.request)
        asynchronous = inspect.signature(AsyncClient.request)
        self.assertEqual(
            sync.replace(
                parameters=[
                    parameter.replace(annotation=inspect.Signature.empty)
                    if parameter.name == "body"
                    else parameter
                    for parameter in sync.parameters.values()
                ],
                return_annotation=inspect.Signature.empty,
            ),
            asynchronous.replace(
                parameters=[
                    parameter.replace(annotation=inspect.Signature.empty)
                    if parameter.name == "body"
                    else parameter
                    for parameter in asynchronous.parameters.values()
                ],
                return_annotation=inspect.Signature.empty,
            ),
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
                self._uploads = set()
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
                    "base_url": None,
                    "trust": None,
                    "timeouts": None,
                    "redirect_policy": None,
                    "retry_policy": None,
                    "client_certificate": None,
                    "client_certificates_for": (),
                    "network": None,
                    "pool": None,
                }
                inputs = {
                    "profile": "exact-profile",
                    "protocol": "h2",
                    "context": "fetch",
                    "proxy": "http://proxy.invalid",
                    "cookies": False,
                    "timeout_ms": 1234,
                    "base_url": "https://origin.invalid/api/",
                    "trust": phantom_http.Trust(roots=(b"certificate",)),
                    "timeouts": None,
                    "redirect_policy": None,
                    "retry_policy": None,
                    "client_certificate": object(),
                    "client_certificates_for": (("https://origin.invalid", object()),),
                    "pool": phantom_http.PoolOptions(
                        max_http2_connections_per_origin=2
                    ),
                    "network": phantom_http.NetworkOptions(
                        local_addresses=("127.0.0.1",)
                    ),
                }
                fields = iter([("X-Duplicate", b"a"), ("X-Duplicate", "b")])
                budget = object()
                request = {
                    "headers": fields,
                    "trailers": (),
                    "expect_continue_ms": None,
                    "body": b"bytes",
                    "params": None,
                    "json": inspect.signature(AsyncClient.request)
                    .parameters["json"]
                    .default,
                    "form": None,
                    "maximum_body_bytes": 16 * 1024 * 1024,
                    "body_length": None,
                    "upload": None,
                    "content_decoding": None,
                    "redirect_policy": None,
                    "retry_policy": None,
                    "redirect_history_limit": None,
                    "transfer_control": None,
                    "diagnostics": None,
                    "budget": budget,
                    "timeout_ms": 42,
                    "timeouts": None,
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
                                "trailers": (),
                                "expect_continue_ms": None,
                                "body": None,
                                "params": None,
                                "json": inspect.signature(AsyncClient.request)
                                .parameters["json"]
                                .default,
                                "form": None,
                                "maximum_body_bytes": 16 * 1024 * 1024,
                                "body_length": None,
                                "upload": None,
                                "content_decoding": None,
                                "redirect_policy": None,
                                "retry_policy": None,
                                "redirect_history_limit": None,
                                "transfer_control": None,
                                "diagnostics": None,
                                "budget": None,
                                "timeout_ms": None,
                                "timeouts": None,
                            }
                        )
                        self.assertEqual(forwarded, expected)
                        if explicit:
                            self.assertIs(forwarded["headers"], fields)
                            self.assertIs(forwarded["budget"], budget)
                    finally:
                        client.close()
                self.assertEqual(shutdown, [{"timeout_ms": 5000}])
