"""Runtime signatures and forwarding remain aligned with the typed facade."""

import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

import phantom_http
from phantom_http import AsyncClient, Client


class InstalledTypingTests(unittest.TestCase):
    def test_type_payload_and_external_consumer_checks(self):
        package = resources.files(phantom_http)
        for name in ("py.typed", "_native.pyi"):
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
