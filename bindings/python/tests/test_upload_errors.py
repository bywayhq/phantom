"""Primary failure precedence controls without loading a native extension."""

import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def facade_module():
    source = Path(__file__).parents[1] / "python/phantom_http/__init__.py"
    if not source.is_file():
        package = importlib.util.find_spec("phantom_http")
        if package is None or package.origin is None:
            raise RuntimeError("missing installed package")
        source = Path(package.origin)
    name = "_phantom_upload_error_control"
    native = types.ModuleType(name + "._native")
    native.NativeError = type("NativeError", (Exception,), {})
    native.NativeProfile = type("NativeProfile", (), {})
    sys.modules[native.__name__] = native
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FACADE = facade_module()


class Pump:
    def __init__(self, original=None, cleanup=None, settled=True):
        self.native = object()
        self.error = original
        self.cleanup_error = cleanup
        self.closed = False
        self.finishes = settled
        self.settled = asyncio.get_running_loop().create_future()
        self.settled.set_result(None)

    def check_loop(self):
        pass

    def check_wait(self):
        pass

    def close(self):
        self.closed = True

    async def wait(self, *_):
        await asyncio.sleep(0)
        return self.finishes


class NativeResponse:
    status = 200
    protocol = "h2"
    headers = []

    def __init__(self, error=None):
        self.error = error
        self.closed = False

    async def read(self, _):
        if self.error is not None:
            raise self.error
        return b"body"

    async def read_chunk(self, _):
        return await self.read(0)

    def close(self):
        self.closed = True


class UploadErrorTests(unittest.IsolatedAsyncioTestCase):
    def assert_primary(self, error, kind, cleanup, original=None):
        self.assertEqual(error.kind, kind)
        self.assertEqual(error.protocol, "h2")
        self.assertEqual(error.timeout_phase, "total" if kind == "timeout" else None)
        self.assertIs(error.original, original)
        self.assertIs(error.cleanup_error, cleanup)
        self.assertNotIn("private", str(error))
        self.assertNotIn("private", repr(error))
        self.assertNotIn("private", repr(error.args))
        self.assertTrue(error.__suppress_context__)

    async def test_request_preserves_native_kind_when_cleanup_also_fails(self):
        original = ValueError("private-producer")
        cleanup = OSError("private-cleanup")
        for kind in ("connect", "tls", "attempt_budget_exhausted", "timeout"):
            with self.subTest(kind=kind):
                pump = Pump(original, cleanup)

                class NativeClient:
                    cookies = object()

                    async def request(self, *_, kind=kind, **__):
                        raise FACADE._native.NativeError(
                            "request",
                            kind,
                            "h2",
                            "total" if kind == "timeout" else None,
                        )

                async def source():
                    yield b"unused"

                client = FACADE.AsyncClient._from_native(NativeClient())
                with (
                    patch.object(FACADE._upload, "Upload", return_value=pump),
                    self.assertRaises(FACADE.Error) as caught,
                ):
                    await client.request(
                        "POST", "https://example.invalid", body=source()
                    )
                self.assert_primary(caught.exception, kind, cleanup, original)
                self.assertTrue(pump.closed)
                if kind == "timeout":
                    self.assertIsInstance(caught.exception, FACADE.TimeoutError)
                elif kind == "attempt_budget_exhausted":
                    self.assertIsInstance(
                        caught.exception, FACADE.AttemptBudgetExhausted
                    )

    async def test_body_errors_keep_native_metadata_and_upload_causes(self):
        for method in ("read", "read_chunk"):
            for kind in ("timeout", "response_body_limit", "http2"):
                with self.subTest(method=method, kind=kind):
                    cleanup = OSError("private-cleanup")
                    pump = Pump(cleanup=cleanup)
                    native = NativeResponse(
                        FACADE._native.NativeError(
                            "request",
                            kind,
                            "h2",
                            "total" if kind == "timeout" else None,
                        )
                    )
                    response = FACADE.AsyncResponse(native, pump)
                    with self.assertRaises(FACADE.Error) as caught:
                        if method == "read":
                            await response.read(max_bytes=10)
                        else:
                            await response.read_chunk()
                    self.assert_primary(caught.exception, kind, cleanup)
                    self.assertTrue(native.closed)

    async def test_successful_read_still_reports_cleanup_failure(self):
        cleanup = OSError("private-cleanup")
        response = FACADE.AsyncResponse(NativeResponse(), Pump(cleanup=cleanup))
        with self.assertRaises(FACADE.UploadError) as caught:
            await response.read(max_bytes=10)
        self.assertIs(caught.exception.cleanup_error, cleanup)

    async def test_cleanup_timeout_does_not_replace_existing_timeout(self):
        native = NativeResponse(
            FACADE._native.NativeError("request", "timeout", "h2", "total")
        )
        response = FACADE.AsyncResponse(native, Pump(settled=False))
        with self.assertRaises(FACADE.TimeoutError) as caught:
            await response.read(max_bytes=10)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertEqual(caught.exception.timeout_phase, "total")
        self.assertEqual(caught.exception.cleanup_error.kind, "shutdown_timeout")

    async def test_existing_body_error_and_cancellation_keep_exact_identity(self):
        for method in ("read", "read_chunk"):
            for primary in (
                FACADE.TimeoutError("request", "timeout", "h2", "read_idle"),
                asyncio.CancelledError(),
            ):
                with self.subTest(method=method, primary=type(primary)):
                    cleanup = OSError("private-cleanup")
                    response = FACADE.AsyncResponse(
                        NativeResponse(primary), Pump(cleanup=cleanup)
                    )
                    with self.assertRaises(type(primary)) as caught:
                        if method == "read":
                            await response.read(max_bytes=10)
                        else:
                            await response.read_chunk()
                    self.assertIs(caught.exception, primary)
                    if isinstance(primary, FACADE.Error):
                        self.assertIs(caught.exception.cleanup_error, cleanup)
                    else:
                        self.assertEqual(primary.__dict__, {})

    async def test_native_request_body_retains_source_and_protocol(self):
        original = ValueError("private-producer")
        cleanup = OSError("private-cleanup")
        response = FACADE.AsyncResponse(
            NativeResponse(
                FACADE._native.NativeError("request", "request_body", "h2", None)
            ),
            Pump(original, cleanup),
        )
        with self.assertRaises(FACADE.UploadError) as caught:
            await response.read(max_bytes=10)
        self.assert_primary(caught.exception, "request_body", cleanup, original)

    async def test_async_context_exits_do_not_mask_existing_failure(self):
        cleanup = OSError("private-cleanup")
        for owner in ("client", "response"):
            with self.subTest(owner=owner):
                primary = FACADE.TimeoutError("request", "timeout", "h2", "total")
                pump = Pump(cleanup=cleanup)
                if owner == "response":
                    context = FACADE.AsyncResponse(NativeResponse(), pump)
                else:

                    class NativeClient:
                        cookies = object()

                        async def shutdown(self, _):
                            pass

                    context = FACADE.AsyncClient._from_native(NativeClient())
                    context._uploads.add(pump)
                with self.assertRaises(FACADE.TimeoutError) as caught:
                    async with context:
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertIs(primary.cleanup_error, cleanup)

    async def test_sync_context_exit_keeps_primary_and_exposes_cleanup(self):
        for owner_type in (FACADE.Client, FACADE.Response):
            with self.subTest(owner=owner_type):
                primary = FACADE.BodyLimitExceeded(
                    "request", "response_body_limit", "h2"
                )
                cleanup = OSError("private-cleanup")
                owner = object.__new__(owner_type)
                with (
                    patch.object(
                        owner_type,
                        "close",
                        side_effect=FACADE.UploadError(None, cleanup),
                    ),
                    self.assertRaises(FACADE.BodyLimitExceeded) as caught,
                    owner,
                ):
                    raise primary
                self.assertIs(caught.exception, primary)
                self.assertIs(primary.cleanup_error, cleanup)

    async def test_caller_exception_metadata_cannot_replace_primary(self):
        class CallerError(Exception):
            @property
            def cleanup_error(self):
                raise AssertionError("caller property must not be inspected")

        for owner_type in (FACADE.AsyncResponse, FACADE.AsyncClient):
            with self.subTest(owner=owner_type):
                owner = object.__new__(owner_type)
                if owner_type is FACADE.AsyncResponse:
                    owner._upload = None
                close = "aclose" if owner_type is FACADE.AsyncResponse else "close"

                async def fail_close():
                    raise OSError("private-cleanup")

                primary = CallerError("caller failure")
                with (
                    patch.object(owner, close, side_effect=fail_close),
                    self.assertRaises(CallerError) as caught,
                ):
                    async with owner:
                        raise primary
                self.assertIs(caught.exception, primary)
        for owner_type in (FACADE.Response, FACADE.Client):
            with self.subTest(owner=owner_type):
                owner = object.__new__(owner_type)
                primary = CallerError("caller failure")
                with (
                    patch.object(
                        owner, "close", side_effect=OSError("private-cleanup")
                    ),
                    self.assertRaises(CallerError) as caught,
                    owner,
                ):
                    raise primary
                self.assertIs(caught.exception, primary)


if __name__ == "__main__":
    unittest.main()
