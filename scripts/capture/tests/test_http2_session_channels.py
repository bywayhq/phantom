"""TLS and raw stream failures must retain their actual input operation cause."""

import asyncio
import errno
import ssl
import traceback
import unittest

from scripts.capture.http2_session import (
    CaptureFailures,
    ConnectionRecord,
    PlainChannel,
    TlsChannel,
    generate_certificate,
    raise_capture_failures,
    server_context,
)


class CaptureFailureReportingTests(unittest.TestCase):
    def test_traceback_reports_each_nested_cleanup_cause(self):
        primary = ValueError("incomplete origin record")
        descriptor = OSError(errno.EBADF, "proxy writer descriptor")
        nested = CaptureFailures(primary, (descriptor,))
        pending = asyncio.TimeoutError("pending proxy writer")

        with self.assertRaises(CaptureFailures) as caught:
            raise_capture_failures(None, (nested, pending))

        rendered = "".join(
            traceback.format_exception(type(caught.exception), caught.exception, None)
        )
        for detail in (
            "ValueError",
            "incomplete origin record",
            "OSError",
            "proxy writer descriptor",
            "pending proxy writer",
        ):
            self.assertIn(detail, rendered)
        self.assertIs(caught.exception.cleanup[0], nested)
        self.assertIs(nested.primary, primary)
        self.assertIs(nested.cleanup[0], descriptor)
        self.assertIs(caught.exception.cleanup[1], pending)


class ChannelFailuresTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_cancellation_retains_its_original_object_and_local_cause(
        self,
    ):
        cancellation = asyncio.CancelledError("original cleanup cancellation")
        local = OSError(errno.EIO, "original independent failure")
        with self.assertRaises(asyncio.CancelledError) as caught:
            raise_capture_failures(None, (cancellation, local))
        self.assertIs(caught.exception, cancellation)
        self.assertIs(cancellation.__cause__.cleanup[1], local)

    def record(self):
        return ConnectionRecord(listener="tls", accepted=0.0)

    async def test_three_expected_peer_disconnects_are_raw_eof(self) -> None:
        for failure in (
            ConnectionResetError(errno.ECONNRESET, "reset"),
            ConnectionAbortedError(errno.ECONNABORTED, "aborted"),
            BrokenPipeError(errno.EPIPE, "pipe"),
        ):
            reader = asyncio.StreamReader()
            reader.set_exception(failure)
            record = self.record()
            channel = PlainChannel(reader, None, record, lambda: 1.0)
            self.assertEqual(await channel.read(), b"")
            self.assertEqual(record.client_eof, 1.0)

    async def test_windows_netname_deleted_reset_is_raw_eof(self) -> None:
        failure = ConnectionResetError(errno.EINVAL, "network name deleted")
        failure.winerror = 64
        reader = asyncio.StreamReader()
        reader.set_exception(failure)
        record = self.record()
        channel = PlainChannel(reader, None, record, lambda: 1.0)
        self.assertEqual(await channel.read(), b"")
        self.assertEqual(record.client_eof, 1.0)

    async def test_windows_non_peer_errors_retain_their_original_cause(self) -> None:
        ordinary = OSError(errno.EINVAL, "local invalid operation")
        ordinary.winerror = 64
        cancelled = ConnectionResetError(errno.EINVAL, "local cancelled operation")
        cancelled.winerror = 995
        for failure in (
            ordinary,
            ConnectionResetError(errno.EINVAL, "local invalid reset"),
            cancelled,
            ConnectionResetError(errno.EIO, "local I/O failure"),
            ConnectionResetError(errno.EBADF, "local descriptor failure"),
        ):
            with self.subTest(failure=failure):
                reader = asyncio.StreamReader()
                reader.set_exception(failure)
                record = self.record()
                channel = PlainChannel(reader, None, record, lambda: 1.0)
                with self.assertRaises(type(failure)) as caught:
                    await channel.read()
                self.assertIs(caught.exception, failure)
                self.assertIsNone(record.client_eof)

    async def test_unrelated_original_raw_read_errors_are_not_eof(self) -> None:
        for failure in (
            ConnectionError("other"),
            PermissionError("permission"),
            ConnectionResetError(errno.EIO, "local read failure"),
            ConnectionAbortedError(errno.EBADF, "local descriptor failure"),
            BrokenPipeError("unqualified pipe failure"),
        ):
            reader = asyncio.StreamReader()
            reader.set_exception(failure)
            record = self.record()
            channel = PlainChannel(reader, None, record, lambda: 1.0)
            with self.assertRaises(type(failure)) as caught:
                await channel.read()
            self.assertIs(caught.exception, failure)
            self.assertIsNone(record.client_eof)

    async def test_actual_invalid_tls_record_is_not_clean_eof(self) -> None:
        record = self.record()
        channel = TlsChannel(
            server_context(generate_certificate("server.phantom.test")),
            asyncio.StreamReader(),
            None,
            record,
            lambda: 1.0,
        )
        channel.incoming.write(b"not a TLS record")
        with self.assertRaises(ssl.SSLError):
            await channel.read()
        self.assertIsNone(record.client_eof)
        self.assertIsNone(channel.peer_handshake_failure)

    async def test_actual_invalid_tls_handshake_has_explicit_peer_marker(self) -> None:
        channel = TlsChannel(
            server_context(generate_certificate("server.phantom.test")),
            asyncio.StreamReader(),
            None,
            self.record(),
            lambda: 1.0,
        )
        channel.incoming.write(b"not a TLS record")
        with self.assertRaises(ssl.SSLError) as caught:
            await channel.handshake()
        self.assertIs(channel.peer_handshake_failure, caught.exception)
