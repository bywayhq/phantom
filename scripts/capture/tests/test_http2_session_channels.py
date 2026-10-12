"""TLS and raw stream failures must retain their actual input operation cause."""

import asyncio
import errno
import ssl
import unittest

from scripts.capture.http2_session import (
    ConnectionRecord,
    PlainChannel,
    TlsChannel,
    generate_certificate,
    raise_capture_failures,
    server_context,
)


class ChannelFailuresTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_cancellation_retains_its_original_object_and_local_cause(self):
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
