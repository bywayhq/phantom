import argparse
import asyncio
import io
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from scripts.capture import chrome_http3
from scripts.capture.quic_packet_diff import QuicPacketCapture


class StartupFailure(OSError):
    pass


class StartupTransport:
    def get_extra_info(self, name):
        if name != "sockname":
            raise AssertionError(f"unexpected transport field {name}")
        return "127.0.0.1", 43210


class StartupServer:
    def __init__(self, close_error=None):
        self._transport = StartupTransport()
        self.acquired = False
        self.close_calls = 0
        self.close_error = close_error

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class StartupOutput(io.StringIO):
    def __init__(self, server, failure):
        super().__init__()
        self.server = server
        self.failure = failure

    def write(self, text):
        if not self.server.acquired:
            raise AssertionError("startup output preceded acquisition")
        raise self.failure


class ChromeHttp3StartupTests(unittest.TestCase):
    def test_output_failure_after_acquisition_closes_server_and_clears_capture(self):
        self.check_startup_failure(StartupFailure("startup output failed"))

    def test_output_interrupt_after_acquisition_closes_server_and_clears_capture(self):
        self.check_startup_failure(KeyboardInterrupt("startup output interrupted"))

    def test_bookkeeping_failure_after_acquisition_closes_server_and_clears_capture(
        self,
    ):
        self.check_startup_failure(
            StartupFailure("bound port bookkeeping failed"), bookkeeping=True
        )

    def test_startup_failure_keeps_primary_and_both_cleanup_causes(self):
        previous = ValueError("startup original cause")
        primary = StartupFailure("startup output failed")
        primary.__cause__ = previous
        close = StartupFailure("server close failed")
        clear = StartupFailure("packet clear failed")

        self.check_startup_failure(
            primary, close_error=close, clear_error=clear, previous=previous
        )

    def test_startup_interrupt_keeps_identity_when_cleanup_also_interrupts(self):
        self.check_startup_failure(
            KeyboardInterrupt("startup first interrupt"),
            close_error=KeyboardInterrupt("server close interrupt"),
            clear_error=StartupFailure("packet clear failed"),
        )

    def test_completed_startup_keeps_bound_metadata_and_fixture(self):
        server = StartupServer()
        args = startup_arguments(packet_summary=None)
        output = io.StringIO()
        capture_type = chrome_http3.Capture

        def completed_capture(**kwargs):
            capture = capture_type(**kwargs)
            capture.complete.set()
            return capture

        async def acquire(host, port, **kwargs):
            self.assertEqual((host, port), ("127.0.0.1", 0))
            server.acquired = True
            return server

        with (
            patch.object(chrome_http3, "serve", side_effect=acquire),
            patch.object(chrome_http3.QuicConfiguration, "load_cert_chain"),
            patch.object(chrome_http3, "Capture", side_effect=completed_capture),
            patch.object(capture_type, "fixture", return_value="format=literal\n"),
            patch.object(chrome_http3.sys, "stderr", output),
        ):
            result = asyncio.run(chrome_http3.run(args))

        self.assertTrue(server.acquired)
        self.assertGreaterEqual(server.close_calls, 1)
        self.assertEqual(args.listen, "127.0.0.1:43210")
        self.assertEqual(args.launch_arguments, "--origin=127.0.0.1:43210")
        self.assertEqual(output.getvalue(), "listening on 127.0.0.1:43210\n")
        self.assertEqual(result.fixture, "format=literal\n")
        self.assertIsNone(result.packet_summary)
        self.assertIsNone(result.client_hello_fixture)

    def test_failed_acquisition_keeps_original_error_without_closing_server(self):
        primary = StartupFailure("acquisition failed")
        server = StartupServer()

        with (
            patch.object(chrome_http3, "serve", side_effect=primary),
            patch.object(chrome_http3.QuicConfiguration, "load_cert_chain"),
            patch.object(chrome_http3.sys, "stderr", io.StringIO()),
            self.assertRaises(StartupFailure) as raised,
        ):
            asyncio.run(chrome_http3.run(startup_arguments(packet_summary=None)))

        self.assertIs(raised.exception, primary)
        self.assertFalse(server.acquired)
        self.assertEqual(server.close_calls, 0)

    def check_startup_failure(
        self,
        primary,
        *,
        bookkeeping=False,
        close_error=None,
        clear_error=None,
        previous=None,
    ):
        server = StartupServer(close_error)
        capture = QuicPacketCapture()
        capture.add_datagram(b"literal buffered datagram")
        clear_calls = []
        original_clear = capture.clear
        observed = None

        async def acquire(host, port, **kwargs):
            self.assertEqual((host, port), ("127.0.0.1", 0))
            server.acquired = True
            return server

        def fail_bookkeeping(*args):
            self.assertTrue(server.acquired)
            raise primary

        def clear_capture():
            clear_calls.append("clear")
            if clear_error is not None:
                raise clear_error
            original_clear()

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(chrome_http3, "serve", side_effect=acquire)
            )
            stack.enter_context(
                patch.object(chrome_http3.QuicConfiguration, "load_cert_chain")
            )
            stack.enter_context(
                patch.object(chrome_http3, "QuicPacketCapture", return_value=capture)
            )
            stack.enter_context(
                patch.object(capture, "clear", side_effect=clear_capture)
            )
            stack.enter_context(
                patch.object(chrome_http3.sys, "stderr", StartupOutput(server, primary))
            )
            if bookkeeping:
                stack.enter_context(
                    patch.object(
                        chrome_http3, "record_bound_port", side_effect=fail_bookkeeping
                    )
                )
            try:
                asyncio.run(chrome_http3.run(startup_arguments()))
            except BaseException as error:
                observed = error

        try:
            self.assertTrue(server.acquired)
            self.assertEqual(server.close_calls, 1)
            self.assertEqual(clear_calls, ["clear"])
            self.assertIs(observed, primary)
            if clear_error is None:
                self.assertEqual(capture.buffered_datagram_count, 0)
            else:
                self.assertEqual(capture.buffered_datagram_count, 1)

            if close_error is not None or clear_error is not None:
                cleanup = observed.__cause__
                self.assertIs(getattr(cleanup, "server_error", None), close_error)
                self.assertIs(getattr(cleanup, "capture_error", None), clear_error)
                self.assertIs(getattr(cleanup, "previous_cause", None), previous)
        finally:
            original_clear()


def startup_arguments(*, packet_summary=Path("unused-summary.json")):
    return argparse.Namespace(
        listen="127.0.0.1:0",
        launch_arguments="--origin=127.0.0.1:<port>",
        packet_summary=packet_summary,
        client_hello=None,
        certificate=Path("unused-certificate.pem"),
        private_key=Path("unused-private-key.pem"),
        timeout=0.1,
    )


if __name__ == "__main__":
    unittest.main()
