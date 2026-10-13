import contextlib
import io
import unittest
from unittest import mock

from scripts.capture import quic_resumption
from scripts.capture.quic_resumption import (
    SCENARIOS,
    RunRecord,
    RunResult,
    capture_run,
    parse_client_hello,
    render_fixture,
)

ODD_SUITES = bytes.fromhex("0100002b0303" + "00" * 32 + "000001130101000000")
EVEN_SUITES = bytes.fromhex("0100002b0303" + "00" * 32 + "000002130101000000")


class CaptureInputTests(unittest.IsolatedAsyncioTestCase):
    def test_odd_cipher_vector_is_refused_by_shared_parser_and_compare(self):
        from scripts.capture.snapshot_compare import Variation, compare_hello

        self.assertEqual(parse_client_hello(EVEN_SUITES).cipher_suites, (0x1301,))
        with self.assertRaises(ValueError):
            parse_client_hello(ODD_SUITES)
        with self.assertRaises(ValueError):
            compare_hello("hello", ODD_SUITES, EVEN_SUITES, Variation())

    def test_malformed_derived_vectors_raise_input_errors(self):
        from scripts.capture.quic_resumption import (
            KEY_SHARE,
            PRE_SHARED_KEY,
            PSK_KEY_EXCHANGE_MODES,
            ClientHelloShape,
        )

        for kind, body, method in (
            (KEY_SHARE, b"\x00\x01\x00", "key_share_groups"),
            (KEY_SHARE, b"\x00\x00\x00", "key_share_groups"),
            (PRE_SHARED_KEY, b"\x00\x01\x00\x00\x00\x00\x00\x00\x00", "pre_shared_key"),
            (PRE_SHARED_KEY, b"\x00\x00\x00\x01\x02", "pre_shared_key"),
            (PSK_KEY_EXCHANGE_MODES, b"", "psk_key_exchange_modes"),
            (PSK_KEY_EXCHANGE_MODES, b"\x02\x01", "psk_key_exchange_modes"),
        ):
            shape = ClientHelloShape((), ((kind, body),))
            with self.subTest(kind=kind, body=body), self.assertRaises(ValueError):
                getattr(shape, method)()

    def test_cli_input_failures_precede_all_run_acquisition(self):
        for option, value in (
            ("--timeout", "nan"),
            ("--timeout", "inf"),
            ("--timeout", "0"),
            ("--repeat", "129"),
            ("--client-version", "154\nformat=injected"),
            ("--operating-system", "test\x7f"),
        ):
            arguments = [
                "--browser",
                "manual",
                "--client-version",
                "0",
                "--scenario",
                "accept",
            ]
            arguments += [option, value]
            with (
                self.subTest(option=option, value=value),
                mock.patch.object(quic_resumption, "capture_run") as capture,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                quic_resumption.main(arguments)
            self.assertEqual(raised.exception.code, 2)
            capture.assert_not_called()

    async def test_invalid_deadlines_fail_before_capture_acquisition(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with (
                self.subTest(timeout=timeout),
                mock.patch.object(
                    quic_resumption, "generate_certificate"
                ) as certificate,
                mock.patch.object(quic_resumption, "serving") as listener,
                mock.patch.object(quic_resumption, "BrowserDriver") as browser,
                self.assertRaises(ValueError),
            ):
                await capture_run(
                    SCENARIOS["accept"],
                    browser="manual",
                    executable=None,
                    headless=True,
                    listen_host="127.0.0.1",
                    timeout=timeout,
                    field_trial_config=False,
                )
            certificate.assert_not_called()
            listener.assert_not_called()
            browser.assert_not_called()

    def test_literal_metadata_is_refused_before_fixture_serialization(self):
        result = RunResult(RunRecord(), 1, "manual", timed_out=True)
        for field in ("client", "client_version", "operating_system", "launch_mode"):
            for value in (
                "test\nformat=injected",
                "test\rnext=x",
                "test\0",
                "test\x7f",
                "tést",
            ):
                values = {
                    "client": "scripted",
                    "client_version": "0",
                    "operating_system": "test",
                    "launch_mode": "manual",
                    "listen_host": "127.0.0.1",
                }
                values[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    render_fixture(SCENARIOS["accept"], [result], **values)


if __name__ == "__main__":
    unittest.main()
