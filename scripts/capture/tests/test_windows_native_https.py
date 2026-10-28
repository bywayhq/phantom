"""Independent wire, hook and owner contracts; no browser or DNS-policy changes."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from scripts.capture import windows_native_dns_capture as driver
from scripts.capture import windows_native_https as capture
from scripts.capture.browser_launch import LaunchPlan
from scripts.capture.native_dns import HttpsAnswer

RDATA = bytes.fromhex("00010000010003026832000500080006fe0d00020000")
QUERY = bytes.fromhex(
    "123401000001000000000000"
    "055f38343433065f687474707306736572766572077068616e746f6d04746573740000410001"
)
REPLY = (
    bytes.fromhex("123485000001000100000000")
    + QUERY[12:]
    + bytes.fromhex("c00c00410001000000050016")
    + RDATA
)
SERVICE = "_8443._https.server.phantom.test"
FIXTURE = (
    "format=phantom-ech-client-hello-v2\nscenario=accept\n"
    "listen_address=127.0.0.1:8443\n"
    "dns_ech_config_list_hex=0006fe0d00020000\nconnection_count=1\n"
    "connection_0_ech_accepted=true\nconnection_0_inner_server_name=server.phantom.test\n"
    "connection_0_handshake=ok\nconnection_0_request_served=true\n"
)


def evidence() -> tuple[SimpleNamespace, list[dict]]:
    done = asyncio.Event()
    done.set()
    result = SimpleNamespace(
        reports=[
            {"kind": "firefox-config", "time_ms": 1000},
            {
                "kind": "dnsquery-return",
                "host": SERVICE,
                "query_type": 65,
                "status": 0,
                "time_ms": 1003,
                "records": [[65, 1, 5]],
            },
        ],
        timed_out=False,
        errors=[],
        origins=SimpleNamespace(done=done),
        frida_version="17.24.3",
    )
    records = [
        {
            "name": SERVICE,
            "kind": 65,
            "unix_ns": 1_001_000_000,
            "response_queued_ns": 1_002_000_000,
            "query_hex": QUERY.hex(),
            "response_hex": REPLY.hex(),
            "error": None,
        }
    ]
    return result, records


class EvidenceTests(unittest.TestCase):
    def test_success_requires_wire_native_api_accepted_ech_and_browser_done(
        self,
    ) -> None:
        result, records = evidence()
        self.assertEqual(
            capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE),
            {
                "positive_https_wire_responses": 1,
                "successful_native_https_returns": 1,
                "ech_accepted_connections": [0],
                "browser_body_completed": True,
            },
        )

    def test_wire_or_api_alone_does_not_prove_selection_or_body_completion(
        self,
    ) -> None:
        result, records = evidence()
        with self.assertRaisesRegex(RuntimeError, "positive native HTTPS"):
            capture.validate(result, [], HttpsAnswer(8443, RDATA), FIXTURE)
        result.reports.pop()
        with self.assertRaisesRegex(RuntimeError, "native HTTPS API"):
            capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)
        for field, replacement in (
            ("ech_accepted=true", "ech_accepted=false"),
            ("inner_server_name=server.phantom.test", "inner_server_name=other.test"),
            ("handshake=ok", "handshake=failed"),
            ("request_served=true", "request_served=false"),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(RuntimeError, "accepted ECH"),
            ):
                result, records = evidence()
                capture.validate(
                    result,
                    records,
                    HttpsAnswer(8443, RDATA),
                    FIXTURE.replace(field, replacement),
                )
        result.origins.done.clear()
        with self.assertRaisesRegex(RuntimeError, "browser did not complete"):
            capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)

    def test_bad_hook_state_or_unfinished_dns_send_is_rejected(self) -> None:
        for change in (
            "timeout",
            "hook-error",
            "version",
            "missing-ready",
            "early-wire",
            "unsent",
            "peer-error",
        ):
            result, records = evidence()
            if change == "timeout":
                result.timed_out = True
            elif change == "hook-error":
                result.errors.append("hook attachment failed")
            elif change == "version":
                result.frida_version = "other"
            elif change == "missing-ready":
                result.reports.pop(0)
            elif change == "early-wire":
                records[0]["unix_ns"] = 999_000_000
            elif change == "unsent":
                del records[0]["response_queued_ns"]
            else:
                records[0]["error"] = "send failed"
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)

    def test_nonpositive_or_wrong_type_native_api_result_is_rejected(self) -> None:
        for field, value in (
            ("status", 9501),
            ("query_type", 1),
            ("records", [[65, 1, 4]]),
            ("time_ms", 999),
        ):
            result, records = evidence()
            result.reports[1][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(RuntimeError, "native HTTPS API"),
            ):
                capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)

    def test_raw_query_cannot_be_reclassified_by_journal_labels(self) -> None:
        for wire in (
            QUERY[:-4] + bytes.fromhex("00010001"),
            QUERY.replace(b"server", b"absent"),
        ):
            result, records = evidence()
            records[0]["query_hex"] = wire.hex()
            records[0]["response_hex"] = (
                REPLY[:12] + wire[12:] + REPLY[len(QUERY) :]
            ).hex()
            with self.subTest(query=wire), self.assertRaises(RuntimeError):
                capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)

    def test_response_corruption_or_trailing_data_is_rejected(self) -> None:
        for reply in (
            REPLY[:-1],
            REPLY[:-1] + b"\xff",
            b"\xab\xcd" + REPLY[2:],
            REPLY + b"\x00",
        ):
            result, records = evidence()
            records[0]["response_hex"] = reply.hex()
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                capture.validate(result, records, HttpsAnswer(8443, RDATA), FIXTURE)

    def test_fixture_publication_identity_and_unique_fields_are_checked(self) -> None:
        for fixture in (
            FIXTURE + "scenario=accept\n",
            FIXTURE + "not-a-field\n",
            FIXTURE.replace("connection_count=1", "connection_count=65"),
            FIXTURE.replace("scenario=accept", "scenario=reject"),
            FIXTURE.replace("127.0.0.1:8443", "127.0.0.1:8444"),
            FIXTURE.replace("0006fe0d00020000", "0006fe0d00020001"),
        ):
            result, records = evidence()
            with (
                self.subTest(fixture=fixture),
                self.assertRaises((ValueError, RuntimeError)),
            ):
                capture.validate(result, records, HttpsAnswer(8443, RDATA), fixture)


class MetadataTests(unittest.TestCase):
    def test_metadata_is_single_bounded_lowercase_hex_and_keeps_exact_bytes(
        self,
    ) -> None:
        peer = capture.NativeHttpsPeer(Path("unused"), {})
        peer.diagnostic("other retained peer diagnostic")
        self.assertIsNone(peer.rdata)
        peer.diagnostic(capture.METADATA_PREFIX + RDATA.hex())
        self.assertEqual(peer.rdata, RDATA)
        self.assertEqual(
            capture.ech_config(peer.rdata), bytes.fromhex("0006fe0d00020000")
        )
        with self.assertRaisesRegex(ValueError, "repeated"):
            peer.diagnostic(capture.METADATA_PREFIX + RDATA.hex())
        for text in ("", "abc", RDATA.hex().upper(), "0" * 1026, " " + RDATA.hex()):
            with self.subTest(text=text), self.assertRaises(ValueError):
                capture.NativeHttpsPeer(Path("unused"), {}).diagnostic(
                    capture.METADATA_PREFIX + text
                )


class OwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_retains_files_after_process_failure_and_can_be_retried(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            peer = capture.NativeHttpsPeer(Path(directory), {})
            stream = peer.files.enter_context(
                (Path(directory) / "owned.log").open("wb")
            )
            attempts = []

            def close() -> None:
                attempts.append("close")
                if len(attempts) == 1:
                    raise RuntimeError("owned process remains live")

            peer.process = SimpleNamespace(close=close)
            with self.assertRaisesRegex(RuntimeError, "remains live"):
                await peer.close()
            self.assertFalse(stream.closed)
            await peer.close()
            self.assertTrue(stream.closed)
            self.assertEqual(attempts, ["close", "close"])

    async def test_browser_uses_nss_trust_and_native_defaults_without_verification_bypass(
        self,
    ) -> None:
        peer = capture.NativeHttpsPeer(Path("unused"), {"ech_peer": {}})
        peer.database = b"owned NSS database"
        plan = LaunchPlan(
            browser="firefox", executable=Path("firefox.exe"), headless=False
        )
        with patch.object(capture.chrome_ech, "_TrustedFirefox") as launch:
            peer.browser(plan, "http://127.0.0.1:9000/")
        configured, url, database = launch.call_args.args
        self.assertEqual(
            configured.firefox_preferences,
            (
                ("network.trr.mode", 5),
                ("network.proxy.type", 0),
                ("network.http.http3.enable", False),
            ),
        )
        self.assertEqual(configured.extra_arguments, ())
        self.assertEqual(database, peer.database)
        self.assertEqual(url, "http://127.0.0.1:9000/")
        self.assertEqual(plan.firefox_preferences, ())


class DriverTests(unittest.IsolatedAsyncioTestCase):
    def owners(self, events: list[str]) -> tuple[SimpleNamespace, SimpleNamespace]:
        tls = SimpleNamespace(
            start=AsyncMock(side_effect=lambda: events.append("https-start")),
            close=AsyncMock(side_effect=lambda: events.append("https-close")),
            completed=AsyncMock(return_value=FIXTURE),
            answer=HttpsAnswer(8443, RDATA),
            origin="https://server.phantom.test:8443",
            browser=lambda plan, url: None,
        )
        dns = SimpleNamespace(
            start=AsyncMock(side_effect=lambda: events.append("dns-start")),
            close=AsyncMock(side_effect=lambda: events.append("dns-close")),
            failed=asyncio.Event(),
            failures=[],
            address=("127.0.0.53", 53),
            records=lambda: evidence()[1],
        )
        return tls, dns

    async def test_peer_and_dns_are_ready_before_policy_and_external_factory_is_passed(
        self,
    ) -> None:
        events = []
        tls, dns = self.owners(events)
        result, _ = evidence()
        result.origins.connections = []
        result.moz_log_text = "retained native DNS log"
        browser = AsyncMock(return_value=(result, "recorded browser arguments"))
        record = {}

        def guard(_record: dict, action: str, *extra: str) -> dict:
            events.append(action)
            if action == "Install":
                self.assertEqual(events, ["https-start", "dns-start", "Install"])
                self.assertEqual(
                    extra[-4:], ("-DnsScene", "native-https-ech", "-OriginPort", "8443")
                )
            return {}

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(driver, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeHttpsPeer", return_value=tls),
            patch.object(
                driver, "NativeDnsServer", return_value=dns
            ) as dns_constructor,
            patch.object(driver, "guard", side_effect=guard),
            patch.object(driver.firefox, "run_once", browser),
            patch.object(driver.firefox, "render_run", return_value=["retained hooks"]),
        ):
            await driver.capture(
                Path("unused.exe"), record, scenario="native-https-ech"
            )
        dns_constructor.assert_called_once_with(
            "server.phantom.test", https_answer=tls.answer
        )
        self.assertEqual(browser.call_args.kwargs["external_https_origin"], tls.origin)
        self.assertIs(browser.call_args.kwargs["browser_factory"], tls.browser)
        self.assertEqual(events[-1], "Verify")
        self.assertIn("dns-close", events)
        self.assertIn("https-close", events)
        self.assertTrue(record["positive"]["browser_body_completed"])

    async def test_stage_failure_does_not_install_policy_and_collects_tls_owner(
        self,
    ) -> None:
        events = []
        tls, _dns = self.owners(events)
        failure = ValueError("peer metadata failed")
        tls.start.side_effect = failure
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(driver, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeHttpsPeer", return_value=tls),
            patch.object(driver, "NativeDnsServer") as dns_constructor,
            patch.object(driver, "guard", return_value={}) as guard,
            self.assertRaises(ValueError) as raised,
        ):
            await driver.capture(Path("unused.exe"), {}, scenario="native-https-ech")
        self.assertIs(raised.exception, failure)
        dns_constructor.assert_not_called()
        tls.close.assert_awaited_once()
        self.assertEqual([call.args[1] for call in guard.call_args_list], ["Verify"])

    async def test_browser_failure_or_cancellation_collects_both_owners_and_restores(
        self,
    ) -> None:
        for error in (ValueError("browser failed"), asyncio.CancelledError()):
            events = []
            tls, dns = self.owners(events)
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(driver, "OUTPUT", Path(temporary)),
                patch.object(capture, "NativeHttpsPeer", return_value=tls),
                patch.object(driver, "NativeDnsServer", return_value=dns),
                patch.object(driver, "guard", return_value={}) as guard,
                patch.object(driver.firefox, "run_once", AsyncMock(side_effect=error)),
                self.assertRaises(type(error)),
            ):
                await driver.capture(
                    Path("unused.exe"), {}, scenario="native-https-ech"
                )
            tls.close.assert_awaited_once()
            dns.close.assert_awaited_once()
            tls.completed.assert_not_awaited()
            self.assertEqual(
                [call.args[1] for call in guard.call_args_list], ["Install", "Verify"]
            )

    async def test_live_dns_failure_collects_browser_before_closing_tls_and_restoring(
        self,
    ) -> None:
        events = []
        tls, dns = self.owners(events)
        failure = ValueError("DNS peer failed")
        dns.failures.append(failure)
        dns.failed.set()

        async def browser(*args: object, **kwargs: object) -> None:
            try:
                await asyncio.Event().wait()
            finally:
                events.append("browser-collected")

        def guard(_record: dict, action: str, *extra: str) -> dict:
            events.append(action)
            return {}

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(driver, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeHttpsPeer", return_value=tls),
            patch.object(driver, "NativeDnsServer", return_value=dns),
            patch.object(driver, "guard", side_effect=guard),
            patch.object(driver.firefox, "run_once", side_effect=browser),
            self.assertRaisesRegex(RuntimeError, "native DNS peer failed") as raised,
        ):
            await driver.capture(Path("unused.exe"), {}, scenario="native-https-ech")
        self.assertIs(raised.exception.__cause__, failure)
        self.assertLess(events.index("browser-collected"), events.index("https-close"))
        self.assertLess(events.index("browser-collected"), events.index("dns-close"))
        self.assertEqual(events[-1], "Verify")
        tls.close.assert_awaited_once()
        dns.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
