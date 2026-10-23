"""Firefox ECH profile, identity, and owned launch controls."""

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.capture import chrome_ech as ech
from scripts.capture.browser_launch import LaunchedBrowser


class FirefoxEchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.certificate = self.root / "leaf.pem"
        self.key = self.root / "key.pem"
        self.database = self.root / "cert9.db"
        self.certificate.write_bytes(b"public certificate input")
        self.key.write_bytes(b"private key input")
        self.database.write_bytes(b"SQLite format 3\x00owned database")
        self.run = ech.CaptureRun(
            browser="firefox",
            browser_path=Path("firefox.exe"),
            client_version="158.0.1",
            operating_system="Windows 11",
            scenario="accept",
            origin="127.0.0.1:0",
            capture_binary=Path("capture.exe"),
            headless=False,
            certificate=self.certificate,
            private_key=self.key,
            certificate_sha256=hashlib.sha256(
                self.certificate.read_bytes()
            ).hexdigest(),
            cert9_db=self.database,
            cert9_sha256=hashlib.sha256(self.database.read_bytes()).hexdigest(),
        )

    def test_explicit_doh_profile_has_no_trust_or_name_resolution_bypass(self) -> None:
        plan = ech.launch_plan(self.run, template="https://127.0.0.1:32123/dns-query")
        self.assertEqual(
            dict(plan.firefox_preferences),
            {
                "network.trr.mode": 3,
                "network.trr.uri": "https://127.0.0.1:32123/dns-query",
                "network.trr.allow-rfc1918": True,
                "network.http.http3.enable": False,
            },
        )
        self.assertEqual(plan.extra_arguments, ())
        self.assertEqual(plan.profile_files, ())
        self.assertEqual(
            ech.origin_url("127.0.0.1:443"), "https://server.phantom.test/"
        )
        self.assertEqual(
            ech.origin_url("127.0.0.1:32124"), "https://server.phantom.test:32124/"
        )

    def test_identity_arguments_and_metadata_record_actual_profile_inputs(self) -> None:
        arguments = ech.capture_arguments(self.run, ech.launch_plan(self.run))
        self.assertEqual(
            arguments[1:4], ["--identity", str(self.certificate), str(self.key)]
        )
        self.assertIn(ech.FIREFOX_DNS_CONFIGURATION, arguments)
        self.assertTrue(
            arguments[-1].endswith("'https://server.phantom.test:<origin-port>/'")
        )
        self.assertNotIn("ignore-certificate", arguments[-1])
        certificate, key, database = ech.capture_inputs(self.run)
        self.assertEqual(
            (certificate, key, database),
            (
                self.certificate.read_bytes(),
                self.key.read_bytes(),
                self.database.read_bytes(),
            ),
        )

    def test_untrusted_or_oversized_inputs_fail_before_peer_acquisition(self) -> None:
        cases = [
            replace(self.run, cert9_sha256="0" * 64),
            replace(self.run, certificate_sha256="0" * 64),
            replace(self.run, cert9_sha256="invalid"),
            replace(self.run, certificate=None),
        ]
        for run in cases:
            with (
                self.subTest(run=run.cert9_sha256),
                patch.object(ech, "ProcessContainer") as owner,
            ):
                with self.assertRaises(ValueError):
                    ech.capture(run)
                owner.assert_not_called()
        with (
            patch.object(ech, "MAX_IDENTITY_BYTES", 4),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            ech.capture_inputs(self.run)
        with (
            patch.object(ech, "MAX_CERT9_BYTES", 4),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            ech.capture_inputs(self.run)
        self.database.write_bytes(b"not an NSS database")
        with self.assertRaisesRegex(ValueError, "NSS SQL"):
            ech.capture_inputs(
                replace(
                    self.run,
                    cert9_sha256=hashlib.sha256(self.database.read_bytes()).hexdigest(),
                )
            )

    def test_unsupported_modes_and_origin_boundaries_are_rejected(self) -> None:
        for run in (
            replace(self.run, quic=True),
            replace(self.run, dns_from_policy=True),
            replace(self.run, origin="192.0.2.1:443"),
            replace(self.run, origin="127.0.0.1:65536"),
            replace(self.run, browser="chrome"),
        ):
            with (
                self.subTest(browser=run.browser, origin=run.origin),
                self.assertRaises(ValueError),
            ):
                ech.capture_inputs(run)
        for template in (
            "https://127.0.0.1.evil:3/dns-query",
            "https://user@127.0.0.1:3/dns-query",
            "https://127.0.0.1:3/other",
            "https://127.0.0.1:3/dns-query?secret",
        ):
            self.assertIsNone(
                ech.parse_ready_line(
                    f"ready doh_template={template} origin=127.0.0.1:443"
                )
            )

    def test_profile_database_is_copied_before_the_existing_launcher_starts(
        self,
    ) -> None:
        profile = self.root / "disposable"
        profile.mkdir()
        database = self.database.read_bytes()
        browser = ech._TrustedFirefox(ech.launch_plan(self.run), ech.URL, database)
        sentinel = Mock()

        def start(_owner: LaunchedBrowser, actual: Path) -> Mock:
            self.assertEqual(actual, profile)
            self.assertEqual((actual / "cert9.db").read_bytes(), database)
            return sentinel

        with patch.object(LaunchedBrowser, "_start", start):
            self.assertIs(browser._start(profile), sentinel)
        self.assertEqual(self.database.read_bytes(), database)

    def test_success_uses_reported_port_and_preserves_existing_owner_cleanup(
        self,
    ) -> None:
        observer = Mock()
        observer.ready = ("https://127.0.0.1:32123/dns-query", "127.0.0.1:32124", None)
        owner = Mock()
        owner.start.return_value = True
        owner.poll.return_value = 0

        def container(_command: list[str], *, stdout: object, stderr: object) -> Mock:
            stdout.write(b"format=owned-test\n")
            stdout.flush()
            self.assertEqual(
                Path(_command[2]).read_bytes(), self.certificate.read_bytes()
            )
            self.assertEqual(Path(_command[3]).read_bytes(), self.key.read_bytes())
            return owner

        with (
            patch.object(ech, "ProcessContainer", side_effect=container),
            patch.object(ech, "_CaptureOutput", return_value=observer),
            patch.object(ech, "_TrustedFirefox") as browser,
        ):
            result = ech.capture(self.run)
        plan, url, database = browser.call_args.args
        self.assertEqual(url, "https://server.phantom.test:32124/")
        self.assertEqual(
            dict(plan.firefox_preferences)["network.trr.uri"], observer.ready[0]
        )
        self.assertEqual(database, self.database.read_bytes())
        self.assertIn(f"cert9_sha256={self.run.cert9_sha256}\n", result)
        owner.close.assert_called_once_with()
        browser.return_value.__exit__.assert_called_once()

    def test_failed_ready_identity_never_launches_a_browser_and_closes_peer(
        self,
    ) -> None:
        observer = Mock()
        observer.ready = ("https://127.0.0.1:3/dns-query", "127.0.0.2:4", None)
        owner = Mock()
        owner.start.return_value = True
        with (
            patch.object(ech, "ProcessContainer", return_value=owner),
            patch.object(ech, "_CaptureOutput", return_value=observer),
            patch.object(ech, "_TrustedFirefox") as browser,
            self.assertRaisesRegex(RuntimeError, "origin does not match"),
        ):
            ech.capture(self.run)
        browser.assert_not_called()
        owner.close.assert_called_once_with()

    def test_added_identity_metadata_cannot_exceed_the_fixture_limit(self) -> None:
        observer = Mock()
        observer.ready = ("https://127.0.0.1:32123/dns-query", "127.0.0.1:32124", None)
        owner = Mock()
        owner.start.return_value = True
        owner.poll.return_value = 0

        def container(_command: list[str], *, stdout: object, stderr: object) -> Mock:
            stdout.write(b"fixture\n")
            stdout.flush()
            return owner

        with (
            patch.object(ech, "ProcessContainer", side_effect=container),
            patch.object(ech, "_CaptureOutput", return_value=observer),
            patch.object(ech, "_TrustedFirefox"),
            patch.object(ech, "MAX_CAPTURE_OUTPUT", 16),
            self.assertRaisesRegex(ValueError, "output limit"),
        ):
            ech.capture(self.run)
        owner.close.assert_called_once_with()


class FirefoxEchResumptionTests(unittest.TestCase):
    setUp = FirefoxEchTests.setUp

    def test_sequences_use_the_actual_seed_url_without_changing_preferences(
        self,
    ) -> None:
        for sequence in ("early-accept", "early-reject", "ech-retry"):
            with self.subTest(sequence=sequence):
                run = replace(self.run, resumption=sequence)
                plan = ech.launch_plan(run)
                self.assertEqual(plan, ech.launch_plan(self.run))
                arguments = ech.capture_arguments(run, plan)
                self.assertEqual(arguments[4:6], ["--resumption", sequence])
                self.assertEqual(arguments[6], "accept")
                self.assertTrue(
                    arguments[-1].endswith(
                        "'https://server.phantom.test:<origin-port>/seed'"
                    )
                )
                self.assertEqual(
                    ech.capture_url(run, "127.0.0.1:32124"),
                    "https://server.phantom.test:32124/seed",
                )
                self.assertIsNotNone(ech.capture_inputs(run))

    def test_sequence_validation_precedes_peer_acquisition(self) -> None:
        for changes in (
            {"resumption": "unknown"},
            {"resumption": "early-accept", "scenario": "reject"},
            {"resumption": "early-accept", "quic": True},
            {"resumption": "early-accept", "browser": "chrome"},
        ):
            with (
                self.subTest(changes=changes),
                patch.object(ech, "ProcessContainer") as owner,
            ):
                with self.assertRaisesRegex(ValueError, "Firefox TCP"):
                    ech.capture(replace(self.run, **changes))
                owner.assert_not_called()

    def test_sequence_launch_uses_reported_port_and_keeps_no_offer_output(self) -> None:
        run = replace(self.run, resumption="early-accept")
        observer = Mock()
        observer.ready = ("https://127.0.0.1:32123/dns-query", "127.0.0.1:32124", None)
        owner = Mock()
        owner.start.return_value = True
        owner.poll.return_value = 0
        output = b"resumption_sequence=early-accept\nresumption_served_probe_gets=1\nresumption_slot_5_early_plaintext_bytes=0\n"

        def container(command: list[str], *, stdout: object, stderr: object) -> Mock:
            self.assertEqual(command[4:6], ["--resumption", "early-accept"])
            stdout.write(output)
            stdout.flush()
            return owner

        with (
            patch.object(ech, "ProcessContainer", side_effect=container),
            patch.object(ech, "_CaptureOutput", return_value=observer),
            patch.object(ech, "_TrustedFirefox") as browser,
        ):
            fixture = ech.capture(run)
        self.assertEqual(
            browser.call_args.args[1], "https://server.phantom.test:32124/seed"
        )
        self.assertIn(output.decode("ascii"), fixture)
        self.assertNotIn("early_data_offered=true", fixture)
        self.assertNotIn("early_data_accepted=true", fixture)
        owner.close.assert_called_once_with()
        browser.return_value.__exit__.assert_called_once()
