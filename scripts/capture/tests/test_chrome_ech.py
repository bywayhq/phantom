import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from pathlib import Path

from scripts.capture.chrome_ech import (
    DNS_CONFIGURATION,
    SPKI_PLACEHOLDER,
    URL,
    CaptureRun,
    capture_arguments,
    check_policy,
    launch_plan,
    local_state,
    main,
    parse_ready_line,
    parse_reg_query,
    read_policy,
)

EDGE_KEY = r"HKLM\SOFTWARE\Policies\Microsoft\Edge"
TEMPLATE = "https://127.0.0.1:65355/dns-query"
# A SHA-256 hash in base64, as the example prints it.
SPKI = "q" * 43 + "="
REG_OUTPUT = (
    "\r\n"
    f"{EDGE_KEY}\r\n"
    "    DnsOverHttpsMode    REG_SZ    secure\r\n"
    f"    DnsOverHttpsTemplates    REG_SZ    {TEMPLATE}\r\n"
    "    MetricsReportingEnabled    REG_DWORD    0x0\r\n"
    "\r\n"
)
EDGE_RUN = CaptureRun(
    browser="edge",
    browser_path=Path("msedge.exe"),
    client_version="153.0.4234.48",
    operating_system="Windows 11",
    scenario="accept",
    origin="127.0.0.1:443",
    capture_binary=Path("capture.exe"),
    headless=True,
    doh_port=65355,
    dns_from_policy=True,
)


class ChromeEchTest(unittest.TestCase):
    def test_local_state_sends_every_lookup_to_the_template(self) -> None:
        self.assertEqual(
            json.loads(local_state("https://127.0.0.1:5/dns-query")),
            {
                "dns_over_https": {
                    "mode": "secure",
                    "templates": "https://127.0.0.1:5/dns-query",
                }
            },
        )

    def test_ready_line_yields_the_template_and_origin(self) -> None:
        self.assertEqual(
            parse_ready_line(
                "ready doh_template=https://127.0.0.1:5353/dns-query "
                "origin=127.0.0.1:443\n"
            ),
            ("https://127.0.0.1:5353/dns-query", "127.0.0.1:443", None),
        )

    def test_quic_ready_line_yields_the_certificate_key_hash(self) -> None:
        self.assertEqual(
            parse_ready_line(
                "ready doh_template=https://127.0.0.1:5353/dns-query "
                f"origin=127.0.0.1:443 spki={SPKI}\n"
            ),
            ("https://127.0.0.1:5353/dns-query", "127.0.0.1:443", SPKI),
        )
        self.assertIsNone(
            parse_ready_line(
                "ready doh_template=https://127.0.0.1:5353/dns-query "
                "origin=127.0.0.1:443 spki=--flag\n"
            )
        )

    def test_other_lines_and_non_loopback_templates_are_not_ready(self) -> None:
        self.assertIsNone(parse_ready_line("Compiling phantom-net\n"))
        self.assertIsNone(
            parse_ready_line("ready doh_template=https://10.0.0.1/dns-query origin=x\n")
        )
        self.assertIsNone(parse_ready_line("ready doh_template=https://127.0.0.1/q\n"))

    def test_capture_arguments_record_the_launch(self) -> None:
        run = CaptureRun(
            browser="chrome",
            browser_path=Path("chrome.exe"),
            client_version="154.0.8037.58",
            operating_system="Windows 11",
            scenario="reject",
            origin="127.0.0.1:443",
            capture_binary=Path("capture.exe"),
            headless=True,
        )
        arguments = capture_arguments(run, launch_plan(run))
        self.assertEqual(
            arguments[:7],
            [
                "capture.exe",
                "reject",
                "127.0.0.1:443",
                "Google Chrome",
                "154.0.8037.58",
                "Windows 11",
                DNS_CONFIGURATION,
            ],
        )
        self.assertEqual(arguments[7], "headless")
        self.assertIn("--disable-quic", arguments[8])
        self.assertIn("--ignore-certificate-errors", arguments[8])
        self.assertNotIn("--host-resolver-rules", arguments[8])
        self.assertTrue(arguments[8].endswith(URL))

    def test_quic_arguments_enable_quic_and_record_the_key_placeholder(self) -> None:
        run = replace(
            EDGE_RUN, browser="chrome", doh_port=None, dns_from_policy=False, quic=True
        )
        arguments = capture_arguments(run, launch_plan(run))
        self.assertEqual(arguments[1:3], ["--quic", "accept"])
        launch = arguments[-1]
        self.assertIn("--enable-quic", launch)
        self.assertNotIn("--disable-quic", launch)
        self.assertIn("--origin-to-force-quic-on=server.phantom.test:9", launch)
        self.assertIn(
            f"--ignore-certificate-errors-spki-list={SPKI_PLACEHOLDER}", launch
        )
        self.assertIn(
            f"--ignore-certificate-errors-spki-list={SPKI}",
            launch_plan(run, SPKI).extra_arguments,
        )

    def test_chrome_arguments_name_no_doh_port_by_default(self) -> None:
        run = replace(EDGE_RUN, browser="chrome", doh_port=None, dns_from_policy=False)
        arguments = capture_arguments(run, launch_plan(run))
        self.assertNotIn("--doh-port", arguments)
        self.assertEqual(arguments[1], "accept")

    def test_policy_arguments_pass_the_port_and_record_the_policy(self) -> None:
        arguments = capture_arguments(EDGE_RUN, launch_plan(EDGE_RUN))
        self.assertEqual(arguments[1:4], ["--doh-port", "65355", "accept"])
        self.assertEqual(
            arguments[8],
            f"policy {EDGE_KEY} DnsOverHttpsMode=secure "
            "DnsOverHttpsTemplates=<doh_template>",
        )
        self.assertNotIn("Local State", " ".join(arguments))

    def test_reg_query_output_yields_string_values(self) -> None:
        self.assertEqual(
            parse_reg_query(REG_OUTPUT),
            {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": TEMPLATE},
        )

    def test_policy_is_read_from_the_64_bit_view_without_writing(self) -> None:
        calls = []

        def run(arguments, **_options):
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, REG_OUTPUT, "")

        self.assertEqual(read_policy(EDGE_KEY, run)["DnsOverHttpsMode"], "secure")
        self.assertEqual(calls, [["reg", "query", EDGE_KEY, "/reg:64"]])

    def test_a_missing_policy_key_reads_as_no_values(self) -> None:
        def run(arguments, **_options):
            return subprocess.CompletedProcess(arguments, 1, "", "ERROR")

        self.assertEqual(read_policy(EDGE_KEY, run), {})

    def test_matching_policy_passes(self) -> None:
        check_policy(EDGE_RUN, lambda key: parse_reg_query(REG_OUTPUT))

    def test_absent_or_different_policy_fails_before_launch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "DnsOverHttpsMode is absent"):
            check_policy(EDGE_RUN, lambda key: {})
        with self.assertRaisesRegex(
            RuntimeError, "DnsOverHttpsTemplates is 'https://127.0.0.1:5/dns-query'"
        ):
            check_policy(
                EDGE_RUN,
                lambda key: {
                    "DnsOverHttpsMode": "secure",
                    "DnsOverHttpsTemplates": "https://127.0.0.1:5/dns-query",
                },
            )
        with self.assertRaisesRegex(RuntimeError, "DnsOverHttpsMode is 'automatic'"):
            check_policy(
                EDGE_RUN,
                lambda key: {
                    "DnsOverHttpsMode": "automatic",
                    "DnsOverHttpsTemplates": TEMPLATE,
                },
            )

    def test_policy_mode_needs_a_fixed_port_and_a_known_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "--doh-port"):
            check_policy(replace(EDGE_RUN, doh_port=None), lambda key: {})
        with self.assertRaisesRegex(ValueError, "not supported for chrome"):
            check_policy(replace(EDGE_RUN, browser="chrome"), lambda key: {})

    def test_doh_port_outside_the_tcp_range_is_refused(self) -> None:
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            main(
                [
                    "--browser=edge",
                    "--browser-path=msedge.exe",
                    "--client-version=1",
                    "--operating-system=Windows",
                    "--scenario=accept",
                    "--capture-binary=capture.exe",
                    "--output=out.txt",
                    "--doh-port=70000",
                ]
            )


if __name__ == "__main__":
    unittest.main()


class AndroidBrowserRefusalTests(unittest.TestCase):
    def test_android_browsers_are_refused(self) -> None:
        for browser in ("chrome-android", "brave-android", "edge-android"):
            with (
                self.subTest(browser=browser),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                main(
                    [
                        "--browser",
                        browser,
                        "--browser-path",
                        "adb",
                        "--client-version",
                        "1",
                        "--scenario",
                        "accept",
                        "--capture-binary",
                        "capture",
                        "--output",
                        "out.txt",
                    ]
                )
