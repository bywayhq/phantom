import json
import unittest
from pathlib import Path

from scripts.capture.chrome_ech import (
    DNS_CONFIGURATION,
    URL,
    CaptureRun,
    capture_arguments,
    launch_plan,
    local_state,
    parse_ready_line,
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
            ("https://127.0.0.1:5353/dns-query", "127.0.0.1:443"),
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


if __name__ == "__main__":
    unittest.main()
