import shlex
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.capture.browser_launch import (
    CHROMIUM_BROWSERS,
    CHROMIUM_FLAGS,
    PROFILE_PLACEHOLDER,
    LaunchedBrowser,
    LaunchPlan,
    chromium_arguments,
    firefox_arguments,
    firefox_user_js,
    recorded_arguments,
    render_preferences,
)

URL = "http://127.0.0.1:9450/run/token"


class BrowserLaunchTests(unittest.TestCase):
    def test_headless_chromium_arguments_isolate_profile_and_end_with_url(
        self,
    ) -> None:
        profile = Path("profile")

        arguments = chromium_arguments(profile, URL, headless=True)

        self.assertEqual(
            arguments,
            ["--headless=new", f"--user-data-dir={profile}", *CHROMIUM_FLAGS, URL],
        )

    def test_headful_chromium_arguments_omit_headless_and_keep_extra_order(
        self,
    ) -> None:
        arguments = chromium_arguments(
            Path("profile"), URL, headless=False, extra=("--b", "--a")
        )

        self.assertNotIn("--headless=new", arguments)
        self.assertEqual(arguments[-3:], ["--b", "--a", URL])

    def test_firefox_arguments_use_a_separate_profile_directory(self) -> None:
        arguments = firefox_arguments(Path("profile"), URL, headless=True)

        self.assertEqual(
            arguments,
            [
                "--headless",
                "--wait-for-browser",
                "--no-remote",
                "--profile",
                "profile",
                URL,
            ],
        )

    def test_firefox_preferences_disable_background_services(self) -> None:
        preferences = firefox_user_js()

        self.assertIn(
            'user_pref("network.captive-portal-service.enabled", false);', preferences
        )
        self.assertIn('user_pref("network.proxy.type", 0);', preferences)
        self.assertIn(
            'user_pref("browser.startup.homepage_override.mstone", "ignore");',
            preferences,
        )
        self.assertTrue(preferences.endswith(");\n"))

    def test_recorded_arguments_replace_the_machine_local_profile(self) -> None:
        profile = Path("C:/Temp/phantom-capture-profile-x")
        arguments = chromium_arguments(profile, URL, headless=True)

        recorded = recorded_arguments(arguments, profile)

        self.assertNotIn(str(profile), recorded)
        self.assertIn(f"--user-data-dir={PROFILE_PLACEHOLDER}", shlex.split(recorded))

    def test_plan_records_launch_mode_and_portable_arguments(self) -> None:
        plan = LaunchPlan("firefox", Path("firefox.exe"), headless=False)

        self.assertEqual(plan.launch_mode, "headful")
        self.assertEqual(plan.client_name, "Mozilla Firefox")
        self.assertEqual(
            shlex.split(plan.recorded_arguments(URL)),
            [
                "--wait-for-browser",
                "--no-remote",
                "--profile",
                PROFILE_PLACEHOLDER,
                URL,
            ],
        )

    def test_chromium_forks_launch_with_the_chromium_arguments(self) -> None:
        chrome = LaunchPlan("chrome", Path("chrome.exe"), headless=True)
        for browser, client in (("brave", "Brave"), ("opera", "Opera")):
            plan = LaunchPlan(browser, Path(f"{browser}.exe"), headless=True)

            self.assertIn(browser, CHROMIUM_BROWSERS)
            self.assertEqual(plan.client_name, client)
            self.assertEqual(
                plan.recorded_arguments(URL), chrome.recorded_arguments(URL)
            )

    def test_manual_plan_never_starts_a_process(self) -> None:
        plan = LaunchPlan("manual", None, headless=False)

        self.assertEqual(plan.launch_mode, "manual")
        self.assertEqual(plan.recorded_arguments(URL), "manual")
        with self.assertRaises(ValueError):
            LaunchedBrowser(plan, URL)

    def test_process_launch_requires_an_executable(self) -> None:
        with self.assertRaises(ValueError):
            LaunchedBrowser(LaunchPlan("chrome", None, headless=True), URL)

    def test_firefox_profile_receives_extra_preferences_and_files(self) -> None:
        plan = LaunchPlan(
            "firefox",
            Path(sys.executable),
            headless=True,
            firefox_preferences=(("network.dns.localDomains", "a.test"),),
            profile_files=(("cert_override.txt", "line\tvalue\n"),),
        )

        with LaunchedBrowser(plan, URL) as browser:
            preferences = (browser.profile / "user.js").read_text(encoding="utf-8")
            override = (browser.profile / "cert_override.txt").read_bytes()

        self.assertTrue(
            preferences.endswith('user_pref("network.dns.localDomains", "a.test");\n')
        )
        self.assertEqual(override, b"line\tvalue\n")
        self.assertEqual(
            render_preferences(plan.firefox_preferences),
            'network.dns.localDomains="a.test"',
        )

    def test_profile_file_names_cannot_leave_the_profile(self) -> None:
        plan = LaunchPlan(
            "chrome",
            Path(sys.executable),
            headless=True,
            profile_files=(("../escape.txt", ""),),
        )
        browser = LaunchedBrowser(plan, URL)

        with self.assertRaises(ValueError), browser:
            pass

        self.assertIsNone(browser.profile)

    def test_failed_launch_removes_the_temporary_profile(self) -> None:
        before = set(Path(tempfile.gettempdir()).glob("phantom-capture-profile-*"))
        missing = Path(tempfile.gettempdir()) / "phantom-missing-browser.exe"
        browser = LaunchedBrowser(LaunchPlan("firefox", missing, headless=True), URL)

        with self.assertRaises(OSError), browser:
            pass

        self.assertIsNone(browser.profile)
        after = set(Path(tempfile.gettempdir()).glob("phantom-capture-profile-*"))
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
