import shlex
import unittest
import unittest.mock
from pathlib import Path
from xml.sax.saxutils import escape

from scripts.capture.android_device import (
    ANDROID_BROWSERS,
    EMULATOR_HOST_LOOPBACK,
    AndroidLaunch,
    AndroidSession,
    TypingFailed,
    command_line_text,
    device_arguments,
    focused_field_text,
    gecko_config_text,
    reverse_ports,
)
from scripts.capture.browser_launch import (
    CHROMIUM_BROWSERS,
    CHROMIUM_FLAGS,
    FIREFOX_PREFERENCES,
    LaunchedBrowser,
    LaunchPlan,
)

URL = "https://server.phantom.test:9450/run/token"


def screen(focused: str) -> str:
    text = escape(focused, {'"': "&quot;"})
    return f'<hierarchy><node text="{text}" focused="true" /></hierarchy>'


RULES = "--host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost"


class RecordingDevice:
    def __init__(self, screen: str = "") -> None:
        self.commands: list[tuple[str, ...]] = []
        self.pushed: list[tuple[str, str]] = []
        self.screen = screen

    def run(self, *arguments: str, check: bool = True) -> str:
        self.commands.append(arguments)
        if arguments[:2] == ("shell", "uiautomator"):
            return "dumped"
        if arguments[:2] == ("shell", "cat"):
            return self.next_screen()
        return ""

    def next_screen(self) -> str:
        return self.screen

    def shell(self, *arguments: str, check: bool = True) -> str:
        return self.run("shell", *arguments, check=check)

    def push_text(self, text: str, device_path: str) -> None:
        self.pushed.append((device_path, text))


class AndroidArgumentTests(unittest.TestCase):
    def test_resolver_rules_point_at_the_emulator_route_to_host_loopback(
        self,
    ) -> None:
        arguments = device_arguments([RULES, "--disable-quic"])

        self.assertEqual(
            arguments,
            [
                "--host-resolver-rules=MAP server.phantom.test "
                f"{EMULATOR_HOST_LOOPBACK}, EXCLUDE localhost",
                "--disable-quic",
            ],
        )

    def test_port_qualified_resolver_rules_keep_their_port(self) -> None:
        arguments = device_arguments(
            ["--host-resolver-rules=MAP server.phantom.test 127.0.0.1:4433"]
        )

        self.assertEqual(
            arguments,
            [
                "--host-resolver-rules=MAP server.phantom.test "
                f"{EMULATOR_HOST_LOOPBACK}:4433"
            ],
        )

    def test_only_device_loopback_ports_are_reversed_once_each(self) -> None:
        ports = reverse_ports(
            "http://127.0.0.1:9450/page",
            [
                "--proxy-server=http://127.0.0.1:9451",
                RULES.replace("127.0.0.1", "127.0.0.1:9999"),
                "--x=http://localhost:9450/",
            ],
        )

        self.assertEqual(ports, [9450, 9451])

    def test_named_origin_needs_no_reverse(self) -> None:
        self.assertEqual(reverse_ports(URL, [RULES]), [])

    def test_command_line_file_starts_with_a_program_name(self) -> None:
        text = command_line_text(["--disable-fre", RULES])

        self.assertTrue(text.endswith("\n"))
        self.assertEqual(shlex.split(text), ["_", "--disable-fre", RULES])

    def test_gecko_config_lists_preferences_in_order(self) -> None:
        text = gecko_config_text(
            [("network.dns.localDomains", "a.test"), ("network.trr.mode", 5)]
        )

        self.assertEqual(
            text,
            'prefs:\n  network.dns.localDomains: "a.test"\n  network.trr.mode: 5\n',
        )

    def test_browser_without_debug_configuration_refuses_switches(self) -> None:
        launch = AndroidLaunch(ANDROID_BROWSERS["opera-android"], URL, ("--x",))

        with self.assertRaises(ValueError):
            launch.configuration()


class AndroidPlanTests(unittest.TestCase):
    def test_android_chromium_plan_records_device_switches_and_url(self) -> None:
        plan = LaunchPlan("chrome-android", Path("adb"), False, (RULES,))

        recorded = shlex.split(plan.recorded_arguments(URL))

        self.assertEqual(plan.launch_mode, "android-typed")
        self.assertEqual(
            LaunchPlan(
                "chrome-android", Path("adb"), False, android_entry="intent"
            ).launch_mode,
            "android-intent",
        )
        self.assertEqual(plan.client_name, "Google Chrome")
        self.assertIn("chrome-android", CHROMIUM_BROWSERS)
        self.assertEqual(recorded[0], "--disable-fre")
        self.assertEqual(recorded[1 : 1 + len(CHROMIUM_FLAGS)], list(CHROMIUM_FLAGS))
        self.assertEqual(recorded[-2], device_arguments([RULES])[0])
        self.assertEqual(recorded[-1], URL)
        self.assertNotIn("--headless=new", recorded)

    def test_android_proxy_launch_leaves_out_the_direct_route_flag(self) -> None:
        proxy = "--proxy-server=http://127.0.0.1:9451"
        plan = LaunchPlan("chrome-android", Path("adb"), False, (proxy,))

        recorded = shlex.split(plan.recorded_arguments(URL))

        self.assertIn(proxy, recorded)
        self.assertNotIn("--no-proxy-server", recorded)
        self.assertIn(
            "--no-proxy-server",
            shlex.split(
                LaunchPlan("chrome-android", Path("adb"), False).recorded_arguments(URL)
            ),
        )

    def test_android_profile_cannot_receive_files(self) -> None:
        plan = LaunchPlan(
            "chrome-android",
            Path("adb"),
            False,
            profile_files=(("cert_override.txt", ""),),
        )

        with self.assertRaises(ValueError):
            LaunchedBrowser(plan, URL).android_launch()

    def test_firefox_android_launch_carries_the_baseline_preferences_first(
        self,
    ) -> None:
        plan = LaunchPlan(
            "firefox-android",
            Path("adb"),
            False,
            firefox_preferences=(("network.dns.localDomains", "a.test"),),
        )

        launch = LaunchedBrowser(plan, URL).android_launch()

        self.assertEqual(launch.arguments, ())
        self.assertEqual(
            launch.preferences,
            (*FIREFOX_PREFERENCES, ("network.dns.localDomains", "a.test")),
        )


class AndroidSessionTests(unittest.TestCase):
    def test_session_clears_configures_launches_and_cleans_up(self) -> None:
        device = RecordingDevice()
        browser = ANDROID_BROWSERS["chrome-android"]
        launch = AndroidLaunch(
            browser,
            "http://127.0.0.1:9450/a?b=1&c=2",
            ("--disable-fre",),
            entry="intent",
            settle=0,
        )

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            started = list(device.commands)

        package = browser.package
        stops = [
            ("shell", "am", "force-stop", b.package) for b in ANDROID_BROWSERS.values()
        ]
        self.assertEqual(started[: len(stops)], stops)
        self.assertEqual(started[len(stops)], ("shell", "am", "kill-all"))
        self.assertEqual(started[len(stops) + 1], ("shell", "pm", "clear", package))
        self.assertIn(
            ("shell", "am", "set-debug-app", "--persistent", package), started
        )
        self.assertIn(("reverse", "tcp:9450", "tcp:9450"), started)
        self.assertEqual(
            started[-1],
            (
                "shell",
                "am",
                "start",
                "-W",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                "'http://127.0.0.1:9450/a?b=1&c=2'",
                "-p",
                package,
            ),
        )
        self.assertEqual(
            device.pushed,
            [("/data/local/tmp/chrome-command-line", "_ --disable-fre\n")],
        )
        stopped = device.commands[len(started) :]
        self.assertIn(("shell", "am", "force-stop", package), stopped)
        self.assertIn(("reverse", "--remove", "tcp:9450"), stopped)
        self.assertIn(
            ("shell", "rm", "-f", "/data/local/tmp/chrome-command-line"), stopped
        )
        self.assertIn(("shell", "am", "clear-debug-app"), stopped)

    def test_typed_entry_presses_enter_once_the_focused_field_holds_the_url(
        self,
    ) -> None:
        url = "http://127.0.0.1:9450/a?b=1&c=2"
        device = RecordingDevice(screen=screen(url))
        browser = ANDROID_BROWSERS["chrome-android"]
        launch = AndroidLaunch(browser, url, settle=0, typing_delay=0)

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            started = list(device.commands)

        typed = started.index(("shell", "input", "text", "http:/"))
        self.assertIn("about:blank", started[typed - 2])
        self.assertEqual(
            started[typed - 1], ("shell", "input", "keycombination", "113", "40")
        )
        self.assertEqual(started[typed + 1][:2], ("shell", "uiautomator"))
        self.assertEqual(started[-1], ("shell", "input", "keyevent", "66"))

    def test_typed_entry_continues_from_the_characters_that_arrived(self) -> None:
        url = "http://127.0.0.1:9450/"
        device = RecordingDevice(screen=screen("http:"))
        screens = iter([screen("http:"), screen(url)])
        device.next_screen = lambda: next(screens)  # type: ignore[attr-defined]
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"], url, settle=0, typing_delay=0
        )

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            typed = [
                c[3] for c in device.commands if c[:3] == ("shell", "input", "text")
            ]

        self.assertEqual(typed, ["http:/", "//127."])

    def test_typed_entry_clears_a_field_that_is_not_a_url_prefix(self) -> None:
        url = "http://127.0.0.1:9450/"
        device = RecordingDevice()
        screens = iter([screen("hxyz"), screen(url)])
        device.next_screen = lambda: next(screens)  # type: ignore[attr-defined]
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"], url, settle=0, typing_delay=0
        )

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            commands = list(device.commands)

        focus = ("shell", "input", "keycombination", "113", "40")
        cleared = commands.index(focus, commands.index(focus) + 1)
        self.assertEqual(
            commands[cleared + 1], ("shell", "input", "keycombination", "113", "29")
        )
        self.assertEqual(commands[cleared + 2], ("shell", "input", "keyevent", "67"))
        self.assertEqual(commands[cleared + 3], ("shell", "input", "text", "http:/"))

    def test_typed_entry_types_over_and_then_removes_an_inline_completion(self) -> None:
        url = "http://127.0.0.1:9450/"
        device = RecordingDevice()
        screens = iter(
            [
                screen("http:/"),
                screen("http://127.0.0.0"),
                screen("http://127.0.0.1:94"),
                screen("http://127.0.0.1:9450/"),
            ]
        )
        device.next_screen = lambda: next(screens)  # type: ignore[attr-defined]
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"], url, settle=0, typing_delay=0
        )

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            commands = list(device.commands)

        typed = [c[3] for c in commands if c[:3] == ("shell", "input", "text")]
        self.assertEqual(typed, ["http:/", "/127.0", ".0.1:9", "450/"])
        self.assertEqual(
            commands.count(("shell", "input", "keycombination", "113", "40")), 1
        )

    def test_typed_entry_deletes_a_completion_after_the_whole_url(self) -> None:
        url = "http://127.0.0.1:9450/"
        device = RecordingDevice()
        screens = iter([screen(url + "page"), screen(url)])
        device.next_screen = lambda: next(screens)  # type: ignore[attr-defined]
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"], url, settle=0, typing_delay=0
        )
        # Pretend every chunk but the last already arrived.
        session = AndroidSession(device, launch)  # type: ignore[arg-type]
        with (
            unittest.mock.patch(
                "scripts.capture.android_device.TYPING_CHUNK", len(url)
            ),
            session,
        ):
            commands = list(device.commands)

        enter = commands.index(("shell", "input", "keyevent", "66"))
        self.assertEqual(commands[enter - 3], ("shell", "input", "keyevent", "67"))

    def test_typed_entry_never_submits_a_partial_url(self) -> None:
        device = RecordingDevice(screen=screen("htt"))
        browser = ANDROID_BROWSERS["chrome-android"]
        launch = AndroidLaunch(browser, URL, settle=0, typing_delay=0, typing_timeout=0)

        with self.assertRaises(TypingFailed):
            AndroidSession(device, launch).__enter__()  # type: ignore[arg-type]

        self.assertNotIn(("shell", "input", "keyevent", "66"), device.commands)
        # Each of the three attempts starts from a cleared profile.
        self.assertEqual(
            device.commands.count(("shell", "pm", "clear", browser.package)), 3
        )
        self.assertIn(
            ("shell", "am", "force-stop", browser.package), device.commands[-6:]
        )

    def test_typed_entry_taps_wait_on_a_not_responding_dialog(self) -> None:
        url = "http://127.0.0.1:9450/"
        dialog = (
            '<hierarchy><node text="Close app" focused="true" />'
            '<node text="Wait" resource-id="android:id/aerr_wait" '
            'bounds="[70,1304][1010,1430]" /></hierarchy>'
        )
        device = RecordingDevice()
        screens = iter([dialog, screen("http:/"), screen(url)])
        device.next_screen = lambda: next(screens)  # type: ignore[attr-defined]
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"], url, settle=0, typing_delay=0
        )

        with AndroidSession(device, launch):  # type: ignore[arg-type]
            commands = list(device.commands)

        tap = commands.index(("shell", "input", "tap", "540", "1367"))
        self.assertEqual(
            commands[tap + 1], ("shell", "input", "keycombination", "113", "40")
        )
        self.assertEqual(commands[-1], ("shell", "input", "keyevent", "66"))

    def test_focused_field_text_reads_only_the_focused_node(self) -> None:
        dump = (
            "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy>"
            '<node text="suggestion" focused="false" />'
            '<node text="a?b=1&amp;c=2" focused="true" /></hierarchy>'
        )

        self.assertEqual(focused_field_text(dump), "a?b=1&c=2")
        self.assertIsNone(focused_field_text("ERROR: null root node"))

    def test_typed_entry_refuses_a_url_adb_would_mangle(self) -> None:
        browser = ANDROID_BROWSERS["chrome-android"]

        with self.assertRaises(ValueError):
            AndroidLaunch(browser, "http://127.0.0.1:9450/a%20b")


if __name__ == "__main__":
    unittest.main()
