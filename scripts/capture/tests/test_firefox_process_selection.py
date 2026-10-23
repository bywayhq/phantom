import asyncio
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.capture import firefox_socket_hooks as hooks

BROWSER = Path("C:/Firefox/firefox.exe").resolve()
PROFILE = Path("C:/Temp/owned-profile")


def process(pid: int, parent: int, *, content: bool = False) -> dict[str, object]:
    return {
        "ProcessId": pid,
        "ParentProcessId": parent,
        "ExecutablePath": str(BROWSER),
        "CommandLine": "firefox.exe "
        + ("-contentproc " if content else "")
        + f"--profile {PROFILE}",
    }


class ParentSelectionTests(unittest.TestCase):
    def select(
        self, listing: list[dict[str, object]], launcher: int | None = 11
    ) -> int | None:
        return hooks.browser_process(listing, executable=BROWSER, launcher_pid=launcher)

    def test_owned_bootstrap_is_not_a_second_firefox_launcher(self) -> None:
        bootstrap = {
            "ProcessId": 10,
            "ParentProcessId": 9,
            "ExecutablePath": "C:/Python/python.exe",
            "CommandLine": f'python -I -S -c "bootstrap" firefox.exe --profile {PROFILE}',
        }
        listing = [
            bootstrap,
            process(11, 10),
            process(12, 11),
            process(13, 12, content=True),
        ]
        self.assertEqual(self.select(listing), 12)

    def test_no_launcher_attaches_to_the_confirmed_browser(self) -> None:
        self.assertEqual(
            self.select([process(11, 10), process(12, 11, content=True)]), 11
        )

    def test_unrelated_profile_processes_cannot_be_selected(self) -> None:
        unrelated = process(51, 50)
        wrong_executable = process(61, 11)
        wrong_executable["ExecutablePath"] = str(BROWSER.parent / "other.exe")
        listing = [unrelated, wrong_executable, process(11, 10), process(12, 11)]
        self.assertEqual(self.select(listing), 12)
        self.assertIsNone(self.select([unrelated]))

    def test_missing_or_inaccessible_owned_identity_is_rejected(self) -> None:
        for listing in ([], [process(12, 11, content=True)], [process(12, 11)]):
            with self.subTest(listing=listing):
                self.assertIsNone(self.select(listing))
        root = process(11, 10)
        root["ExecutablePath"] = None
        self.assertIsNone(self.select([root]))
        self.assertIsNone(self.select([process(11, 10)], launcher=None))

    def test_ambiguous_or_cyclic_ancestry_is_rejected(self) -> None:
        for listing in (
            [process(11, 10), process(12, 11), process(13, 11)],
            [process(11, 10), process(12, 11), process(13, 12)],
            [process(11, 11)],
            [process(11, 10), process(11, 10)],
        ):
            with self.subTest(listing=listing):
                self.assertIsNone(self.select(listing))

    def test_windows_executable_identity_ignores_case_and_slash_spelling(self) -> None:
        root = process(11, 10)
        root["ExecutablePath"] = str(BROWSER).upper().replace("/", "\\")
        self.assertEqual(self.select([root]), 11)


class NativeSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_selection_reports_owned_identity_and_still_cleans_up(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["h2-backup"])
        plan = hooks.LaunchPlan("firefox", BROWSER, False)
        browser = Mock()
        browser.plan = plan
        browser.profile = PROFILE
        browser.launcher_pid = 11
        browser.__enter__ = Mock(return_value=browser)
        browser.__exit__ = Mock()
        listing = [process(11, 10), process(12, 11), process(13, 11)]
        listing[0]["CommandLine"] += " private-command-argument"
        with (
            patch.object(hooks, "LaunchedBrowser", return_value=browser),
            patch.object(hooks, "profile_processes", return_value=listing),
            patch.object(hooks, "Hooks") as attach,
        ):
            native = hooks._FirefoxNative(owner, plan, "http://127.0.0.1/", {})
            native.attach_requested.set()
            native.work()

        self.assertEqual(len(native.failures), 1)
        message = str(native.failures[0])
        self.assertTrue(
            message.startswith("no Firefox parent process for the capture profile: ")
        )
        diagnostic = json.loads(message.split(": ", 1)[1])
        self.assertEqual(diagnostic["launcher_pid"], 11)
        self.assertEqual(diagnostic["profile"], str(PROFILE))
        self.assertEqual(diagnostic["executable"], str(BROWSER))
        self.assertEqual([row["pid"] for row in diagnostic["processes"]], [11, 12, 13])
        self.assertEqual(
            [row["parent_pid"] for row in diagnostic["processes"]], [10, 11, 11]
        )
        self.assertFalse(any(row["content_process"] for row in diagnostic["processes"]))
        self.assertNotIn("private-command-argument", message)
        attach.assert_not_called()
        browser.__exit__.assert_called_once()
        self.assertFalse(native.cleanup_failed)
        await asyncio.sleep(0)

    async def test_native_worker_attaches_only_to_the_selected_owned_parent(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["h2-backup"])
        plan = hooks.LaunchPlan("firefox", BROWSER, False)
        browser = Mock()
        browser.plan = plan
        browser.profile = PROFILE
        browser.launcher_pid = 11
        browser.__enter__ = Mock(return_value=browser)
        browser.__exit__ = Mock()
        hooks_ready = SimpleNamespace(wait=lambda _seconds: True)
        agent = Mock(ready=hooks_ready, failure=None)
        with (
            patch.object(hooks, "LaunchedBrowser", return_value=browser),
            patch.object(
                hooks,
                "profile_processes",
                return_value=[process(11, 10), process(12, 11)],
            ),
            patch.object(hooks, "Hooks", return_value=agent) as attach,
        ):
            native = hooks._FirefoxNative(owner, plan, "http://127.0.0.1/", {})
            native.attach_requested.set()
            agent.attach.side_effect = native.stop_requested.set
            native.work()

        attach.assert_called_once_with(12, {})
        agent.attach.assert_called_once()
        agent.detach.assert_called_once()
        browser.__exit__.assert_called_once()
        self.assertTrue(native.launcher)
        self.assertEqual(native.failures, [])
        await asyncio.sleep(0)
