"""Headful evidence needs remote shutdown, process exit and a complete NetLog."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture.tests.test_alt_svc_race_startup_lifecycle import CaptureResources


class HeadfulExitTests(unittest.IsolatedAsyncioTestCase):
    async def capture(
        self, *, headless=False, complete=True, exited=True, owned_browser=True
    ):
        resources = CaptureResources("healthy")
        self.addAsyncCleanup(resources.backup)
        resources.install()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        profile = Path(directory.name)
        netlog = profile / "netlog.json"
        document = {
            "constants": {
                "logEventTypes": {},
                "logSourceType": {},
                "logEventPhase": {},
            },
            "events": [],
        }
        if complete:
            document["polledData"] = {}
        netlog.write_text(json.dumps(document), encoding="utf-8")
        controlled = race.BrowserDriver
        observed = {"close": [], "fallback": [], "wait": []}

        class Driver(controlled):
            def __init__(self, plan, url):
                super().__init__(plan, url)
                observed["plan"] = plan
                self.browser = (
                    SimpleNamespace(process=object(), profile=profile)
                    if owned_browser
                    else None
                )

            async def __aexit__(self, *details):
                observed["fallback"].append(details)
                await super().__aexit__(*details)

        async def close(actual_profile, browser, run):
            self.assertEqual(actual_profile, profile)
            self.assertEqual(browser, "chrome")
            self.assertTrue(run.done.is_set())
            self.assertEqual(resources.h2_exchanges[-1][1:], (b"204", b""))
            observed["close"].append("after-done")

        async def wait(process, timeout):
            observed["wait"].append(timeout)
            if not headless:
                self.assertEqual(observed["close"], ["after-done"])
            return exited

        try:
            with (
                patch.object(race, "BrowserDriver", Driver),
                patch.object(race, "close_headful_browser", close),
                patch.object(race, "wait_for_exit", wait),
            ):
                observed["result"] = await race.capture_run(
                    race.Scenario(
                        "close", "controlled page completion", "blackhole", ()
                    ),
                    listen_host="127.0.0.1",
                    browser="chrome",
                    executable=None,
                    headless=headless,
                    netlog=netlog,
                    timeout=5,
                )
        except BaseException as error:
            observed["error"] = error

        self.assertTrue(await resources.closed_before_backup())
        self.assertEqual(len(observed["fallback"]), 1)
        self.assertEqual(observed["wait"], [60.0] if owned_browser else [])
        return observed

    async def test_headful_closes_after_done_before_waiting_for_exit(self):
        observed = await self.capture()

        self.assertNotIn("error", observed)
        self.assertTrue(observed["result"].exited_gracefully)
        self.assertEqual(observed["close"], ["after-done"])
        self.assertIn("--remote-debugging-port=0", observed["plan"].extra_arguments)
        self.assertIn(
            "--remote-debugging-address=127.0.0.1", observed["plan"].extra_arguments
        )

    async def test_headful_rejects_incomplete_netlog_despite_process_exit(self):
        observed = await self.capture(complete=False)

        self.assertNotIn("result", observed)
        self.assertIsInstance(observed["error"], ValueError)
        self.assertIn("NetLog is incomplete", str(observed["error"]))

    async def test_headful_exit_timeout_reaches_force_cleanup_without_success(self):
        observed = await self.capture(exited=False)

        self.assertNotIn("result", observed)
        error = observed["error"]
        self.assertIsInstance(error, TimeoutError)
        self.assertIn("did not exit", str(error))
        self.assertIs(observed["fallback"][0][1], error)

    async def test_complete_netlog_cannot_replace_observation_of_the_owned_process_exit(
        self,
    ):
        observed = await self.capture(owned_browser=False)

        self.assertNotIn("result", observed)
        self.assertIsInstance(observed["error"], RuntimeError)
        self.assertIn("exit was not observed", str(observed["error"]))
        self.assertEqual(observed["close"], [])

    async def test_headless_keeps_dump_dom_without_remote_shutdown_or_completeness_change(
        self,
    ):
        observed = await self.capture(headless=True, complete=False, exited=False)

        self.assertNotIn("error", observed)
        self.assertEqual(observed["close"], [])
        self.assertFalse(observed["result"].exited_gracefully)
        self.assertIn("--dump-dom", observed["plan"].extra_arguments)
        self.assertFalse(
            any(
                flag.startswith("--remote-debugging")
                for flag in observed["plan"].extra_arguments
            )
        )
