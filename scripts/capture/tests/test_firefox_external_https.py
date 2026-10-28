import asyncio
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.browser_launch import LaunchedBrowser, LaunchPlan


class ExternalHttpsTests(unittest.IsolatedAsyncioTestCase):
    def test_external_origin_requires_the_fixed_hostname_and_explicit_port(
        self,
    ) -> None:
        self.assertEqual(
            hooks.native_https_port("https://server.phantom.test:8443"), 8443
        )
        for origin in (
            "http://server.phantom.test:8443",
            "https://other.phantom.test:8443",
            "https://server.phantom.test",
            "https://server.phantom.test:443",
            "https://server.phantom.test:0",
            "https://server.phantom.test:65536",
            "https://server.phantom.test:08443",
            "https://user@server.phantom.test:8443",
            "https://server.phantom.test:8443/",
            "https://server.phantom.test:8443?x",
            "https://server.phantom.test:8443#x",
            "https://server.phantom.test:8443\n",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                hooks.native_https_port(origin)

    async def test_invalid_external_scene_fails_before_binding(self) -> None:
        scenario = hooks.SCENARIOS["http1-idle"]
        for selected, origin in (
            (scenario, "https://other.phantom.test:8443"),
            (
                replace(scenario, rewrite_lookup=True),
                "https://server.phantom.test:8443",
            ),
            (replace(scenario, target="h2"), "https://server.phantom.test:8443"),
        ):
            with (
                self.subTest(scenario=selected, origin=origin),
                patch.object(hooks.asyncio, "start_server", AsyncMock()) as start,
                self.assertRaises(ValueError),
            ):
                await hooks.run_once(
                    selected, Path("unused"), external_https_origin=origin
                )
            start.assert_not_awaited()

    async def test_external_origin_cannot_adopt_prepared_listeners(self) -> None:
        scenario = hooks.SCENARIOS["http1-idle"]
        owner = hooks._FirefoxRun(scenario)
        listener = await asyncio.start_server(
            owner.origins.accept_target, "127.0.0.1", 0
        )
        owner.origins.listeners.append(listener)
        owner.origins.port = listener.sockets[0].getsockname()[1]
        with self.assertRaisesRegex(ValueError, "cannot use prepared"):
            await hooks.run_once(
                scenario,
                Path("unused"),
                prepared=owner,
                external_https_origin="https://server.phantom.test:8443",
            )
        self.assertFalse(listener.is_serving())
        self.assertFalse(owner.origins.peers)

    async def test_factory_failure_closes_only_the_controller_listener(self) -> None:
        scenario = hooks.SCENARIOS["http1-idle"]
        owner = hooks._FirefoxRun(scenario)
        cause = RuntimeError("independent trusted browser setup failure")
        observed = []

        def factory(plan: LaunchPlan, url: str) -> LaunchedBrowser:
            observed.append((plan, url))
            self.assertEqual(owner.origins.port, 8443)
            self.assertEqual(
                owner.origins.target_url, "https://server.phantom.test:8443"
            )
            self.assertIn(
                b"const T = 'https://server.phantom.test:8443';", owner.origins.page()
            )
            raise cause

        with (
            patch.object(hooks, "_FirefoxRun", return_value=owner),
            self.assertRaises(RuntimeError) as failure,
        ):
            await hooks.run_once(
                scenario,
                Path("unused"),
                external_https_origin="https://server.phantom.test:8443",
                browser_factory=factory,
            )

        self.assertIs(failure.exception, cause)
        self.assertEqual(len(observed), 1)
        plan, url = observed[0]
        self.assertEqual(plan.profile_files, ())
        self.assertEqual(plan.firefox_preferences, ())
        self.assertEqual(url, f"http://127.0.0.1:{owner.origins.page_port}/")
        self.assertEqual(len(owner.origins.listeners), 1)
        self.assertTrue(all(not item.is_serving() for item in owner.origins.listeners))
        self.assertIsNone(owner.native)

    async def test_cancellation_collects_the_custom_browser_before_the_controller(
        self,
    ) -> None:
        scenario = hooks.SCENARIOS["http1-idle"]
        owner = hooks._FirefoxRun(scenario)
        started = asyncio.Event()
        loop = asyncio.get_running_loop()
        exits = []
        creations = []

        class Browser:
            def __enter__(self) -> "Browser":
                loop.call_soon_threadsafe(started.set)
                return self

            def __exit__(self, *_args: object) -> None:
                exits.append(all(item.is_serving() for item in owner.origins.listeners))

        browser = Browser()

        def factory(plan: LaunchPlan, url: str) -> Browser:
            creations.append((plan, url))
            return browser

        with patch.object(hooks, "_FirefoxRun", return_value=owner):
            task = asyncio.create_task(
                hooks.run_once(
                    scenario,
                    Path("unused"),
                    external_https_origin="https://server.phantom.test:8443",
                    browser_factory=factory,
                )
            )
            try:
                await asyncio.wait_for(started.wait(), 2)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

        self.assertEqual(len(creations), 1)
        self.assertEqual(exits, [True])
        self.assertIs(owner.native.browser, browser)
        self.assertTrue(owner.native.future.done())
        self.assertEqual(len(owner.origins.listeners), 1)
        self.assertTrue(all(not item.is_serving() for item in owner.origins.listeners))
        self.assertFalse(owner.origins.writers)
        self.assertFalse(owner.origins.peers)
