"""Mac orchestration controls; no browser or host resolver changes."""

from __future__ import annotations

import asyncio
import unittest
from collections.abc import Awaitable, Callable
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from scripts.capture import mac_native_dns_capture as capture
from scripts.capture.browser_failures import BrowserLaunchFailures

NONCE = "ab" * 16
DOMAIN = f"n-{NONCE}.phantom.test"
BASELINE = """DNS configuration

resolver #1
  nameserver[0] : 192.0.2.1
  flags    : Request A records
  order    : 200000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 4 (en0)
  flags    : Scoped, Request A records
"""
OWNED = f"""DNS configuration

resolver #7
  domain   : {DOMAIN}
  nameserver[0] : 127.0.0.1
  port     : 1053
  flags    : Supplemental, Request A records
  order    : 100000
"""


class ResolverTests(unittest.TestCase):
    def test_resolver_display_indices_do_not_change_the_baseline(self) -> None:
        baseline = capture.resolver_blocks(BASELINE)
        text = OWNED + BASELINE.replace("resolver #1", "resolver #8")
        capture.verify_dns(text, baseline, DOMAIN, 1053, installed=True)
        capture.verify_dns(
            BASELINE.replace("resolver #1", "resolver #9"),
            baseline,
            DOMAIN,
            1053,
            installed=False,
        )

    def test_address_port_duplicates_and_baseline_changes_are_rejected(self) -> None:
        baseline = capture.resolver_blocks(BASELINE)
        for text in (
            OWNED.replace("127.0.0.1", "192.0.2.9") + BASELINE,
            OWNED.replace("1053", "1054") + BASELINE,
            OWNED + OWNED + BASELINE,
            OWNED + BASELINE.replace("192.0.2.1", "192.0.2.2"),
            BASELINE,
        ):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                capture.verify_dns(text, baseline, DOMAIN, 1053, installed=True)
        with self.assertRaisesRegex(RuntimeError, "remains registered"):
            capture.verify_dns(
                OWNED + BASELINE, baseline, DOMAIN, 1053, installed=False
            )

    def test_unrecognized_scutil_output_is_not_an_empty_baseline(self) -> None:
        for text in ("", "unrecognized output", "DNS configuration\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                capture.resolver_blocks(text)


class RetryEvidenceTests(unittest.TestCase):
    def records(self) -> list[dict]:
        return [
            {
                "name": DOMAIN,
                "kind": 1,
                "transport": "udp",
                "query_hex": "1234",
                "peer": ("127.0.0.1", 10001),
                "unix_ns": 10,
                "disposition": "dropped-first-udp-a",
                "response_hex": None,
                "error": None,
            },
            {
                "name": DOMAIN,
                "kind": 1,
                "transport": "udp",
                "query_hex": "abcd",
                "peer": ("127.0.0.1", 10002),
                "unix_ns": 20,
                "response_hex": "abcd",
                "error": None,
                "response_queued_ns": 21,
            },
        ]

    def test_later_answer_can_use_another_transaction_and_source_port(self) -> None:
        capture.verify_retry(self.records(), DOMAIN)
        rows = self.records()
        rows[1]["transport"] = "tcp"
        rows[1]["response_drained_ns"] = rows[1].pop("response_queued_ns")
        capture.verify_retry(rows, DOMAIN)

    def test_missing_unsent_drop_or_later_sent_answer_is_rejected(self) -> None:
        cases = []
        rows = self.records()
        cases.extend(([], rows[:1], rows[1:], list(reversed(rows))))
        for index, changes in (
            (0, {"response_hex": "1234"}),
            (0, {"response_queued_ns": 11}),
            (0, {"response_drained_ns": 11}),
            (0, {"transport": "tcp"}),
            (0, {"error": "drop failed"}),
            (1, {"name": "other.phantom.test"}),
            (1, {"kind": 28}),
            (1, {"transport": "tcp"}),
            (1, {"error": "send failed"}),
            (1, {"response_hex": None}),
        ):
            rows = self.records()
            rows[index].update(changes)
            cases.append(rows)
        rows = self.records()
        del rows[1]["response_queued_ns"]
        cases.append(rows)
        rows = self.records()
        cases.append([rows[0].copy(), *rows])
        rows = self.records()
        cases.append([rows[1].copy(), *rows])
        for rows in cases:
            with (
                self.subTest(rows=rows),
                self.assertRaisesRegex(RuntimeError, "dropped UDP A"),
            ):
                capture.verify_retry(rows, DOMAIN)


class OriginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origin = capture.Origin(DOMAIN, NONCE)
        self.expected_close_error = None
        await self.origin.start()

    async def asyncTearDown(self) -> None:
        if self.expected_close_error is None:
            await self.origin.close()
        else:
            kind, message = self.expected_close_error
            with self.assertRaisesRegex(kind, message):
                await self.origin.close()

    async def connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.origin.port)

        async def close() -> None:
            writer.close()
            await writer.wait_closed()

        self.addAsyncCleanup(close)
        return reader, writer

    async def get(self, target: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.origin.port)
        writer.write(
            f"GET {target} HTTP/1.1\r\nHost: {DOMAIN}:{self.origin.port}\r\n\r\n".encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_token_body_is_consumed_before_the_script_requests_done(self) -> None:
        page = await self.get(f"/start?token={NONCE}")
        self.assertIn(b"then(r=>r.text())", page)
        self.assertLess(page.index(b"text!=='ok\\n'"), page.index(b"fetch('/done?"))
        self.assertTrue((await self.get(f"/body?token={NONCE}")).endswith(b"ok\n"))
        self.assertFalse(self.origin.done.is_set())
        await self.get(f"/done?token={NONCE}")
        self.assertTrue(self.origin.done.is_set())

    async def test_other_run_token_cannot_complete_the_scene(self) -> None:
        response = await self.get("/done?token=elsewhere")
        self.assertIn(b"404 Not Found", response)
        self.assertFalse(self.origin.done.is_set())

    async def test_unused_tcp_connection_can_close_without_starting_a_request(
        self,
    ) -> None:
        reader, writer = await self.connection()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        await asyncio.wait_for(asyncio.gather(*tuple(self.origin.tasks)), 1)
        self.assertEqual(self.origin.errors, [])
        self.assertEqual(self.origin.requests, [])
        self.assertFalse(self.origin.body_drained)
        self.assertFalse(self.origin.done.is_set())
        self.assertEqual(self.origin.writers, set())

    async def test_partial_request_header_eof_remains_a_retained_failure(self) -> None:
        reader, writer = await self.connection()
        partial = f"GET /body?token={NONCE} HTTP/1.1\r\nHost:".encode("ascii")
        writer.write(partial)
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        await asyncio.wait_for(asyncio.gather(*tuple(self.origin.tasks)), 1)
        self.assertEqual(len(self.origin.errors), 1)
        self.assertIsInstance(self.origin.errors[0], asyncio.IncompleteReadError)
        self.assertEqual(self.origin.errors[0].partial, partial)
        self.assertEqual(self.origin.requests, [])
        self.assertFalse(self.origin.body_drained)
        self.assertFalse(self.origin.done.is_set())
        self.assertEqual(self.origin.writers, set())
        self.expected_close_error = (asyncio.IncompleteReadError, "bytes read")

    async def test_done_before_the_measured_body_is_a_retained_failure(self) -> None:
        response = await self.get(f"/done?token={NONCE}")
        self.assertEqual(response, b"")
        self.assertFalse(self.origin.done.is_set())
        self.assertFalse(self.origin.body_drained)
        self.expected_close_error = (
            ValueError,
            "completion preceded the measured body",
        )

    async def test_ninth_active_connection_stops_admission_and_is_reported(
        self,
    ) -> None:
        for _ in range(8):
            await self.connection()
        reader, _ = await self.connection()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertFalse(self.origin.server.is_serving())
        self.expected_close_error = (RuntimeError, "connection limit exceeded")

    async def test_sixty_fifth_connection_exceeds_the_lifetime_limit(self) -> None:
        for _ in range(64):
            self.assertIn(b"404 Not Found", await self.get("/favicon.ico"))
        reader, _ = await self.connection()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertFalse(self.origin.server.is_serving())
        self.expected_close_error = (RuntimeError, "connection limit exceeded")


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_during_spawn_keeps_the_owner_collectable(self) -> None:
        started, release = asyncio.Event(), asyncio.Event()
        process = SimpleNamespace()

        async def spawn(*_args: object, **_kwargs: object) -> SimpleNamespace:
            started.set()
            await release.wait()
            return process

        guard = capture.ResolverGuard(NONCE, 1053, {})
        with patch.object(capture.asyncio, "create_subprocess_exec", side_effect=spawn):
            task = asyncio.create_task(guard.start())
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertIs(guard.process, process)

    async def test_guard_invocation_is_isolated_and_does_not_inherit_control_writer(
        self,
    ) -> None:
        record = {}
        stdout = asyncio.StreamReader()
        stdout.feed_data(
            (f'{{"event":"installed","domain":"{DOMAIN}","port":1053}}\n').encode()
        )
        process = SimpleNamespace(stdout=stdout)
        launch = AsyncMock(return_value=process)
        with patch.object(capture.asyncio, "create_subprocess_exec", launch):
            await capture.ResolverGuard(NONCE, 1053, record).start()
        command = launch.call_args.args
        self.assertEqual(command[:3], ("/usr/bin/sudo", "-n", "--"))
        self.assertIn("-I", command)
        self.assertTrue(launch.call_args.kwargs["close_fds"])
        self.assertEqual(command[-4:], ("--nonce", NONCE, "--port", "1053"))

    async def test_missing_restoration_acknowledgment_is_a_failure(self) -> None:
        process = SimpleNamespace(
            stdin=SimpleNamespace(
                write=lambda _: None, drain=AsyncMock(), close=lambda: None
            ),
            communicate=AsyncMock(return_value=(b"", b"owner failed")),
            returncode=1,
        )
        record = {}
        guard = capture.ResolverGuard(NONCE, 1053, record)
        guard.process = process
        with self.assertRaisesRegex(RuntimeError, "successful restoration"):
            await guard.close()
        self.assertEqual(record["guard_stderr"], "owner failed")


class OwnershipTests(unittest.IsolatedAsyncioTestCase):
    def owners(self, events: list, *, done: bool = False) -> tuple:
        def event(name: str) -> Callable[..., Awaitable[None]]:
            async def perform(*_args: object) -> None:
                events.append(name)

            return perform

        complete = asyncio.Event()
        if done:
            complete.set()
        dns = SimpleNamespace(
            start=AsyncMock(side_effect=event("dns-start")),
            close=AsyncMock(side_effect=event("dns-close")),
            address=("127.0.0.1", 1053),
            failed=asyncio.Event(),
            failures=[],
            records=lambda: [
                {
                    "name": DOMAIN,
                    "kind": 1,
                    "error": None,
                    "response_hex": "1234",
                    "response_queued_ns": 1,
                }
            ],
        )
        origin = SimpleNamespace(
            start=AsyncMock(side_effect=event("origin-start")),
            close=AsyncMock(side_effect=event("origin-close")),
            done=complete,
            port=1234,
            requests=[],
        )
        guard = SimpleNamespace(
            start=AsyncMock(side_effect=event("guard-start")),
            close=AsyncMock(side_effect=event("guard-close")),
        )
        driver = SimpleNamespace(
            __aenter__=AsyncMock(side_effect=event("browser-start")),
            __aexit__=AsyncMock(side_effect=event("browser-close")),
        )
        return dns, origin, guard, driver

    def patches(self, owners: tuple, events: list) -> ExitStack:
        stack = ExitStack()
        for name, owner in zip(
            ("NativeDnsServer", "Origin", "ResolverGuard", "BrowserDriver"),
            owners,
            strict=True,
        ):
            stack.enter_context(patch.object(capture, name, return_value=owner))
        stack.enter_context(
            patch.object(capture.secrets, "token_hex", return_value=NONCE)
        )
        stack.enter_context(
            patch.object(capture, "dns_configuration", AsyncMock(return_value=BASELINE))
        )

        async def wait_dns(*_args: object, installed: bool) -> str:
            events.append("registered" if installed else "restored")
            return OWNED + BASELINE if installed else BASELINE

        stack.enter_context(patch.object(capture, "wait_dns", side_effect=wait_dns))
        return stack

    async def test_success_joins_browser_then_restores_before_closing_peers(
        self,
    ) -> None:
        events = []
        owners = self.owners(events, done=True)
        with self.patches(owners, events):
            await capture.capture(Path("firefox"), {})
        self.assertEqual(
            events,
            [
                "dns-start",
                "origin-start",
                "guard-start",
                "registered",
                "browser-start",
                "browser-close",
                "guard-close",
                "restored",
                "origin-close",
                "dns-close",
            ],
        )

    async def test_repeated_cancellation_waits_for_restoration_acknowledgment(
        self,
    ) -> None:
        events = []
        owners = self.owners(events)
        entered, restoring, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def enter() -> None:
            entered.set()

        async def close() -> None:
            restoring.set()
            await release.wait()
            events.append("guard-close")

        owners[3].__aenter__.side_effect = enter
        owners[2].close.side_effect = close
        with self.patches(owners, events):
            task = asyncio.create_task(capture.capture(Path("firefox"), {}))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            await asyncio.wait_for(restoring.wait(), 1)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(
            events[-4:], ["guard-close", "restored", "origin-close", "dns-close"]
        )

    async def test_retry_scene_requires_drop_and_sent_answer_before_success(
        self,
    ) -> None:
        events = []
        owners = self.owners(events, done=True)
        rows = RetryEvidenceTests().records()
        owners[0].records = lambda: rows
        record = {}
        with self.patches(owners, events):
            await capture.capture(Path("firefox"), record, drop_first_udp_a=True)
        self.assertTrue(record["drop_first_udp_a"])
        self.assertEqual(record["dns_records"], rows)
        self.assertEqual(
            events[-5:],
            ["browser-close", "guard-close", "restored", "origin-close", "dns-close"],
        )

    async def test_retry_scene_missing_drop_cannot_publish_even_after_done(
        self,
    ) -> None:
        events = []
        owners = self.owners(events, done=True)
        record = {}
        with (
            self.patches(owners, events),
            self.assertRaisesRegex(RuntimeError, "dropped UDP A"),
        ):
            await capture.capture(Path("firefox"), record, drop_first_udp_a=True)
        self.assertEqual(
            events[-4:], ["guard-close", "restored", "origin-close", "dns-close"]
        )

    async def test_retry_scene_without_repeat_or_done_times_out_and_restores(
        self,
    ) -> None:
        events = []
        owners = self.owners(events)
        rows = RetryEvidenceTests().records()[:1]
        owners[0].records = lambda: rows
        record = {}
        with (
            self.patches(owners, events),
            patch.object(capture, "RUN_SECONDS", 0.01),
            self.assertRaisesRegex(TimeoutError, "scene did not complete"),
        ):
            await capture.capture(Path("firefox"), record, drop_first_udp_a=True)
        self.assertEqual(record["dns_records"], rows)
        self.assertEqual(
            events[-4:], ["guard-close", "restored", "origin-close", "dns-close"]
        )

    async def test_retry_scene_cleanup_failure_still_prevents_success(self) -> None:
        events = []
        owners = self.owners(events, done=True)
        owners[0].records = RetryEvidenceTests().records
        failure = RuntimeError("retry resolver restore failed")
        owners[2].close.side_effect = failure
        record = {}
        with (
            self.patches(owners, events),
            self.assertRaisesRegex(RuntimeError, "retry resolver restore failed"),
        ):
            await capture.capture(Path("firefox"), record, drop_first_udp_a=True)
        self.assertEqual(
            record["cleanup_errors"], ["RuntimeError: retry resolver restore failed"]
        )
        self.assertEqual(events[-3:], ["restored", "origin-close", "dns-close"])

    async def test_primary_and_cleanup_failures_remain_distinct(self) -> None:
        events = []
        owners = self.owners(events)
        original, cleanup = (
            RuntimeError("launch failed"),
            RuntimeError("restore failed"),
        )
        owners[3].__aenter__.side_effect = original
        owners[2].close.side_effect = cleanup
        with (
            self.patches(owners, events),
            self.assertRaises(BrowserLaunchFailures) as raised,
        ):
            await capture.capture(Path("firefox"), {})
        self.assertIs(raised.exception.primary, original)
        self.assertEqual(raised.exception.cleanup, (cleanup,))
        self.assertEqual(events[-3:], ["restored", "origin-close", "dns-close"])


class CommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_scutil_spawn_is_collected_and_killed_before_return(
        self,
    ) -> None:
        started, release = asyncio.Event(), asyncio.Event()
        process = SimpleNamespace(
            returncode=None, kill=Mock(), wait=AsyncMock(return_value=-9)
        )

        async def spawn(*_args: object, **_kwargs: object) -> SimpleNamespace:
            started.set()
            await release.wait()
            return process

        with patch.object(capture.asyncio, "create_subprocess_exec", side_effect=spawn):
            task = asyncio.create_task(capture.dns_configuration())
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once()
        process.wait.assert_awaited_once()

    def process(self, stdout: bytes, stderr: bytes, code: int) -> SimpleNamespace:
        def reader(data: bytes) -> asyncio.StreamReader:
            stream = asyncio.StreamReader()
            stream.feed_data(data)
            stream.feed_eof()
            return stream

        return SimpleNamespace(
            stdout=reader(stdout),
            stderr=reader(stderr),
            returncode=code,
            wait=AsyncMock(return_value=code),
            kill=Mock(),
        )

    async def test_scutil_output_is_bounded_before_it_can_become_a_baseline(
        self,
    ) -> None:
        process = self.process(b"x" * 524289, b"", 0)
        with (
            patch.object(
                capture.asyncio,
                "create_subprocess_exec",
                AsyncMock(return_value=process),
            ),
            self.assertRaisesRegex(RuntimeError, "exceeds 512 KiB"),
        ):
            await capture.dns_configuration()
        process.wait.assert_awaited_once()

    async def test_failed_scutil_preserves_the_failure_instead_of_empty_configuration(
        self,
    ) -> None:
        process = self.process(b"partial", b"operation denied", 7)
        with (
            patch.object(
                capture.asyncio,
                "create_subprocess_exec",
                AsyncMock(return_value=process),
            ),
            self.assertRaisesRegex(RuntimeError, "operation denied"),
        ):
            await capture.dns_configuration()


if __name__ == "__main__":
    unittest.main()
