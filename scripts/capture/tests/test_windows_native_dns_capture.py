"""Hosted controller controls; no browser, DNS routing or NRPT mutation."""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from scripts.capture import windows_native_dns_capture as capture
from scripts.capture.browser_failures import BrowserLaunchFailures


def result() -> SimpleNamespace:
    done = asyncio.Event()
    done.set()
    return SimpleNamespace(
        timed_out=False,
        errors=[],
        reports=[{"kind": "firefox-config", "time_ms": 1000}],
        frida_version="17.24.3",
        origins=SimpleNamespace(
            done=done,
            connections=[SimpleNamespace(requests=[(1002, "/close?i=0")])],
        ),
    )


def answer(**changes: object) -> dict:
    record = {
        "name": capture.firefox.TARGET_HOST,
        "kind": 1,
        "transport": "udp",
        "unix_ns": 1_001_000_000,
        "response_hex": "1234",
        "response_queued_ns": 1_002_000_000,
        "error": None,
    }
    record.update(changes)
    return record


def dropped(**changes: object) -> dict:
    record = {
        "name": capture.firefox.TARGET_HOST,
        "kind": 1,
        "transport": "udp",
        "unix_ns": 1_000_500_000,
        "disposition": "dropped-first-udp-a",
        "response_hex": None,
        "error": None,
    }
    record.update(changes)
    return record


def two_server_records() -> list[dict]:
    host = capture.firefox.TARGET_HOST
    name = (
        b"".join(bytes((len(label),)) + label.encode() for label in host.split("."))
        + b"\0"
    )
    query = bytes.fromhex("123401000001000000000000") + name + bytes.fromhex("00010001")
    reply = (
        bytes.fromhex("123485000001000100000000")
        + query[12:]
        + bytes.fromhex("c00c000100010000000500047f000001")
    )
    return [
        dropped(
            server="127.0.0.53",
            role="primary",
            query_hex=query.hex(),
            disposition="dropped-owned-udp",
        ),
        answer(
            server="127.0.0.54",
            role="secondary",
            query_hex=query.hex(),
            response_hex=reply.hex(),
        ),
    ]


class AcceptanceTests(unittest.TestCase):
    def test_cli_defaults_to_initial_and_records_selected_intervention(self) -> None:
        for argv, scene in (
            ([], "initial"),
            (["--scenario", "drop-first-udp-a"], "drop-first-udp-a"),
            (["--scenario", "two-server"], "two-server"),
        ):

            def stage(record: dict) -> Path:
                record["browser_before"] = {"version": "157.0"}
                return Path("unused.exe")

            with (
                self.subTest(scene=scene),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(capture, "OUTPUT", Path(temporary) / "capture"),
                patch.object(capture, "require_hosted"),
                patch.object(capture, "file_digest", return_value="hash"),
                patch.object(capture, "stage_browser", side_effect=stage),
                patch.object(
                    capture, "browser_identity", return_value={"version": "157.0"}
                ),
                patch.object(capture, "guard", return_value={"staged_processes": []}),
                patch.object(capture, "capture", new_callable=AsyncMock) as run,
            ):
                capture.main(argv)
                record = json.loads((capture.OUTPUT / "result.json").read_text())
                self.assertEqual(record["scenario"], scene)
                self.assertEqual(record["status"], "complete")
                self.assertEqual(
                    record["interventions"]["drop_first_udp_a"],
                    scene == "drop-first-udp-a",
                )
                self.assertEqual(run.await_args.kwargs, {"scenario": scene})

    def test_unknown_cli_scene_is_rejected_before_host_or_dns_changes(self) -> None:
        with (
            patch.object(capture, "require_hosted") as hosted,
            patch.object(capture.sys, "stderr", new_callable=io.StringIO),
            self.assertRaises(SystemExit) as error,
        ):
            capture.main(["--scenario", "other"])
        self.assertEqual(error.exception.code, 2)
        hosted.assert_not_called()

    def test_hosted_guard_refuses_desktop_before_any_commands(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(RuntimeError, "hosted windows-2025"),
        ):
            capture.require_hosted()

    def test_only_known_hosted_platforms_are_accepted(self) -> None:
        values = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Windows",
            "IMAGEOS": "win25",
        }
        with (
            patch.dict(os.environ, values, clear=True),
            patch.object(capture.sys, "platform", "win32"),
        ):
            for image in ("win25", "win25-vs2026"):
                with (
                    self.subTest(image=image),
                    patch.dict(os.environ, {"IMAGEOS": image}),
                ):
                    capture.require_hosted()
                    for name in values:
                        with (
                            self.subTest(name=name),
                            patch.dict(os.environ, {name: "other"}),
                            self.assertRaises(RuntimeError),
                        ):
                            capture.require_hosted()
            for image in ("", "win22", "win25-vs2026-extra", "Win25"):
                with (
                    self.subTest(image=image),
                    patch.dict(os.environ, {"IMAGEOS": image}),
                    self.assertRaises(RuntimeError),
                ):
                    capture.require_hosted()
            with (
                patch.object(capture.sys, "platform", "linux"),
                self.assertRaises(RuntimeError),
            ):
                capture.require_hosted()

    def test_post_attach_sent_a_and_body_completion_are_required(self) -> None:
        self.assertEqual(
            capture.validate_result(result(), [answer()]),
            {"post_attach_a_responses": 1, "https_query_count": 0},
        )
        for changes in (
            {"unix_ns": 999_000_000},
            {"name": "other.test"},
            {"kind": 28},
            {"response_hex": None},
            {"error": "failed"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(RuntimeError, "no owned A response"),
            ):
                capture.validate_result(result(), [answer(**changes)])
        unsent = answer()
        del unsent["response_queued_ns"]
        with self.assertRaisesRegex(RuntimeError, "no owned A response"):
            capture.validate_result(result(), [unsent])
        incomplete = result()
        incomplete.origins.done.clear()
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            capture.validate_result(incomplete, [answer()])

    def test_timeout_hook_error_and_missing_origin_never_succeed(self) -> None:
        for field, value in (
            ("timed_out", True),
            ("errors", ["error"]),
            ("reports", []),
        ):
            failed = result()
            setattr(failed, field, value)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                capture.validate_result(failed, [answer()])
        missing = result()
        missing.origins.connections = []
        with self.assertRaisesRegex(RuntimeError, "owned origin"):
            capture.validate_result(missing, [answer()])

    def test_body_check_precedes_done_and_does_not_rewrite_dns(self) -> None:
        for scene in capture.SCENARIOS.values():
            with self.subTest(scene=scene.name):
                self.assertFalse(scene.rewrite_lookup)
                self.assertEqual(scene.target, "http1")
                self.assertEqual(scene.limit_seconds, 30)
                self.assertLess(
                    scene.script.index("text !== 'ok\\n'"),
                    scene.script.index("fetch('/done'"),
                )

    def test_recovery_requires_one_unanswered_query_then_a_sent_udp_answer(
        self,
    ) -> None:
        observed = capture.validate_result(
            result(), [dropped(), answer()], scenario="drop-first-udp-a"
        )
        self.assertEqual(observed["dropped_udp_a_queries"], 1)
        self.assertEqual(observed["post_drop_udp_a_responses"], 1)
        self.assertEqual(observed["dropped_query_unix_ns"], 1_000_500_000)
        self.assertEqual(observed["first_post_drop_query_unix_ns"], 1_001_000_000)
        self.assertEqual(observed["first_post_drop_response_queued_ns"], 1_002_000_000)
        incomplete = result()
        incomplete.origins.done.clear()
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            capture.validate_result(
                incomplete, [dropped(), answer()], scenario="drop-first-udp-a"
            )

    def test_missing_duplicate_or_answered_drop_never_proves_recovery(self) -> None:
        for records in (
            [answer()],
            [dropped(), dropped(), answer()],
            [dropped(response_hex="1234"), answer()],
            [dropped(response_queued_ns=1_000_600_000), answer()],
            [dropped(response_drained_ns=1_000_600_000), answer()],
        ):
            with self.subTest(records=records), self.assertRaises(RuntimeError):
                capture.validate_result(result(), records, scenario="drop-first-udp-a")

    def test_wrong_or_pre_hook_drop_never_proves_recovery(self) -> None:
        for changes in (
            {"name": "other.test"},
            {"kind": 28},
            {"kind": True},
            {"transport": "tcp"},
            {"error": "failed"},
            {"unix_ns": 999_999_999},
            {"unix_ns": "1000500000"},
            {"unix_ns": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                capture.validate_result(
                    result(),
                    [dropped(**changes), answer()],
                    scenario="drop-first-udp-a",
                )
        for key in ("unix_ns", "response_hex", "error"):
            query = dropped()
            del query[key]
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                capture.validate_result(
                    result(), [query, answer()], scenario="drop-first-udp-a"
                )

    def test_recovery_answer_must_follow_drop_in_journal_and_time(self) -> None:
        for records in (
            [answer(), dropped()],
            [answer(unix_ns=999_000_000), dropped(), answer()],
            [dropped()],
        ):
            with self.subTest(records=records), self.assertRaises(RuntimeError):
                capture.validate_result(result(), records, scenario="drop-first-udp-a")
        for changes in (
            {"name": "other.test"},
            {"kind": 28},
            {"kind": True},
            {"transport": "tcp", "response_drained_ns": 1_002_000_000},
            {"error": "failed"},
            {"response_hex": None},
            {"response_hex": b"1234"},
            {"unix_ns": 1_000_500_000},
            {"unix_ns": "1001000000"},
            {"response_queued_ns": 1_000_999_999},
            {"response_queued_ns": "1002000000"},
        ):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                capture.validate_result(
                    result(),
                    [dropped(), answer(**changes)],
                    scenario="drop-first-udp-a",
                )
        for key in ("unix_ns", "response_queued_ns", "error"):
            response = answer()
            del response[key]
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                capture.validate_result(
                    result(), [dropped(), response], scenario="drop-first-udp-a"
                )

    def test_two_server_accepts_observed_order_without_inventing_serial_failover(
        self,
    ) -> None:
        for order in (1, -1, 0):
            with self.subTest(order=order):
                rows = two_server_records()
                rows[1]["unix_ns"] = rows[0]["unix_ns"] + order * 100
                rows[1]["response_queued_ns"] = rows[1]["unix_ns"] + 50
                positive = capture.validate_result(
                    result(),
                    sorted(rows, key=lambda row: row["unix_ns"]),
                    scenario="two-server",
                )
                self.assertEqual(
                    positive["secondary_query_minus_primary_query_ns"], order * 100
                )
                self.assertEqual(
                    positive["secondary_answer_minus_primary_query_ns"],
                    order * 100 + 50,
                )
                self.assertEqual(positive["primary_dropped_udp_a_queries"], 1)
                self.assertEqual(positive["secondary_udp_a_responses"], 1)
                self.assertEqual(
                    positive["observed_order"],
                    {1: "primary-first", -1: "secondary-first", 0: "same-timestamp"}[
                        order
                    ],
                )

    def test_two_server_refuses_missing_wrong_peer_transport_or_answer_evidence(
        self,
    ) -> None:
        for index, changes in (
            (0, {"server": "127.0.0.54"}),
            (0, {"role": "secondary"}),
            (0, {"response_hex": "1234"}),
            (0, {"response_queued_ns": 1_001_000_000}),
            (0, {"response_drained_ns": 1_001_000_000}),
            (0, {"disposition": "dropped-first-udp-a"}),
            (0, {"transport": "tcp"}),
            (0, {"unix_ns": 999_999_999}),
            (0, {"error": "send failed"}),
            (0, {"query_hex": "broken"}),
            (0, {"kind": 28}),
            (1, {"server": "192.0.2.1"}),
            (1, {"transport": "tcp"}),
            (1, {"unix_ns": 999_999_999}),
            (1, {"response_hex": "1234"}),
            (1, {"response_queued_ns": 1_000_000_000}),
            (1, {"response_queued_ns": True}),
        ):
            with self.subTest(index=index, changes=changes):
                rows = two_server_records()
                rows[index].update(changes)
                with self.assertRaises(RuntimeError):
                    capture.validate_result(result(), rows, scenario="two-server")
        for index, field in (
            (0, "response_hex"),
            (1, "response_queued_ns"),
            (0, "query_hex"),
        ):
            rows = two_server_records()
            del rows[index][field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                capture.validate_result(result(), rows, scenario="two-server")
        for index in (0, 1):
            rows = two_server_records()
            rows.pop(index)
            with self.subTest(missing_peer=index), self.assertRaises(RuntimeError):
                capture.validate_result(result(), rows, scenario="two-server")
        rows = two_server_records()
        rows[0]["query_hex"] = rows[0]["query_hex"][:-4] + "0003"
        with self.assertRaisesRegex(RuntimeError, "invalid IN question"):
            capture.validate_result(result(), rows, scenario="two-server")

    def test_two_server_journals_merge_by_time_and_retain_ties_and_peer_sequence(
        self,
    ) -> None:
        primary = SimpleNamespace(
            address=("127.0.0.53", 53),
            records=lambda: [{"unix_ns": 20}, {"unix_ns": 30}],
        )
        secondary = SimpleNamespace(
            address=("127.0.0.54", 53),
            records=lambda: [{"unix_ns": 10}, {"unix_ns": 30}],
        )
        rows = capture.dns_records([primary, secondary])
        self.assertEqual(
            [(row["unix_ns"], row["role"], row["peer_sequence"]) for row in rows],
            [
                (10, "secondary", 0),
                (20, "primary", 0),
                (30, "primary", 1),
                (30, "secondary", 1),
            ],
        )

    def test_command_failure_keeps_raw_exit_and_output(self) -> None:
        record = {}

        def fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
            kwargs["stdout"].write(b"partial")
            kwargs["stderr"].write(b"failure")
            return subprocess.CompletedProcess(["tool"], 9)

        with (
            patch.object(capture.subprocess, "run", side_effect=fail),
            self.assertRaises(subprocess.CalledProcessError) as failure,
        ):
            capture.command(record, "tool")
        self.assertEqual(record["commands"][0]["exit"], 9)
        self.assertEqual(record["commands"][0]["stdout"], "partial")
        self.assertEqual(record["commands"][0]["stderr"], "failure")
        self.assertEqual(failure.exception.stdout, b"partial")
        self.assertEqual(failure.exception.stderr, b"failure")

    def test_command_timeout_keeps_partial_output_and_original_error(self) -> None:
        record = {}
        timeout = subprocess.TimeoutExpired(["tool"], 2)

        def expire(*args: object, **kwargs: object) -> None:
            kwargs["stdout"].write(b"partial")
            kwargs["stderr"].write(b"still running")
            raise timeout

        with (
            patch.object(capture.subprocess, "run", side_effect=expire),
            self.assertRaises(subprocess.TimeoutExpired) as failure,
        ):
            capture.command(record, "tool", timeout=2)
        self.assertIs(failure.exception, timeout)
        self.assertEqual(timeout.stdout, b"partial")
        self.assertEqual(timeout.stderr, b"still running")
        self.assertIsNone(record["commands"][0]["exit"])
        self.assertEqual(record["commands"][0]["stdout"], "partial")
        self.assertEqual(record["commands"][0]["stderr"], "still running")

    @unittest.skipUnless(
        os.name == "nt" and shutil.which("pwsh"), "Windows PowerShell is unavailable"
    )
    def test_command_collects_parent_while_watchdog_is_alive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            child = directory / "watch.ps1"
            release = directory / "release"
            child.write_text(
                "$ErrorActionPreference='Stop'\n"
                "$limit=[DateTime]::UtcNow.AddSeconds(30)\n"
                f"while (-not (Test-Path -LiteralPath '{release}')) {{ "
                "if ([DateTime]::UtcNow -ge $limit) { throw 'watch control was not released' }; "
                "Start-Sleep -Milliseconds 50 }\n",
                encoding="utf-8",
            )
            parent = directory / "parent.ps1"
            identity = directory / "watch.pid"
            parent.write_text(
                "$ErrorActionPreference='Stop'\n"
                "$watch=Start-Process -FilePath (Get-Process -Id $PID).Path "
                "-WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile',"
                f"'-NonInteractive','-File','\"{child}\"') "
                f"-RedirectStandardOutput '{directory / 'watch.stdout'}' "
                f"-RedirectStandardError '{directory / 'watch.stderr'}'\n"
                f"[IO.File]::WriteAllText('{identity}',[string]$watch.Id)\n"
                "@{armed=$true} | ConvertTo-Json -Compress\n",
                encoding="utf-8",
            )
            record = {}
            try:
                self.assertEqual(
                    json.loads(
                        capture.command(
                            record,
                            "pwsh",
                            "-NoProfile",
                            "-NonInteractive",
                            "-File",
                            str(parent),
                            timeout=15,
                        )
                    ),
                    {"armed": True},
                )
                watched = int(identity.read_text())
                alive = subprocess.run(
                    [
                        "pwsh",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        f"Get-Process -Id {watched} -ErrorAction Stop | Out-Null",
                    ],
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(alive.returncode, 0, alive.stderr)
            finally:
                release.touch()
                if identity.exists():
                    watched = int(identity.read_text())
                    collected = subprocess.run(
                        [
                            "pwsh",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            "$ErrorActionPreference='Stop'; "
                            f"$watch=Get-Process -Id {watched} -ErrorAction SilentlyContinue; "
                            "if ($watch) { $null=$watch.Handle; "
                            "if (-not $watch.WaitForExit(6000)) { throw 'watch control did not exit' } }; exit 0",
                        ],
                        capture_output=True,
                        timeout=8,
                    )
                    self.assertEqual(collected.returncode, 0, collected.stderr)

    def test_failed_main_reports_guard_output_and_watchdog_without_hiding_error(
        self,
    ) -> None:
        failure = RuntimeError("install failed")

        def stage(record: dict) -> Path:
            record["commands"] = [
                {"argv": ["other-tool"], "exit": 1, "stderr": "not guard output"},
                {
                    "argv": ["pwsh", str(capture.GUARD), "-Action", "Preflight"],
                    "exit": 0,
                },
                {
                    "argv": ["pwsh", str(capture.GUARD), "-Action", "Install"],
                    "exit": 1,
                    "stdout": "install output",
                    "stderr": "x" * 20000,
                },
            ]
            (capture.OUTPUT / "nrpt-state.json.watch.stderr").write_text(
                "watch failure" + "y" * 20000, encoding="utf-8"
            )
            raise failure

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary) / "capture"),
            patch.object(capture, "require_hosted"),
            patch.object(capture, "guard", return_value={}),
            patch.object(capture, "stage_browser", side_effect=stage),
            patch.object(capture.sys, "stderr", new_callable=io.StringIO) as stderr,
            self.assertRaises(RuntimeError) as raised,
        ):
            capture.main([])
        self.assertIs(raised.exception, failure)
        diagnostic = json.loads(stderr.getvalue())
        self.assertEqual(diagnostic["kind"], "windows-native-dns-guard-failure")
        self.assertEqual(len(diagnostic["commands"]), 1)
        command = diagnostic["commands"][0]
        self.assertEqual(command["action"], "Install")
        self.assertEqual(command["exit"], 1)
        self.assertEqual(command["stdout"], "install output")
        self.assertEqual(command["stderr"], "x" * 8192)
        self.assertTrue(command["stderr_truncated"])
        self.assertFalse(command["stdout_truncated"])
        self.assertEqual(
            diagnostic["watchdog_stderr"], ("watch failure" + "y" * 20000)[:8192]
        )
        self.assertTrue(diagnostic["watchdog_stderr_truncated"])
        self.assertLess(len(stderr.getvalue()), 20000)

    def test_unverified_installer_never_extracts_or_changes_dns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            (stage / "Firefox Setup 157.0.exe").write_bytes(b"not the pinned installer")
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": temporary}),
                patch.object(capture.tempfile, "mkdtemp", return_value=temporary),
                patch.object(capture, "command") as command,
                patch.object(capture, "guard") as guard,
            ):
                with self.assertRaisesRegex(RuntimeError, "installer hash"):
                    capture.stage_browser({})
                self.assertEqual(command.call_count, 1)
                guard.assert_not_called()


class OwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_scene_selects_drop_once_and_preserves_browser_cleanup(self) -> None:
        for scene in ("initial", "drop-first-udp-a"):
            records = (
                [dropped(), answer()] if scene == "drop-first-udp-a" else [answer()]
            )
            peer = SimpleNamespace(
                start=AsyncMock(),
                close=AsyncMock(),
                address=("127.0.0.53", 53),
                failed=asyncio.Event(),
                failures=[],
                records=lambda records=records: records,
            )
            observed = result()
            observed.moz_log_text = ""
            record = {}
            with (
                self.subTest(scene=scene),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(capture, "OUTPUT", Path(temporary)),
                patch.object(capture, "NativeDnsServer", return_value=peer) as server,
                patch.object(capture, "guard", return_value={}) as guard,
                patch.object(capture, "asdict", return_value={}),
                patch.object(capture.firefox, "render_run", return_value=[]),
                patch.object(
                    capture.firefox,
                    "run_once",
                    new_callable=AsyncMock,
                    return_value=(observed, ["firefox"]),
                ) as browser,
            ):
                await capture.capture(Path("unused.exe"), record, scenario=scene)
                server.assert_called_once_with(
                    capture.firefox.TARGET_HOST,
                    drop_first_udp_a=scene == "drop-first-udp-a",
                )
                browser.assert_awaited_once_with(
                    capture.SCENARIOS[scene],
                    Path("unused.exe"),
                    headful=True,
                    failure_path=Path(temporary) / "firefox-failed.json",
                )
                self.assertEqual(
                    [call.args[1] for call in guard.call_args_list],
                    ["Install", "Verify"],
                )
                peer.close.assert_awaited_once()
                self.assertEqual(record["cleanup_errors"], [])
                self.assertEqual(record["positive"]["post_attach_a_responses"], 1)

    def two_peers(self) -> list[SimpleNamespace]:
        rows = two_server_records()
        return [
            SimpleNamespace(
                start=AsyncMock(),
                close=AsyncMock(),
                address=(address, 53),
                failed=asyncio.Event(),
                failures=[],
                records=lambda row=row: [row],
            )
            for address, row in zip(("127.0.0.53", "127.0.0.54"), rows, strict=True)
        ]

    async def test_two_server_starts_both_before_install_and_closes_concurrently(
        self,
    ) -> None:
        peers = self.two_peers()
        events = []
        both_closing = asyncio.Event()

        async def close(index: int) -> None:
            events.append(f"close{index}")
            if all(f"close{i}" in events for i in range(2)):
                both_closing.set()
            await both_closing.wait()

        for i, peer in enumerate(peers):
            peer.start.side_effect = lambda i=i: events.append(f"start{i}")

            async def close_peer(index: int = i) -> None:
                await close(index)

            peer.close.side_effect = close_peer

        def guard(record: dict, action: str, *extra: str) -> dict:
            events.append(action)
            if action == "Install":
                self.assertEqual(events, ["start0", "start1", "Install"])
                self.assertEqual(extra[-2:], ("-DnsScene", "two-server"))
            return {}

        observed = result()
        observed.moz_log_text = ""
        record = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", side_effect=peers) as factory,
            patch.object(capture, "guard", side_effect=guard),
            patch.object(capture, "asdict", return_value={}),
            patch.object(capture.firefox, "render_run", return_value=[]),
            patch.object(
                capture.firefox,
                "run_once",
                new_callable=AsyncMock,
                return_value=(observed, []),
            ),
        ):
            await asyncio.wait_for(
                capture.capture(Path("unused.exe"), record, scenario="two-server"), 1
            )
            rows = json.loads((capture.OUTPUT / "dns.json").read_text())
        self.assertEqual(
            factory.call_args_list[0].args, (capture.firefox.TARGET_HOST, "127.0.0.53")
        )
        self.assertEqual(factory.call_args_list[0].kwargs, {"drop_owned_udp": True})
        self.assertEqual(
            factory.call_args_list[1].args, (capture.firefox.TARGET_HOST, "127.0.0.54")
        )
        self.assertEqual(factory.call_args_list[1].kwargs, {})
        self.assertEqual([row["role"] for row in rows], ["primary", "secondary"])
        self.assertEqual(record["positive"]["secondary_udp_a_responses"], 1)
        self.assertEqual(events[-1], "Verify")
        for peer in peers:
            peer.close.assert_awaited_once()

    async def test_secondary_start_failure_closes_both_without_installing_or_launching(
        self,
    ) -> None:
        peers = self.two_peers()
        peers[1].start.side_effect = ValueError("secondary bind failed")
        record = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", side_effect=peers),
            patch.object(capture, "guard", return_value={}) as guard,
            patch.object(
                capture.firefox, "run_once", new_callable=AsyncMock
            ) as browser,
            self.assertRaisesRegex(ValueError, "secondary bind failed"),
        ):
            await capture.capture(Path("unused.exe"), record, scenario="two-server")
        guard.assert_called_once_with(record, "Verify")
        browser.assert_not_called()
        for peer in peers:
            peer.close.assert_awaited_once()

    async def test_either_peer_failure_collects_browser_both_peers_and_restore_errors(
        self,
    ) -> None:
        for failed_index in (0, 1):
            peers = self.two_peers()
            original = ValueError("bad DNS")
            peers[failed_index].failures = [original]
            peers[failed_index].failed.set()
            peers[0].close.side_effect = RuntimeError("primary close failed")
            collected = asyncio.Event()

            async def browser(
                *args: object, collected: asyncio.Event = collected, **kwargs: object
            ) -> None:
                try:
                    await asyncio.Event().wait()
                finally:
                    collected.set()

            def guard(record: dict, action: str, *extra: str) -> dict:
                if action == "Verify":
                    raise RuntimeError("restore failed")
                return {}

            record = {}
            with (
                self.subTest(failed_peer=failed_index),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(capture, "OUTPUT", Path(temporary)),
                patch.object(capture, "NativeDnsServer", side_effect=peers),
                patch.object(capture, "guard", side_effect=guard),
                patch.object(capture.firefox, "run_once", side_effect=browser),
                self.assertRaises(BrowserLaunchFailures) as failure,
            ):
                await capture.capture(Path("unused.exe"), record, scenario="two-server")
            self.assertIs(failure.exception.primary.__cause__, original)
            self.assertTrue(collected.is_set())
            self.assertEqual(
                record["cleanup_errors"],
                ["RuntimeError: primary close failed", "RuntimeError: restore failed"],
            )
            self.assertEqual(
                record["dns_peer_failures"][failed_index]["failures"],
                ["ValueError: bad DNS"],
            )
            for peer in peers:
                peer.close.assert_awaited_once()

    async def test_parent_cancellation_during_both_closes_collects_before_restore(
        self,
    ) -> None:
        peers = self.two_peers()
        closing = asyncio.Event()
        release = asyncio.Event()
        started = []
        finished = []

        async def close(index: int) -> None:
            started.append(index)
            if len(started) == 2:
                closing.set()
            await release.wait()
            finished.append(index)

        for index, peer in enumerate(peers):

            async def close_peer(index: int = index) -> None:
                await close(index)

            peer.close.side_effect = close_peer

        def guard(record: dict, action: str, *extra: str) -> dict:
            if action == "Verify":
                self.assertEqual(sorted(finished), [0, 1])
            return {}

        record = {}
        interruptions = []

        async def run_capture() -> None:
            try:
                await capture.capture(Path("unused.exe"), record, scenario="two-server")
            except asyncio.CancelledError as error:
                # Python 3.10 recreates cancellation at the task boundary.
                interruptions.append(error)
                raise

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", side_effect=peers),
            patch.object(capture, "guard", side_effect=guard) as checked_guard,
            patch.object(
                capture.firefox,
                "run_once",
                new_callable=AsyncMock,
                side_effect=ValueError("browser failed"),
            ),
        ):
            owner = asyncio.create_task(run_capture())
            try:
                await asyncio.wait_for(closing.wait(), 1)
                owner.cancel()
                await asyncio.sleep(0)
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await owner
        self.assertEqual(len(interruptions), 1)
        failure = interruptions[0].__cause__
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertIsInstance(failure.primary, ValueError)
        self.assertEqual(
            [call.args[1] for call in checked_guard.call_args_list],
            ["Install", "Verify"],
        )
        self.assertTrue(
            any(isinstance(error, asyncio.CancelledError) for error in failure.cleanup)
        )
        for peer in peers:
            peer.close.assert_awaited_once()

    async def test_controller_cancellation_collects_pending_browser_and_both_peers(
        self,
    ) -> None:
        peers = self.two_peers()
        started = asyncio.Event()
        collected = asyncio.Event()

        async def browser(*args: object, **kwargs: object) -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                collected.set()

        record = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", side_effect=peers),
            patch.object(capture, "guard", return_value={}) as guard,
            patch.object(capture.firefox, "run_once", side_effect=browser),
        ):
            owner = asyncio.create_task(
                capture.capture(Path("unused.exe"), record, scenario="two-server")
            )
            try:
                await asyncio.wait_for(started.wait(), 1)
            finally:
                owner.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await owner
        self.assertTrue(collected.is_set())
        self.assertEqual(
            [call.args[1] for call in guard.call_args_list], ["Install", "Verify"]
        )
        for peer in peers:
            peer.close.assert_awaited_once()

    async def test_browser_failure_and_cancellation_still_collect_both_peers(
        self,
    ) -> None:
        for error in (ValueError("browser failed"), asyncio.CancelledError()):
            peers = self.two_peers()
            record = {}
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(capture, "OUTPUT", Path(temporary)),
                patch.object(capture, "NativeDnsServer", side_effect=peers),
                patch.object(capture, "guard", return_value={}) as guard,
                patch.object(
                    capture.firefox,
                    "run_once",
                    new_callable=AsyncMock,
                    side_effect=error,
                ),
                self.assertRaises(type(error)) as failure,
            ):
                await capture.capture(Path("unused.exe"), record, scenario="two-server")
            if isinstance(error, ValueError):
                self.assertIs(failure.exception, error)
            self.assertEqual(
                [call.args[1] for call in guard.call_args_list], ["Install", "Verify"]
            )
            for peer in peers:
                peer.close.assert_awaited_once()

    async def test_peer_failure_cancels_and_collects_browser_then_restores(
        self,
    ) -> None:
        events = []
        failed = asyncio.Event()
        failed.set()

        async def browser(*args: object, **kwargs: object) -> None:
            try:
                await asyncio.Event().wait()
            finally:
                events.append("browser-collected")

        async def close() -> None:
            events.append("dns-closed")

        peer = SimpleNamespace(
            start=AsyncMock(),
            close=close,
            address=("127.0.0.53", 53),
            failed=failed,
            failures=[ValueError("bad DNS")],
            records=list,
        )

        def guard(record: dict, action: str, *extra: str) -> dict:
            events.append(action)
            return {}

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", return_value=peer),
            patch.object(capture.firefox, "run_once", side_effect=browser),
            patch.object(capture, "guard", side_effect=guard),
            self.assertRaisesRegex(RuntimeError, "native DNS peer failed"),
        ):
            await capture.capture(Path("unused.exe"), {})
        self.assertEqual(
            events, ["Install", "browser-collected", "dns-closed", "Verify"]
        )

    async def test_install_failure_still_closes_peer_and_restores(self) -> None:
        peer = SimpleNamespace(
            start=AsyncMock(),
            close=AsyncMock(),
            address=("127.0.0.53", 53),
            failed=asyncio.Event(),
            failures=[],
            records=list,
        )
        actions = []

        def guard(record: dict, action: str, *extra: str) -> dict:
            actions.append(action)
            if action == "Install":
                raise RuntimeError("installation interrupted after intent")
            return {}

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", return_value=peer),
            patch.object(capture, "guard", side_effect=guard),
            patch.object(
                capture.firefox, "run_once", new_callable=AsyncMock
            ) as browser,
        ):
            with self.assertRaisesRegex(RuntimeError, "installation interrupted"):
                await capture.capture(Path("unused.exe"), {})
            browser.assert_not_called()
            peer.close.assert_awaited_once()
        self.assertEqual(actions, ["Install", "Verify"])

    async def test_restore_error_is_not_hidden_by_primary_failure(self) -> None:
        peer = SimpleNamespace(
            start=AsyncMock(side_effect=ValueError("bind failed")),
            close=AsyncMock(),
            failed=asyncio.Event(),
            failures=[],
            records=list,
        )
        record = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(capture, "OUTPUT", Path(temporary)),
            patch.object(capture, "NativeDnsServer", return_value=peer),
            patch.object(capture, "guard", side_effect=RuntimeError("restore failed")),
            self.assertRaises(BrowserLaunchFailures) as failure,
        ):
            await capture.capture(Path("unused.exe"), record)
        self.assertIsInstance(failure.exception.primary, ValueError)
        self.assertEqual(str(failure.exception.primary), "bind failed")
        self.assertEqual(record["cleanup_errors"], ["RuntimeError: restore failed"])

    async def test_raw_report_write_failure_cannot_prevent_restoration(self) -> None:
        peer = SimpleNamespace(
            start=AsyncMock(side_effect=ValueError("bind failed")),
            close=AsyncMock(),
            failed=asyncio.Event(),
            failures=[],
            records=list,
        )
        record = {}
        with (
            patch.object(capture, "NativeDnsServer", return_value=peer),
            patch.object(capture, "write_json", side_effect=OSError("disk full")),
            patch.object(capture, "guard", return_value={"restored": True}) as guard,
            self.assertRaises(BrowserLaunchFailures),
        ):
            await capture.capture(Path("unused.exe"), record)
        guard.assert_called_once_with(record, "Verify")
        self.assertEqual(record["cleanup_errors"], ["OSError: disk full"])


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell parser is unavailable")
class GuardTests(unittest.TestCase):
    def invoke_functions(self, body: str) -> subprocess.CompletedProcess:
        """Load only guard functions and replace NRPT cmdlets with in-memory peers."""
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "test.ps1"
            wrapper.write_text(
                "$ErrorActionPreference='Stop'\n"
                "[Console]::Error.WriteLine('guard-test:started')\n"
                "$tokens=$null; $errors=$null\n"
                f"$ast=[Management.Automation.Language.Parser]::ParseFile('{capture.GUARD.as_posix()}',[ref]$tokens,[ref]$errors)\n"
                "if ($errors.Count) { throw ($errors | Out-String) }\n"
                "$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | "
                "ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
                "[Console]::Error.WriteLine('guard-test:functions-loaded')\n"
                f"$StatePath='{Path(temporary).as_posix()}/state.json'\n"
                "$TargetName='127.0.0.1.nip.io'; $DnsAddress='127.0.0.53'\n"
                "$script:removed=@(); $script:rules=@()\n"
                "function Get-DnsClientNrptRule { $script:rules }\n"
                "function Remove-DnsClientNrptRule { param($Name,[switch]$Force) "
                "$script:removed+= $Name; $script:rules=@($script:rules | Where-Object Name -ne $Name) }\n"
                "[Console]::Error.WriteLine('guard-test:body')\n" + body,
                encoding="utf-8",
            )
            try:
                return subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except subprocess.TimeoutExpired as error:
                raise AssertionError(
                    "guard PowerShell timed out; "
                    f"stdout={error.stdout!r}; stderr={error.stderr!r}"
                ) from error

    def test_hosted_guard_accepts_only_known_images_and_keeps_runner_checks(
        self,
    ) -> None:
        outcome = self.invoke_functions(
            "$hosted=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] "
            "-and $n.Name -eq 'Assert-Hosted'},$false)\n"
            "$check=$hosted.Body.EndBlock.Statements[0].Extent.Text\n"
            "$env:GITHUB_ACTIONS='true'; $env:RUNNER_ENVIRONMENT='github-hosted'; $env:RUNNER_OS='Windows'\n"
            "$accepted=@(); $refused=@()\n"
            "foreach ($image in @('win25','win25-vs2026','','win22','win25-vs2026-extra','Win25')) {\n"
            "$env:ImageOS=$image\n"
            "try { Invoke-Expression $check; $accepted+=,$image } "
            "catch { if ($_ -notmatch 'hosted windows-2025') { throw }; $refused+=,$image }\n"
            "}\n"
            "$env:ImageOS='win25-vs2026'\n"
            "foreach ($name in @('GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS')) {\n"
            "$original=[Environment]::GetEnvironmentVariable($name)\n"
            "[Environment]::SetEnvironmentVariable($name,'other')\n"
            "try { Invoke-Expression $check; throw 'unexpected host acceptance' } "
            "catch { if ($_ -notmatch 'hosted windows-2025') { throw } }\n"
            "[Environment]::SetEnvironmentVariable($name,$original)\n"
            "}\n"
            "@{accepted=$accepted;refused=$refused} | ConvertTo-Json -Compress\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout),
            {
                "accepted": ["win25", "win25-vs2026"],
                "refused": ["", "win22", "win25-vs2026-extra", "Win25"],
            },
        )

    def test_host_provenance_retains_actual_runner_image(self) -> None:
        outcome = self.invoke_functions(
            "$hosted=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] "
            "-and $n.Name -eq 'Assert-Hosted'},$false)\n"
            "$system=[pscustomobject]@{Caption='Windows Server 2025';BuildNumber='26100';ProductType=3}\n"
            "$env:ImageOS='win25-vs2026'; $env:ImageVersion='20261021.278.1'\n"
            "& { Invoke-Expression $hosted.Body.EndBlock.Statements[-1].Extent.Text } | ConvertTo-Json -Compress\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout),
            {
                "caption": "Windows Server 2025",
                "build": "26100",
                "product_type": 3,
                "image_os": "win25-vs2026",
                "image_version": "20261021.278.1",
            },
        )

    def test_preflight_retains_dns_values_without_cim_metadata(self) -> None:
        outcome = self.invoke_functions(
            "$deep='metadata'; 1..14 | ForEach-Object { $deep=@{nested=$deep} }\n"
            "function Assert-Hosted { @{build='26100'} }\n"
            "function Get-DnsClientNrptPolicy { [pscustomobject]@{Namespace=@('other.test');"
            "NameServers=@('192.0.2.1');DnsSecValidationRequired=$true;CimClass=$deep;"
            "CimInstanceProperties=$deep;CimSystemProperties=$deep} }\n"
            "function Get-DnsClientServerAddress { [pscustomobject]@{InterfaceAlias='Ethernet';"
            "InterfaceIndex=4;AddressFamily=2;ServerAddresses=@('192.0.2.2','192.0.2.3');"
            "CimClass=$deep;CimInstanceProperties=$deep;CimSystemProperties=$deep} }\n"
            "$preflight=$ast.EndBlock.Statements | Where-Object { "
            "$_ -is [Management.Automation.Language.IfStatementAst] -and "
            "$_.Clauses[0].Item1.Extent.Text -eq \"`$Action -eq 'Preflight'\" }\n"
            "Invoke-Expression $preflight.Clauses[0].Item2.Statements[0].Extent.Text\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout),
            {
                "host": {"build": "26100"},
                "rules": [],
                "policy": [
                    {
                        "Namespace": ["other.test"],
                        "NameServers": ["192.0.2.1"],
                        "DnsSecValidationRequired": True,
                    }
                ],
                "dns_servers": [
                    {
                        "InterfaceAlias": "Ethernet",
                        "InterfaceIndex": 4,
                        "AddressFamily": 2,
                        "ServerAddresses": ["192.0.2.2", "192.0.2.3"],
                    }
                ],
            },
        )

    def test_preflight_serialization_warning_is_a_failure(self) -> None:
        outcome = self.invoke_functions(
            "$deep='value'; 1..14 | ForEach-Object { $deep=@{nested=$deep} }\n"
            "function Assert-Hosted { @{build='26100'} }\n"
            "function Get-DnsClientNrptPolicy { }\n"
            "function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=$deep} }\n"
            "$preflight=$ast.EndBlock.Statements | Where-Object { "
            "$_ -is [Management.Automation.Language.IfStatementAst] -and "
            "$_.Clauses[0].Item1.Extent.Text -eq \"`$Action -eq 'Preflight'\" }\n"
            "Invoke-Expression $preflight.Clauses[0].Item2.Statements[0].Extent.Text\n"
        )
        self.assertNotEqual(outcome.returncode, 0, outcome.stdout)
        self.assertIn("serialization has exceeded", outcome.stderr)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(outcome.stdout)

    def test_timeout_keeps_phase_and_raw_output(self) -> None:
        timeout = subprocess.TimeoutExpired(
            ["pwsh"], 15, output=b"partial", stderr=b"guard-test:functions-loaded\n"
        )
        with (
            patch.object(subprocess, "run", side_effect=timeout) as run,
            self.assertRaisesRegex(
                AssertionError, "guard PowerShell timed out"
            ) as failure,
        ):
            self.invoke_functions("throw 'body must not run'")
        self.assertIs(failure.exception.__cause__, timeout)
        self.assertIn(repr(timeout.stdout), str(failure.exception))
        self.assertIn(repr(timeout.stderr), str(failure.exception))
        self.assertEqual(run.call_args.kwargs["timeout"], 15)

    def test_restore_removes_only_nonce_scoped_rule_and_restores_baseline(self) -> None:
        outcome = self.invoke_functions(
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$baseline=[pscustomobject]@{Name='existing';Namespace=@('other.test');NameServers=@('10.0.0.1')}\n"
            "$script:rules=@($baseline)\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce=$nonce;baseline=@(Rules);"
            "rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state\n"
            "$script:rules+= [pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress);DisplayName=$nonce;Comment=$nonce}\n"
            "$restored=Restore-Owned\n"
            "@{removed=$script:removed;restored=$restored.restored;remaining=@($script:rules.Name)} | ConvertTo-Json -Compress\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout),
            {"removed": ["owned"], "restored": True, "remaining": ["existing"]},
        )

    def test_restore_refuses_unrelated_baseline_change(self) -> None:
        outcome = self.invoke_functions(
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111';"
            "baseline=@();rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='unowned';Namespace=@($TargetName);NameServers=@($DnsAddress);DisplayName='someone-else';Comment='someone-else'})\n"
            "try { Restore-Owned; throw 'unexpected success' } catch {"
            "if ($_ -notmatch 'baseline differs') { throw }; if ($script:removed.Count) { throw 'removed unrelated rule' }; 'refused' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(outcome.stdout.strip(), "refused")

    def test_restore_recognizes_native_address_without_changing_baseline(self) -> None:
        outcome = self.invoke_functions(
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$baseline=[pscustomobject]@{Name='existing';Namespace=@('other.test');"
            "NameServers=[Net.IPAddress]::Parse('192.0.2.1')}\n"
            "$script:rules=@($baseline)\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce=$nonce;baseline=@(Rules);"
            "rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state\n"
            "$script:rules+=[pscustomobject]@{Name='owned';Namespace=@($TargetName);"
            "NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName=$nonce;Comment=$nonce}\n"
            "$restored=Restore-Owned\n"
            "@{removed=$script:removed;restored=$restored.restored;remaining=@($script:rules.Name);"
            "server=$script:rules[0].NameServers.ToString()} | ConvertTo-Json -Compress\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout),
            {
                "removed": ["owned"],
                "restored": True,
                "remaining": ["existing"],
                "server": "192.0.2.1",
            },
        )

    def test_owned_native_address_keeps_exact_scope(self) -> None:
        outcome = self.invoke_functions(
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{nonce=$nonce;server=$DnsAddress}\n"
            "$script:rules=@(\n"
            "[pscustomobject]@{Name='native';Namespace=@($TargetName);NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='string';Namespace=@($TargetName);NameServers=@('127.0.0.53');DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='other-address';Namespace=@($TargetName);NameServers=[Net.IPAddress]::Parse('127.0.0.54');DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='extra-address';Namespace=@($TargetName);NameServers=@([Net.IPAddress]::Parse('127.0.0.53'),[Net.IPAddress]::Parse('192.0.2.1'));DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='no-address';Namespace=@($TargetName);NameServers=@();DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='other-name';Namespace=@('other.test');NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='extra-name';Namespace=@($TargetName,'other.test');NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName=$nonce;Comment=$nonce},\n"
            "[pscustomobject]@{Name='other-display';Namespace=@($TargetName);NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName='other';Comment=$nonce},\n"
            "[pscustomobject]@{Name='other-comment';Namespace=@($TargetName);NameServers=[Net.IPAddress]::Parse('127.0.0.53');DisplayName=$nonce;Comment='other'})\n"
            "ConvertTo-Json -InputObject @((Owned-Rules $state).Name) -Compress\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(json.loads(outcome.stdout), ["native", "string"])

    def test_restore_mismatch_reports_bounded_comparison_and_still_refuses(
        self,
    ) -> None:
        outcome = self.invoke_functions(
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce=$nonce;"
            "baseline=@();rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='unowned';Namespace=@('other.test');"
            "NameServers=@('192.0.2.1');Comment=('x'*10000)},"
            "[pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress);DisplayName=$nonce;Comment=$nonce})\n"
            "try { Restore-Owned; throw 'unexpected success' } catch {"
            "if ($_ -notmatch 'baseline differs') { throw }; "
            "if ((Read-State).restored -or ($script:removed -join ',') -ne 'owned') { throw 'ownership or failure changed' }; 'refused' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(outcome.stdout.strip(), "refused")
        diagnostic = json.loads(
            next(line for line in outcome.stderr.splitlines() if line.startswith("{"))
        )
        self.assertEqual(diagnostic["kind"], "nrpt-baseline-mismatch")
        self.assertEqual(diagnostic["baseline"], "[]")
        self.assertEqual(diagnostic["baseline_length"], 2)
        self.assertEqual(diagnostic["rule_name"], "owned")
        self.assertEqual(diagnostic["owned_rule_names"], ["owned"])
        self.assertEqual(diagnostic["owned_rule_count"], 1)
        self.assertIn('"Name":"unowned"', diagnostic["current"])
        self.assertEqual(len(diagnostic["current"]), 2048)
        self.assertGreater(diagnostic["current_length"], 10000)
        self.assertLess(len(outcome.stderr), 5000)

    def test_two_server_restore_removes_only_exact_ordered_list_and_nonce(self) -> None:
        outcome = self.invoke_functions(
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=@($DnsAddress,'127.0.0.54');nonce=$nonce;baseline=@();rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@([Net.IPAddress]::Parse($DnsAddress),[Net.IPAddress]::Parse('127.0.0.54'));DisplayName=$nonce;Comment=$nonce})\n"
            "Restore-Owned | Out-Null\n"
            "if (($script:removed -join ',') -ne 'owned' -or -not (Read-State).restored) { throw 'ordered rule was not restored' }; 'restored'\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(outcome.stdout.strip(), "restored")

    def test_tampered_server_intents_refuse_owned_lookup_restore_watch_and_verify(
        self,
    ) -> None:
        for servers in (
            "@()",
            "@('127.0.0.54')",
            "@('127.0.0.54','127.0.0.53')",
            "@('127.0.0.53','127.0.0.53')",
            "@('127.0.0.53','127.0.0.54','127.0.0.54')",
            "@('127.0.0.53','192.0.2.1')",
        ):
            with self.subTest(servers=servers):
                outcome = self.invoke_functions(
                    "function Assert-Hosted { @{} }\n"
                    "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
                    "$state=[pscustomobject]@{hostname=$TargetName;server="
                    + servers
                    + ";nonce=$nonce;baseline=@();rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null;owner_pid=123;owner_start='old';deadline='2099-01-01T00:00:00Z'}\n"
                    "Save-State $state\n"
                    "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress,'127.0.0.54');DisplayName=$nonce;Comment=$nonce})\n"
                    "foreach ($check in 'Owned','Restore','Watch','Verify') {\n"
                    "try { if ($check -eq 'Owned') { Owned-Rules (Read-State) | Out-Null } elseif ($check -eq 'Restore') { Restore-Owned | Out-Null } else { $Action=$check; $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text } }; throw 'unexpected success' } catch { if ($_ -notmatch 'server intent is outside') { throw } }\n"
                    "}\n"
                    "if ($script:removed.Count -ne 0 -or (Read-State).restored) { throw 'tampered intent removed a rule' }; 'refused-all'\n"
                )
                self.assertEqual(outcome.returncode, 0, outcome.stderr)
                self.assertEqual(outcome.stdout.strip(), "refused-all")

    def test_two_server_owned_rule_rejects_wrong_order_duplicates_and_partial_list(
        self,
    ) -> None:
        for servers in (
            "@('127.0.0.53')",
            "@('127.0.0.54','127.0.0.53')",
            "@('127.0.0.53','127.0.0.54','127.0.0.54')",
            "@('127.0.0.53','192.0.2.1')",
        ):
            with self.subTest(servers=servers):
                outcome = self.invoke_functions(
                    "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
                    "$state=[pscustomobject]@{hostname=$TargetName;server=@($DnsAddress,'127.0.0.54');nonce=$nonce;baseline=@();rule_name='owned';restored=$false;restored_at=$null;watchdog_pid=$null}\n"
                    "Save-State $state\n"
                    "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers="
                    + servers
                    + ";DisplayName=$nonce;Comment=$nonce})\n"
                    "try { Restore-Owned | Out-Null; throw 'unexpected success' } catch { if ($_ -notmatch 'baseline differs') { throw } }\n"
                    "if ($script:removed.Count -ne 0 -or (Read-State).restored) { throw 'wrong rule removed' }; 'refused'\n"
                )
                self.assertEqual(outcome.returncode, 0, outcome.stderr)
                self.assertEqual(outcome.stdout.strip(), "refused")

    def test_two_server_install_records_list_before_watch_and_passes_only_fixed_addresses(
        self,
    ) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-DnsClientNrptPolicy { @() }\n"
            "function Get-Process { param($Id,$ErrorAction) [pscustomobject]@{StartTime=[DateTime]'2026-10-23T00:00:00Z';Path='pwsh'} }\n"
            "function Start-Process { param($FilePath,$WindowStyle,[switch]$PassThru,$ArgumentList,$RedirectStandardOutput,$RedirectStandardError)\n"
            "if ((Canonical @((Read-State).server)) -ne (Canonical @($DnsAddress,'127.0.0.54')) -or $WindowStyle -ne 'Hidden') { throw 'durable intent differs' }; Set-Content -LiteralPath \"$StatePath.ready\" -Value 456; [pscustomobject]@{Id=456;HasExited=$false;StartTime=[DateTime]'2026-10-23T00:00:00Z'} }\n"
            "function Add-DnsClientNrptRule { param($Namespace,$NameServers,$DisplayName,$Comment,[switch]$PassThru)\n"
            "if ((Canonical @($NameServers)) -ne (Canonical @($DnsAddress,'127.0.0.54'))) { throw 'address escape' };\n"
            "$rule=[pscustomobject]@{Name='new-guid';Namespace=@($Namespace);NameServers=@($NameServers | ForEach-Object { [Net.IPAddress]::Parse($_) });DisplayName=$DisplayName;Comment=$Comment};$script:rules=@($rule);$rule }\n"
            "$Action='Install';$OwnerPid=123;$DnsScene='two-server'\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(
            json.loads(outcome.stdout)["server"], ["127.0.0.53", "127.0.0.54"]
        )

    def test_two_server_watchdog_restores_from_saved_list_without_scene_argument(
        self,
    ) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-Process { param($Id,$ErrorAction) $null }\n"
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=@($DnsAddress,'127.0.0.54');nonce=$nonce;baseline=@();rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null;owner_pid=999;owner_start='old';deadline='2099-01-01T00:00:00Z'}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress,'127.0.0.54');DisplayName=$nonce;Comment=$nonce})\n"
            "$Action='Watch';$DnsScene='initial'\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
            "if (($script:removed -join ',') -ne 'owned' -or -not (Read-State).restored) { throw 'saved list not restored' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertTrue(json.loads(outcome.stdout)["restored"])

    def test_install_arms_watchdog_before_add_and_records_guid(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-DnsClientNrptPolicy { @() }\n"
            "function Get-Process { param($Id,$ErrorAction) [pscustomobject]@{StartTime=[DateTime]'2026-10-23T00:00:00Z';Path='pwsh'} }\n"
            "$script:events=@()\n"
            "function Start-Process { param($FilePath,$WindowStyle,[switch]$PassThru,$ArgumentList,$RedirectStandardOutput,$RedirectStandardError)\n"
            "if ($WindowStyle -ne 'Hidden' -or $ArgumentList -notcontains 'Watch') { throw 'watch arguments differ' };\n"
            "$script:events+='armed'; Set-Content -LiteralPath \"$StatePath.ready\" -Value 456;\n"
            "[pscustomobject]@{Id=456;HasExited=$false;StartTime=[DateTime]'2026-10-23T00:00:00Z'} }\n"
            "function Add-DnsClientNrptRule { param($Namespace,$NameServers,$DisplayName,$Comment,[switch]$PassThru)\n"
            "if (-not (Test-Path $StatePath)) { throw 'intent not durable' }; $script:events+='add';\n"
            "$rule=[pscustomobject]@{Name='new-guid';Namespace=@($Namespace);NameServers=[Net.IPAddress]::Parse($NameServers);DisplayName=$DisplayName;Comment=$Comment};\n"
            "$script:rules=@($rule); $rule }\n"
            "$Action='Install'; $OwnerPid=123\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
            "if (($script:events -join ',') -ne 'armed,add') { throw 'watch did not precede mutation' }\n"
            "if ((Read-State).rule_name -ne 'new-guid') { throw 'GUID missing' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(json.loads(outcome.stdout)["rule_name"], "new-guid")

    def test_failed_watchdog_never_adds_rule(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-DnsClientNrptPolicy { @() }\n"
            "function Get-Process { param($Id) [pscustomobject]@{StartTime=[DateTime]'2026-10-23T00:00:00Z';Path='pwsh'} }\n"
            "function Start-Process { [pscustomobject]@{Id=456;HasExited=$true;StartTime=[DateTime]'2026-10-23T00:00:00Z'} }\n"
            "function Start-Sleep { throw 'an exited watchdog must not be polled' }\n"
            "function Add-DnsClientNrptRule { throw 'rule must not be added' }\n"
            "$Action='Install'; $OwnerPid=123\n"
            "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text };\n"
            "throw 'unexpected success' } catch { if ($_ -notmatch 'watchdog did not arm') { throw }; 'refused' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(outcome.stdout.strip(), "refused")

    def test_unready_watchdog_is_joined_and_failure_observed_after_restore(
        self,
    ) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-DnsClientNrptPolicy { @() }\n"
            "$script:joined=0; $script:added=0\n"
            "$watch=[pscustomobject]@{Id=456;HasExited=$true;StartTime=[DateTime]'2026-10-23T00:00:00Z';ExitCode=9}\n"
            "$watch | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds) "
            "if ($milliseconds -ne 5000) { throw 'join bound differs' }; $script:joined++; return $true }\n"
            "function Get-Process { param($Id,$ErrorAction) "
            "if ($Id -eq 123 -or $Id -eq $PID) { [pscustomobject]@{StartTime=[DateTime]'2026-10-23T00:00:00Z';Path='pwsh'} } else { $watch } }\n"
            "function Start-Process { $watch }\n"
            "function Add-DnsClientNrptRule { $script:added++; throw 'rule must not be added' }\n"
            "$Action='Install'; $OwnerPid=123\n"
            "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text };"
            "throw 'unexpected install success' } catch { if ($_ -notmatch 'watchdog did not arm') { throw } }\n"
            "$state=Read-State\n"
            "if ($state.watchdog_pid -ne 456 -or ([DateTime]$state.watchdog_start).ToUniversalTime() -ne $watch.StartTime.ToUniversalTime()) { throw 'unready watchdog ownership was not saved' }\n"
            "$Action='Verify'\n"
            "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text };"
            "throw 'unexpected verification success' } catch { if ($_ -notmatch 'watchdog failed after restoration') { throw } }\n"
            "if (-not (Read-State).restored -or $script:joined -ne 1 -or $script:added -ne 0) { throw 'failed watchdog was not restored and joined without DNS mutation' }\n"
            "'unready-watchdog-restored-and-joined'\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertIn("unready-watchdog-restored-and-joined", outcome.stdout)

    def test_watchdog_keeps_matching_owner_until_it_exits(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "$script:lookups=0; $script:polls=0\n"
            "function Get-Process { param($Id,$ErrorAction) $script:lookups++; "
            "if ($script:lookups -eq 1) { [pscustomobject]@{StartTime=[DateTime]'2026-10-23T00:00:00Z'} } }\n"
            "function Start-Sleep { param($Seconds) "
            "if ($Seconds -ne 1) { throw 'watch poll bound differs' }; $script:polls++ }\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111';"
            "baseline=@();rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null;owner_pid=123;"
            "owner_start='2026-10-23T00:00:00.0000000Z';deadline='2099-01-01T00:00:00Z'}\n"
            "Save-State $state\n"
            "$Action='Watch'\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
            "if ($script:lookups -ne 2 -or $script:polls -ne 1 -or -not (Read-State).restored) { throw 'matching owner was not retained until its exit' }\n"
            "'matching-owner-retained'\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertIn("matching-owner-retained", outcome.stdout)

    def test_watchdog_restores_on_owner_death_before_guid_was_saved(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-Process { param($Id,$ErrorAction) $null }\n"
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce=$nonce;baseline=@();"
            "rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null;owner_pid=999;owner_start='old';deadline='2099-01-01T00:00:00Z'}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress);DisplayName=$nonce;Comment=$nonce})\n"
            "$Action='Watch'\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
            "if (-not (Read-State).restored -or ($script:removed -join ',') -ne 'owned') { throw 'watchdog did not restore' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertTrue(json.loads(outcome.stdout)["restored"])

    def test_watchdog_failure_remains_visible_after_successful_restore(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111';"
            "baseline=@();rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null}\n"
            "Save-State $state; Set-Content -LiteralPath \"$StatePath.watch.stderr\" -Value 'watch failed'\n"
            "$Action='Verify'\n"
            "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text };"
            "throw 'unexpected success' } catch { if ($_ -notmatch 'watchdog reported an error') { throw } }\n"
            "if (-not (Read-State).restored) { throw 'restoration was not completed first' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertTrue(json.loads(outcome.stdout)["restored"])

    @unittest.skipUnless(os.name == "nt", "Windows process handles are required")
    def test_restore_observes_actual_watchdog_exit_status(self) -> None:
        for exit_code in (0, 9):
            with self.subTest(exit_code=exit_code):
                outcome = self.invoke_functions(
                    "function Assert-Hosted { @{} }\n"
                    '$child="$StatePath.child.ps1"; $release="$StatePath.release"\n'
                    "Set-Content -LiteralPath $child -Value @'\n"
                    "param([string]$Release,[int]$Code)\n"
                    "$limit=[DateTime]::UtcNow.AddSeconds(10)\n"
                    "while (-not (Test-Path -LiteralPath $Release)) {\n"
                    "if ([DateTime]::UtcNow -ge $limit) { exit 91 }; Start-Sleep -Milliseconds 20\n"
                    "}\n"
                    "exit $Code\n"
                    "'@\n"
                    "$started=Start-Process -FilePath (Get-Process -Id $PID).Path -WindowStyle Hidden -PassThru "
                    "-ArgumentList @('-NoProfile','-NonInteractive','-File',\"`\"$child`\"\",'-Release',\"`\"$release`\"\",'-Code',"
                    f"'{exit_code}')\n"
                    "try {\n"
                    "$script:observed=Get-Process -Id $started.Id\n"
                    "$watch=[pscustomobject]@{StartTime=$script:observed.StartTime}\n"
                    "$watch | Add-Member -MemberType ScriptProperty -Name Handle -Value { $script:observed.Handle }\n"
                    "$watch | Add-Member -MemberType ScriptProperty -Name ExitCode -Value { $script:observed.ExitCode }\n"
                    "$watch | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds)\n"
                    "if ($milliseconds -ne 5000) { throw 'join bound differs' }\n"
                    "Set-Content -LiteralPath $release -Value stop\n"
                    "$script:observed.WaitForExit($milliseconds) }\n"
                    "function Get-Process { param($Id,$ErrorAction)\n"
                    "if ($Id -ne $started.Id) { throw 'unexpected process' }; $watch }\n"
                    "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111';"
                    "baseline=@();rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$started.Id;"
                    "watchdog_start=$watch.StartTime.ToUniversalTime().ToString('o')}\n"
                    "Save-State $state; $Action='Verify'; $success=$false\n"
                    "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | "
                    "ForEach-Object { Invoke-Expression $_.Extent.Text }; $success=$true }\n"
                    f"catch {{ if ({exit_code} -eq 0 -or $_ -notmatch 'watchdog failed after restoration') {{ throw }} }}\n"
                    "if (-not $started.WaitForExit(5000)) { throw 'child was not collected' }\n"
                    "@{success=$success;restored=(Read-State).restored;actual_exit=$started.ExitCode} | ConvertTo-Json -Compress\n"
                    "} finally {\n"
                    "if (-not $started.HasExited) { $started.Kill(); $started.WaitForExit(); throw 'child required forced cleanup' }\n"
                    "$started.Dispose(); $script:observed.Dispose()\n"
                    "}\n"
                )
                self.assertEqual(outcome.returncode, 0, outcome.stderr)
                self.assertEqual(
                    json.loads(outcome.stdout.splitlines()[-1]),
                    {
                        "success": exit_code == 0,
                        "restored": True,
                        "actual_exit": exit_code,
                    },
                )

    def test_watchdog_restores_when_owner_identity_becomes_unavailable(self) -> None:
        outcome = self.invoke_functions(
            "function Assert-Hosted { @{} }\n"
            "function Get-Process { param($Id,$ErrorAction) "
            "[pscustomobject]@{} | Add-Member -MemberType ScriptProperty -Name StartTime "
            "-Value { throw 'owner exited during identity lookup' } -PassThru }\n"
            "$nonce='phantom-native-dns-11111111-1111-1111-1111-111111111111'\n"
            "$state=[pscustomobject]@{hostname=$TargetName;server=$DnsAddress;nonce=$nonce;baseline=@();"
            "rule_name=$null;restored=$false;restored_at=$null;watchdog_pid=$null;owner_pid=999;owner_start='old';deadline='2099-01-01T00:00:00Z'}\n"
            "Save-State $state\n"
            "$script:rules=@([pscustomobject]@{Name='owned';Namespace=@($TargetName);NameServers=@($DnsAddress);DisplayName=$nonce;Comment=$nonce})\n"
            "$Action='Watch'\n"
            "$ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
            "if (-not (Read-State).restored -or ($script:removed -join ',') -ne 'owned') { throw 'watchdog did not restore' }\n"
            "'restored-after-owner-disappeared'\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertIn("owner-identity-unavailable", outcome.stdout)
        self.assertIn("null-valued expression", outcome.stdout)
        self.assertIn("restored-after-owner-disappeared", outcome.stdout)


if __name__ == "__main__":
    unittest.main()
