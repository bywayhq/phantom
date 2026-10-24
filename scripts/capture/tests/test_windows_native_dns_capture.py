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
        "unix_ns": 1_001_000_000,
        "response_hex": "1234",
        "response_queued_ns": 1_002_000_000,
        "error": None,
    }
    record.update(changes)
    return record


class AcceptanceTests(unittest.TestCase):
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
        self.assertFalse(capture.SCENARIO.rewrite_lookup)
        self.assertEqual(capture.SCENARIO.target, "http1")
        self.assertLess(
            capture.SCENARIO.script.index("text !== 'ok\\n'"),
            capture.SCENARIO.script.index("fetch('/done'"),
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
            capture.main()
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
            "$state=[pscustomobject]@{nonce=$nonce}\n"
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
