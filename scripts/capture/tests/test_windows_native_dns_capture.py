"""Hosted controller controls; no browser, DNS routing or NRPT mutation."""

from __future__ import annotations

import asyncio
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

    def test_only_pinned_hosted_platform_is_accepted(self) -> None:
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
            capture.require_hosted()
            for name in values:
                with (
                    self.subTest(name=name),
                    patch.dict(os.environ, {name: "other"}),
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
        failed = subprocess.CompletedProcess(["tool"], 9, b"partial", b"failure")
        with (
            patch.object(capture.subprocess, "run", return_value=failed),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            capture.command(record, "tool")
        self.assertEqual(record["commands"][0]["exit"], 9)
        self.assertEqual(record["commands"][0]["stdout"], "partial")
        self.assertEqual(record["commands"][0]["stderr"], "failure")

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
                "$tokens=$null; $errors=$null\n"
                f"$ast=[Management.Automation.Language.Parser]::ParseFile('{capture.GUARD.as_posix()}',[ref]$tokens,[ref]$errors)\n"
                "if ($errors.Count) { throw ($errors | Out-String) }\n"
                "$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | "
                "ForEach-Object { Invoke-Expression $_.Extent.Text }\n"
                f"$StatePath='{Path(temporary).as_posix()}/state.json'\n"
                "$TargetName='127.0.0.1.nip.io'; $DnsAddress='127.0.0.53'\n"
                "$script:removed=@(); $script:rules=@()\n"
                "function Get-DnsClientNrptRule { $script:rules }\n"
                "function Remove-DnsClientNrptRule { param($Name,[switch]$Force) "
                "$script:removed+= $Name; $script:rules=@($script:rules | Where-Object Name -ne $Name) }\n"
                + body,
                encoding="utf-8",
            )
            return subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
                capture_output=True,
                text=True,
                timeout=15,
            )

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
            "$rule=[pscustomobject]@{Name='new-guid';Namespace=@($Namespace);NameServers=@($NameServers);DisplayName=$DisplayName;Comment=$Comment};\n"
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
            "function Start-Process { [pscustomobject]@{Id=456;HasExited=$true} }\n"
            "function Add-DnsClientNrptRule { throw 'rule must not be added' }\n"
            "$Action='Install'; $OwnerPid=123\n"
            "try { $ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { Invoke-Expression $_.Extent.Text };\n"
            "throw 'unexpected success' } catch { if ($_ -notmatch 'watchdog did not arm') { throw }; 'refused' }\n"
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(outcome.stdout.strip(), "refused")

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
