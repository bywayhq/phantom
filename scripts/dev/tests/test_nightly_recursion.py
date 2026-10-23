import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.dev.tests.test_wsl_cargo import BASH

SCRIPT = Path(__file__).resolve().parents[2] / "ci" / "check-nightly-recursion.sh"


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class NightlyRecursionTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        scripts = self.root / "scripts"
        (scripts / "ci").mkdir(parents=True)
        (scripts / "dev").mkdir()
        self.script = scripts / "ci" / SCRIPT.name
        shutil.copyfile(SCRIPT, self.script)
        wrapper = scripts / "dev" / "with-cargo-lock.sh"
        wrapper.write_text('#!/usr/bin/env bash\nexec "$@"\n', newline="\n")
        wrapper.chmod(0o755)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$@" >"$FAKE_ARGS"\n'
            'printf "%s" "$FAKE_OUTPUT"\n'
            'exit "$FAKE_STATUS"\n',
            newline="\n",
        )
        cargo.chmod(0o755)
        self.arguments = self.root / "arguments.txt"
        self.log = self.root / "cargo.log"

    def run_check(
        self, output: str = "", status: int = 0, log: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, str(self.script), "nightly-test", "2", str(log or self.log)],
            env={
                **os.environ,
                "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                "FAKE_ARGS": str(self.arguments),
                "FAKE_OUTPUT": output,
                "FAKE_STATUS": str(status),
            },
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_success_checks_locked_public_client_and_preserves_full_log(self) -> None:
        result = self.run_check("finished\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text(), "finished\n")
        self.assertEqual(
            self.arguments.read_text().splitlines(),
            [
                "+nightly-test",
                "check",
                "-j",
                "2",
                "-p",
                "phantom-http",
                "--all-targets",
                "--all-features",
                "--locked",
            ],
        )

    def test_cargo_failure_preserves_status_and_diagnostics(self) -> None:
        result = self.run_check("error: source failure\n", 101)
        self.assertEqual(result.returncode, 101)
        self.assertIn("error: source failure", result.stdout)

    def test_recursion_warning_fails_even_when_cargo_succeeds(self) -> None:
        for warning in (
            "warning: recursion_depth_exceeding_limit\n",
            "warning: overflow evaluating the requirement T: Send\n",
        ):
            with self.subTest(warning=warning):
                result = self.run_check(warning)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(warning, result.stdout)

    def test_unrelated_nightly_warning_stays_in_cargo_log(self) -> None:
        warning = "warning: unrelated nightly diagnostic\n"
        result = self.run_check(warning)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text(), warning)
        self.assertNotIn(warning, result.stdout)

    def test_unwritable_log_fails_before_running_cargo(self) -> None:
        result = self.run_check(log=self.root / "missing" / "cargo.log")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.arguments.exists())

    def test_missing_arguments_and_invalid_jobs_are_rejected(self) -> None:
        for arguments in [[], ["nightly-test", "0", str(self.log)]]:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [BASH, str(self.script), *arguments],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertFalse(self.arguments.exists())


if __name__ == "__main__":
    unittest.main()
