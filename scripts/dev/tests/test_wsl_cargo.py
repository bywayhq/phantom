import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WSL_CARGO = REPO / "scripts" / "dev" / "wsl-cargo.sh"
GATE = REPO / "scripts" / "dev" / "gate.sh"


def find_bash() -> str | None:
    """A POSIX bash; on Windows, System32's bash.exe starts WSL instead."""
    bash = shutil.which("bash")
    if bash is None or "system32" in bash.lower():
        return None
    return bash


BASH = find_bash()

# Stand-ins for the Windows tools: each records its arguments, one per line.
FAKE_WSL = """#!/usr/bin/env bash
printf '%s\\n' "$@" >"$FAKE_LOG"
exit "${FAKE_STATUS:-0}"
"""
FAKE_CYGPATH = """#!/usr/bin/env bash
printf 'C:\\\\checkout\\n'
"""


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class WslCargoTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.bin = Path(directory.name)
        self.log = self.bin / "wsl.log"
        for name, text in (("wsl.exe", FAKE_WSL), ("cygpath", FAKE_CYGPATH)):
            path = self.bin / name
            path.write_text(text, encoding="utf-8", newline="\n")
            path.chmod(0o755)

    def run_script(self, script: Path, *arguments: str, **environment: str):
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            **environment,
        }
        env.pop("PHANTOM_WSL_DISTRO", None)
        env.update(environment)
        return subprocess.run(
            [BASH, str(script), *arguments],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def wsl_arguments(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()

    def test_cargo_runs_in_the_checkout_with_a_linux_target_directory(self) -> None:
        result = self.run_script(
            WSL_CARGO, "--target-name", "lint", "clippy", "--workspace"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.wsl_arguments()
        self.assertEqual(arguments[:5], ["--cd", "C:\\checkout", "-e", "bash", "-lc"])
        script = "\n".join(arguments[5:-5])
        self.assertIn("export DOCS_RS=1", script)
        self.assertIn('CARGO_TARGET_DIR="$HOME/.cache/phantom-gate/$1/$2"', script)
        checkout = arguments[-4]
        self.assertRegex(checkout, r"^[^/\\]+-[0-9]+$")
        self.assertEqual(arguments[-3:], ["lint", "clippy", "--workspace"])

    def test_the_distribution_comes_from_the_option_or_the_environment(self) -> None:
        self.run_script(WSL_CARGO, "--version", PHANTOM_WSL_DISTRO="Ubuntu-24.04")
        self.assertEqual(self.wsl_arguments()[:2], ["-d", "Ubuntu-24.04"])

        self.run_script(
            WSL_CARGO,
            "--distro",
            "Debian",
            "--version",
            PHANTOM_WSL_DISTRO="Ubuntu-24.04",
        )
        self.assertEqual(self.wsl_arguments()[:2], ["-d", "Debian"])

    def test_cargo_exit_status_is_returned(self) -> None:
        result = self.run_script(WSL_CARGO, "check", FAKE_STATUS="101")
        self.assertEqual(result.returncode, 101)

    def test_invalid_arguments_are_refused(self) -> None:
        self.assertEqual(self.run_script(WSL_CARGO).returncode, 64)
        result = self.run_script(WSL_CARGO, "--target-name", "../x", "check")
        self.assertEqual(result.returncode, 64)
        self.assertFalse(self.log.exists())

    def test_the_gate_stops_before_any_step_when_wsl_has_no_cargo(self) -> None:
        result = self.run_script(GATE, "--linux", FAKE_STATUS="1")

        self.assertEqual(result.returncode, 69)
        self.assertIn("--linux needs WSL with Cargo", result.stderr)
        self.assertEqual(self.wsl_arguments()[-1], "--version")

    def test_the_gate_refuses_a_distribution_without_linux(self) -> None:
        result = self.run_script(GATE, "--wsl-distro", "Ubuntu-24.04")

        self.assertEqual(result.returncode, 64)
        self.assertIn("--wsl-distro applies only to --linux", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
