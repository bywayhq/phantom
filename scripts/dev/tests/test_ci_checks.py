import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BASH = shutil.which("bash")
if BASH is not None and "system32" in BASH.lower():
    BASH = None

INJECT_SEARCH = """\
git() {
  if [[ $1 == grep && $* == *"$GREP_PATTERN"* ]]; then
    [[ $GREP_STATUS == 1 ]] || echo 'injected search failure' >&2
    return "$GREP_STATUS"
  fi
  command git "$@"
}
export -f git
exec bash "$1"
"""


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class CiCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ("check-tool-pins.sh", "check-unsafe-boundaries.sh"):
            destination = self.root / "scripts/ci" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / "scripts/ci" / name, destination)
        self.write("scripts/requirements.in", "ruff==0.16.9\n")
        self.write("scripts/requirements.txt", "ruff==0.16.9\n")
        self.write("pyproject.toml", 'required-version = "==0.16.9"\n')
        self.write(".github/workflows/ci.yml", "  SHELLCHECK_VERSION: v0.11.0\n")
        self.write(
            ".config/nextest.toml", 'nextest-version = { recommended = "0.9.145" }\n'
        )
        self.write(
            "tools.md",
            "ruff@0.16.9 --with ruff==0.16.9 nightly-2026-09-01\n"
            "ShellCheck 0.11.0 cargo-nextest@0.9.145\n",
        )
        self.write(
            "crates/phantom-quic-btls/src/lib.rs",
            "#[allow(unsafe_code)]\nmod backend;\n",
        )
        self.write(
            "crates/phantom-net/src/lib.rs",
            "#[allow(unsafe_code)]\nmod socket_ffi;\n"
            "#[allow(unsafe_code)]\nmod system_dns_ffi;\n"
            "#[allow(unsafe_code)]\nmod linux_dns_ffi;\n"
            "#[allow(unsafe_code)]\nmod macos_dns_ffi;\n",
        )
        self.write("Cargo.toml", '[workspace.lints.rust]\nunsafe_code = "forbid"\n')
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-C", str(self.root), "add", "."],
            check=True,
        )

    def write(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def run_check(self, name: str, pattern: str, status: int):
        return subprocess.run(
            [
                BASH,
                "-c",
                INJECT_SEARCH,
                "check-test",
                str(self.root / "scripts/ci" / name),
            ],
            cwd=self.root,
            env={**os.environ, "GREP_PATTERN": pattern, "GREP_STATUS": str(status)},
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_unsafe_checks_propagate_attribute_and_manifest_search_failures(
        self,
    ) -> None:
        for pattern in ("*.rs", "*Cargo.toml"):
            with self.subTest(pattern=pattern):
                result = self.run_check("check-unsafe-boundaries.sh", pattern, 2)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("git grep failed with status 2", result.stderr)
                self.assertNotIn("unsafe code is allowed only", result.stdout)

    def test_no_manifest_relaxation_matches_is_success(self) -> None:
        result = self.run_check("check-unsafe-boundaries.sh", "*Cargo.toml", 1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unsafe_checks_reject_missing_audited_allowances(self) -> None:
        for package, module in (
            ("phantom-quic-btls", "backend"),
            ("phantom-net", "socket_ffi"),
            ("phantom-net", "system_dns_ffi"),
            ("phantom-net", "linux_dns_ffi"),
            ("phantom-net", "macos_dns_ffi"),
        ):
            with self.subTest(module=module):
                path = f"crates/{package}/src/lib.rs"
                original = (self.root / path).read_text(encoding="utf-8")
                self.write(
                    path,
                    original.replace(
                        f"#[allow(unsafe_code)]\nmod {module};",
                        f"mod {module};",
                    ),
                )
                result = self.run_check("check-unsafe-boundaries.sh", "unused", 1)
                self.write(path, original)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("unsafe_code allowance(s)", result.stderr)
                self.assertIn(
                    "allowance moved outside audited declarations", result.stderr
                )

    def test_unsafe_checks_reject_renamed_audited_modules(self) -> None:
        for package, module in (
            ("phantom-quic-btls", "backend"),
            ("phantom-net", "socket_ffi"),
            ("phantom-net", "system_dns_ffi"),
            ("phantom-net", "linux_dns_ffi"),
            ("phantom-net", "macos_dns_ffi"),
        ):
            with self.subTest(module=module):
                path = f"crates/{package}/src/lib.rs"
                original = (self.root / path).read_text(encoding="utf-8")
                self.write(path, original.replace(f"mod {module};", "mod other_ffi;"))
                result = self.run_check("check-unsafe-boundaries.sh", "unused", 1)
                self.write(path, original)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(
                    "allowance moved outside audited declarations", result.stderr
                )
                self.assertNotIn("unsafe_code allowance(s)", result.stderr)

    def test_unsafe_checks_reject_allowances_moved_onto_other_modules(self) -> None:
        for package, module in (
            ("phantom-quic-btls", "backend"),
            ("phantom-net", "socket_ffi"),
            ("phantom-net", "system_dns_ffi"),
            ("phantom-net", "linux_dns_ffi"),
            ("phantom-net", "macos_dns_ffi"),
        ):
            with self.subTest(module=module):
                path = f"crates/{package}/src/lib.rs"
                original = (self.root / path).read_text(encoding="utf-8")
                self.write(
                    path,
                    original.replace(
                        f"#[allow(unsafe_code)]\nmod {module};",
                        f"mod {module};\n#[allow(unsafe_code)]\nmod other_ffi;",
                    ),
                )
                result = self.run_check("check-unsafe-boundaries.sh", "unused", 1)
                self.write(path, original)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(
                    "allowance moved outside audited declarations", result.stderr
                )
                self.assertNotIn("unsafe_code allowance(s)", result.stderr)

    def test_pin_checks_propagate_each_search_failure(self) -> None:
        for pattern in (
            "ruff@",
            "--with ",
            "nightly-",
            "ShellCheck ",
            "cargo-nextest@",
        ):
            with self.subTest(pattern=pattern):
                result = self.run_check("check-tool-pins.sh", pattern, 2)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("git grep failed with status 2", result.stderr)
                self.assertNotIn(" agree", result.stdout)

    def test_optional_pin_search_no_matches_is_success(self) -> None:
        result = self.run_check("check-tool-pins.sh", "ShellCheck ", 1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
