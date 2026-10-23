import contextlib
import io
import os
import runpy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
AUDITED_MODULES = (
    ("crates/phantom-quic-btls/src/lib.rs", "backend"),
    ("crates/phantom-net/src/lib.rs", "socket_ffi"),
    ("crates/phantom-net/src/lib.rs", "system_dns_ffi"),
    ("crates/phantom-net/src/lib.rs", "linux_dns_ffi"),
    ("crates/phantom-net/src/lib.rs", "macos_dns_ffi"),
    ("bindings/go/native/src/lib.rs", "ffi"),
    ("bindings/node/src/lib.rs", "ffi"),
)
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
        for name in (
            "check-tool-pins.sh",
            "check-unsafe-boundaries.sh",
            "check_unsafe_boundaries.py",
        ):
            destination = self.root / "scripts/ci" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / "scripts/ci" / name, destination)
        self.write("scripts/requirements.in", "ruff==0.17.1\n")
        self.write("scripts/requirements.txt", "ruff==0.17.1\n")
        self.write("pyproject.toml", 'required-version = "==0.17.1"\n')
        self.write(".github/workflows/ci.yml", "  SHELLCHECK_VERSION: v0.11.0\n")
        self.write(
            ".config/nextest.toml", 'nextest-version = { recommended = "0.9.145" }\n'
        )
        self.write(
            "tools.md",
            "ruff@0.17.1 --with ruff==0.17.1 nightly-2026-09-01\n"
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
        self.write("bindings/go/native/src/lib.rs", "#[allow(unsafe_code)]\nmod ffi;\n")
        self.write("bindings/node/src/lib.rs", "#[allow(unsafe_code)]\nmod ffi;\n")
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

    def test_unsafe_checks_propagate_manifest_search_failure(self) -> None:
        result = self.run_check("check-unsafe-boundaries.sh", "*Cargo.toml", 2)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("git grep failed with status 2", result.stderr)
        self.assertNotIn("unsafe code is allowed only", result.stdout)

    def test_unsafe_source_enumeration_failure_cannot_report_success(self) -> None:
        scanner = runpy.run_path(str(REPO / "scripts/ci/check_unsafe_boundaries.py"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(
                subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(2, ["git", "ls-files"]),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(scanner["main"](), 2)
        self.assertIn("unsafe boundary source scan failed", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_no_manifest_relaxation_matches_is_success(self) -> None:
        result = self.run_check("check-unsafe-boundaries.sh", "*Cargo.toml", 1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unsafe_checks_reject_missing_audited_allowances(self) -> None:
        for path, module in AUDITED_MODULES:
            with self.subTest(path=path, module=module):
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
        for path, module in AUDITED_MODULES:
            with self.subTest(path=path, module=module):
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
        for path, module in AUDITED_MODULES:
            with self.subTest(path=path, module=module):
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

    def check_source(self, source: str, name: str = "crates/phantom-net/src/escape.rs"):
        self.write(name, source)
        subprocess.run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-C",
                str(self.root),
                "add",
                "--",
                name,
            ],
            check=True,
        )
        return self.run_check("check-unsafe-boundaries.sh", "unused", 1)

    def test_multiline_and_conditional_allowances_cannot_escape(self) -> None:
        for attribute in (
            '#[allow(\n unsafe_code,\n reason = "wrapped reason"\n)]',
            '#[expect(\n unsafe_code,\n reason = "wrapped reason"\n)]',
            "#[cfg_attr(all(),\n allow(\n unsafe_code,\n))]",
            "#[cfg_attr(any(), cfg_attr(all(), expect(unsafe_code)))]",
            '#![allow(\n unused, unsafe_code, reason = "inner"\n)]',
            "#[r#allow(r#unsafe_code)]",
            "#[allow(dead_code,\n unsafe_code, unused_imports)]",
        ):
            with self.subTest(attribute=attribute):
                result = self.check_source(attribute + "\npub unsafe fn escaped() {}\n")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("outside the audited FFI modules", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_literal_and_comment_lookalikes_are_not_allowances(self) -> None:
        source = r"""
// #[allow(unsafe_code)]
/// #[expect(unsafe_code)]
/* #[allow(unsafe_code)] /* nested */ #[expect(unsafe_code)] */
const A: &str = "\"#[allow(unsafe_code)]";
const B: &str = r####"#[expect(unsafe_code)]"####;
const C: &[u8] = br##"#[allow(unsafe_code)]"##;
const D: &[u8] = b"#[allow(unsafe_code)]";
const E: &std::ffi::CStr = c"#[allow(unsafe_code)]";
const F: &std::ffi::CStr = cr#"#[allow(unsafe_code)]"#;
const G: char = '\'';
const H: char = '"';
const I: u8 = b'"';
const J: char = '\u{22}';
fn borrow<'a>(value: &'a str) -> &'a str { value }
#[allow(dead_code, reason = "#[allow(unsafe_code)]")]
fn ordinary() {}
"""
        result = self.check_source(source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.check_source(
            source + "#[expect(unsafe_code)]\nunsafe fn real() {}"
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_audited_attributes_allow_wrapping_and_comments(self) -> None:
        path = "crates/phantom-quic-btls/src/lib.rs"
        result = self.check_source(
            "#[cfg(any())]\n#[cfg_attr(all(), r#allow(\n r#unsafe_code,\n"
            ' reason = r#"ignore #[allow(unsafe_code)]"#\n))]\n'
            '#[doc = "boundary"] /* same item */\nmod backend;\n',
            path,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_audited_names_cannot_be_impostor_items(self) -> None:
        for declaration in (
            "#[allow(unsafe_code)] pub mod backend;",
            "#[allow(unsafe_code)] pub(crate) mod backend;",
            "#[allow(unsafe_code)] mod backend {}",
            "mod nested { #[allow(unsafe_code)] mod backend; }",
            "#[allow(unsafe_code)] fn backend() {}",
            "macro_rules! item { () => { #[allow(unsafe_code)] mod backend; } }",
            "#![allow(unsafe_code)] mod backend;",
        ):
            with self.subTest(declaration=declaration):
                result = self.check_source(
                    declaration, "crates/phantom-quic-btls/src/lib.rs"
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("moved outside audited declarations", result.stderr)

    def test_duplicate_audited_allowance_is_rejected(self) -> None:
        result = self.check_source(
            "#[allow(unsafe_code)] #[expect(unsafe_code)] mod backend;",
            "crates/phantom-quic-btls/src/lib.rs",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unsafe_code allowance(s)", result.stderr)

    def test_untracked_and_vendored_sources_are_excluded(self) -> None:
        source = "#[allow(unsafe_code)] unsafe fn excluded() {}"
        self.write("untracked.rs", source)
        result = self.check_source(source, "vendor/upstream.rs")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_tracked_missing_and_invalid_utf8_sources_fail_closed(self) -> None:
        name = "crates/phantom-net/src/escape.rs"
        self.check_source("pub fn ordinary() {}", name)
        path = self.root / name
        for content in (None, b"\xff"):
            with self.subTest(content=content):
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                result = self.run_check("check-unsafe-boundaries.sh", "unused", 1)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("unsafe boundary source scan failed", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_unterminated_relevant_rust_source_fails_closed(self) -> None:
        for source in (
            "/* unsafe_code",
            'const A: &str = "unsafe_code',
            'const A: &str = br###"unsafe_code"##;',
            "#[allow(unsafe_code)] fn f( {}",
        ):
            with self.subTest(source=source):
                result = self.check_source(source)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("unsafe boundary source scan failed", result.stderr)
                self.assertEqual(result.stdout, "")

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
