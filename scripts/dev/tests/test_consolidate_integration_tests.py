import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev import consolidate_integration_tests as consolidator

REPO = Path(__file__).resolve().parents[3]

MANIFEST = """\
[package]
name = "demo"
edition = "2024"

[features]
extra = []
more = []

[[test]]
name = "gated"
required-features = ["extra", "more"]

[[test]]
name = "plain"
path = "tests/plain.rs"

[dev-dependencies]
"""

TLS_SUPPORT = """\
pub(super) fn certificate() -> &'static str {
    inner::name()
}

mod inner {
    pub(super) fn name() -> &'static str {
        "cert"
    }
}
"""

GATED = """\
//! Tests behind two features.

#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

#[test]
fn reads_the_certificate() {
    assert_eq!(tls_support::certificate(), "cert");
}
"""

PLAIN = """\
//! Tests without a gate.

#[path = "support/tls.rs"]
mod tls;

#[test]
fn also_reads_the_certificate() {
    assert_eq!(tls::certificate(), "cert");
}
"""

GROUPS = {"crates/demo": {"only": ("the demo crate", ["gated", "plain"])}}


class CrateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.crate = self.root / "crates" / "demo"
        self.write("crates/demo/Cargo.toml", MANIFEST)
        self.write("crates/demo/tests/support/tls.rs", TLS_SUPPORT)
        self.write("crates/demo/tests/gated.rs", GATED)
        self.write("crates/demo/tests/plain.rs", PLAIN)
        self.write("docs/testing.md", "Run crates/demo/tests/plain.rs.\n")
        self.run_git("init", "-q")
        # A host with core.autocrlf=true would warn about each LF file.
        self.run_git("config", "core.autocrlf", "false")
        self.run_git("config", "core.safecrlf", "false")
        self.run_git("add", ".")
        cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, cwd)
        patch = mock.patch.object(consolidator, "GROUPS", GROUPS)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def run_git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, check=True)

    def consolidate(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            consolidator.consolidate("crates/demo")
        return output.getvalue()


# A successful run formats each generated `main.rs` with rustfmt.
@unittest.skipIf(shutil.which("rustfmt") is None, "needs rustfmt on PATH")
class ConsolidateTests(CrateTestCase):
    def test_moves_each_file_into_its_group(self) -> None:
        self.consolidate()
        tests = self.crate / "tests"
        self.assertEqual(sorted(p.name for p in tests.glob("*.rs")), [])
        self.assertTrue((tests / "only" / "gated.rs").is_file())
        self.assertTrue((tests / "only" / "plain.rs").is_file())

    def test_required_features_become_the_module_gate(self) -> None:
        self.consolidate()
        main = self.read("crates/demo/tests/only/main.rs")
        self.assertIn(
            '#[cfg(all(unix, all(feature = "extra", feature = "more")))]\nmod gated;',
            main,
        )
        self.assertIn("\nmod plain;", main)
        self.assertNotIn("#![cfg(unix)]", self.read("crates/demo/tests/only/gated.rs"))

    def test_moved_targets_leave_the_manifest(self) -> None:
        self.consolidate()
        manifest = self.read("crates/demo/Cargo.toml")
        self.assertNotIn("[[test]]", manifest)
        self.assertIn("[features]", manifest)
        self.assertIn("[dev-dependencies]", manifest)

    def test_support_files_load_once_as_a_shared_module(self) -> None:
        self.consolidate()
        support = self.read("crates/demo/tests/support/mod.rs")
        self.assertIn("pub(crate) mod tls;", support)
        self.assertIn(
            "pub(crate) fn certificate", self.read("crates/demo/tests/support/tls.rs")
        )
        self.assertIn(
            "use crate::support::tls as tls_support;",
            self.read("crates/demo/tests/only/gated.rs"),
        )
        self.assertIn(
            "use crate::support::tls;", self.read("crates/demo/tests/only/plain.rs")
        )

    def test_a_nested_module_keeps_its_visibility_toward_the_file(self) -> None:
        self.consolidate()
        tls = self.read("crates/demo/tests/support/tls.rs")
        self.assertIn("pub(crate) fn certificate", tls)
        self.assertIn("    pub(super) fn name", tls)

    def test_rewrites_paths_in_tracked_text_files(self) -> None:
        self.consolidate()
        self.assertEqual(
            self.read("docs/testing.md"), "Run crates/demo/tests/only/plain.rs.\n"
        )

    def test_a_second_run_moves_nothing(self) -> None:
        self.consolidate()
        self.assertIn("nothing to move", self.consolidate())

    def test_a_new_file_joins_the_existing_group(self) -> None:
        self.consolidate()
        self.write("crates/demo/tests/late.rs", "#[test]\nfn runs() {}\n")
        self.run_git("add", ".")
        groups = {
            "crates/demo": {"only": ("the demo crate", ["gated", "late", "plain"])}
        }
        with mock.patch.object(consolidator, "GROUPS", groups):
            self.consolidate()
        main = self.read("crates/demo/tests/only/main.rs")
        self.assertIn("\nmod late;", main)
        self.assertIn('all(feature = "extra", feature = "more")', main)


class RefusalTests(CrateTestCase):
    def test_an_unplaced_file_stops_the_move(self) -> None:
        self.write("crates/demo/tests/stray.rs", "#[test]\nfn runs() {}\n")
        with self.assertRaises(SystemExit) as stop:
            self.consolidate()
        self.assertIn("add stray to a group", str(stop.exception))
        self.assertTrue((self.crate / "tests" / "plain.rs").is_file())

    def test_a_target_setting_without_a_module_equivalent_stops_the_move(self) -> None:
        manifest = MANIFEST.replace('path = "tests/plain.rs"', "harness = false")
        self.write("crates/demo/Cargo.toml", manifest)
        with self.assertRaises(SystemExit) as stop:
            self.consolidate()
        self.assertIn("sets `harness`", str(stop.exception))
        self.assertTrue((self.crate / "tests" / "plain.rs").is_file())


class RepositoryTests(unittest.TestCase):
    def test_grouped_crates_have_no_top_level_test_files(self) -> None:
        for crate_dir, groups in consolidator.GROUPS.items():
            with self.subTest(crate=crate_dir):
                tests = REPO / crate_dir / "tests"
                stray = sorted(p.name for p in tests.glob("*.rs"))
                self.assertEqual(
                    stray, [], "run scripts/dev/consolidate_integration_tests.py"
                )
                tracked = subprocess.run(
                    ["git", "ls-files", "--", f"{crate_dir}/tests"],
                    cwd=REPO,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.splitlines()
                depth = len(Path(crate_dir, "tests").parts)
                binaries = {
                    Path(f).parts[depth]
                    for f in tracked
                    if len(Path(f).parts) > depth + 1
                } - {"support"}
                self.assertEqual(
                    sorted(binaries),
                    sorted(groups),
                    f"the tracked directories under {crate_dir}/tests and its "
                    "GROUPS entry in consolidate_integration_tests.py name "
                    "different test binaries",
                )


if __name__ == "__main__":
    unittest.main()
