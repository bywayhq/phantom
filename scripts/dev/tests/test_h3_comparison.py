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

PACKAGES = ("h3", "h3-datagram", "h3-quinn", "h3-webtransport")
LICENSE = b"Literal shared license\nSecond license line\n"
INJECT_GIT_FAILURE = """\
git() {
  if [[ $* == *"$FAILED_COMMAND"* ]]; then
    echo 'injected Git failure' >&2
    return 73
  fi
  command git "$@"
}
export -f git
exec bash "$1" "$2" "$3"
"""


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class H3ComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "vendor/h3"
        self.source.mkdir(parents=True)
        (self.source / "LICENSE").write_bytes(LICENSE)
        self.destination = self.root / "comparison"
        self.script = REPO / "scripts/ci/stage-h3-comparison.sh"
        self.git("init", "-q")
        self.link_blob = self.blob(b"../LICENSE")
        for package in PACKAGES:
            path = self.source / package
            path.mkdir()
            (path / "LICENSE").write_bytes(b"../LICENSE")
            (path / "source.rs").write_bytes(b"literal source\x00\r\n")
            self.index_link(package, self.link_blob)
            target = path / "target/nested"
            target.mkdir(parents=True)
            (target / "build-output").write_bytes(b"excluded")

    def git(self, *arguments: str, data: bytes | None = None):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            input=data,
            capture_output=True,
            check=True,
            timeout=30,
        )

    def blob(self, data: bytes) -> str:
        result = self.git("hash-object", "-w", "--stdin", data=data)
        return result.stdout.decode().strip()

    def index_link(self, package: str, blob: str, mode: str = "120000") -> None:
        self.git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"{mode},{blob},vendor/h3/{package}/LICENSE",
        )

    def stage(self, failed_command: str | None = None):
        arguments = [BASH, str(self.script), str(self.root), str(self.destination)]
        if failed_command is not None:
            arguments = [
                BASH,
                "-c",
                INJECT_GIT_FAILURE,
                "h3-comparison-test",
                str(self.script),
                str(self.root),
                str(self.destination),
            ]

        return subprocess.run(
            arguments,
            env={**os.environ, "FAILED_COMMAND": failed_command or ""},
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_placeholders_materialize_full_license_without_changing_source(
        self,
    ) -> None:
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for package in PACKAGES:
            with self.subTest(package=package):
                self.assertEqual(
                    (self.destination / package / "LICENSE").read_bytes(), LICENSE
                )
                self.assertFalse((self.destination / package / "LICENSE").is_symlink())
                self.assertEqual(
                    (self.source / package / "LICENSE").read_bytes(), b"../LICENSE"
                )
                self.assertEqual(
                    (self.destination / package / "source.rs").read_bytes(),
                    b"literal source\x00\r\n",
                )
                self.assertFalse((self.destination / package / "target").exists())
                self.assertTrue((self.source / package / "target").exists())

    def test_actual_symlinks_materialize_the_same_full_license(self) -> None:
        for package in PACKAGES:
            path = self.source / package / "LICENSE"
            path.unlink()
            try:
                path.symlink_to("../LICENSE")
            except OSError as error:
                self.skipTest(f"host cannot create symlinks: {error}")

        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for package in PACKAGES:
            self.assertEqual(
                (self.destination / package / "LICENSE").read_bytes(), LICENSE
            )
            self.assertTrue((self.source / package / "LICENSE").is_symlink())

    def test_wrong_checkout_symlink_target_is_rejected(self) -> None:
        path = self.source / "h3/LICENSE"
        path.unlink()
        try:
            path.symlink_to("../../LICENSE")
        except OSError as error:
            self.skipTest(f"host cannot create symlinks: {error}")

        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checkout link target changed", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_wrong_tracked_mode_is_rejected(self) -> None:
        self.index_link("h3", self.link_blob, "100644")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly the four tracked H3 LICENSE links", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_wrong_tracked_target_is_rejected(self) -> None:
        for target in (b"../../LICENSE", b"../LICENSE\n"):
            with self.subTest(target=target):
                self.index_link("h3", self.blob(target))
                result = self.stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("tracked link target changed", result.stderr)
                self.assertFalse(self.destination.exists())

    def test_extra_tracked_link_is_rejected(self) -> None:
        self.index_link("unlisted", self.link_blob)
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly the four tracked H3 LICENSE links", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_wrong_placeholder_bytes_are_rejected(self) -> None:
        for data in (b"../LICENSE\n", b"../../LICENSE", LICENSE):
            with self.subTest(data=data):
                (self.source / "h3/LICENSE").write_bytes(data)
                result = self.stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("checkout placeholder bytes changed", result.stderr)
                self.assertFalse(self.destination.exists())

    def test_git_failures_are_reported_without_creating_comparison(self) -> None:
        for command in ("ls-files", "cat-file"):
            with self.subTest(command=command):
                result = self.stage(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("injected Git failure", result.stderr)
                self.assertIn("cannot read tracked", result.stderr)
                self.assertFalse(self.destination.exists())

    def test_changed_full_license_remains_visible_to_comparison(self) -> None:
        changed = b"Different license content\n"
        (self.source / "LICENSE").write_bytes(changed)
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "h3/LICENSE").read_bytes(), changed)

        reference = self.root / "upstream-license"
        reference.write_bytes(LICENSE)
        comparison = subprocess.run(
            [
                BASH,
                "-c",
                'diff -q "$1" "$2"',
                "license-comparison-test",
                str(reference),
                str(self.destination / "h3/LICENSE"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            comparison.returncode, 1, comparison.stdout + comparison.stderr
        )


if __name__ == "__main__":
    unittest.main()
