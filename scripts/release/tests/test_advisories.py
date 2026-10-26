import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import tomllib

SPEC = importlib.util.spec_from_file_location(
    "release_advisories", Path(__file__).resolve().parents[1] / "check-advisories.py"
)
advisories = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(advisories)


class AdvisoryChecks(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        root_patch = patch.object(advisories, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.write(
            "Cargo.toml",
            '[workspace.dependencies]\nh2 = { path = "vendor/h2" }\n'
            'tls = { path = "vendor/tls" }\nquinn = { path = "vendor/quinn" }\n',
        )
        self.manifest("h2", "phantom-http2", "0.5.20-phantom.23", "http2", "0.5.20")
        self.manifest("tls", "phantom-btls-sys", "0.5.6-phantom.3", "btls-sys", "0.5.6")
        self.manifest(
            "quinn",
            "phantom-quinn-proto",
            "0.11.18-phantom.7",
            "quinn-proto",
            "0.11.18",
        )
        self.lock = (
            'version = 3\n[[package]]\nname = "phantom-http2"\n'
            'version = "0.5.20-phantom.23"\n[[package]]\n'
            'name = "phantom-btls-sys"\nversion = "0.5.6-phantom.3"\n'
            '[[package]]\nname = "phantom-quinn-proto"\n'
            'version = "0.11.18-phantom.7"\n'
            '[[package]]\nname = "quinn-udp"\nversion = "0.5.16"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        self.write("Cargo.lock", self.lock)
        self.write("vendor/h2/CHANGELOG.md", "# 0.4.15\n")
        self.config = {
            "lineage": [
                {
                    "fork": "phantom-http2",
                    "upstream": ["http2", "0.5.20"],
                    "identity": ["h2", "0.4.15"],
                    "files": {
                        "vendor/h2/CHANGELOG.md": self.digest("# 0.4.15\n"),
                    },
                }
            ],
            "rust-fixes": {
                "RUSTSEC-2026-0258": {
                    "fork": "phantom-http2",
                    "identity": ["h2", "0.4.15"],
                    **self.backport("h2"),
                }
            },
            "source-fixes": {
                "CVE-2026-35189": {
                    "fork": "phantom-btls-sys",
                    "version": "0.5.6-phantom.3",
                    "upstream": ["btls-sys", "0.5.6"],
                    "boringssl-revision": "reviewed-native-revision",
                    **self.backport("tls"),
                },
                **{
                    advisory: {
                        "fork": "phantom-quinn-proto",
                        "version": "0.11.18-phantom.7",
                        "upstream": ["quinn-proto", "0.11.18"],
                        **self.backport("quinn"),
                    }
                    for advisory in ("GHSA-53rm-773f-4q8c", "GHSA-wppq-2f6r-wfvm")
                },
            },
            "registry-fixes": {
                "GHSA-6pp4-4cxf-xf88": {"identity": ["quinn-udp", "0.5.16"]}
            },
        }

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))

    def manifest(
        self, directory: str, name: str, version: str, upstream: str, baseline: str
    ) -> None:
        self.write(
            f"vendor/{directory}/Cargo.toml",
            f'[package]\nname = "{name}"\nversion = "{version}"\n'
            f'[package.metadata.phantom]\nupstream-package = "{upstream}"\n'
            f'upstream-version = "{baseline}"\n'
            'boringssl-revision = "reviewed-native-revision"\n',
        )

    @staticmethod
    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def backport(self, directory: str) -> dict:
        source = f"vendor/{directory}/source"
        retained_patch = f"vendor/{directory}/patches/security.patch"
        self.write(source, "fixed source\n")
        self.write(retained_patch, "reviewed patch\n")
        self.write(f"vendor/{directory}/patches/series", "security.patch\n")
        return {
            "files": {source: self.digest("fixed source\n")},
            "patches": {retained_patch: self.digest("reviewed patch\n")},
        }

    @staticmethod
    def report(identifier: str = "RUSTSEC-2026-0258", version: str = "0.4.15") -> dict:
        return {
            "vulnerabilities": {
                "count": 1,
                "list": [
                    {
                        "advisory": {"id": identifier},
                        "package": {"name": "h2", "version": version},
                    }
                ],
            },
            "warnings": {},
        }

    def test_checked_backports_keep_direct_and_lineage_audit_identities(self) -> None:
        packages, identities, backports = advisories.audit_inputs(self.config)
        self.assertIn(("h2", "0.4.15"), packages)
        self.assertIn(("http2", "0.5.20"), packages)
        self.assertIn(("quinn-udp", "0.5.16"), packages)
        self.assertEqual(identities["phantom-http2"], ("http2", "0.5.20"))
        self.assertEqual(
            {item["advisory"] for item in backports},
            {
                "RUSTSEC-2026-0258",
                "CVE-2026-35189",
                "GHSA-53rm-773f-4q8c",
                "GHSA-wppq-2f6r-wfvm",
                "GHSA-6pp4-4cxf-xf88",
            },
        )
        with redirect_stdout(io.StringIO()):
            advisories.review_audit(self.report(), 1, self.config)

    def test_vulnerable_or_modified_source_fails_for_each_backport(self) -> None:
        for directory in ("h2", "tls", "quinn"):
            with self.subTest(directory=directory):
                self.write(f"vendor/{directory}/source", "vulnerable source\n")
                with self.assertRaisesRegex(RuntimeError, "evidence changed"):
                    advisories.audit_inputs(self.config)
                self.write(f"vendor/{directory}/source", "fixed source\n")

    def test_missing_and_altered_patches_fail(self) -> None:
        for directory in ("h2", "tls", "quinn"):
            path = self.root / f"vendor/{directory}/patches/security.patch"
            with self.subTest(directory=directory, failure="missing"):
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    advisories.audit_inputs(self.config)
            with self.subTest(directory=directory, failure="altered"):
                self.write(str(path.relative_to(self.root)), "different patch\n")
                with self.assertRaisesRegex(RuntimeError, "evidence changed"):
                    advisories.audit_inputs(self.config)
            self.write(str(path.relative_to(self.root)), "reviewed patch\n")

    def test_unapplied_and_duplicate_patch_series_entries_fail(self) -> None:
        for directory in ("h2", "tls", "quinn"):
            for text in ("other.patch\n", "security.patch\nsecurity.patch\n"):
                with self.subTest(directory=directory, series=text):
                    self.write(f"vendor/{directory}/patches/series", text)
                    with self.assertRaisesRegex(RuntimeError, "occur once"):
                        advisories.audit_inputs(self.config)
            self.write(f"vendor/{directory}/patches/series", "security.patch\n")

    def test_lock_manifest_and_reviewed_version_mismatches_fail(self) -> None:
        for before, after in (
            ("0.5.6-phantom.3", "0.5.6-phantom.2"),
            ("0.11.18-phantom.7", "0.11.18-phantom.6"),
            ("0.5.20-phantom.23", "0.5.20-phantom.24"),
        ):
            with self.subTest(version=after):
                self.write("Cargo.lock", self.lock.replace(before, after))
                with self.assertRaisesRegex(RuntimeError, "locked fork version"):
                    advisories.audit_inputs(self.config)
        self.write("Cargo.lock", self.lock)
        config = copy.deepcopy(self.config)
        config["source-fixes"]["CVE-2026-35189"]["version"] = "0.5.6-phantom.2"
        with self.assertRaisesRegex(RuntimeError, "backport package version"):
            advisories.audit_inputs(config)

    def test_native_revision_change_requires_fresh_review(self) -> None:
        config = copy.deepcopy(self.config)
        config["source-fixes"]["CVE-2026-35189"]["boringssl-revision"] = "another"
        with self.assertRaisesRegex(RuntimeError, "BoringSSL revision"):
            advisories.audit_inputs(config)

    def test_new_upstream_or_lineage_evidence_requires_review(self) -> None:
        self.write("vendor/h2/CHANGELOG.md", "# 0.4.16\n")
        with self.assertRaisesRegex(RuntimeError, "evidence changed"):
            advisories.audit_inputs(self.config)
        self.write("vendor/h2/CHANGELOG.md", "# 0.4.15\n")
        config = copy.deepcopy(self.config)
        config["lineage"][0]["upstream"][1] = "0.5.21"
        with self.assertRaisesRegex(RuntimeError, "fork lineage changed"):
            advisories.audit_inputs(config)

    def test_missing_lineage_and_empty_source_evidence_fail(self) -> None:
        config = copy.deepcopy(self.config)
        config["lineage"] = []
        with self.assertRaisesRegex(RuntimeError, "missing HTTP/2 h2 advisory lineage"):
            advisories.audit_inputs(config)
        config = copy.deepcopy(self.config)
        config["source-fixes"]["CVE-2026-35189"]["files"] = {}
        with self.assertRaisesRegex(RuntimeError, "evidence is empty"):
            advisories.audit_inputs(config)

    def test_real_registry_h2_cannot_receive_the_forks_backport_exception(self) -> None:
        self.write(
            "Cargo.lock",
            self.lock + '\n[[package]]\nname = "h2"\nversion = "0.4.15"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        )
        with self.assertRaisesRegex(
            RuntimeError, "cannot exempt a registry dependency"
        ):
            advisories.audit_inputs(self.config)

    def test_old_or_unreviewed_udp_versions_fail(self) -> None:
        for version in ("0.5.15", "0.5.17"):
            with self.subTest(version=version):
                self.write("Cargo.lock", self.lock.replace('"0.5.16"', f'"{version}"'))
                with self.assertRaisesRegex(RuntimeError, "registry fix version"):
                    advisories.audit_inputs(self.config)

    def test_known_source_advisory_cannot_be_omitted(self) -> None:
        for identifier in advisories.SOURCE_ADVISORIES:
            config = copy.deepcopy(self.config)
            del config["source-fixes"][identifier]
            with (
                self.subTest(advisory=identifier),
                self.assertRaisesRegex(
                    RuntimeError, "source advisory reviews are missing"
                ),
            ):
                advisories.audit_inputs(config)

    def test_unrelated_or_different_version_findings_are_not_exempt(self) -> None:
        for report in (self.report("RUSTSEC-2026-9999"), self.report(version="0.4.14")):
            with (
                self.subTest(report=report),
                self.assertRaisesRegex(RuntimeError, "unresolved advisory"),
            ):
                advisories.review_audit(report, 1, self.config)

    def test_warnings_and_audit_errors_remain_failures_with_known_findings(
        self,
    ) -> None:
        report = self.report()
        report["warnings"] = {"unmaintained": [{"package": {"name": "example"}}]}
        with self.assertRaisesRegex(RuntimeError, "warnings require review"):
            advisories.review_audit(report, 1, self.config)
        with self.assertRaisesRegex(RuntimeError, "audit failed"):
            advisories.review_audit(self.report(), 2, self.config)
        with self.assertRaisesRegex(RuntimeError, "audit failed"):
            advisories.review_audit(
                {"vulnerabilities": {"count": 0, "list": []}, "warnings": {}},
                1,
                self.config,
            )

    def test_check_retains_raw_findings_and_both_http2_names(self) -> None:
        self.write("scripts/release/advisory-fixes.json", json.dumps(self.config))
        raw = self.report()

        def audit(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            kwargs["stdout"].write(json.dumps(raw))
            kwargs["stderr"].write("audit database receipt\n")
            return subprocess.CompletedProcess(command, 1)

        output = self.root / "receipts"
        with (
            patch.object(advisories.subprocess, "run", side_effect=audit),
            redirect_stdout(io.StringIO()),
        ):
            advisories.check(output)
        lock = tomllib.loads((output / "upstream-identities.lock").read_text())
        self.assertIn(
            {"name": "h2", "version": "0.4.15", "source": lock["package"][0]["source"]},
            lock["package"],
        )
        self.assertEqual(json.loads((output / "audit.json").read_text()), raw)
        self.assertIn("audit database receipt", (output / "audit.log").read_text())
        backports = json.loads((output / "retained-backports.json").read_text())
        self.assertEqual(len(backports), 5)


if __name__ == "__main__":
    unittest.main()
