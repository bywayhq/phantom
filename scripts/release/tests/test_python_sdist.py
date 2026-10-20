"""Source archive controls use fake Cargo output; no native builds or installs."""

import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tomllib

SPEC = importlib.util.spec_from_file_location(
    "python_sdist", Path(__file__).parents[1] / "python_sdist.py"
)
sdist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdist)

PYPROJECT = """[build-system]
requires = ["maturin>=1.9.4,<2"]
build-backend = "maturin"
[project]
name = "phantom-http"
version = "0.2.0"
license-files = ["LICENSE-MIT", "LICENSE-APACHE"]
[tool.maturin]
python-source = "python"
module-name = "phantom_http._native"
manifest-path = 'bindings\\python\\Cargo.toml'
"""
LICENSE = b"Actual retained license text\n"


def write_archive(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files:
            info = tarfile.TarInfo(name)
            if isinstance(data, tarfile.TarInfo):
                archive.addfile(data)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def license_entries():
    return [(f"source/{path}", b"../LICENSE") for path in sorted(sdist.H3_LICENSES)]


def lock(packages):
    lines = ["version = 4"]
    for package in packages:
        lines.append("[[package]]")
        for key, value in package.items():
            lines.append(f"{key} = {json.dumps(value)}")
    return "\n".join(lines)


class SourceArchiveTests(unittest.TestCase):
    def test_portable_manifest_and_installed_notice_fields_preserve_other_toml(self):
        result = sdist.rewrite_pyproject(PYPROJECT, ["third-party-notices/a/LICENSE"])
        parsed = tomllib.loads(result)
        self.assertEqual(parsed["build-system"]["requires"], ["maturin==1.9.6"])
        self.assertEqual(
            parsed["tool"]["maturin"]["manifest-path"], "bindings/python/Cargo.toml"
        )
        self.assertEqual(
            parsed["tool"]["maturin"]["module-name"], "phantom_http._native"
        )
        self.assertEqual(
            parsed["project"]["license-files"],
            ["LICENSE-MIT", "LICENSE-APACHE", "third-party-notices/a/LICENSE"],
        )
        self.assertEqual(
            result, sdist.rewrite_pyproject(result, ["third-party-notices/a/LICENSE"])
        )

    def test_missing_maturin_manifest_path_is_added_without_changing_source_root(self):
        text = PYPROJECT.rsplit("manifest-path", 1)[0]
        result = tomllib.loads(sdist.rewrite_pyproject(text, []))
        self.assertEqual(
            result["tool"]["maturin"]["manifest-path"], "bindings/python/Cargo.toml"
        )
        self.assertEqual(result["tool"]["maturin"]["python-source"], "python")

    def test_unsupported_multiline_field_fails_instead_of_corrupting_metadata(self):
        text = PYPROJECT.replace(
            '["LICENSE-MIT", "LICENSE-APACHE"]',
            '[\n"LICENSE-MIT",\n"LICENSE-APACHE",\n]',
        )
        with self.assertRaises((ValueError, tomllib.TOMLDecodeError)):
            sdist.rewrite_pyproject(text, [])

    def test_placeholder_and_expected_link_both_become_actual_license_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            entries = license_entries()
            link = tarfile.TarInfo(entries[0][0])
            link.type = tarfile.SYMTYPE
            link.linkname = "../LICENSE"
            entries[0] = (link.name, link)
            entries.append(("source/python/phantom_http/py.typed", b""))
            write_archive(archive, entries)
            extracted = sdist.extract_source(archive, root / "tree", LICENSE)
            for path in sdist.H3_LICENSES:
                self.assertEqual((extracted / path).read_bytes(), LICENSE)
                self.assertFalse((extracted / path).is_symlink())
            self.assertTrue((extracted / "python/phantom_http/py.typed").is_file())

    def test_unsafe_duplicate_and_foreign_link_members_are_rejected(self):
        cases = [
            [("source/../escaped", b"bad")],
            [("C:/escaped", b"bad")],
            [("source/a", b"one"), ("source/A", b"two")],
            [("source/a.", b"bad")],
            [("source/a ", b"bad")],
            [("source/CON.txt", b"bad")],
            [("source/LPT1/file", b"bad")],
            [("other/a", b"bad")],
        ]
        link = tarfile.TarInfo("source/unowned-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        cases.append([(link.name, link)])
        for entries in cases:
            with (
                self.subTest(entries=entries),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                archive = root / "source.tar.gz"
                write_archive(archive, [*license_entries(), *entries])
                with self.assertRaises(ValueError):
                    sdist.extract_source(archive, root / "tree", LICENSE)

    def test_missing_and_modified_license_payloads_fail(self):
        for entries in [
            license_entries()[:-1],
            [(name, b"unknown") for name, _ in license_entries()],
        ]:
            with (
                self.subTest(entries=entries),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                archive = root / "source.tar.gz"
                write_archive(archive, entries)
                with self.assertRaises(ValueError):
                    sdist.extract_source(archive, root / "tree", LICENSE)

    def test_archive_count_and_expanded_size_limits_precede_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            write_archive(archive, license_entries())
            for limit in ["MAX_FILES", "MAX_BYTES"]:
                with self.subTest(limit=limit), patch.object(sdist, limit, 1):
                    with self.assertRaisesRegex(ValueError, "bounds"):
                        sdist.extract_source(archive, root / "tree", LICENSE)
                    self.assertFalse((root / "tree").exists())

    def test_canonical_archive_is_deterministic_and_contains_real_file_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "phantom_http-0.2.0"
            source.mkdir()
            (source / "LICENSE").write_bytes(LICENSE)
            (source / "py.typed").write_bytes(b"")
            (source / "build.sh").write_bytes(b"#!/bin/sh\n")
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            sdist.canonical_archive(source, first, {"build.sh"})
            sdist.canonical_archive(source, second, {"build.sh"})
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )
            with tarfile.open(first) as archive:
                info = archive.getmember("phantom_http-0.2.0/LICENSE")
                self.assertEqual(archive.extractfile(info).read(), LICENSE)
                self.assertEqual((info.uid, info.gid, info.mtime), (0, 0, 0))
                self.assertEqual(
                    archive.getmember("phantom_http-0.2.0/build.sh").mode, 0o755
                )
                self.assertTrue(all(entry.isfile() for entry in archive))
            with self.assertRaises(FileExistsError):
                sdist.canonical_archive(source, first)


class LockClosureTests(unittest.TestCase):
    def setUp(self):
        self.library = {
            "name": "library",
            "version": "1.0.0",
            "source": "registry+index",
            "checksum": "first",
        }
        self.newer = {**self.library, "version": "2.0.0", "checksum": "second"}
        self.client = {
            "name": "client",
            "version": "0.2.0",
            "dependencies": ["library 1.0.0"],
        }
        self.before = lock([self.library, self.newer, self.client])

    def test_only_closure_pruning_and_unambiguous_edge_disambiguation_are_allowed(self):
        client = {**self.client, "dependencies": ["library"]}
        self.assertEqual(
            sdist.verify_lock_pruning(self.before, lock([self.library, client])),
            {"before": 3, "after": 2, "removed": 1},
        )

    def test_added_version_source_checksum_or_edge_fails(self):
        changed_source = {**self.library, "source": "registry+other"}
        cases = [
            [
                self.library,
                self.newer,
                self.client,
                {"name": "extra", "version": "1.0.0"},
            ],
            [{**self.library, "version": "1.1.0"}],
            [changed_source],
            [{**self.library, "checksum": "tampered"}],
            [
                self.library,
                self.newer,
                {**self.client, "dependencies": ["library 2.0.0"]},
            ],
        ]
        for packages in cases:
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                sdist.verify_lock_pruning(self.before, lock(packages))

    def test_ambiguous_edges_and_duplicate_packages_fail(self):
        for packages in [
            [self.library, self.newer, {**self.client, "dependencies": ["library"]}],
            [self.library, self.library],
        ]:
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                sdist.verify_lock_pruning(self.before, lock(packages))

    def test_feature_unified_edges_may_be_pruned_without_changing_remaining_identity(
        self,
    ):
        original = copy.deepcopy(self.client)
        original["dependencies"].append("library 2.0.0")
        self.assertEqual(
            sdist.verify_lock_pruning(
                lock([self.library, self.newer, original]),
                lock([self.library, self.client]),
            )["removed"],
            1,
        )


class RepairFlowTests(unittest.TestCase):
    def test_actual_notice_collector_and_metadata_agree_before_promotion(self):
        self.run_repair(fail_locked=False)

    def test_failed_locked_validation_never_promotes_an_archive(self):
        self.run_repair(fail_locked=True)

    def test_different_notice_producing_compiler_never_promotes_an_archive(self):
        self.run_repair(fail_locked=False, fail_toolchain=True)

    def run_repair(self, *, fail_locked, fail_toolchain=False):
        tools = sdist.load_module(
            "sdist_test_tools", sdist.ROOT / "scripts/release/cli_artifact.py"
        )
        binding = sdist.load_module(
            "sdist_test_binding", sdist.ROOT / "scripts/dev/check_python_binding.py"
        )
        original_lock = lock([{"name": "phantom-python", "version": "0.2.0"}])
        revision = "a" * 40
        license_text = b"MIT\n" + b"retained license\n" * 100
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = root / "sysroot"
            docs = sysroot / "share/doc/rust"
            docs.mkdir(parents=True)
            (docs / "COPYRIGHT").write_text("Retained compiler runtime copyright")
            (docs / "LICENSE-MIT").write_bytes(license_text)
            (docs / "licenses").mkdir()
            for name in (
                "MIT.txt",
                "Apache-2.0.txt",
                "long-license-" + "x" * 75 + ".txt",
            ):
                (docs / "licenses" / name).write_bytes(license_text)
            archive = root / "raw.tar.gz"
            prefix = "phantom_http-0.2.0"
            files = [
                (path.replace("source/", prefix + "/", 1), data)
                for path, data in license_entries()
            ]
            files.extend(
                (f"{prefix}/{name}", data)
                for name, data in [
                    ("Cargo.lock", original_lock.encode()),
                    ("pyproject.toml", PYPROJECT.encode()),
                    (
                        "PKG-INFO",
                        b"Metadata-Version: 2.4\nName: phantom-http\nVersion: 0.2.0\nLicense-File: LICENSE-MIT\n\n",
                    ),
                    ("LICENSE-MIT", license_text),
                    ("LICENSE-APACHE", b"Apache license"),
                    (
                        "bindings/python/Cargo.toml",
                        b'[package]\nname="phantom-python"\nversion="0.2.0"',
                    ),
                    ("build.sh", b"#!/bin/sh\n"),
                    ("python/phantom_http/py.typed", b""),
                ]
            )
            write_archive(archive, files)
            original_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            calls = []

            class Commands:
                def __init__(self, logs):
                    logs.mkdir(parents=True)

                def run(self, args, **kwargs):
                    calls.append(args)
                    if args[:2] == ["git", "rev-parse"]:
                        return revision.encode()
                    if args[:2] == ["git", "show"]:
                        if args[-1].endswith("rust-toolchain.toml"):
                            return b'[toolchain]\nchannel="1.99.1"\ncomponents=["clippy","rustfmt"]\n'
                        return (
                            original_lock.encode()
                            if args[-1].endswith("Cargo.lock")
                            else license_text
                        )
                    if args[:2] == ["git", "ls-tree"]:
                        return b"100755 blob exact-object\tbuild.sh\0"
                    if args == ["rustc", "--print", "sysroot"]:
                        return str(sysroot).encode()
                    if args == ["rustc", "-vV"]:
                        return (
                            b"release: 1.98.0" if fail_toolchain else b"release: 1.99.1"
                        )
                    if args[:2] == ["cargo", "metadata"]:
                        if fail_locked and "--locked" in args:
                            raise ValueError("controlled locked metadata failure")
                        source = kwargs["cwd"]
                        return json.dumps(
                            {
                                "packages": [
                                    {
                                        "name": "phantom-python",
                                        "version": "0.2.0",
                                        "id": "python",
                                        "manifest_path": str(
                                            source / "bindings/python/Cargo.toml"
                                        ),
                                        "license": "MIT OR Apache-2.0",
                                    }
                                ],
                                "resolve": {"nodes": [{"id": "python", "deps": []}]},
                            }
                        ).encode()
                    raise AssertionError(args)

            fake_tools = SimpleNamespace(
                **{
                    name: getattr(tools, name)
                    for name in [
                        "ALLOC_STDLIB_LICENSE_PATH",
                        "copy_notices",
                        "copy_rust_notices",
                        "write_json",
                        "digest",
                    ]
                },
                Commands=Commands,
            )
            options = SimpleNamespace(
                source_archive=archive, source_revision=revision, output=root / "result"
            )
            with patch.object(sdist, "load_module", side_effect=[fake_tools, binding]):
                if fail_locked or fail_toolchain:
                    with self.assertRaisesRegex(
                        ValueError, "controlled locked|notice-producing"
                    ):
                        sdist.repair(options)
                    self.assertFalse((options.output / "verified").exists())
                    self.assertFalse(list(options.output.glob("**/*.tar.gz")))
                    return
                candidate = sdist.repair(options)
            self.assertEqual(
                hashlib.sha256(archive.read_bytes()).hexdigest(), original_digest
            )
            self.assertEqual(candidate.name, "phantom_http-0.2.0.tar.gz")
            receipt = json.loads((candidate.parent / "receipt.json").read_text())
            self.assertEqual(receipt["input_sha256"], original_digest)
            self.assertEqual(
                receipt["archive_sha256"],
                hashlib.sha256(candidate.read_bytes()).hexdigest(),
            )
            self.assertIn("not yet verified", receipt["validation"])
            self.assertEqual(receipt["source_builder_toolchain"], "1.99.1")
            with tarfile.open(candidate) as result:
                self.assertEqual(result.getmember(prefix + "/build.sh").mode, 0o755)
                self.assertEqual(
                    tomllib.loads(
                        result.extractfile(prefix + "/rust-toolchain.toml")
                        .read()
                        .decode()
                    ),
                    {"toolchain": {"channel": "1.99.1", "profile": "minimal"}},
                )
                project = tomllib.loads(
                    result.extractfile(prefix + "/pyproject.toml").read().decode()
                )
                metadata = BytesParser().parsebytes(
                    result.extractfile(prefix + "/PKG-INFO").read()
                )
                self.assertEqual(
                    set(metadata.get_all("License-File")),
                    set(project["project"]["license-files"]),
                )
                for path in project["project"]["license-files"]:
                    self.assertTrue(result.extractfile(prefix + "/" + path).read())
                inventory = json.load(
                    result.extractfile(prefix + "/third-party-notices/inventory.json")
                )
                for item in inventory:
                    for notice in item["notices"]:
                        payload = result.extractfile(
                            prefix + "/third-party-notices/" + notice["file"]
                        ).read()
                        self.assertEqual(
                            hashlib.sha256(payload).hexdigest(), notice["sha256"]
                        )
            self.assertEqual(
                sum(args[:2] == ["cargo", "metadata"] for args in calls), 2
            )
            self.assertTrue(
                all("--offline" in args for args in calls if args[0] == "cargo")
            )


if __name__ == "__main__":
    unittest.main()
