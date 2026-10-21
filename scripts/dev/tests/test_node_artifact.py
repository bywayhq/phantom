import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "node_artifact", Path(__file__).resolve().parents[2] / "release/node_artifact.py"
)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)
TARGET = "x86_64-pc-windows-msvc"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def successful_tap(count=19):
    return (
        f"# tests {count}\n# pass {count}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
    ).encode()


class NodeArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.tools = SimpleNamespace(digest=digest, write_json=write_json)

    def staging(self):
        staging = self.directory / "staging"
        staging.mkdir()
        (staging / "notices").mkdir()
        for name, data in (
            ("phantom.node", b"native bytes"),
            ("index.cjs", b"facade bytes"),
            ("notices/LICENSE", b"notice bytes"),
        ):
            (staging / name).write_bytes(data)
        return staging

    def archive(self, staging, entries=None):
        path = self.directory / "candidate.tgz"
        with tarfile.open(path, "w:gz") as archive:
            if entries is None:
                for file in staging.rglob("*"):
                    if file.is_file():
                        archive.add(
                            file, "package/" + file.relative_to(staging).as_posix()
                        )
            else:
                for entry in entries:
                    if isinstance(entry, str):
                        entry = tarfile.TarInfo(entry)
                        entry.size = 4
                    archive.addfile(entry, io.BytesIO(b"data"))
        return path

    def records(self, target=TARGET):
        return [
            {"reason": "build-script-executed", "package_id": "native-build"},
            {
                "reason": "compiler-artifact",
                "package_id": "node",
                "target": {"name": "phantom_node", "kind": ["cdylib", "rlib"]},
                "profile": {"test": False, "opt_level": "3"},
                "filenames": [
                    str(self.directory / artifact.TARGETS[target][2]),
                    str(self.directory / "libphantom_node.rlib"),
                ],
            },
            {"reason": "build-finished", "success": True},
        ]

    def test_actual_optimized_cdylib_and_dependency_inputs_are_required(self):
        for target in artifact.TARGETS:
            records = self.records(target)
            packages, binary = artifact.build_records(
                "\n".join(map(json.dumps, records)), target
            )
            self.assertEqual(packages, {"node", "native-build"})
            self.assertEqual(binary.name, artifact.TARGETS[target][2])
        records = self.records()
        for mutation in ("optimization", "failed", "missing", "duplicate"):
            changed = json.loads(json.dumps(records))
            if mutation == "optimization":
                changed[1]["profile"]["opt_level"] = "0"
            elif mutation == "failed":
                changed[-1]["success"] = False
            elif mutation == "missing":
                changed[1]["filenames"] = []
            else:
                changed.insert(2, changed[1])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.build_records("\n".join(map(json.dumps, changed)), TARGET)

    def test_staged_metadata_is_private_host_specific_and_has_no_scripts(self):
        source = json.loads((artifact.ROOT / "bindings/node/package.json").read_text())
        for target, (platform, architecture, _) in artifact.TARGETS.items():
            with self.subTest(target=target):
                package = artifact.package_metadata(source, source["version"], target)
                self.assertTrue(package["private"])
                self.assertEqual(package["os"], [platform])
                self.assertEqual(package["cpu"], [architecture])
                self.assertIn("phantom.node", package["files"])
                self.assertNotIn("scripts", package)
                self.assertNotIn("devDependencies", package)
                self.assertEqual(package["exports"], source["exports"])
        source["private"] = False
        with self.assertRaisesRegex(ValueError, "private"):
            artifact.package_metadata(source, source["version"], TARGET)

    def test_runtime_dependencies_and_source_version_mismatch_fail(self):
        source = json.loads((artifact.ROOT / "bindings/node/package.json").read_text())
        with self.assertRaisesRegex(ValueError, "identity"):
            artifact.package_metadata(source, "mismatched-version", TARGET)
        source["dependencies"] = {"unlocked-runtime": "*"}
        with self.assertRaisesRegex(ValueError, "runtime npm"):
            artifact.package_metadata(source, source["version"], TARGET)

    def test_archive_retains_exact_native_facade_and_notices_and_rejects_changes(self):
        staging = self.staging()
        archive = self.archive(staging)
        inspected = artifact.inspect_archive(archive, staging, self.tools)
        self.assertEqual(
            inspected["package/phantom.node"], digest(staging / "phantom.node")
        )
        self.assertIn("package/notices/LICENSE", inspected)
        (staging / "phantom.node").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "exact staged payload"):
            artifact.inspect_archive(archive, staging, self.tools)
        (staging / "phantom.node").unlink()
        with self.assertRaisesRegex(ValueError, "exact staged payload"):
            artifact.inspect_archive(archive, staging, self.tools)

    def test_archive_rejects_escape_alias_duplicate_and_link_entries(self):
        staging = self.staging()
        link = tarfile.TarInfo("package/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "index.cjs"
        for entries in (
            ("../escape",),
            ("/absolute",),
            ("package/a/../b",),
            ("package/a\\b",),
            ("package/C:/file",),
            ("package/a/./b",),
            ("package/a", "package/A"),
            ("package/a", "package/a"),
            (link,),
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                artifact.inspect_archive(
                    self.archive(staging, entries), staging, self.tools
                )

    def test_archive_bounds_precede_reading_its_payload(self):
        staging = self.staging()
        archive = self.archive(staging)
        with (
            patch.object(artifact, "MAX_ARCHIVE_BYTES", 1),
            self.assertRaisesRegex(ValueError, "bounds"),
        ):
            artifact.inspect_archive(archive, staging, self.tools)

    def test_installed_peers_use_package_resolution_including_worker_and_native_paths(
        self,
    ):
        destination = self.directory / "tests"
        artifact.copied_tests(destination)
        client = (destination / "client.test.cjs").read_text()
        self.assertNotIn("path.resolve(__dirname, '..')", client)
        self.assertNotIn("require('..')", client)
        self.assertIn("require.resolve('@byway/phantom')", client)
        self.assertIn("require('node:worker_threads')", client)
        self.assertIn("'phantom.node'", client)
        for name in (
            "http2.test.cjs",
            "pipeline.test.cjs",
            "configuration.test.cjs",
            "profiles.test.cjs",
            "session-sharing.test.cjs",
            "transfer.test.cjs",
            "request-controls.test.cjs",
            "prepared-bodies.test.cjs",
            "server-pins.test.cjs",
            "diagnostics.test.cjs",
            "diagnostics-http2.test.cjs",
            "transfer-http2.test.cjs",
            "content-decoding.test.cjs",
            "redirects.test.cjs",
            "retries.test.cjs",
            "uploads.test.cjs",
            "upload-http3.test.cjs",
        ):
            test = (destination / name).read_text()
            self.assertNotIn("require('..')", test)
            self.assertIn("require('@byway/phantom')", test)
        for name in ("types.cts", "types.mts"):
            copied = (destination / name).read_text()
            self.assertIn("from '@byway/phantom'", copied)
            self.assertNotIn("../index.cjs", copied)
            self.assertNotIn("../index.mjs", copied)
        loader = (destination / "native-loader.test.cjs").read_text()
        self.assertIn("require.resolve('@byway/phantom')", loader)
        self.assertNotIn("path.join(__dirname, '../index.cjs')", loader)
        transfer = (destination / "transfer-facade.test.cjs").read_text()
        self.assertIn("require.resolve('@byway/phantom')", transfer)
        self.assertNotIn("path.resolve(__dirname, '../index.cjs')", transfer)
        diagnostics = (destination / "diagnostics-facade.test.cjs").read_text()
        self.assertIn("require.resolve('@byway/phantom')", diagnostics)
        self.assertNotIn("path.resolve(__dirname, '../index.cjs')", diagnostics)
        for name in (
            "prepared-bodies-facade",
            "request-controls-facade",
            "session-snapshot-facade",
            "server-pins-facade",
            "upload-pump",
        ):
            copied = (destination / f"{name}.test.cjs").read_text()
            self.assertIn("require.resolve('@byway/phantom')", copied)
            self.assertNotIn("path.resolve(__dirname, '../index.cjs')", copied)
        fixtures = artifact.ROOT / "bindings/node/tests/fixtures"
        for source in fixtures.iterdir():
            self.assertEqual(
                source.read_bytes(),
                (destination / "fixtures" / source.name).read_bytes(),
            )

    def test_test_import_drift_fails_instead_of_silently_skipping_a_control(self):
        root = self.directory / "root"
        source = root / "bindings/node/tests"
        source.mkdir(parents=True)
        (source / "client.test.cjs").write_text("// changed import layout")
        with (
            patch.object(artifact, "ROOT", root),
            self.assertRaisesRegex(ValueError, "import changed"),
        ):
            artifact.copied_tests(self.directory / "copied")

    def test_shared_public_checks_keep_installed_native_and_types_controls(self):
        consumer = self.directory / "consumer"
        consumer.mkdir()
        package = consumer / "node_modules/@byway/phantom"
        package.mkdir(parents=True)
        calls = []

        def run(args, **options):
            calls.append((args, options))
            if "-e" in args:
                return json.dumps(
                    {"entry": str(package / "index.cjs"), "version": "0.2.0"}
                ).encode()
            return successful_tap() if "--test" in args else b""

        with patch.object(
            artifact, "h3_peer_environment", side_effect=lambda _r, _d, env: env
        ) as peer_environment:
            result = artifact.public_checks(
                consumer,
                Path("node"),
                Path("npm-cli.js"),
                "0.2.0",
                SimpleNamespace(run=run),
                self.tools,
                {"isolated": "environment"},
                consumer / "cache",
                "@byway/phantom-win32-x64-msvc",
            )
        peer_environment.assert_called_once()
        self.assertEqual(result["loopback_checks"]["pass"], 19)
        self.assertEqual(len(calls), 4)
        peer = next(args for args, _ in calls if "--test" in args)
        self.assertIn("tests/native-loader.test.cjs", peer)
        self.assertIn("tests/pipeline.test.cjs", peer)
        for name in (
            "compact-profiles",
            "session-sharing",
            "transfer",
            "transfer-http2",
            "transfer-facade",
            "server-pins",
            "server-pins-facade",
            "diagnostics",
            "diagnostics-http2",
            "diagnostics-facade",
            "prepared-bodies-facade",
            "request-controls-facade",
            "session-snapshot-facade",
            "upload-pump",
            "content-decoding",
            "redirects",
            "retries",
            "uploads",
            "upload-http3",
        ):
            self.assertIn(f"tests/{name}.test.cjs", peer)
        self.assertIn(
            'require("@byway/phantom-win32-x64-msvc")',
            (consumer / "tests/client.test.cjs").read_text(),
        )
        compiler = consumer / "compiler"
        self.assertEqual(
            (compiler / "package-lock.json").read_bytes(),
            (artifact.ROOT / "bindings/node/package-lock.json").read_bytes(),
        )
        self.assertEqual(calls[2][0][:3], ["node", "npm-cli.js", "ci"])
        self.assertEqual(calls[2][1]["cwd"], compiler)
        self.assertIn(str(compiler / "node_modules/typescript/bin/tsc"), calls[3][0])
        self.assertTrue(
            all(options["env"] == {"isolated": "environment"} for _, options in calls)
        )

    def test_loopback_summary_requires_complete_unskipped_controls(self):
        self.assertEqual(artifact.tap_summary(successful_tap())["pass"], 19)
        for raw in (
            successful_tap(18),
            successful_tap().replace(b"# skipped 0", b"# skipped 1"),
            successful_tap().replace(b"# pass 19", b"# pass 18"),
            successful_tap() + b"# tests 19\n",
            b"no summary",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                artifact.tap_summary(raw)

    def test_explicit_runtime_checks_major_host_and_adjacent_npm(self):
        node = self.directory / "node"
        node.touch()
        cli = self.directory / "node_modules/npm/bin/npm-cli.js"
        cli.parent.mkdir(parents=True)
        cli.touch()
        identity = {
            "versions": {"node": "22.23.3"},
            "platform": "win32",
            "architecture": "x64",
        }
        commands = SimpleNamespace(
            run=lambda args: (
                b"10.0.0" if "--version" in args else json.dumps(identity).encode()
            )
        )
        _, actual_cli, actual = artifact.runtime(node, 22, TARGET, commands)
        self.assertEqual(actual_cli, cli)
        self.assertEqual(actual["npm"], "10.0.0")
        with self.assertRaisesRegex(ValueError, "major and native host"):
            artifact.runtime(node, 24, TARGET, commands)
        identity["architecture"] = "arm64"
        with self.assertRaisesRegex(ValueError, "major and native host"):
            artifact.runtime(node, 22, TARGET, commands)
        identity["architecture"] = "x64"
        cli.unlink()
        with self.assertRaisesRegex(ValueError, "bundled npm"):
            artifact.runtime(node, 22, TARGET, commands)

    def test_npm_uses_distinct_empty_configs_without_host_loader_overrides(self):
        node = self.directory / "runtime/node.exe"
        inherited = {
            "PATH": "host-path",
            "NODE_OPTIONS": "--require host-module",
            "NODE_PATH": "host-modules",
            "LD_LIBRARY_PATH": "host-libraries",
            "DYLD_LIBRARY_PATH": "host-libraries",
            "DYLD_FALLBACK_LIBRARY_PATH": "host-libraries",
            "NPM_CONFIG_USERCONFIG": "host-user",
            "NPM_CONFIG_GLOBALCONFIG": "host-global",
        }
        with patch.dict(os.environ, inherited, clear=True):
            environment = artifact.npm_environment(self.directory, node)
            self.assertEqual(os.environ, inherited)
        user = Path(environment["NPM_CONFIG_USERCONFIG"])
        global_config = Path(environment["NPM_CONFIG_GLOBALCONFIG"])
        self.assertNotEqual(user.resolve(), global_config.resolve())
        for config in (user, global_config):
            self.assertTrue(config.is_file())
            self.assertEqual(config.parent, self.directory)
            self.assertEqual(config.read_bytes(), b"")
        for key in inherited.keys() - {
            "PATH",
            "NPM_CONFIG_USERCONFIG",
            "NPM_CONFIG_GLOBALCONFIG",
        }:
            self.assertNotIn(key, environment)
        self.assertEqual(
            environment["PATH"], str(node.parent) + os.pathsep + "host-path"
        )

    def test_failed_installation_preserves_candidate_without_verified_artifact(self):
        binary = self.directory / "phantom_node.dll"
        binary.write_bytes(b"owned native bytes")
        output = self.directory / "output"
        directory = self.directory
        records = self.records()

        class Commands:
            def __init__(self, logs):
                logs.mkdir(parents=True)

            def run(self, args, **options):
                if args[:2] == ["git", "status"]:
                    return b""
                if args[:2] == ["git", "rev-parse"]:
                    return b"fixed-source"
                if args[0] == "rustc":
                    return str(directory).encode()
                if args[:2] == ["cargo", "metadata"]:
                    return json.dumps(
                        {"packages": [{"name": "phantom-node", "version": "0.2.0"}]}
                    ).encode()
                if args[:2] == ["cargo", "build"]:
                    return "\n".join(map(json.dumps, records)).encode()
                if "pack" in args:
                    archive = output / "candidate/byway-phantom-0.2.0.tgz"
                    staging = options["cwd"]
                    with tarfile.open(archive, "w:gz") as tar:
                        for path in staging.rglob("*"):
                            if path.is_file():
                                tar.add(
                                    path,
                                    "package/" + path.relative_to(staging).as_posix(),
                                )
                    return b'[{"filename":"byway-phantom-0.2.0.tgz"}]'
                return b"toolchain"

        def notices(_metadata, _packages, destination):
            destination.mkdir()
            (destination / "LICENSE").write_text("native notice")
            return []

        tools = SimpleNamespace(
            Commands=Commands,
            digest=digest,
            write_json=write_json,
            host_identity=lambda *_: {},
            build_jobs=lambda: "1",
            copy_notices=notices,
            copy_rust_notices=lambda _sysroot, destination: destination.mkdir(),
            dependency_inspection=lambda *_: [],
        )
        args = SimpleNamespace(
            target=TARGET, node22=Path("node22"), node24=Path("node24"), output=output
        )
        with (
            patch.object(artifact, "artifact_tools", return_value=tools),
            patch.object(
                artifact, "runtime", return_value=(Path("node"), Path("npm-cli.js"), {})
            ),
            patch.object(
                artifact,
                "installed_checks",
                side_effect=ValueError("installed Worker control failed"),
            ),
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(ValueError, "Worker control failed"),
        ):
            artifact.verify(args)
        self.assertTrue((output / "candidate/byway-phantom-0.2.0.tgz").is_file())
        self.assertFalse((output / "verified").exists())
        self.assertEqual(binary.read_bytes(), b"owned native bytes")
        artifact.inspect_archive(
            output / "candidate/byway-phantom-0.2.0.tgz", output / "staging", self.tools
        )


if __name__ == "__main__":
    unittest.main()
