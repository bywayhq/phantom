import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "go_artifact", Path(__file__).resolve().parents[2] / "release/go_artifact.py"
)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)

TARGET = "x86_64-pc-windows-msvc"


class GoArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def records(self, filename):
        return [
            {"reason": "build-script-executed", "package_id": "tls-build"},
            {
                "reason": "compiler-artifact",
                "package_id": "go-native",
                "target": {"name": "phantom_go", "kind": ["cdylib", "rlib"]},
                "profile": {"test": False, "opt_level": "3"},
                "filenames": [
                    str(self.root / filename),
                    str(self.root / "native.rlib"),
                ],
            },
            {"reason": "build-finished", "success": True},
        ]

    def test_actual_cargo_records_select_one_optimized_native_library_per_host(self):
        for target, filename in artifact.LIBRARIES.items():
            with self.subTest(target=target):
                records = self.records(filename)
                raw = "\n".join(json.dumps(record) for record in records)
                packages, library = artifact.build_records(raw, target)
                self.assertEqual(packages, {"tls-build", "go-native"})
                self.assertEqual(library, self.root / filename)

    def test_missing_duplicate_unoptimized_and_failed_builds_reject(self):
        for mutation in ("missing", "duplicate", "unoptimized", "failed", "unfinished"):
            records = self.records("phantom_go.dll")
            if mutation == "missing":
                records[1]["filenames"] = ["elsewhere.so"]
            elif mutation == "duplicate":
                records.insert(1, records[1])
            elif mutation == "unoptimized":
                records[1]["profile"]["opt_level"] = "1"
            elif mutation == "failed":
                records[-1]["success"] = False
            else:
                records.pop()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.build_records(
                    "\n".join(json.dumps(record) for record in records), TARGET
                )

    def test_module_copy_is_self_contained_go_source_with_both_licenses(self):
        destination = self.root / "module"
        artifact.copy_module(artifact.ROOT / "bindings/go", destination)
        self.assertTrue((destination / "client_test.go").is_file())
        self.assertTrue((destination / "http2_test.go").is_file())
        self.assertTrue((destination / "native.h").is_file())
        self.assertFalse((destination / "native").exists())
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            self.assertEqual(
                (destination / name).read_bytes(), (artifact.ROOT / name).read_bytes()
            )

    def test_missing_or_changed_module_license_fails_before_distribution(self):
        source = self.root / "source"
        artifact.copy_module(artifact.ROOT / "bindings/go", source)
        (source / "LICENSE-MIT").write_text("wrong license")
        with self.assertRaisesRegex(ValueError, "license differs"):
            artifact.copy_module(source, self.root / "wrong")
        (source / "LICENSE-MIT").unlink()
        with self.assertRaisesRegex(ValueError, "missing or nonregular"):
            artifact.copy_module(source, self.root / "missing")

    def test_fresh_go_caches_and_explicit_native_loader_replace_inherited_state(self):
        with patch.dict(
            os.environ,
            {
                "GOWORK": "checkout/go.work",
                "GOFLAGS": "-mod=vendor",
                "CGO_LDFLAGS": "-Lwrong",
                "LD_LIBRARY_PATH": "wrong",
            },
        ):
            for target, name in artifact.LIBRARIES.items():
                library = self.root / "native with spaces" / name
                environment = artifact.installation_environment(
                    self.root, library, target
                )
                self.assertEqual(environment["GOWORK"], "off")
                self.assertEqual(environment["GOENV"], "off")
                self.assertEqual(environment["GOFLAGS"], "")
                self.assertEqual(environment["GOPROXY"], "off")
                self.assertEqual(environment["GOTOOLCHAIN"], "local")
                for variable in ("GOCACHE", "GOMODCACHE", "GOPATH"):
                    self.assertTrue(
                        Path(environment[variable]).is_relative_to(self.root)
                    )
                if target == TARGET:
                    self.assertEqual(environment["PHANTOM_GO_LIBRARY"], str(library))
                    self.assertEqual(environment["CGO_ENABLED"], "0")
                else:
                    self.assertNotIn("wrong", environment["CGO_LDFLAGS"])
                    loader = (
                        "DYLD_LIBRARY_PATH" if "apple" in target else "LD_LIBRARY_PATH"
                    )
                    self.assertEqual(environment[loader], str(library.parent))
                    self.assertEqual(environment["CGO_ENABLED"], "1")

    def events(self):
        return [
            {
                "Action": "pass",
                "Package": artifact.MODULE,
                "Test": f"TestControl{index}",
            }
            for index in range(10)
        ] + [
            {
                "Action": "pass",
                "Package": artifact.MODULE,
                "Test": "TestHTTP3UploadCancellation",
            },
            {"Action": "pass", "Package": artifact.MODULE},
        ]

    def test_existing_controls_and_http3_must_pass_with_no_skips(self):
        events = self.events()
        passed = artifact.completed_tests(
            "\n".join(json.dumps(event) for event in events)
        )
        self.assertEqual(len(passed), 11)
        for mutation in (
            "skip",
            "fail",
            "missing-test",
            "missing-package",
            "duplicate-test",
            "missing-http3",
        ):
            changed = self.events()
            if mutation in {"skip", "fail"}:
                changed[0]["Action"] = mutation
            elif mutation == "missing-test":
                changed.pop(0)
            elif mutation == "missing-package":
                changed.pop()
            elif mutation == "missing-http3":
                changed[-2]["Test"] = "TestDifferentControl"
            else:
                changed[0] = changed[1]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.completed_tests(
                    "\n".join(json.dumps(event) for event in changed)
                )

    def extracted(self):
        tools = artifact.artifact_tools()
        folder = self.root / "paired"
        (folder / "module").mkdir(parents=True)
        (folder / "module/go.mod").write_text(f"module {artifact.MODULE}\n")
        (folder / "lib").mkdir()
        (folder / "lib/phantom_go.dll").write_bytes(b"native bytes")
        identity = {
            "payload_sha256": {
                path.relative_to(folder).as_posix(): tools.digest(path)
                for path in folder.rglob("*")
                if path.is_file()
            }
        }
        tools.write_json(folder / "artifact.json", identity)
        return folder, identity, tools

    def test_extracted_payload_must_match_every_hash_and_have_no_extra_files(self):
        folder, identity, tools = self.extracted()
        for mutation in ("bytes", "extra", "identity"):
            if mutation == "bytes":
                (folder / "lib/phantom_go.dll").write_bytes(b"different native bytes")
            elif mutation == "extra":
                (folder / "extra").write_text("unexpected")
            else:
                (folder / "artifact.json").write_text("{}")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.installed_checks(
                    self.root, "paired", TARGET, identity, None, tools
                )
            (folder / "lib/phantom_go.dll").write_bytes(b"native bytes")
            (folder / "extra").unlink(missing_ok=True)
            tools.write_json(folder / "artifact.json", identity)

    def test_consumer_cannot_resolve_checkout_or_another_go_architecture(self):
        folder, identity, tools = self.extracted()

        class Commands:
            def __init__(self, wrong_host):
                self.wrong_host = wrong_host

            def run(self, args, **_):
                if args[1] == "env":
                    return json.dumps(
                        {
                            "GOHOSTOS": "windows",
                            "GOHOSTARCH": "arm64" if self.wrong_host else "amd64",
                        }
                    ).encode()
                return json.dumps(
                    {"Path": artifact.MODULE, "Dir": str(artifact.ROOT / "bindings/go")}
                ).encode()

        for wrong_host, message in (
            (True, "toolchain host"),
            (False, "resolve the extracted"),
        ):
            with (
                self.subTest(wrong_host=wrong_host),
                self.assertRaisesRegex(ValueError, message),
            ):
                artifact.installed_checks(
                    self.root,
                    folder.name,
                    TARGET,
                    identity,
                    Commands(wrong_host),
                    tools,
                )

    def test_failed_installation_retains_archive_without_verified_promotion(self):
        tools = artifact.artifact_tools()
        library = self.root / "phantom_go.dll"
        library.write_bytes(b"native bytes")
        records = self.records(library.name)
        output = self.root / "output"
        raw = "\n".join(json.dumps(record) for record in records).encode()
        directory = self.root

        class Commands:
            def __init__(self, logs):
                logs.mkdir(parents=True)

            def run(self, args, **_):
                if args[:2] == ["git", "status"]:
                    return b""
                if args[:2] == ["git", "rev-parse"]:
                    return b"fixed-source"
                if args[:2] == ["cargo", "metadata"]:
                    return b'{"packages":[{"name":"phantom-go","version":"0.2.0"}]}'
                if args[:2] == ["cargo", "build"]:
                    return raw
                return str(directory).encode()

        def notices(_metadata, _packages, destination):
            destination.mkdir()
            (destination / "LICENSE").write_text("native notice")
            return []

        with (
            patch.object(tools, "Commands", Commands),
            patch.object(tools, "host_identity", return_value={}),
            patch.object(tools, "copy_notices", notices),
            patch.object(
                tools,
                "copy_rust_notices",
                lambda _root, destination: destination.mkdir(),
            ),
            patch.object(tools, "dependency_inspection", return_value=[]),
            patch.object(artifact, "artifact_tools", return_value=tools),
            patch.object(
                artifact, "installed_checks", side_effect=ValueError("failed control")
            ),
            patch.dict(os.environ, {}, clear=True),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(ValueError, "failed control"),
        ):
            artifact.verify(TARGET, output)
        self.assertFalse((output / "verified").exists())
        archives = list(output.glob("*.zip"))
        self.assertEqual(len(archives), 1)
        extracted = self.root / "outside"
        tools.extract_archive(archives[0], extracted)
        installed = next(extracted.glob("*/lib/phantom_go.dll"))
        self.assertEqual(installed.read_bytes(), b"native bytes")


if __name__ == "__main__":
    unittest.main()
