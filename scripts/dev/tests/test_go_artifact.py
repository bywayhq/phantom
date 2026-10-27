import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
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
                "GOPRIVATE": "*",
                "GONOPROXY": "*",
                "GONOSUMDB": "*",
                "GOINSECURE": "*",
                "GOVCS": "*:all",
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
                self.assertEqual(environment["GOVCS"], "off")
                for variable in ("GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE"):
                    self.assertNotIn(variable, environment)
                for variable in ("GOCACHE", "GOMODCACHE", "GOPATH"):
                    self.assertTrue(
                        Path(environment[variable]).is_relative_to(self.root)
                    )
                self.assertEqual(environment["PHANTOM_GO_LIBRARY"], str(library))
                self.assertEqual(environment["CGO_ENABLED"], "0")
                for variable in ("CGO_LDFLAGS", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
                    self.assertNotIn(variable, environment)

    def test_dependency_proxy_keeps_pinned_source_and_license(self):
        source = self.root / "source"
        source.mkdir()
        sums = b"example.test/ffi v1.2.3 h1:source\nexample.test/ffi v1.2.3/go.mod h1:mod\n"
        (source / "go.sum").write_bytes(sums)
        cache = self.root / "cache"
        download = cache / "cache/download/example.test/ffi/@v"
        download.mkdir(parents=True)
        for suffix in ("zip", "mod", "info"):
            (download / f"v1.2.3.{suffix}").write_bytes(suffix.encode())
        package = cache / "example.test/ffi@v1.2.3"
        package.mkdir(parents=True)
        (package / "LICENSE").write_bytes(b"ffi license")
        (package / "README.md").write_bytes(b"Go runtime attribution")
        go_root = self.root / "go-root"
        go_root.mkdir()
        (go_root / "LICENSE").write_bytes(b"Go runtime BSD license")
        record = {
            "Path": "example.test/ffi",
            "Version": "v1.2.3",
            "Sum": "h1:source",
            "GoModSum": "h1:mod",
            "Dir": str(package),
            **{
                key: str(download / f"v1.2.3.{suffix}")
                for key, suffix in (("Zip", "zip"), ("GoMod", "mod"), ("Info", "info"))
            },
        }

        class Commands:
            def run(self, args, **_):
                if args[1] == "list":
                    return b"example.test/ffi@v1.2.3\n"
                if args[1] == "env":
                    return str(go_root).encode()
                return json.dumps(record).encode()

        proxy, notices = self.root / "proxy", self.root / "notices"
        environment = {"GOMODCACHE": str(cache)}
        records = artifact.stage_go_dependencies(
            source, proxy, notices, Commands(), environment
        )
        self.assertEqual(records[0]["module"], "example.test/ffi@v1.2.3")
        self.assertEqual(
            (proxy / "example.test/ffi/@v/v1.2.3.zip").read_bytes(), b"zip"
        )
        self.assertEqual(
            (notices / "example.test/ffi/v1.2.3/LICENSE").read_bytes(), b"ffi license"
        )
        self.assertEqual((source / "go.sum").read_bytes(), sums)
        self.assertEqual(
            (notices / "go-runtime/LICENSE").read_bytes(), b"Go runtime BSD license"
        )
        self.assertEqual(
            (notices / "example.test/ffi/v1.2.3/README.md").read_bytes(),
            b"Go runtime attribution",
        )
        for field in ("Sum", "GoModSum", "Version"):
            original = record[field]
            record[field] = "changed"
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "pinned"),
            ):
                artifact.stage_go_dependencies(
                    source, proxy, notices, Commands(), environment
                )
            record[field] = original

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
        version = "0.0.0"
        source = self.root / "source"
        module = source / "bindings/go"
        for name, data in self.module_files().items():
            destination = module / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        (module / "version.go").write_text(
            f'package phantom\nconst nativePackageVersion = "{version}"\n'
        )
        (module / "README.md").write_text("fixture module")
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            shutil.copyfile(module / name, source / name)
        (source / "Cargo.lock").write_text("fixture lock")
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
                    return json.dumps(
                        {"packages": [{"name": "phantom-go", "version": version}]}
                    ).encode()
                if args[:2] == ["cargo", "build"]:
                    return raw
                return str(directory).encode()

        def notices(_metadata, _packages, destination):
            destination.mkdir()
            (destination / "LICENSE").write_text("native notice")
            return []

        with (
            patch.object(artifact, "ROOT", source),
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
            patch.object(artifact, "stage_module_proxy", return_value={}),
            patch.object(artifact, "stage_go_dependencies", return_value=[]),
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

    def test_version_declaration_matches_cargo_before_packaging_on_lf_or_crlf(self):
        for newline in (b"\n", b"\r\n"):
            (self.root / "version.go").write_bytes(
                newline.join(
                    [b"package phantom", b'const nativePackageVersion = "0.2.0"', b""]
                )
            )
            self.assertEqual(
                artifact.checked_module_version(self.root, "0.2.0"), "v0.2.0"
            )
            with self.assertRaisesRegex(ValueError, "differs from native"):
                artifact.checked_module_version(self.root, "0.3.0")
        for version in ("2.0.0", "0.2.0+changed", "0.2.0-pre", "0.02.0"):
            (self.root / "version.go").write_text(
                f'const nativePackageVersion = "{version}"\n'
            )
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "stable v0 or v1"),
            ):
                artifact.checked_module_version(self.root, version)

    def module_files(self):
        return {
            "go.mod": f"module {artifact.MODULE}\n\ngo 1.26\n".encode(),
            "go.sum": b"",
            "version.go": b'package phantom\nconst nativePackageVersion = "0.2.0"\n',
            "native.h": b"native header\n",
            "LICENSE-MIT": b"MIT\n",
            "LICENSE-APACHE": b"Apache\n",
            "native/src/lib.rs": b"// Retained in a real Go VCS module zip.\n",
        }

    def git_commands(self, files, irregular=()):
        class Commands:
            def run(self, args, **_):
                if args[:2] == ["git", "ls-tree"]:
                    return b"".join(
                        f"100644 blob {index}\tbindings/go/{path}\0".encode()
                        for index, path in enumerate(files)
                    ) + b"".join(irregular)
                if args[:3] == ["git", "cat-file", "blob"]:
                    return list(files.values())[int(args[-1])]
                if args[:2] == ["git", "show"]:
                    return b"2026-10-20T12:00:00+00:00\n"
                raise AssertionError(args)

        return Commands()

    def test_proxy_uses_full_canonical_git_module_not_checkout_or_flat_archive(self):
        files = self.module_files()
        files.update(
            {
                "vendor/ignored.go": b"vendor",
                "nested/go.mod": b"module example.test/nested\n",
                "nested/ignored.go": b"nested",
            }
        )
        proxy = self.root / "proxy with spaces"
        identity = artifact.stage_module_proxy(
            proxy,
            "fixed-source",
            "v0.2.0",
            self.git_commands(files, (b"120000 blob absent\tbindings/go/link.go\0",)),
        )
        folder = proxy / artifact.MODULE / "@v"
        with zipfile.ZipFile(folder / "v0.2.0.zip") as archive:
            self.assertEqual(len(archive.namelist()), 7)
            self.assertEqual(
                archive.read(f"{artifact.MODULE}@v0.2.0/version.go"),
                files["version.go"],
            )
            self.assertIn(
                f"{artifact.MODULE}@v0.2.0/native/src/lib.rs", archive.namelist()
            )
        self.assertEqual(identity["tag"], "bindings/go/v0.2.0")
        self.assertEqual(identity["source_revision"], "fixed-source")
        self.assertEqual((folder / "v0.2.0.mod").read_bytes(), files["go.mod"])
        self.assertEqual(set(identity["files_sha256"]), set(self.module_files()))

    def test_proxy_rejects_missing_support_files_and_wrong_module_identity(self):
        for mutation in ("identity", "license", "version"):
            files = self.module_files()
            if mutation == "identity":
                files["go.mod"] = b"module example.test/another\n"
            else:
                files.pop("LICENSE-MIT" if mutation == "license" else "version.go")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.stage_module_proxy(
                    self.root / mutation, "source", "v0.2.0", self.git_commands(files)
                )

    def proxy_consumer(self, mutation=None):
        tools = artifact.artifact_tools()
        proxy = self.root / "proxy"
        identity = artifact.stage_module_proxy(
            proxy, "fixed-source", "v0.2.0", self.git_commands(self.module_files())
        )
        observed = []

        class Commands:
            def run(self, args, *, cwd, env, **_):
                observed.append((args, cwd, env))
                cache = Path(env["GOMODCACHE"])
                folder = cache / f"{artifact.MODULE}@v0.2.0"
                downloads = cache / "cache/download" / artifact.MODULE / "@v"
                if args[:2] == ["go", "get"]:
                    (cwd / "go.sum").write_text(
                        f"{artifact.MODULE} v0.2.0 h1:source\n"
                        f"{artifact.MODULE} v0.2.0/go.mod h1:module\n"
                    )
                    return b""
                if args[:3] == ["go", "mod", "download"]:
                    downloads.mkdir(parents=True)
                    for suffix in ("zip", "mod"):
                        shutil.copyfile(
                            proxy / artifact.MODULE / f"@v/v0.2.0.{suffix}",
                            downloads / f"v0.2.0.{suffix}",
                        )
                    with zipfile.ZipFile(downloads / "v0.2.0.zip") as archive:
                        archive.extractall(cache)
                    if mutation == "zip":
                        (downloads / "v0.2.0.zip").write_bytes(b"tampered")
                    if mutation == "file":
                        (folder / "native.h").write_bytes(b"changed")
                    return json.dumps(
                        {
                            "Path": artifact.MODULE,
                            "Version": "v0.9.0" if mutation == "version" else "v0.2.0",
                            "Dir": str(folder if mutation != "foreign" else proxy),
                            "Zip": str(downloads / "v0.2.0.zip"),
                            "GoMod": str(downloads / "v0.2.0.mod"),
                            "Sum": "h1:changed"
                            if mutation == "sums" and cwd.name.endswith("1")
                            else "h1:source",
                            "GoModSum": "h1:module",
                        }
                    ).encode()
                if args[:2] == ["go", "list"]:
                    return json.dumps(
                        {
                            "Path": artifact.MODULE,
                            "Version": "v0.2.0",
                            "Dir": str(folder),
                            **(
                                {"Replace": {"Dir": "wrong"}}
                                if mutation == "replace"
                                else {}
                            ),
                        }
                    ).encode()
                if args[:2] == ["go", "build"]:
                    return b""
                if args[:3] == ["go", "mod", "verify"]:
                    return b"bad" if mutation == "verify" else b"all modules verified\n"
                return b"bad" if mutation == "marker" else b"external-consumer-ok\n"

        result = artifact.module_proxy_checks(
            self.root,
            self.root / "native/phantom_go.dll",
            TARGET,
            proxy,
            identity,
            Commands(),
            tools,
        )
        return result, observed

    def test_versioned_consumer_uses_two_fresh_caches_without_a_replace(self):
        result, observed = self.proxy_consumer()
        self.assertEqual(result["fresh_caches"], 2)
        self.assertIn("no public tag", result["scope"])
        caches = {env["GOMODCACHE"] for _, _, env in observed}
        self.assertEqual(len(caches), 2)
        for _args, cwd, env in observed:
            self.assertEqual(env["GOPROXY"], (self.root / "proxy").as_uri())
            self.assertEqual(env["GOVCS"], "off")
            self.assertEqual(env["GOSUMDB"], "off")
            self.assertNotIn("replace", (cwd / "go.mod").read_text())
        self.assertEqual(sum(args[:2] == ["go", "get"] for args, _, _ in observed), 1)

    def test_versioned_consumer_rejects_wrong_cache_source_resolution_and_checksums(
        self,
    ):
        for mutation in (
            "zip",
            "file",
            "version",
            "foreign",
            "replace",
            "sums",
            "verify",
            "marker",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                original = self.root
                self.root = Path(directory).resolve()
                try:
                    with self.assertRaises(ValueError):
                        self.proxy_consumer(mutation)
                finally:
                    self.root = original


if __name__ == "__main__":
    unittest.main()
