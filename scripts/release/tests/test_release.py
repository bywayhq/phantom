import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tomllib


def load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).parents[1] / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load("verify_packages", "verify-packages.py")
publish = load("publish_packages", "publish.py")
advisories = load("check_advisories", "check-advisories.py")


class ReleaseChecks(unittest.TestCase):
    def test_consumer_inherits_the_workspace_msrv_and_keeps_staged_dependencies(self):
        text = (verify.ROOT / "tests/downstream/public-api/Cargo.toml").read_text(
            encoding="utf-8"
        )
        versions = {"phantom-http": "0.2.0", "phantom-testkit": "0.3.0"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ("1.91", "1.92.1"):
                (root / "Cargo.toml").write_text(
                    f'[workspace.package]\nrust-version = "{version}"\n',
                    encoding="utf-8",
                )
                with self.subTest(version=version), patch.object(verify, "ROOT", root):
                    manifest = tomllib.loads(verify.consumer_manifest(text, versions))
                    self.assertEqual(manifest["package"]["rust-version"], version)
                    self.assertEqual(manifest["package"]["edition"], "2024")
                    for alias, package in (
                        ("phantom", "phantom-http"),
                        ("phantom-testkit", "phantom-testkit"),
                    ):
                        table = (
                            "dependencies" if alias == "phantom" else "dev-dependencies"
                        )
                        dependency = manifest[table][alias]
                        self.assertEqual(dependency["version"], "=" + versions[package])
                        self.assertEqual(dependency["registry"], "phantom-staging")
                        self.assertNotIn("path", dependency)
                    self.assertEqual(manifest["features"]["full"], ["phantom/full"])
                    self.assertEqual(
                        manifest["features"]["diagnostics"], ["phantom/diagnostics"]
                    )

    def test_structured_output_excludes_dependency_download_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.json"
            log = root / "metadata.log"
            verify.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('{\"packages\": []}'); "
                    'print("Downloading crates ...", file=sys.stderr)',
                ],
                root,
                log,
                stdout=metadata,
            )
            self.assertEqual(json.loads(metadata.read_text()), {"packages": []})
            self.assertEqual(log.read_text().strip(), "Downloading crates ...")

    def test_sparse_paths_cover_all_name_lengths(self):
        for name, expected in [
            ("a", "1/a"),
            ("ab", "2/ab"),
            ("abc", "3/a/abc"),
            ("Abcd", "ab/cd/abcd"),
        ]:
            self.assertEqual(verify.index_path(name), expected)

    def test_index_preserves_aliases_features_and_target_build_dependencies(self):
        manifest = {
            "package": {
                "name": "phantom-example",
                "version": "0.1.0",
                "links": "native",
            },
            "features": {"tls": ["dep:tls"]},
            "dependencies": {
                "tls": {
                    "package": "phantom-btls",
                    "version": "=1.0.0",
                    "optional": True,
                }
            },
            "target": {"cfg(windows)": {"build-dependencies": {"cmake": "0.1"}}},
        }
        record = verify.index_record(manifest, "checksum", {"phantom-btls"})
        local, external = record["deps"]
        self.assertEqual(
            (local["name"], local["package"], local["registry"]),
            ("tls", "phantom-btls", None),
        )
        self.assertTrue(local["optional"])
        self.assertEqual(
            (external["kind"], external["target"], external["registry"]),
            ("build", "cfg(windows)", verify.CRATES_IO),
        )
        self.assertEqual(record["features2"], manifest["features"])
        self.assertEqual(record["links"], "native")

    def test_install_root_redirects_staged_dependencies_without_replacing_crates_io(
        self,
    ):
        manifest = {
            "package": {"name": "phantom-cli", "version": "0.2.0"},
            "dependencies": {
                "phantom": {
                    "package": "phantom-http",
                    "version": "=0.2.0",
                    "features": ["fingerprint-import"],
                },
                "phantom-profile": "=0.2.0",
                "tokio": "1",
            },
            "dev-dependencies": {"phantom-testkit": "=0.2.0"},
        }
        versions = dict.fromkeys(
            ("phantom-cli", "phantom-http", "phantom-profile", "phantom-testkit"),
            "0.2.0",
        )
        settings = tomllib.loads(
            verify.install_registry_config("http://127.0.0.1:321", manifest, versions)
        )
        self.assertEqual(
            settings["registries"]["phantom-staging"]["index"],
            "sparse+http://127.0.0.1:321/",
        )
        self.assertEqual(
            settings["patch"]["crates-io"],
            {
                name: {"version": "=0.2.0", "registry": "phantom-staging"}
                for name in ("phantom-http", "phantom-profile")
            },
        )
        self.assertNotIn("source", settings)
        self.assertNotIn(
            "path",
            verify.install_registry_config("http://127.0.0.1:321", manifest, versions),
        )

    def test_cli_artifacts_must_identify_the_staged_client_and_root(self):
        base = "http://127.0.0.1:321"
        versions = {"phantom-cli": "0.2.0", "phantom-http": "0.2.0"}
        selected = {
            name: f"sparse+{base}/#{name}@{version}"
            for name, version in versions.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "cli-install.log"
            records = [
                {"reason": "compiler-artifact", "package_id": identity}
                for identity in selected.values()
            ]
            records.append(
                {
                    "reason": "compiler-artifact",
                    "package_id": "registry+https://github.com/rust-lang/crates.io-index#tokio@1.0.0",
                }
            )

            def write():
                log.write_text(
                    "Installing staged CLI\n" + "\n".join(map(json.dumps, records)),
                    encoding="utf-8",
                )

            write()
            self.assertEqual(
                verify.installed_package_sources(log, base, versions), selected
            )
            for wrong in (
                "registry+https://github.com/rust-lang/crates.io-index#phantom-http@0.2.0",
                f"sparse+{base}/#phantom-http@0.1.0",
                "path+file:///checkout#phantom-http@0.2.0",
            ):
                records[1]["package_id"] = wrong
                write()
                with (
                    self.subTest(identity=wrong),
                    self.assertRaisesRegex(ValueError, "bypassed staging"),
                ):
                    verify.installed_package_sources(log, base, versions)
            records.pop(1)
            write()
            with self.assertRaisesRegex(ValueError, "omitted staged"):
                verify.installed_package_sources(log, base, versions)

    def test_tls_dependencies_use_their_published_archive_identities(self):
        versions = {name: version for name, version, _manifest in publish.plan()}
        workspace = tomllib.loads((publish.ROOT / "Cargo.toml").read_text())[
            "workspace"
        ]
        for alias in ("btls-sys", "btls", "tokio-btls"):
            with self.subTest(alias=alias):
                dependency = workspace["dependencies"][alias].copy()
                manifest = publish.ROOT / dependency.pop("path") / "Cargo.toml"
                package = tomllib.loads(manifest.read_text())["package"]
                self.assertEqual(package["name"], "phantom-" + alias)
                self.assertNotIn(package["name"], versions)
                self.assertEqual(dependency["package"], package["name"])
                self.assertEqual(dependency["version"], "=" + package["version"])
                consumer = {
                    "package": {"name": "consumer", "version": "1.0.0"},
                    "dependencies": {alias: dependency},
                }
                record = verify.index_record(consumer, "checksum", versions)["deps"][0]
                self.assertEqual(record["package"], package["name"])
                self.assertEqual(record["req"], "=" + package["version"])
                self.assertEqual(record["registry"], verify.CRATES_IO)

        native = tomllib.loads(
            (publish.ROOT / "vendor/btls-sys/Cargo.toml").read_text()
        )["package"]
        wrapper = tomllib.loads((publish.ROOT / "vendor/btls/Cargo.toml").read_text())
        # cargo package removes the path but retains the exact registry version.
        del wrapper["dependencies"]["btls-sys"]["path"]
        dependencies = verify.index_record(wrapper, "checksum", versions)["deps"]
        dependency = next(item for item in dependencies if item["name"] == "btls-sys")
        self.assertEqual(dependency["package"], native["name"])
        self.assertEqual(dependency["req"], "=" + native["version"])
        self.assertEqual(dependency["registry"], verify.CRATES_IO)
        self.assertEqual(
            next(item for item in dependencies if item["name"] == "libc")["registry"],
            verify.CRATES_IO,
        )

    def test_transport_forks_use_their_staged_archive_identities(self):
        versions = {name: version for name, version, _manifest in publish.plan()}
        workspace = tomllib.loads((publish.ROOT / "Cargo.toml").read_text())[
            "workspace"
        ]
        for alias in ("http2", "wreq-proto", "h3", "h3-datagram", "h3-quinn"):
            with self.subTest(alias=alias):
                dependency = workspace["dependencies"][alias].copy()
                manifest = publish.ROOT / dependency.pop("path") / "Cargo.toml"
                native = tomllib.loads(manifest.read_text())["package"]
                self.assertEqual(versions.get(native["name"]), native["version"])
                self.assertEqual(dependency["version"], "=" + native["version"])
                consumer = {
                    "package": {"name": "consumer", "version": "1.0.0"},
                    "dependencies": {alias: dependency},
                }
                record = verify.index_record(consumer, "checksum", versions)["deps"][0]
                self.assertEqual(record["package"], native["name"])
                self.assertEqual(record["req"], "=" + native["version"])
                self.assertIsNone(record["registry"])

        transport = tomllib.loads(
            (publish.ROOT / "vendor/wreq-proto/Cargo.toml").read_text()
        )
        http2 = transport["dependencies"]["http2"].copy()
        del http2["path"]
        self.assertIn(http2["package"], versions)
        self.assertEqual(http2["version"], "=" + versions[http2["package"]])
        transport["dependencies"]["http2"] = http2
        record = next(
            dependency
            for dependency in verify.index_record(transport, "checksum", versions)[
                "deps"
            ]
            if dependency["name"] == "http2"
        )
        self.assertIsNone(record["registry"])

    def test_index_rejects_a_dependency_that_still_uses_git_or_path(self):
        for source in ["git", "path"]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                verify.index_record(
                    {
                        "package": {"name": "example", "version": "0.1.0"},
                        "dependencies": {"bad": {"version": "1", source: "somewhere"}},
                    },
                    "",
                    set(),
                )

    def test_owner_addition_is_verified(self):
        with (
            patch.object(
                publish, "owners", side_effect=[{"0xARYA"}, {"0xARYA", publish.OWNER}]
            ),
            patch.object(publish.subprocess, "run") as command,
        ):
            publish.ensure_owner("phantom-http")
        self.assertEqual(
            command.call_args.args[0],
            ["cargo", "owner", "--add", "github:bywayhq:staff", "phantom-http"],
        )

    def test_missing_team_owner_stops_release(self):
        with (
            patch.object(publish, "owners", return_value={"0xARYA"}),
            patch.object(publish.subprocess, "run"),
            self.assertRaises(RuntimeError),
        ):
            publish.ensure_owner("phantom-http")

    def test_existing_team_ownership_does_not_remove_named_owner(self):
        with (
            patch.object(publish, "owners", return_value={"0xARYA", publish.OWNER}),
            patch.object(publish.subprocess, "run") as command,
        ):
            publish.ensure_owner("phantom-http")
        command.assert_not_called()

    def test_new_versions_follow_dependency_order_without_republishing_unchanged_forks(
        self,
    ):
        plan = publish.plan()
        names = {entry[0] for entry in plan}
        self.assertEqual(len(plan), 11)
        self.assertEqual(plan[0][0], "phantom-http2")
        self.assertEqual(plan[-1][0], "phantom-cli")
        self.assertEqual(
            names,
            {
                "phantom-http2",
                "phantom-wreq-proto",
                "phantom-h3",
                "phantom-h3-datagram",
                "phantom-h3-quinn",
                "phantom-testkit",
                "phantom-profile",
                "phantom-quic-btls",
                "phantom-net",
                "phantom-http",
                "phantom-cli",
            },
        )
        workspace = tomllib.loads((publish.ROOT / "Cargo.toml").read_text())[
            "workspace"
        ]
        seen = set()
        for name, _version, manifest in plan:
            data = tomllib.loads((publish.ROOT / manifest).read_text())
            tables = [data, *data.get("target", {}).values()]
            for table in tables:
                for kind in ("dependencies", "build-dependencies"):
                    for alias, dependency in table.get(kind, {}).items():
                        if isinstance(dependency, dict) and dependency.get("workspace"):
                            dependency = workspace["dependencies"][alias]
                        package = (
                            dependency.get("package", alias)
                            if isinstance(dependency, dict)
                            else alias
                        )
                        if package in names:
                            self.assertIn(package, seen)
            seen.add(name)

        core = tomllib.loads((publish.ROOT / "vendor/h3/h3/Cargo.toml").read_text())
        self.assertNotIn("version", core["dev-dependencies"]["h3-datagram"])

    def test_advisories_include_forks_outside_the_publication_plan(self):
        identities = advisories.upstream_identities()
        self.assertEqual(len(identities), 12)
        self.assertEqual(identities["phantom-http2"][0], "http2")
        self.assertEqual(identities["phantom-btls-sys"][0], "btls-sys")
        self.assertEqual(identities["phantom-quinn-proto"][0], "quinn-proto")

    def test_resume_accepts_only_the_same_clean_commit_and_checksum(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            content = json.dumps({"git": {"sha1": "reviewed", "dirty": False}}).encode()
            info = tarfile.TarInfo("example-1.0.0/.cargo_vcs_info.json")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        data = stream.getvalue()
        record = {"version": {"checksum": hashlib.sha256(data).hexdigest()}}
        with patch.object(publish, "fetch", return_value=data):
            publish.published_from_commit("example", "1.0.0", record, "reviewed")
            with self.assertRaisesRegex(RuntimeError, "was not published from"):
                publish.published_from_commit("example", "1.0.0", record, "different")
            with self.assertRaisesRegex(RuntimeError, "checksum differs"):
                publish.published_from_commit(
                    "example", "1.0.0", {"version": {"checksum": "wrong"}}, "reviewed"
                )

    def test_foreign_owned_name_stops_before_any_upload(self):
        with (
            patch.object(
                publish, "plan", return_value=[("example", "1.0.0", "Cargo.toml")]
            ),
            patch.object(publish, "api", return_value={"crate": {}}),
            patch.object(publish, "owners", return_value={"someone-else"}),
            patch.object(publish.subprocess, "check_output", return_value="reviewed\n"),
            patch.object(publish.subprocess, "run") as command,
            self.assertRaisesRegex(RuntimeError, "owned by another publisher"),
        ):
            publish.release(True)
        command.assert_not_called()
