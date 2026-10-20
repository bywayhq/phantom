"""Registry assembly controls do not build or load native code."""

import copy
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "node_registry", Path(__file__).parents[1] / "node_registry.py"
)
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)
node = registry.load_module(
    "registry_test_node", registry.ROOT / "scripts/release/node_artifact.py"
)
promotion = registry.load_module(
    "registry_test_promotion", registry.ROOT / "scripts/release/promote_prebuilds.py"
)
tools = node.artifact_tools()
REVISION = "a" * 40
VERSION = "0.2.0"


def tar(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in files.items():
            entry = tarfile.TarInfo("package/" + name)
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))


class RegistryAssemblyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git = {
            "Cargo.lock": b"locked cargo\n",
            "bindings/node/package-lock.json": b"locked npm\n",
        }
        for name in (*node.SOURCES, "package.json"):
            self.git["bindings/node/" + name] = (
                (registry.ROOT / "bindings/node" / name)
                .read_bytes()
                .replace(b"\r\n", b"\n")
            )
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            self.git[name] = (registry.ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        self.source = json.loads(self.git["bindings/node/package.json"])
        self.source["version"] = VERSION
        self.git["bindings/node/package.json"] = json.dumps(self.source).encode()

    def candidate(self, target):
        directory = self.root / target
        directory.mkdir()
        payload = {name: self.git["bindings/node/" + name] for name in node.SOURCES}
        payload.update(
            {name: self.git[name] for name in ("LICENSE-MIT", "LICENSE-APACHE")}
        )
        payload["package.json"] = json.dumps(
            node.package_metadata(self.source, VERSION, target)
        ).encode()
        payload["phantom.node"] = ("never executed " + target).encode()
        payload["notices/package/LICENSE"] = b"original native license text"
        payload["notices/rust-runtime/LICENSE"] = b"original runtime notice"
        notices = [
            {
                "name": "native",
                "version": "1.0.0",
                "notices": [
                    {
                        "file": "package/LICENSE",
                        "sha256": registry.sha256(payload["notices/package/LICENSE"]),
                    }
                ],
            }
        ]
        payload["notices/inventory.json"] = json.dumps(notices).encode()
        receipt = {
            "schema": 1,
            "source_revision": REVISION,
            "version": VERSION,
            "target": target,
            "profile": "release",
            "package": node.PACKAGE,
            "cargo_lock_sha256": registry.sha256(self.git["Cargo.lock"]),
            "npm_lock_sha256": registry.sha256(
                self.git["bindings/node/package-lock.json"]
            ),
            "tested_host": {
                "system": promotion.TARGETS[target][0],
                "machine": sorted(promotion.TARGETS[target][1])[0],
            },
            "rustc": "test compiler",
            "cargo": "test cargo",
            "notices": notices,
            "native_linkage": [{"tool": "test linkage"}],
            "native_sha256": registry.sha256(payload["phantom.node"]),
            "installation_checks": [
                {
                    "runtime": {"versions": {"node": f"{major}.0.0"}},
                    "installation": {"version": VERSION},
                    "typescript": "locked compiler; CJS and ESM consumers passed",
                    "loopback_checks": {
                        "tests": 19,
                        "pass": 19,
                        "skipped": 0,
                        "fail": 0,
                        "cancelled": 0,
                        "todo": 0,
                    },
                }
                for major in (22, 24)
            ],
        }
        self.write_candidate(directory, payload, receipt)
        return directory, payload, receipt

    def write_candidate(self, directory, payload, receipt):
        filename = f"byway-phantom-{VERSION}.tgz"
        archive = directory / filename
        tar(archive, payload)
        receipt["archive_sha256"] = tools.digest(archive)
        receipt["payload_sha256"] = {
            "package/" + name: registry.sha256(raw) for name, raw in payload.items()
        }
        tools.write_json(directory / "verification.json", receipt)
        (directory / "SHA256SUMS").write_text(
            f"{tools.digest(archive)}  {filename}\n", newline="\n"
        )

    def read(self, directory):
        return registry.read_candidate(
            directory, REVISION, VERSION, self.git, node, promotion
        )

    def test_three_exact_candidates_retain_native_and_notice_bytes(self):
        for target in registry.PACKAGES:
            directory, payload, receipt = self.candidate(target)
            actual_target, actual, identity, raw = self.read(directory)
            self.assertEqual(actual_target, target)
            self.assertEqual(actual, payload)
            self.assertEqual(json.loads(raw), receipt)
            self.assertEqual(identity["archive_sha256"], receipt["archive_sha256"])

    def test_public_metadata_has_four_identities_exact_dependencies_and_host_filters(
        self,
    ):
        packages = registry.manifests(self.source, VERSION, node)
        self.assertEqual(len(packages), 4)
        self.assertEqual(
            packages[node.PACKAGE]["optionalDependencies"],
            dict.fromkeys(registry.PACKAGES.values(), VERSION),
        )
        self.assertNotIn("phantom.node", packages[node.PACKAGE]["files"])
        for target, name in registry.PACKAGES.items():
            self.assertEqual(packages[name]["os"], [node.TARGETS[target][0]])
            self.assertEqual(packages[name]["cpu"], [node.TARGETS[target][1]])
            self.assertEqual(
                packages[name].get("libc"), ["glibc"] if "linux" in target else None
            )
        for package in packages.values():
            self.assertNotIn("private", package)
            self.assertNotIn("scripts", package)
            self.assertEqual(package["publishConfig"], {"access": "public"})

    def test_wrong_source_version_target_or_incomplete_runtime_receipt_fails(self):
        directory, payload, original = self.candidate(next(iter(registry.PACKAGES)))
        for field, value in [
            ("source_revision", "b" * 40),
            ("version", "0.3.0"),
            ("target", "other"),
            ("installation_checks", []),
        ]:
            with self.subTest(field=field):
                receipt = {**original, field: value}
                self.write_candidate(directory, payload, receipt)
                with self.assertRaises(ValueError):
                    self.read(directory)

    def test_missing_extra_or_modified_files_do_not_pass_payload_identity(self):
        directory, payload, receipt = self.candidate(next(iter(registry.PACKAGES)))
        (directory / "unexpected").write_bytes(b"bad")
        with self.assertRaisesRegex(ValueError, "three verified"):
            self.read(directory)
        (directory / "unexpected").unlink()
        with (directory / f"byway-phantom-{VERSION}.tgz").open("ab") as output:
            output.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.read(directory)
        self.write_candidate(directory, payload, receipt)
        (directory / "SHA256SUMS").unlink()
        with self.assertRaisesRegex(ValueError, "three verified"):
            self.read(directory)

    def test_changed_facade_addon_or_notice_is_rejected_even_with_new_archive_hash(
        self,
    ):
        directory, original, original_receipt = self.candidate(
            next(iter(registry.PACKAGES))
        )
        for file in ("index.cjs", "phantom.node", "notices/package/LICENSE"):
            payload, receipt = copy.deepcopy(original), copy.deepcopy(original_receipt)
            payload[file] += b"changed"
            self.write_candidate(directory, payload, receipt)
            with self.subTest(file=file), self.assertRaises(ValueError):
                self.read(directory)

    def test_only_exact_windows_checkout_conversion_is_accepted(self):
        canonical = b"one\ntwo\n"
        windows = "x86_64-pc-windows-msvc"
        self.assertTrue(
            registry.source_bytes(canonical.replace(b"\n", b"\r\n"), canonical, windows)
        )
        for actual in (b"one\r\nchanged\r\n", b"one\r\r\ntwo\r\n", b"one\r\ntwo\n"):
            self.assertFalse(registry.source_bytes(actual, canonical, windows))
        self.assertFalse(
            registry.source_bytes(
                canonical.replace(b"\n", b"\r\n"), canonical, "x86_64-unknown-linux-gnu"
            )
        )

    def test_unsafe_and_duplicate_archive_members_fail_before_staging(self):
        for names in (
            ["../escape"],
            ["a", "A"],
            ["a/../escape"],
            ["a\\b"],
            ["AUX.txt"],
            ["a./b"],
        ):
            archive = self.root / "unsafe.tgz"
            tar(archive, dict.fromkeys(names, b"bad"))
            with self.subTest(names=names), self.assertRaises(ValueError):
                registry.archive_payload(archive, 1024**2)

    def test_pack_output_matches_staged_metadata_and_files(self):
        staging, packed = self.root / "staging", self.root / "packed"
        staging.mkdir()
        packed.mkdir()
        (staging / "index.cjs").write_bytes(b"not executed")
        metadata = registry.manifests(self.source, VERSION, node)[node.PACKAGE]

        def run(args, **options):
            self.assertIn("--ignore-scripts", args)
            self.assertEqual(options["env"], {"isolated": "yes"})
            filename = f"byway-phantom-{VERSION}.tgz"
            tar(packed / filename, {p.name: p.read_bytes() for p in staging.iterdir()})
            return json.dumps([{"filename": filename}]).encode()

        result = registry.pack_package(
            staging,
            packed,
            metadata,
            Path("node"),
            Path("npm"),
            SimpleNamespace(run=run),
            node,
            tools,
            {"isolated": "yes"},
        )
        self.assertEqual(result["sha256"], tools.digest(packed / result["archive"]))
        self.assertEqual(json.loads((staging / "package.json").read_text()), metadata)

    def test_assembly_rejects_duplicate_targets_without_running_npm(self):
        directory, _, _ = self.candidate(next(iter(registry.PACKAGES)))
        commands = SimpleNamespace(
            run=lambda args: (
                REVISION.encode()
                if args[:2] == ["git", "rev-parse"]
                else self.git[args[-1].split(":", 1)[1]]
            )
        )
        fake_tools = SimpleNamespace(Commands=lambda _: commands)
        fake_node = SimpleNamespace(**vars(node))
        fake_node.artifact_tools = lambda: fake_tools
        args = SimpleNamespace(
            source_revision=REVISION,
            candidate=[directory] * 3,
            output=self.root / "output",
        )
        with (
            patch.object(registry, "load_module", side_effect=[fake_node, promotion]),
            self.assertRaisesRegex(ValueError, "duplicate"),
        ):
            registry.assemble(args)
        self.assertFalse((args.output / "assembled").exists())

    def test_assembly_publishes_four_exact_payloads_only_after_every_pack_passes(self):
        self.assembly_flow(fail_pack=False)

    def test_failed_pack_keeps_evidence_without_an_assembled_result(self):
        self.assembly_flow(fail_pack=True)

    def assembly_flow(self, *, fail_pack):
        candidates = [self.candidate(target)[0] for target in registry.PACKAGES]
        npm, executable = self.root / "npm-cli.js", self.root / "node"
        npm.touch()
        executable.touch()
        git = self.git
        calls = []

        class Commands:
            def __init__(self, logs):
                logs.mkdir(parents=True)

            def run(self, args, **options):
                calls.append(args)
                if args[:2] == ["git", "rev-parse"]:
                    return REVISION.encode()
                if args[:2] == ["git", "show"]:
                    return git[args[-1].split(":", 1)[1]]
                if "pack" in args:
                    if fail_pack and sum("pack" in call for call in calls) == 3:
                        raise ValueError("controlled pack failure")
                    staging = options["cwd"]
                    package = json.loads((staging / "package.json").read_text())
                    filename = (
                        package["name"].removeprefix("@").replace("/", "-")
                        + f"-{VERSION}.tgz"
                    )
                    packed = Path(args[args.index("--pack-destination") + 1])
                    tar(
                        packed / filename,
                        {
                            path.relative_to(staging).as_posix(): path.read_bytes()
                            for path in staging.rglob("*")
                            if path.is_file()
                        },
                    )
                    return json.dumps([{"filename": filename}]).encode()
                raise AssertionError(args)

        fake_tools = SimpleNamespace(**vars(tools))
        fake_tools.Commands = Commands
        fake_node = SimpleNamespace(**vars(node))
        fake_node.artifact_tools = lambda: fake_tools
        args = SimpleNamespace(
            source_revision=REVISION,
            candidate=candidates,
            output=self.root / "output",
            node=executable,
            npm_cli=npm,
        )
        with patch.object(registry, "load_module", side_effect=[fake_node, promotion]):
            if fail_pack:
                with self.assertRaisesRegex(ValueError, "controlled pack"):
                    registry.assemble(args)
                self.assertFalse((args.output / "assembled").exists())
                self.assertTrue(list((args.output / "candidate").glob("*.tgz")))
                return
            output = registry.assemble(args)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(len(manifest["packages"]), 4)
        self.assertIn("install proof pending", manifest["validation"])
        for package in manifest["packages"]:
            archive = output / package["archive"]
            self.assertEqual(tools.digest(archive), package["sha256"])
            payload = registry.archive_payload(archive, node.MAX_ARCHIVE_BYTES)
            if package["name"] == node.PACKAGE:
                self.assertNotIn("phantom.node", payload)
            else:
                target = next(
                    key
                    for key, name in registry.PACKAGES.items()
                    if name == package["name"]
                )
                receipt = json.loads(payload["provenance.json"])
                self.assertEqual(receipt["target"], target)
                self.assertEqual(
                    registry.sha256(payload["phantom.node"]), receipt["native_sha256"]
                )
                self.assertEqual(
                    payload["notices/package/LICENSE"], b"original native license text"
                )
        self.assertEqual(sum("pack" in call for call in calls), 4)


if __name__ == "__main__":
    unittest.main()
