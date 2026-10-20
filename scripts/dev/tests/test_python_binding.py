import contextlib
import csv
import importlib.util
import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "python_binding", Path(__file__).resolve().parents[1] / "check_python_binding.py"
)
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)

DIST = "phantom_http-0.2.0.dist-info"
TARGET = "x86_64-pc-windows-msvc"


class PythonWheelTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def wheel(self, *, tag="win_amd64", extension="_native.pyd", change=None):
        path = self.directory / f"phantom_http-0.2.0-cp310-abi3-{tag}.whl"
        files = {
            f"{DIST}/METADATA": (
                b"Metadata-Version: 2.4\nName: phantom-http\nVersion: 0.2.0\n"
                b"Requires-Python: >=3.10\nLicense-Expression: MIT OR Apache-2.0\n"
                b"License-File: LICENSE-MIT\nLicense-File: LICENSE-APACHE\n\n"
            ),
            f"{DIST}/WHEEL": (
                f"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp310-abi3-{tag}\n\n"
            ).encode(),
            "phantom_http/__init__.py": b"# preserved Python facade\n",
            "phantom_http/py.typed": b"",
            "phantom_http/_native.pyi": b"class NativeResponse: ...\n",
            f"phantom_http/{extension}": b"retained native bytes",
        }
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            files[f"{DIST}/licenses/{name}"] = (
                binding.ROOT / "bindings/python" / name
            ).read_bytes()
        if change:
            change(files)
        rows = [binding.record_row(name, data) for name, data in files.items()]
        record = f"{DIST}/RECORD"
        rows.append([record, "", ""])
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(rows)
        files[record] = output.getvalue().encode()
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return path

    def source_archive(self, *, change=None):
        revision = "a" * 40
        lock = b"source closure lock\n"
        notice = b"dependency license\n"
        inventory = [
            {
                "name": "dependency",
                "notices": [
                    {
                        "file": "dependency/LICENSE",
                        "sha256": binding.hashlib.sha256(notice).hexdigest(),
                    }
                ],
            }
        ]
        files = {
            "Cargo.lock": lock,
            "third-party-notices/dependency/LICENSE": notice,
            "third-party-notices/rust-runtime/COPYRIGHT": b"Rust runtime notices\n",
            "third-party-notices/inventory.json": json.dumps(inventory).encode(),
        }
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            files[name] = (binding.ROOT / "bindings/python" / name).read_bytes()
        license_paths = sorted(name for name in files if name != "Cargo.lock")
        files["PKG-INFO"] = (
            "Metadata-Version: 2.4\nName: phantom-http\nVersion: 0.2.0\n"
            + "".join(f"License-File: {name}\n" for name in license_paths)
            + "\n"
        ).encode()
        if change:
            change(files)
        archive = self.directory / "phantom_http-0.2.0.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in files.items():
                member = tarfile.TarInfo("phantom_http-0.2.0/" + name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        receipt = {
            "source_revision": revision,
            "maturin": binding.MATURIN,
            "archive_sha256": binding.hashlib.sha256(archive.read_bytes()).hexdigest(),
            "cargo_lock_sha256": binding.hashlib.sha256(lock).hexdigest(),
            "original_cargo_lock_sha256": binding.hashlib.sha256(
                b"original workspace lock\n"
            ).hexdigest(),
            "source_builder_toolchain": "1.99.1",
            "notices": inventory,
        }
        receipt_path = self.directory / "receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        return archive, receipt_path, receipt, files

    def source_wheel(self, files, **kwargs):
        def change(payload):
            for name, data in files.items():
                if name.startswith("third-party-notices/"):
                    payload[f"{DIST}/licenses/{name}"] = data
                    payload[f"{DIST}/METADATA"] += f"License-File: {name}\n".encode()
            # Add fields before the metadata/body separator.
            payload[f"{DIST}/METADATA"] = payload[f"{DIST}/METADATA"].replace(
                b"\n\nLicense-File:", b"\nLicense-File:"
            )

        return self.wheel(change=change, **kwargs)

    def test_source_receipt_binds_original_and_closure_locks_and_notice_payload(self):
        archive, path, receipt, files = self.source_archive()
        checked = binding.inspect_source(
            archive,
            path,
            receipt["source_revision"],
            receipt["original_cargo_lock_sha256"],
        )
        wheel = self.source_wheel(files)
        binding.inspect_wheel(wheel, TARGET, "0.2.0")
        binding.inspect_source_notices(wheel, DIST, checked)
        for field in (
            "archive_sha256",
            "cargo_lock_sha256",
            "original_cargo_lock_sha256",
            "source_revision",
            "maturin",
        ):
            invalid = dict(receipt, **{field: "wrong"})
            path.write_text(json.dumps(invalid))
            with self.subTest(field=field), self.assertRaises(ValueError):
                binding.inspect_source(
                    archive,
                    path,
                    receipt["source_revision"],
                    receipt["original_cargo_lock_sha256"],
                )
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "license payload"):
            binding.inspect_source_notices(self.wheel(), DIST, checked)
        with self.assertRaisesRegex(ValueError, "inventory"):
            archive, path, receipt, _ = self.source_archive(
                change=lambda f: f.update(
                    {"third-party-notices/dependency/LICENSE": b"changed"}
                )
            )
            binding.inspect_source(
                archive,
                path,
                receipt["source_revision"],
                receipt["original_cargo_lock_sha256"],
            )

    def test_source_candidate_uses_only_isolated_locked_pep517_archive_and_never_rewrites_notices(
        self,
    ):
        archive, receipt_path, receipt, files = self.source_archive()
        original = self.source_wheel(files)
        directory = self.directory
        calls = []

        class Commands:
            def __init__(self, logs):
                logs.mkdir(parents=True)

            def run(self, args, **kwargs):
                calls.append((args, kwargs))
                if args[:2] == ["git", "status"]:
                    return b""
                if args[:2] == ["git", "rev-parse"]:
                    return receipt["source_revision"].encode()
                if args[:2] == ["git", "show"]:
                    return b"original workspace lock\n"
                if args == ["rustc", "-vV"]:
                    return b"release: 1.99.1"
                if "wheel" in args:
                    self_test.assertNotIn("--no-build-isolation", args)
                    self_test.assertEqual(args[-1], str(archive.resolve()))
                    settings = next(
                        a for a in args if a.startswith("--config-settings=")
                    )
                    self_test.assertIn("--locked", settings)
                    self_test.assertIn("--profile release", settings)
                    self_test.assertNotIn("--release", settings)
                    self_test.assertIn("profile.release.opt-level=3", settings)
                    self_test.assertFalse(kwargs["cwd"].is_relative_to(binding.ROOT))
                    self_test.assertEqual(
                        kwargs["env"]["CARGO_TARGET_DIR"], str(kwargs["cwd"] / "target")
                    )
                    wheels = Path(args[args.index("--wheel-dir") + 1])
                    wheels.mkdir()
                    shutil.copyfile(original, wheels / original.name)
                self_test.assertFalse(args[:2] == ["cargo", "metadata"])
                return b"test-toolchain"

        self_test = self
        real_tools = binding.artifact_tools()
        tools = SimpleNamespace(
            Commands=Commands,
            digest=real_tools.digest,
            host_identity=lambda *_: {},
            build_jobs=lambda: "1",
            dependency_inspection=lambda *_: [],
            write_json=real_tools.write_json,
        )
        installed = {
            "installation": {"version": "0.2.0"},
            "loopback_checks": {"tests": 18, "skipped": 0},
        }
        with (
            patch.object(binding, "artifact_tools", return_value=tools),
            patch.object(
                binding.venv.EnvBuilder, "create", lambda _, path: path.mkdir()
            ),
            patch.object(
                binding, "installed_checks", return_value=installed
            ) as install,
            patch.dict(os.environ, {}, clear=True),
        ):
            output = directory / "candidate-proof"
            binding.verify_candidate(
                TARGET, output, archive, receipt_path, Path("stable-python")
            )
            self.assertEqual(install.call_count, 2)
            result = json.loads((output / "verified/verification.json").read_text())
            self.assertEqual(result["source_distribution"], receipt)
            self.assertEqual(
                (output / "verified" / original.name).read_bytes(),
                original.read_bytes(),
            )
            with (
                patch.object(
                    binding,
                    "installed_checks",
                    side_effect=ValueError("installed failure"),
                ),
                self.assertRaisesRegex(ValueError, "installed failure"),
            ):
                binding.verify_candidate(
                    TARGET, directory / "failed-source", archive, receipt_path
                )
            self.assertFalse((directory / "failed-source/verified").exists())

    def test_current_stable_installation_is_explicitly_limited_without_a_typing_build(
        self,
    ):
        for additional in (None, Path("stable-python")):
            calls = []

            class Commands:
                def run(self, args, *, cwd, calls=calls, **_):
                    calls.append(args)
                    environment = cwd / "environment"
                    if "venv" in args:
                        environment.mkdir()
                    if "-c" in args:
                        if "importlib.metadata" in args[-1]:
                            return json.dumps(
                                {
                                    "version": "0.2.0",
                                    "package": str(
                                        environment / "phantom_http/__init__.py"
                                    ),
                                    "extension": str(
                                        environment / "phantom_http/_native.pyd"
                                    ),
                                }
                            ).encode()
                        return b'{"tests":18,"skipped":0}'
                    return b""

            with (
                self.subTest(additional=additional),
                patch.object(
                    binding.venv.EnvBuilder, "create", lambda _, path: path.mkdir()
                ),
            ):
                checked = binding.installed_checks(self.wheel(), Commands(), additional)
            if additional is None:
                self.assertTrue(any("mypy==1.19.1" in args for args in calls))
                self.assertEqual(checked["coverage"], "full installed suite and typing")
            else:
                self.assertFalse(
                    any(any("mypy" in arg for arg in args) for args in calls)
                )
                self.assertIn("no typing", checked["coverage"])
                self.assertTrue(
                    any("pattern='test_client.py'" in args[-1] for args in calls)
                )
            install = next(args for args in calls if "--no-index" in args)
            self.assertIn("--no-cache-dir", install)
            self.assertIn("--no-deps", install)

    def test_source_assembly_requires_three_exact_installed_consumers(self):
        archive, path, receipt, files = self.source_archive()
        consumers = []
        for target, tag, extension in (
            ("x86_64-unknown-linux-gnu", "manylinux_2_28_x86_64", "_native.abi3.so"),
            (TARGET, "win_amd64", "_native.pyd"),
            ("aarch64-apple-darwin", "macosx_11_0_arm64", "_native.abi3.so"),
        ):
            directory = self.directory / target
            directory.mkdir()
            wheel = self.source_wheel(files, tag=tag, extension=extension)
            shutil.copyfile(wheel, directory / wheel.name)
            (directory / "verification.json").write_text(
                json.dumps(
                    {
                        "target": target,
                        "source_distribution": receipt,
                        "wheel_sha256": binding.hashlib.sha256(
                            wheel.read_bytes()
                        ).hexdigest(),
                        "loopback_checks": {"tests": 18, "skipped": 0},
                        "additional_installations": [
                            {"loopback_checks": {"tests": 18, "skipped": 0}}
                        ],
                    }
                )
            )
            consumers.append(directory)
        for invalid in (consumers[:2], [consumers[0], consumers[0], consumers[2]]):
            with self.assertRaises(ValueError):
                binding.assemble_candidates(
                    self.directory, invalid, self.directory / "rejected"
                )
            self.assertFalse((self.directory / "rejected").exists())
        binding.assemble_candidates(self.directory, consumers, self.directory / "ready")
        self.assertEqual(len(list((self.directory / "ready").glob("*.whl"))), 3)
        self.assertEqual(
            (self.directory / "ready" / archive.name).read_bytes(), archive.read_bytes()
        )

    def test_explicit_host_platform_tags_and_abi_are_checked(self):
        for target, tag, extension in (
            (TARGET, "win_amd64", "_native.pyd"),
            ("x86_64-unknown-linux-gnu", "linux_x86_64", "_native.abi3.so"),
            ("aarch64-apple-darwin", "macosx_11_0_arm64", "_native.abi3.so"),
        ):
            with self.subTest(target=target):
                wheel = self.wheel(tag=tag, extension=extension)
                checked = binding.inspect_wheel(wheel, target, "0.2.0")
                self.assertEqual(checked["tags"], [f"cp310-abi3-{tag}"])
                self.assertEqual(checked["native"], f"phantom_http/{extension}")
                with self.assertRaisesRegex(ValueError, "platform tag"):
                    binding.inspect_wheel(wheel, "unsupported-target", "0.2.0")
        wheel = self.wheel(tag="manylinux_2_17_x86_64", extension="_native.abi3.so")
        with self.assertRaisesRegex(ValueError, "platform tag"):
            binding.inspect_wheel(wheel, "x86_64-unknown-linux-gnu", "0.2.0")

    def test_project_metadata_license_and_native_payload_must_match(self):
        def wrong_metadata(files):
            files[f"{DIST}/METADATA"] = files[f"{DIST}/METADATA"].replace(
                b">=3.10", b">=3.9"
            )

        cases = (
            (wrong_metadata, "package metadata"),
            (
                lambda files: files.pop(f"{DIST}/licenses/LICENSE-MIT"),
                "project license",
            ),
            (
                lambda files: files.pop("phantom_http/_native.pyd"),
                "native Python extension",
            ),
        )
        for change, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                binding.inspect_wheel(self.wheel(change=change), TARGET, "0.2.0")

    def test_license_declarations_and_contents_are_both_verified(self):
        def change(files):
            files[f"{DIST}/licenses/LICENSE-MIT"] = b"different license text"

        with self.assertRaisesRegex(ValueError, "changed project license"):
            binding.inspect_wheel(self.wheel(change=change), TARGET, "0.2.0")

        def omitted(files):
            files[f"{DIST}/METADATA"] = files[f"{DIST}/METADATA"].replace(
                b"License-File: LICENSE-MIT\n", b""
            )

        with self.assertRaisesRegex(ValueError, "license metadata"):
            binding.inspect_wheel(self.wheel(change=omitted), TARGET, "0.2.0")

    def test_installed_typing_payload_is_required(self):
        for name in ("py.typed", "_native.pyi"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "missing wheel payload"),
            ):
                binding.inspect_wheel(
                    self.wheel(
                        change=lambda files, name=name: files.pop(
                            f"phantom_http/{name}"
                        )
                    ),
                    TARGET,
                    "0.2.0",
                )

    def test_record_hashes_sizes_duplicates_and_coverage_are_enforced(self):
        for mutation in ("hash", "missing", "duplicate"):
            wheel = self.wheel()
            with zipfile.ZipFile(wheel) as source:
                files = {
                    info.filename: source.read(info.filename)
                    for info in source.infolist()
                }
            record = f"{DIST}/RECORD"
            rows = list(csv.reader(io.StringIO(files[record].decode())))
            if mutation == "hash":
                rows[0][1] = "sha256=wrong"
            elif mutation == "missing":
                rows.pop(0)
            else:
                rows.append(rows[0])
            output = io.StringIO(newline="")
            csv.writer(output).writerows(rows)
            files[record] = output.getvalue().encode()
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ValueError, "RECORD"),
            ):
                binding.inspect_wheel(wheel, TARGET, "0.2.0")

    def test_unsafe_duplicate_case_alias_and_symlink_paths_are_rejected(self):
        for names in (
            ("../outside",),
            ("/absolute",),
            ("a\\b",),
            ("C:/file",),
            ("a/./b",),
            ("a", "a"),
            ("a", "A"),
            ("symlink",),
        ):
            path = self.directory / "invalid.zip"
            with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for name in names:
                    info = zipfile.ZipInfo(name)
                    info.filename = name  # Preserve raw backslashes on Windows.
                    if name == "symlink":
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, b"payload")
            with (
                zipfile.ZipFile(path) as archive,
                self.subTest(names=names),
                self.assertRaises(ValueError),
            ):
                binding.wheel_files(archive)

    def test_uncompressed_payload_bound_precedes_reading(self):
        wheel = self.wheel()
        with (
            patch.object(binding, "MAX_WHEEL_BYTES", 1),
            zipfile.ZipFile(wheel) as archive,
            self.assertRaisesRegex(ValueError, "bounds"),
        ):
            binding.wheel_files(archive)

    def test_conservative_dependency_closure_excludes_dev_edges_and_handles_cycles(
        self,
    ):
        def dep(package, *kinds):
            return {"pkg": package, "dep_kinds": [{"kind": kind} for kind in kinds]}

        metadata = {
            "packages": [{"id": "root", "name": "phantom-python"}],
            "resolve": {
                "nodes": [
                    {
                        "id": "root",
                        "deps": [
                            dep("normal", None),
                            dep("tool", "build"),
                            dep("dev", "dev"),
                        ],
                    },
                    {
                        "id": "normal",
                        "deps": [dep("root", None), dep("mixed", "dev", "build")],
                    },
                    {"id": "tool", "deps": []},
                    {"id": "mixed", "deps": []},
                ]
            },
        }
        package, selected = binding.dependency_closure(metadata)
        self.assertEqual(package["id"], "root")
        self.assertEqual(selected, {"root", "normal", "tool", "mixed"})

    def test_default_gate_and_explicit_candidate_are_separate_commands(self):
        with (
            patch.object(binding, "check_development") as development,
            patch.object(binding, "verify_candidate") as candidate,
        ):
            with patch("sys.argv", ["check_python_binding.py"]):
                binding.main()
            development.assert_called_once()
            candidate.assert_not_called()
            with patch(
                "sys.argv",
                [
                    "check_python_binding.py",
                    "--release-candidate",
                    "--target",
                    TARGET,
                    "--output",
                    str(self.directory / "out"),
                    "--source-archive",
                    str(self.directory / "source.tar.gz"),
                    "--source-receipt",
                    str(self.directory / "receipt.json"),
                ],
            ):
                binding.main()
            candidate.assert_called_once_with(
                TARGET,
                self.directory / "out",
                self.directory / "source.tar.gz",
                self.directory / "receipt.json",
                None,
            )
            with (
                patch("sys.argv", ["check_python_binding.py", "--target", TARGET]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                binding.main()


if __name__ == "__main__":
    unittest.main()
