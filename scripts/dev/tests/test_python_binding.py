import contextlib
import csv
import importlib.util
import io
import json
import os
import shutil
import stat
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

    def test_notice_rewrite_preserves_original_and_installable_payload_record(self):
        original = self.wheel()
        before = original.read_bytes()
        notices = self.directory / "notices"
        (notices / "crate-1.0").mkdir(parents=True)
        (notices / "crate-1.0/LICENSE").write_bytes(b"offline dependency license\n")
        (notices / "inventory.json").write_bytes(b"{}\n")
        candidate = self.directory / "candidate" / original.name
        candidate.parent.mkdir()
        binding.add_notices(original, candidate, notices, DIST)
        binding.inspect_wheel(candidate, TARGET, "0.2.0")
        self.assertEqual(original.read_bytes(), before)
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(candidate) as output:
            for name in (
                "phantom_http/__init__.py",
                "phantom_http/_native.pyd",
                "phantom_http/py.typed",
                "phantom_http/_native.pyi",
            ):
                self.assertEqual(source.read(name), output.read(name))
            metadata = output.read(f"{DIST}/METADATA")
            self.assertIn(b"License-File: third-party/crate-1.0/LICENSE", metadata)
            installed = self.directory / "isolated-site-packages"
            output.extractall(installed)
        self.assertEqual(
            (installed / "phantom_http/_native.pyd").read_bytes(),
            b"retained native bytes",
        )
        self.assertEqual(
            (installed / DIST / "licenses/third-party/crate-1.0/LICENSE").read_bytes(),
            b"offline dependency license\n",
        )

    def test_notice_collision_leaves_the_original_wheel_unchanged(self):
        original = self.wheel()
        notices = self.directory / "notices"
        notices.mkdir()
        (notices / "LICENSE").write_text("notice")
        first = self.directory / "first.whl"
        binding.add_notices(original, first, notices, DIST)
        before = first.read_bytes()
        with self.assertRaisesRegex(ValueError, "conflicts"):
            binding.add_notices(first, self.directory / "second.whl", notices, DIST)
        self.assertEqual(first.read_bytes(), before)

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
                ],
            ):
                binding.main()
            candidate.assert_called_once_with(TARGET, self.directory / "out")
            with (
                patch("sys.argv", ["check_python_binding.py", "--target", TARGET]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                binding.main()

    def test_failed_install_control_retains_candidates_without_promoting_them(self):
        original = self.wheel()
        output = self.directory / "output"

        class Commands:
            def __init__(self, logs):
                logs.mkdir(parents=True)

            def run(self, args, **_):
                if args[:2] == ["git", "status"]:
                    return b""
                if args[:2] == ["git", "rev-parse"]:
                    return b"fixed-source"
                if args[0] == "rustc":
                    return str(self_directory).encode()
                if args[:2] == ["cargo", "metadata"]:
                    return b"{}"
                if "build" in args:
                    wheels = Path(args[args.index("--out") + 1])
                    wheels.mkdir()
                    shutil.copyfile(original, wheels / original.name)
                return b"test-toolchain"

        self_directory = self.directory

        def notices(_metadata, _ids, directory):
            directory.mkdir()
            (directory / "LICENSE").write_text("dependency notice")
            return []

        tools = SimpleNamespace(
            Commands=Commands,
            digest=lambda path: binding.hashlib.sha256(path.read_bytes()).hexdigest(),
            host_identity=lambda *_: {},
            build_jobs=lambda: "1",
            copy_notices=notices,
            copy_rust_notices=lambda _sysroot, destination: destination.mkdir(),
            dependency_inspection=lambda *_: [],
            write_json=lambda path, value: path.write_text(json.dumps(value)),
        )
        with (
            patch.object(binding, "artifact_tools", return_value=tools),
            patch.object(
                binding,
                "dependency_closure",
                return_value=({"version": "0.2.0"}, set()),
            ),
            patch.object(
                binding.venv.EnvBuilder, "create", lambda _, path: path.mkdir()
            ),
            patch.object(
                binding,
                "installed_checks",
                side_effect=ValueError("loopback control failed"),
            ),
            patch.dict(os.environ, {}, clear=True),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(ValueError, "loopback control failed"),
        ):
            binding.verify_candidate(TARGET, output)
        self.assertFalse((output / "verified").exists())
        self.assertEqual(
            (output / "original" / original.name).read_bytes(), original.read_bytes()
        )
        binding.inspect_wheel(output / "candidate" / original.name, TARGET, "0.2.0")


if __name__ == "__main__":
    unittest.main()
