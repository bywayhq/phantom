import contextlib
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "cli_artifact", Path(__file__).resolve().parents[2] / "release/cli_artifact.py"
)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class CliArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_build_jobs_honors_caller_and_rejects_invalid_bounds(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(artifact.build_jobs(), "2")
        with patch.dict(os.environ, {"CARGO_BUILD_JOBS": "1"}):
            self.assertEqual(artifact.build_jobs(), "1")
        for invalid in ("0", "-1", "", "1.5", "many", "２"):
            with (
                self.subTest(value=invalid),
                patch.dict(os.environ, {"CARGO_BUILD_JOBS": invalid}),
                self.assertRaisesRegex(ValueError, "positive integer"),
            ):
                artifact.build_jobs()

    def test_actual_cargo_artifacts_select_inputs_and_require_release_success(self):
        records = [
            {"reason": "build-script-executed", "package_id": "native-build"},
            {
                "reason": "compiler-artifact",
                "package_id": "cli",
                "target": {"name": "phantom", "kind": ["bin"]},
                "profile": {"test": False, "opt_level": "3"},
                "executable": "/tmp/phantom",
            },
            {"reason": "build-finished", "success": True},
        ]

        def raw():
            return "\n".join(json.dumps(record) for record in records)

        packages, binary = artifact.build_records(raw())
        self.assertEqual(packages, {"native-build", "cli"})
        self.assertEqual(binary, Path("/tmp/phantom"))
        records[1]["profile"]["opt_level"] = "0"
        with self.assertRaisesRegex(ValueError, "release optimization"):
            artifact.build_records(raw())
        records[1]["profile"]["opt_level"] = "3"
        records[-1]["success"] = False
        with self.assertRaisesRegex(ValueError, "successful release"):
            artifact.build_records(raw())

    def test_notices_follow_built_inputs_and_retain_native_sources(self):
        (self.root / "LICENSE-MIT").write_text("project license")
        workspace = self.root / "crates/cli"
        workspace.mkdir(parents=True)
        native = self.root / "vendor/btls-sys"
        (native / "deps/boringssl/third_party/fiat").mkdir(parents=True)
        (native / "LICENSE-MIT").write_text("bindings license")
        (native / "NOTICE").write_text("native revision")
        (native / "deps/boringssl/LICENSE").write_text("native license")
        (native / "deps/boringssl/third_party/fiat/LICENSE").write_text("fiat license")
        packages = [
            {
                "id": "cli",
                "name": "phantom-cli",
                "version": "1",
                "manifest_path": str(workspace / "Cargo.toml"),
            },
            {
                "id": "native",
                "name": "phantom-btls-sys",
                "version": "2",
                "manifest_path": str(native / "Cargo.toml"),
            },
            {
                "id": "unused",
                "name": "unused",
                "version": "3",
                "manifest_path": "/absent/Cargo.toml",
            },
        ]
        destination = self.root / "notices"
        result = artifact.copy_notices(
            {"packages": packages}, {"cli", "native"}, destination, self.root
        )
        self.assertEqual(
            {entry["name"] for entry in result}, {"phantom-cli", "phantom-btls-sys"}
        )
        self.assertEqual(
            (
                destination / "phantom-btls-sys-2/boringssl/third_party/fiat/LICENSE"
            ).read_text(),
            "fiat license",
        )
        for entry in result:
            for notice in entry["notices"]:
                self.assertEqual(
                    artifact.digest(destination / notice["file"]), notice["sha256"]
                )

    def test_absent_license_or_metadata_stops_packaging(self):
        external = self.root / "external"
        external.mkdir()
        package = {"name": "unlicensed", "manifest_path": str(external / "Cargo.toml")}
        with self.assertRaisesRegex(ValueError, "no retained license"):
            artifact.package_notices(package, self.root / "checkout")
        with self.assertRaisesRegex(ValueError, "absent from Cargo metadata"):
            artifact.copy_notices({"packages": []}, {"missing"}, self.root / "notices")

    def test_alloc_stdlib_omission_has_exact_offline_license_and_provenance(self):
        checkout = self.root / "checkout"
        source = self.root / "registry/alloc-stdlib"
        source.mkdir(parents=True)
        package = {
            "id": "alloc",
            "name": "alloc-stdlib",
            "version": "0.3.0",
            "license": "BSD-3-Clause",
            "manifest_path": str(source / "Cargo.toml"),
        }
        pinned = checkout / artifact.ALLOC_STDLIB_LICENSE_PATH
        pinned.parent.mkdir(parents=True)
        pinned.write_bytes(
            (artifact.ROOT / artifact.ALLOC_STDLIB_LICENSE_PATH).read_bytes()
        )
        destination = self.root / "notices"
        result = artifact.copy_notices(
            {"packages": [package]}, {"alloc"}, destination, checkout
        )
        self.assertEqual(
            result[0]["supplementary_notice"],
            {
                "source": artifact.ALLOC_STDLIB_LICENSE_SOURCE,
                "sha256": artifact.ALLOC_STDLIB_LICENSE_SHA256,
            },
        )
        self.assertEqual(
            artifact.digest(destination / result[0]["notices"][0]["file"]),
            artifact.ALLOC_STDLIB_LICENSE_SHA256,
        )
        for key, value in (
            ("version", "0.3.1"),
            ("license", "MIT"),
            ("name", "another-crate"),
        ):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "no retained license"),
            ):
                artifact.package_notices({**package, key: value}, checkout)
        pinned.write_text("modified upstream text")
        with self.assertRaisesRegex(ValueError, "modified pinned"):
            artifact.package_notices(package, checkout)

    def test_tar_and_zip_round_trip_preserve_binary_and_notices(self):
        folder = self.root / "phantom-test"
        folder.mkdir()
        binary = folder / "phantom"
        binary.write_bytes(b"binary\0bytes")
        binary.chmod(0o755)
        (folder / "LICENSE").write_text("license")
        for extension in (".tar.gz", ".zip"):
            with self.subTest(extension=extension):
                archive = self.root / f"artifact{extension}"
                destination = self.root / extension.replace(".", "")
                artifact.create_archive(folder, archive)
                artifact.extract_archive(archive, destination)
                self.assertEqual(
                    artifact.digest(destination / "phantom-test/phantom"),
                    artifact.digest(binary),
                )
                self.assertEqual(
                    (destination / "phantom-test/LICENSE").read_text(), "license"
                )
                if extension == ".tar.gz" and os.name != "nt":
                    self.assertTrue(
                        os.access(destination / "phantom-test/phantom", os.X_OK)
                    )

    def test_archive_traversal_and_tar_links_are_rejected(self):
        for name in ("../escape", "/absolute", "C:/absolute", "..\\escape"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "unsafe archive"),
            ):
                artifact.archive_path(self.root, name)
        archive = self.root / "unsafe.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            entry = tarfile.TarInfo("phantom/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../escape"
            output.addfile(entry)
        with self.assertRaisesRegex(ValueError, "non-file entry"):
            artifact.extract_archive(archive, self.root / "tar")
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("../escape", "bad")
        with self.assertRaisesRegex(ValueError, "unsafe archive"):
            artifact.extract_archive(archive, self.root / "zip")

    def test_command_failure_and_timeout_retain_receipts(self):
        commands = artifact.Commands(self.root / "logs")
        with self.assertRaisesRegex(ValueError, "command failed"):
            commands.run(
                [sys.executable, "-c", "import sys; print('failed'); sys.exit(7)"],
                cwd=self.root,
            )
        receipts = list(commands.logs.glob("*.exit.json"))
        self.assertEqual(json.loads(receipts[0].read_text()), {"returncode": 7})
        error = subprocess.TimeoutExpired(
            ["tool"], 1, output=b"partial", stderr=b"diagnostic"
        )
        with (
            patch.object(subprocess, "run", side_effect=error),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            commands.run(["tool"], timeout=1)
        self.assertEqual((commands.logs / "02-tool.stdout").read_bytes(), b"partial")
        self.assertEqual(
            json.loads((commands.logs / "02-tool.exit.json").read_text()),
            {"timeout_seconds": 1},
        )

    def test_peer_checks_real_upload_chunked_download_and_disconnect(self):
        # Exercise the peer/oracle with a standard HTTP client. Actual CLI
        # execution is deliberately reserved for the native artifact workflow.
        import http.client

        class HttpCommands:
            def run(self, args, *, cwd, expected=0, **_options):
                if args[1:] == ["--version"]:
                    return b"phantom 1\n"
                if args[1:] == ["profiles", "list"]:
                    return artifact.PROFILE.encode() + b"\n"
                if args[1:3] == ["profiles", "export"]:
                    return b'{"custom":"profile"}'
                if args[1:3] == ["profiles", "import"]:
                    return Path(args[3]).read_bytes()
                from urllib.parse import urlsplit

                url = urlsplit(args[2])
                client = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
                try:
                    body = None
                    method = "GET"
                    if "--upload" in args:
                        body = Path(args[args.index("--upload") + 1]).read_bytes()
                        method = "PUT"
                    client.putrequest(method, url.path)
                    if body is not None:
                        client.putheader("Content-Length", str(len(body)))
                    headers = [
                        args[index + 1]
                        for index, value in enumerate(args)
                        if value == "--header"
                    ]
                    for header in headers:
                        name, value = header.split(": ", 1)
                        client.putheader(name, value)
                    client.endheaders(body)
                    response = client.getresponse()
                    if expected == 1:
                        result = response.read(1)
                        report = {
                            "events": [
                                {"phase": "response_body", "outcome": "abandoned"}
                            ]
                        }
                        Path(args[args.index("--diagnostics") + 1]).write_text(
                            json.dumps(report)
                        )
                        return result
                    result = response.read()
                    if "--output" in args:
                        Path(args[args.index("--output") + 1]).write_bytes(result)
                        return b""
                    return result
                finally:
                    client.close()

        checks = artifact.smoke(self.root / "phantom", self.root, HttpCommands(), "1")
        self.assertIn("deadline-cancellation-disconnect", checks)
        self.assertEqual(
            (self.root / "upload.bin").read_bytes(),
            (self.root / "download.bin").read_bytes(),
        )

    def test_peer_propagates_failed_wire_assertions(self):
        def reject(stream, _head):
            stream.sendall(b"rejected")
            raise ValueError("wire mismatch")

        with (
            self.assertRaisesRegex(ValueError, "wire mismatch"),
            artifact.peer(reject) as url,
        ):
            port = int(url.split(":")[2].split("/")[0])
            with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                stream.sendall(b"GET / HTTP/1.1\r\n\r\n")
                self.assertEqual(stream.recv(8), b"rejected")

    def test_host_mismatch_cannot_be_labelled_as_another_target(self):
        with (
            patch.object(artifact.platform, "system", return_value="Linux"),
            self.assertRaisesRegex(ValueError, "target must match"),
        ):
            artifact.host_identity(
                "x86_64-pc-windows-msvc", "host: x86_64-pc-windows-msvc"
            )

    def test_only_completed_installation_with_unchanged_source_is_promoted(self):
        package = self.root / "package"
        package.mkdir()
        (package / "LICENSE").write_text("dependency license")
        for name in ("LICENSE-MIT", "LICENSE-APACHE", "Cargo.lock"):
            (self.root / name).write_text(name)
        binary = self.root / "phantom.exe"
        binary.write_bytes(b"fake executable for packaging orchestration test")
        docs = self.root / "sysroot/share/doc/rust"
        (docs / "licenses").mkdir(parents=True)
        (docs / "COPYRIGHT-library.html").write_text("runtime copyrights")
        (docs / "licenses/MIT.txt").write_text("runtime license")
        (docs / "licenses/Apache-2.0.txt").write_text("runtime Apache license")
        metadata = {
            "packages": [
                {
                    "id": "cli",
                    "name": "phantom-cli",
                    "version": "1",
                    "manifest_path": str(package / "Cargo.toml"),
                }
            ]
        }
        built = "\n".join(
            json.dumps(record)
            for record in [
                {
                    "reason": "compiler-artifact",
                    "package_id": "cli",
                    "target": {"name": "phantom", "kind": ["bin"]},
                    "profile": {"test": False, "opt_level": "3"},
                    "executable": str(binary),
                },
                {"reason": "build-finished", "success": True},
            ]
        ).encode()
        for outcome in ("smoke-failed", "source-changed", "success"):
            with self.subTest(outcome=outcome):
                statuses = iter(
                    [b"", b" M source"] if outcome == "source-changed" else [b"", b""]
                )

                def run(args, statuses=statuses, **_options):
                    key = tuple(args[:2])
                    if key == ("git", "status"):
                        return next(statuses)
                    return {
                        ("git", "rev-parse"): b"0123456789abcdef",
                        ("rustc", "-vV"): b"host: x86_64-pc-windows-msvc",
                        ("cargo", "-V"): b"cargo test-version",
                        ("cargo", "metadata"): json.dumps(metadata).encode(),
                        ("cargo", "build"): built,
                        ("rustc", "--print"): str(self.root / "sysroot").encode(),
                    }[key]

                output = self.root / outcome
                with (
                    patch.object(artifact, "ROOT", self.root),
                    patch.object(artifact.Commands, "run", side_effect=run),
                    patch.object(
                        artifact,
                        "host_identity",
                        return_value={"runtime": "test fixture"},
                    ),
                    patch.object(artifact, "dependency_inspection", return_value=[]),
                    patch.object(
                        artifact,
                        "smoke",
                        side_effect=ValueError("smoke failed")
                        if outcome == "smoke-failed"
                        else None,
                        return_value=["test-fixture"],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    args = SimpleNamespace(
                        output=output, target="x86_64-pc-windows-msvc"
                    )
                    if outcome == "success":
                        artifact.verify(args)
                        receipt = json.loads(
                            (output / "verified/verification.json").read_text()
                        )
                        self.assertEqual(
                            receipt["sha256"],
                            artifact.digest(output / "verified" / receipt["archive"]),
                        )
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "smoke failed|identity changed"
                        ):
                            artifact.verify(args)
                        self.assertFalse((output / "verified").exists())


if __name__ == "__main__":
    unittest.main()
