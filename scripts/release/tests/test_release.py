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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).parents[1] / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load("verify_packages", "verify-packages.py")
publish = load("publish_packages", "publish.py")


class ReleaseChecks(unittest.TestCase):
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

    def test_native_package_is_first_and_dependency_cycle_is_absent(self):
        plan = publish.plan()
        self.assertEqual(plan[0][0], "phantom-btls-sys")
        self.assertEqual(plan[-1][0], "phantom-http")
        self.assertEqual(len({entry[0] for entry in plan}), 17)
        import tomllib

        core = tomllib.loads((publish.ROOT / "vendor/h3/h3/Cargo.toml").read_text())
        self.assertNotIn("version", core["dev-dependencies"]["h3-datagram"])

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
