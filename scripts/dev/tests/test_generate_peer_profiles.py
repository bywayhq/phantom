import copy
import hashlib
import json
import unittest

from scripts.dev.profile_catalog import cli, registry


class PeerCatalogTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(cli.RECORDS.read_text(encoding="utf-8"))
        self.peer = next(
            entry
            for entry in self.document["profiles"]
            if entry["metadata"]["identity"].get("project") == "curl-impersonate"
        )

    def test_peer_uses_one_pinned_identity_without_browser_capture_metadata(self):
        profiles = cli.validate(self.document)
        self.assertEqual(self.peer["id"], "safari/26.0.1/macos/r1")
        self.assertEqual(self.peer["selector"], "safari-26-macos")
        self.assertEqual(self.peer["target"], "SafariMacos26")
        self.assertEqual(
            self.peer["metadata"]["identity"],
            {
                "kind": "Peer",
                "project": "curl-impersonate",
                "source_revision": "6e8f87760a4dd96771e96fc9d55440dcd8845243",
                "recipe": "safari2601",
                "release": "26.0.1",
            },
        )
        self.assertNotIn("mod safari", registry.generate_constructors(profiles))
        self.assertIn("ProfileIdentity::Peer", registry.generate(profiles))
        supplied = {layer["layer"] for layer in self.peer["layers"]}
        self.assertEqual(supplied, {"TcpTls", "Http2"})
        self.assertEqual(
            self.peer["templates"], {"Navigation": "safari_2601_navigation"}
        )
        self.assertEqual(
            {
                layer
                for layer, component in self.peer["composition"].items()
                if component
            },
            {"TcpTls", "Http2"},
        )
        observed = [
            p for p in profiles if p["metadata"]["identity"]["kind"] == "Observed"
        ]
        self.assertEqual(len(observed), 16)

    def test_adopted_recipe_name_depends_on_browser_not_source_project(self):
        metadata = copy.deepcopy(self.peer["metadata"])
        metadata["identity"]["project"] = "another-client"
        metadata["identity"]["recipe"] = "another-preset"
        registry.validate_identity(metadata, "safari/26.0.1/macos/r1", "SafariMacos26")

        for field, value, identifier, target in (
            ("browser", "Chrome", "chrome/26.0.1/macos/r1", "ChromeMacos26"),
            ("platform", "Ios", "safari/26.0.1/ios/r1", "SafariIos26"),
        ):
            variant = copy.deepcopy(metadata)
            variant[field] = value
            with self.subTest(field=field):
                registry.validate_identity(variant, identifier, target)
                with self.assertRaisesRegex(cli.DeclarationError, "recipe target"):
                    registry.validate_identity(variant, identifier, "SafariMacos26")

    def test_peer_identity_cannot_add_observed_build_environment_or_architecture(self):
        for field, value in (
            ("build", "26.0.1"),
            ("environment", "Desktop"),
            ("architecture", "arm64"),
            ("platform_release", "macos-26"),
        ):
            document = copy.deepcopy(self.document)
            peer = next(p for p in document["profiles"] if p["id"] == self.peer["id"])
            peer["metadata"]["identity"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(cli.DeclarationError, "peer identity"),
            ):
                cli.validate(document)

    def test_peer_requires_valid_commit_and_preset_and_matching_id_target(self):
        for field, value in (
            ("source_revision", "main"),
            ("source_revision", "A" * 40),
            ("project", "curl/impersonate"),
            ("recipe", "safari;exit"),
            ("release", "latest"),
        ):
            document = copy.deepcopy(self.document)
            peer = next(p for p in document["profiles"] if p["id"] == self.peer["id"])
            peer["metadata"]["identity"][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(cli.DeclarationError),
            ):
                cli.validate(document)
        for field, value in (
            ("id", "peer/curl-impersonate/safari2601/r1"),
            ("target", "PeerCurlImpersonateSafari2601"),
        ):
            document = copy.deepcopy(self.document)
            peer = next(p for p in document["profiles"] if p["id"] == self.peer["id"])
            peer[field] = value
            with self.subTest(field=field), self.assertRaises(cli.DeclarationError):
                cli.validate(document)

    def test_peer_sources_must_pin_commit_and_cannot_be_relabelled_browser_evidence(
        self,
    ):
        for kind, location in (
            (
                "ExternalSource",
                "https://github.com/lexiforest/curl-impersonate/blob/main/patches/curl.patch",
            ),
            ("ExternalSource", "Cargo.toml"),
            ("Source", "https://example.com/browser"),
            ("Capture", self.peer["layers"][0]["references"][1]["location"]),
        ):
            document = copy.deepcopy(self.document)
            peer = next(p for p in document["profiles"] if p["id"] == self.peer["id"])
            peer["layers"][0]["references"] = [
                {"kind": kind, "location": location, "build": "2.2.3"}
            ]
            with (
                self.subTest(kind=kind, location=location),
                self.assertRaises(cli.DeclarationError),
            ):
                cli.validate(document)

    def test_peer_capture_has_its_own_client_version_and_exact_source_identity(self):
        for field, value in (("build", "26.0.1"), ("location", "Cargo.toml")):
            document = copy.deepcopy(self.document)
            peer = next(p for p in document["profiles"] if p["id"] == self.peer["id"])
            peer["layers"][0]["references"][1][field] = value
            with self.subTest(field=field), self.assertRaises(cli.DeclarationError):
                cli.validate(document)
        identity = copy.deepcopy(self.peer["metadata"]["identity"])
        identity["source_revision"] = "0" * 40
        path = cli.REPO / self.peer["layers"][0]["references"][1]["location"]
        with self.assertRaisesRegex(cli.DeclarationError, "source_revision disagrees"):
            registry.validate_peer_capture(path, identity)
        self.peer["layers"][0]["references"] = [self.peer["layers"][0]["references"][0]]
        with self.assertRaisesRegex(cli.DeclarationError, "capture evidence"):
            cli.validate(self.document)

    def test_retained_raw_observations_and_source_notices_match_recorded_hashes(self):
        directory = (
            cli.REPO / self.peer["layers"][0]["references"][1]["location"]
        ).parent
        hashes = json.loads((directory / "sha256.json").read_text(encoding="utf-8"))
        self.assertEqual(
            set(hashes),
            {
                path.relative_to(directory).as_posix()
                for path in directory.rglob("*")
                if path.is_file() and path.name != "sha256.json"
            },
        )
        for name, expected in hashes.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((directory / name).read_bytes()).hexdigest(),
                    expected,
                )
        license_text = (directory / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        self.assertIn("curl_cffi", license_text)


if __name__ == "__main__":
    unittest.main()
