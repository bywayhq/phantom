import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli

OUTPUT_NAMES = (
    "OUTPUT",
    "COMPONENT_OUTPUT",
    "HTTP2_COMPONENT_OUTPUT",
    "TLS_COMPONENT_OUTPUT",
    "QUIC_COMPONENT_OUTPUT",
    "HTTP1_COMPONENT_OUTPUT",
    "DNS_COMPONENT_OUTPUT",
    "UDP_COMPONENT_OUTPUT",
    "TCP_COMPONENT_OUTPUT",
    "COOKIE_COMPONENT_OUTPUT",
    "PROXY_CONNECT_COMPONENT_OUTPUT",
    "CLIENT_HINTS_COMPONENT_OUTPUT",
)


class CatalogCliTests(unittest.TestCase):
    def expected_outputs(self):
        return {name: getattr(cli, name).read_text() for name in OUTPUT_NAMES}

    def test_absolute_cli_works_outside_the_repository_without_changing_outputs(self):
        outputs = [getattr(cli, name) for name in OUTPUT_NAMES]
        before = {path: hashlib.sha256(path.read_bytes()).digest() for path in outputs}
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli.REPO / "scripts/dev/generate_profiles.py"),
                    "--check",
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            {path: hashlib.sha256(path.read_bytes()).digest() for path in outputs},
            before,
        )

    def test_check_detects_each_stale_output_without_writing_any_output(self):
        expected = self.expected_outputs()
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / f"{name}.rs" for name in OUTPUT_NAMES}
            for stale in OUTPUT_NAMES:
                with self.subTest(stale=stale):
                    for name, path in paths.items():
                        path.write_text("stale" if name == stale else expected[name])
                    before = {name: path.read_bytes() for name, path in paths.items()}
                    with (
                        mock.patch.multiple(cli, **paths),
                        mock.patch.object(
                            sys, "argv", ["generate_profiles.py", "--check"]
                        ),
                        mock.patch.object(cli.sys, "stderr"),
                    ):
                        self.assertEqual(cli.main(), 1)
                    self.assertEqual(
                        {name: path.read_bytes() for name, path in paths.items()},
                        before,
                    )

    def test_invalid_last_declaration_preserves_outputs_and_missing_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {name: root / f"{name}.rs" for name in OUTPUT_NAMES}
            for path in paths.values():
                path.write_bytes(b"retained original\r\n")
            missing = root / "not-created"
            paths["CLIENT_HINTS_COMPONENT_OUTPUT"] = missing / "client_hints.rs"
            with (
                mock.patch.multiple(cli, **paths),
                mock.patch.object(sys, "argv", ["generate_profiles.py"]),
                mock.patch.object(cli.sys, "stderr"),
                mock.patch.object(
                    cli,
                    "load_client_hints_components",
                    side_effect=cli.DeclarationError("invalid client hints"),
                ),
            ):
                self.assertEqual(cli.main(), 1)
            self.assertFalse(missing.exists())
            for name, path in paths.items():
                if name != "CLIENT_HINTS_COMPONENT_OUTPUT":
                    self.assertEqual(path.read_bytes(), b"retained original\r\n")


if __name__ == "__main__":
    unittest.main()
