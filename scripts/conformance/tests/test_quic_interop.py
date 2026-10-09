import json
import tempfile
import unittest
from pathlib import Path

from scripts.conformance.quic_interop import (
    CLIENT_NAME,
    SUPPORTED_TEST,
    parse_result,
    pin_runner_images,
    register_client,
    validate_server,
)


class QuicInteropTests(unittest.TestCase):
    def test_client_image_shell_syntax_is_rejected_without_registry_changes(
        self,
    ) -> None:
        images = [
            "client:local$(printf${IFS}owned)",
            "client:local`printf${IFS}owned`",
            "client:local${HOME}",
            "client:local;true",
            "client:local&true",
            "client:local|true",
            "client:local>marker",
            "client:local'quote",
            "client:local\\escape",
        ]
        original = b'{"server": {"image": "server:pin", "role": "server"}}\n'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "implementations_quic.json"
            for image in images:
                with self.subTest(image=image):
                    path.write_bytes(original)

                    with self.assertRaises(ValueError):
                        register_client(path, image)
                    self.assertEqual(path.read_bytes(), original)

    def test_server_image_shell_syntax_is_rejected_without_registry_changes(
        self,
    ) -> None:
        images = [
            "server:local$(printf${IFS}owned)",
            "server:local`printf${IFS}owned`",
            "server:local${HOME}",
            "server:local;true",
            "server:local&true",
            "server:local|true",
            "server:local>marker",
            "server:local'quote",
            "server:local\\escape",
        ]
        original = b'{"server": {"image": "server:pin", "role": "server"}}\n'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "implementations_quic.json"
            for image in images:
                with self.subTest(image=image):
                    path.write_bytes(original)

                    with self.assertRaises(ValueError):
                        pin_runner_images(path, "server", image)
                    self.assertEqual(path.read_bytes(), original)

    def test_image_reference_spellings_are_preserved_for_client_and_server(
        self,
    ) -> None:
        # Docker distribution/reference regexp.go permits these reference forms.
        # No Docker process or shell is invoked by these registry-only controls.
        digest = "sha256:" + "a" * 64
        images = [
            "phantom:local",
            "library/ubuntu",
            "registry.example:5443/team/client:Release_1.2-3",
            "REGISTRY.EXAMPLE/team/client:Release",
            "[2001:db8::1]:5000/team/client:v1",
            "team/client__build:_tag",
            "team/client--build:latest",
            "team/client@" + digest,
            "team/client:Release@" + digest,
        ]
        original = b'{"server": {"image": "server:pin", "role": "server"}}\n'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "implementations_quic.json"
            for image in images:
                with self.subTest(image=image):
                    path.write_bytes(original)

                    self.assertEqual(register_client(path, image), original)
                    pin_runner_images(path, "server", image)

                    document = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual(document[CLIENT_NAME]["image"], image)
                    self.assertEqual(document["server"]["image"], image)

    def test_registers_and_restores_a_named_client_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "implementations_quic.json"
            path.write_text(
                json.dumps(
                    {
                        "server": {
                            "image": "server:pin",
                            "role": "server",
                            "url": "https://example.test/server",
                        }
                    }
                ),
                encoding="utf-8",
            )
            original = register_client(path, "phantom:local")
            document = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(document[CLIENT_NAME]["role"], "client")
            self.assertEqual(document[CLIENT_NAME]["image"], "phantom:local")
            path.write_bytes(original)
            self.assertNotIn(CLIENT_NAME, json.loads(path.read_text(encoding="utf-8")))

    def test_accepts_only_one_successful_http3_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            document = {
                "clients": [CLIENT_NAME],
                "servers": ["server"],
                "tests": {"3": {"name": SUPPORTED_TEST, "desc": "HTTP/3"}},
                "results": [
                    [
                        {
                            "abbr": "3",
                            "name": SUPPORTED_TEST,
                            "result": "succeeded",
                        }
                    ]
                ],
            }
            path.write_text(json.dumps(document), encoding="utf-8")

            self.assertEqual(
                parse_result(path, "server"),
                {
                    "client": CLIENT_NAME,
                    "server": "server",
                    "status": "succeeded",
                    "test": SUPPORTED_TEST,
                },
            )

            document["results"][0][0]["result"] = "unsupported"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                parse_result(path, "server")

    def test_server_must_be_named_and_server_capable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "implementations_quic.json"
            path.write_text(
                json.dumps(
                    {
                        "server": {
                            "image": "server:pin",
                            "role": "server",
                            "url": "https://example.test/server",
                        },
                        "client": {
                            "image": "client:pin",
                            "role": "client",
                            "url": "https://example.test/client",
                        },
                    }
                ),
                encoding="utf-8",
            )

            validate_server(path, "server")
            with self.assertRaisesRegex(ValueError, "server-capable"):
                validate_server(path, "client")
            with self.assertRaisesRegex(ValueError, "characters"):
                validate_server(path, "../server")

            pin_runner_images(path, "server", "server@sha256:digest")
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["server"]["image"],
                "server@sha256:digest",
            )

    def test_rejects_missing_or_mismatched_result_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            path.write_text(
                json.dumps(
                    {
                        "clients": [CLIENT_NAME],
                        "servers": ["other"],
                        "tests": {"3": {"name": SUPPORTED_TEST}},
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "server set"):
                parse_result(path, "server")


if __name__ == "__main__":
    unittest.main()
