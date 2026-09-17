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
