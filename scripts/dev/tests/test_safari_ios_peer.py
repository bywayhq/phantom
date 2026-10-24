"""Check the adopted iOS preset and retained independent execution capsule."""

import hashlib
import json
import unittest

from scripts.dev.profile_catalog import cli


class SafariIosPeerTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(cli.RECORDS.read_text(encoding="utf-8"))
        self.peer = next(
            entry
            for entry in self.document["profiles"]
            if entry["selector"] == "safari-26-ios"
        )
        self.directory = (
            cli.REPO / self.peer["layers"][0]["references"][1]["location"]
        ).parent

    def test_catalog_round_trip_preserves_identity_composition_and_template_order(self):
        original = cli.validate(self.document)
        restored = cli.validate(json.loads(json.dumps(self.document)))
        self.assertEqual(original, restored)
        self.assertEqual(self.peer["id"], "safari/26.0/ios/r1")
        self.assertEqual(self.peer["target"], "SafariIos26")
        self.assertEqual(
            self.peer["metadata"]["identity"],
            {
                "kind": "Peer",
                "project": "wreq-util",
                "source_revision": "5715529002738f46eea86a7271f918f9374d3582",
                "recipe": "safari-ios-26",
                "release": "26.0",
            },
        )
        self.assertEqual(self.peer["composition"]["TcpTls"], "safari_2601_tls")
        self.assertEqual(self.peer["composition"]["Http2"], "safari_ios26_http2")
        self.assertEqual(
            self.peer["templates"], {"Navigation": "safari_ios26_navigation"}
        )
        self.assertEqual(
            sum(p["metadata"]["identity"]["kind"] == "Observed" for p in original),
            17,
        )
        chrome156 = next(p for p in original if p["target"] == "ChromeWindows156")
        self.assertEqual(chrome156["metadata"]["identity"]["kind"], "Observed")
        self.assertEqual(chrome156["id"], "chrome/156.0.8078.48/windows-11-26200/r1")

    def test_fixture_hashes_cover_every_retained_file(self):
        hashes = json.loads(
            (self.directory / "sha256.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(hashes),
            {
                p.relative_to(self.directory).as_posix()
                for p in self.directory.rglob("*")
                if p.is_file() and p.name != "sha256.json"
            },
        )
        for name, expected in hashes.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((self.directory / name).read_bytes()).hexdigest(),
                    expected,
                )
        self.assertIn(
            "Apache License",
            (self.directory / "LICENSE").read_text(encoding="utf-8"),
        )

    def test_three_independent_processes_complete_two_requests_on_one_connection(self):
        for number in range(1, 4):
            run = self.directory / f"run-{number}"
            with self.subTest(run=number):
                self.assertEqual((run / "exit.txt").read_text().strip(), "0")
                completion = json.loads((run / "run.json").read_text())
                self.assertEqual(completion["connection_count"], 1)
                self.assertFalse(completion["timed_out"])
                self.assertEqual(
                    (run / "response-1.body").read_bytes(), b"peer capture\n"
                )
                self.assertEqual((run / "response-2.body").read_bytes(), b"")
                stream = (run / "connection-0.client.bin").read_bytes()
                self.assertEqual(stream[:24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                self.assertEqual(
                    stream[24:57],
                    bytes.fromhex(
                        "000018040000000000000200000000000300000064"
                        "000400200000000900000001"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
