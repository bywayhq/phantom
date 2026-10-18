"""Keep published testkit captures identical to their retained sources."""

import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class PackagedFixtureTests(unittest.TestCase):
    def test_public_capture_copies_preserve_source_bytes_and_recorded_hashes(self):
        fixtures = [
            (
                "client-hints/chrome-154-windows-navigation.txt",
                "client-hints/chrome/154.0.8037.97/windows-11-26200/navigation.txt",
                "e8296686c4874a9d6d9c783d6e0e028167b7cd89d5ca37df9c840da57a5796c7",
            ),
            (
                "http1/chrome-154-windows-h1-accept.txt",
                "websocket/chrome/154.0.8037.58/windows-11-26200/h1-accept.txt",
                "0a10349caf479b72631725c12a5ef495f12411e0f832e1f0c3f3e284c40849ce",
            ),
            (
                "http1/firefox-157-windows-h1-accept.txt",
                "websocket/firefox/157.0/windows-11-26200/h1-accept.txt",
                "41ee523a20a8cc6cc1416877395eba53ae498216955086cb743f09e254561dbb",
            ),
        ]
        package = ROOT / "crates/phantom-testkit/fixtures"
        for packaged, original, digest in fixtures:
            with self.subTest(packaged=packaged):
                content = (package / packaged).read_bytes()
                self.assertEqual(content, (ROOT / "fixtures" / original).read_bytes())
                self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
