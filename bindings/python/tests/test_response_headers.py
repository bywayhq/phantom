"""Actual raw QPACK markers survive native ownership and both public responses."""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from phantom_http import AsyncClient, Response, ResponseHeader, Trust


class ResponseHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_http3_raw_order_bytes_and_markers_survive_eof_and_close(self):
        with tempfile.TemporaryDirectory(prefix="phantom-header-h3-") as temporary:
            directory = Path(temporary)
            peer = await asyncio.create_subprocess_exec(
                os.environ["PHANTOM_H3_PEER_PYTHON"],
                os.environ["PHANTOM_HEADER_H3_PEER_SCRIPT"],
                "--directory",
                str(directory),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                line = await asyncio.wait_for(peer.stdout.readline(), 10)
                self.assertEqual(json.loads(line), {"event": "ready"})
                data = (directory / "ready.json").read_bytes()
                self.assertLessEqual(len(data), 65536)
                ready = json.loads(data)
                async with AsyncClient(
                    profile="chrome/154.0.8037.97/windows-11-26200/r1",
                    protocol="h3",
                    context="raw",
                    timeout_ms=10000,
                    trust=Trust(roots=(bytes(ready["root_der"]),)),
                ) as client:
                    expected = (
                        ResponseHeader("x-a", b"first", False),
                        ResponseHeader("x-b", b"\x80B", True),
                        ResponseHeader("x-a", b"last", False),
                    )
                    for path in ("/one", "/two"):
                        async with await client.request(
                            "GET", ready["url"] + path
                        ) as response:
                            sync = Response(None, response)
                            self.assertEqual(response.headers, expected)
                            self.assertEqual(sync.headers, expected)
                            self.assertEqual(await response.read(max_bytes=2), b"ok")
                        self.assertEqual(response.headers, expected)
                    peer.stdin.write(b"stop\n")
                    await peer.stdin.drain()
                    peer.stdin.close()
                    _, stderr = await asyncio.wait_for(peer.communicate(), 10)
                    self.assertEqual(peer.returncode, 0, stderr.decode())
            finally:
                if peer.returncode is None:
                    peer.kill()
                    await peer.communicate()
