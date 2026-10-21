"""An independent QUIC peer observes upload cancellation and a live sibling."""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from phantom_http import AsyncClient, ResponseTrailers, Trust
from test_settings_transport import spki_pin

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"


class HTTP3UploadTests(unittest.IsolatedAsyncioTestCase):
    async def test_post_head_upload_close_preserves_live_sibling_and_reuse(self):
        with tempfile.TemporaryDirectory(prefix="phantom-python-h3-") as temporary:
            directory = Path(temporary)
            peer = await asyncio.create_subprocess_exec(
                os.environ["PHANTOM_H3_PEER_PYTHON"],
                os.environ["PHANTOM_H3_PEER_SCRIPT"],
                "--directory",
                str(directory),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def event(expected):
                line = await asyncio.wait_for(peer.stdout.readline(), 10)
                self.assertLessEqual(len(line), 1024)
                self.assertEqual(json.loads(line), {"event": expected})

            def receipt(name):
                data = (directory / name).read_bytes()
                self.assertLessEqual(len(data), 65536)
                return json.loads(data)

            closed = asyncio.Event()
            pending = asyncio.Event()
            pulls = []
            closes = []

            async def source():
                try:
                    pulls.append(1)
                    yield b"U" * 1024
                    pulls.append(2)
                    pending.set()
                    await asyncio.Future()
                finally:
                    closes.append(True)
                    closed.set()

            try:
                await event("ready")
                ready = receipt("ready.json")
                async with AsyncClient(
                    profile=PROFILE,
                    protocol="h3",
                    context="raw",
                    timeout_ms=10000,
                    trust=Trust(
                        roots=(bytes(ready["root_der"]),),
                        server_spki_pins=(
                            bytes(32),
                            spki_pin(directory / "server.pem"),
                        ),
                    ),
                ) as client:
                    warm = await client.request("GET", ready["url"] + "/warm")
                    self.assertEqual(await warm.read(max_bytes=2), b"ok")
                    self.assertEqual(warm.trailers, ResponseTrailers("complete", ()))
                    selected = await client.request(
                        "POST", ready["url"] + "/upload", body=source()
                    )
                    try:
                        self.assertEqual(await selected.read_chunk(1), b"a")
                        self.assertEqual(selected.trailers.state, "pending")
                        await asyncio.wait_for(pending.wait(), 5)
                        healthy = await client.request("GET", ready["url"] + "/healthy")
                        try:
                            await event("live")
                            await selected.aclose()
                            self.assertEqual(
                                selected.trailers, ResponseTrailers("unavailable", None)
                            )
                            await asyncio.wait_for(closed.wait(), 5)
                            await event("cancelled")
                            self.assertEqual(
                                await healthy.read(max_bytes=7), b"healthy"
                            )
                            self.assertEqual(
                                healthy.trailers, ResponseTrailers("complete", ())
                            )
                        finally:
                            await healthy.aclose()
                    finally:
                        await selected.aclose()
                    self.assertEqual(pulls, [1, 2])
                    self.assertEqual(len(closes), 1)
                    reuse = await client.request("GET", ready["url"] + "/reuse")
                    self.assertEqual(await reuse.read(max_bytes=2), b"ok")
                    await event("complete")
                    result = receipt("result.json")
                    self.assertEqual(result["connections"], 1)
                    self.assertEqual(result["protocol"], "h3")
                    self.assertEqual(result["upload_bytes"], 1024)
                    self.assertEqual(
                        result["cancellations"],
                        {"reset_stream": 0x10C, "stop_sending": 0x10C},
                    )
                    self.assertTrue(result["healthy_released"])
                    self.assertEqual(len(set(result["streams"].values())), 4)
                    peer.stdin.write(b"stop\n")
                    await peer.stdin.drain()
                    peer.stdin.close()
                    await asyncio.wait_for(peer.wait(), 8)
            finally:
                if peer.stdin is not None:
                    peer.stdin.close()
                try:
                    await asyncio.wait_for(peer.wait(), 8)
                except asyncio.TimeoutError:
                    peer.kill()
                    await peer.wait()
                    self.fail("HTTP/3 peer did not settle")
                error = await peer.stderr.read()
                self.assertLessEqual(len(error), 65536)
                self.assertEqual(peer.returncode, 0, error.decode(errors="replace"))
                self.assertFalse((directory / "error.json").exists())
