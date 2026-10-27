"""RFC 9220 messages, cancellation and rejection ownership against aioquic."""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from phantom_http import AsyncClient, Profile, TimeoutError, Trust, WebSocketError


class HTTP3WebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_frames_and_cancelled_receive_preserve_live_sibling(self) -> None:
        await self.check_websocket(False)

    async def test_rejection_body_survives_shutdown_timeout_and_retry(self) -> None:
        await self.check_websocket(True)

    async def check_websocket(self, reject: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="phantom-python-ws-h3-") as temporary:
            directory = Path(temporary)
            peer = await asyncio.create_subprocess_exec(
                os.environ["PHANTOM_H3_PEER_PYTHON"],
                os.environ["PHANTOM_WEBSOCKET_H3_PEER_SCRIPT"],
                "--directory",
                str(directory),
                *(["--reject"] if reject else []),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def event(expected: str) -> None:
                line = await asyncio.wait_for(peer.stdout.readline(), 10)
                self.assertLessEqual(len(line), 1024)
                self.assertEqual(json.loads(line), {"event": expected})

            def receipt(name: str) -> dict:
                data = (directory / name).read_bytes()
                self.assertLessEqual(len(data), 65536)
                return json.loads(data)

            client = socket = healthy = response = waiting = None
            try:
                await event("ready")
                ready = receipt("ready.json")
                # Chrome's recipe leaves HTTP/3 WebSockets disabled.
                document = Profile.from_catalog("chrome-154-windows").describe()
                document["profile"]["http3"]["request"][
                    "extended_connect_pseudo_header_order"
                ] = ["Method", "Protocol", "Scheme", "Authority", "Path"]
                profile = Profile.import_json(json.dumps(document).encode())
                client = AsyncClient(
                    profile=profile,
                    protocol="h3",
                    context="raw",
                    timeout_ms=10000,
                    trust=Trust(roots=(bytes(ready["root_der"]),)),
                )
                warm = await client.get(ready["url"] + "/warm")
                self.assertEqual(await warm.read(max_bytes=2), b"ok")
                url = ready["url"].replace("https:", "wss:")
                if reject:
                    with self.assertRaises(WebSocketError) as failure:
                        await client.websocket(url + "/reject", protocol="h3")
                    self.assertEqual(failure.exception.kind, "handshake_rejected")
                    response = failure.exception.response
                    await event("rejected")
                    self.assertEqual((response.status, response.protocol), (403, "h3"))
                    self.assertEqual(
                        [
                            field.value
                            for field in response.headers
                            if field.name == "x-duplicate"
                        ],
                        [b"one", b"two"],
                    )
                    with self.assertRaises(TimeoutError):
                        await client.close(timeout_ms=0)
                    self.assertEqual(await response.read_chunk(2), b"de")
                    peer.stdin.write(b"release\n")
                    await peer.stdin.drain()
                    await event("complete")
                    self.assertEqual(await response.read(max_bytes=4), b"nied")
                    await client.close()
                else:
                    socket = await client.websocket(
                        url + "/echo",
                        protocol="h3",
                        headers=[("sec-websocket-protocol", "chat")],
                    )
                    self.assertEqual(
                        (socket.status, socket.protocol, socket.selected_protocol),
                        (200, "h3", "chat"),
                    )
                    await socket.send("hello")
                    self.assertEqual(await socket.recv(), "hello")
                    await socket.send(b"\x00\xff")
                    self.assertEqual(await socket.recv(), b"\x00\xff")
                    await socket.aclose(1000, "done")
                    self.assertTrue(socket.is_closed)
                    socket = await client.websocket(url + "/cancel", protocol="h3")
                    waiting = asyncio.create_task(socket.recv())
                    healthy = await client.get(ready["url"] + "/healthy")
                    await event("live")
                    waiting.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await waiting
                    await event("cancelled")
                    self.assertEqual(await healthy.read(max_bytes=7), b"healthy")
                    reuse = await client.get(ready["url"] + "/reuse")
                    self.assertEqual(await reuse.read(max_bytes=2), b"ok")
                    await event("complete")
                result = receipt("result.json")
                self.assertEqual(result["connections"], 1)
                self.assertEqual(result["rejected"], reject)
                self.assertEqual(
                    len(set(result["streams"].values())), 2 if reject else 5
                )
                if not reject:
                    self.assertEqual(result["frames"], 3)
                    self.assertTrue(result["healthy_released"])
                    self.assertEqual(
                        result["cancellations"],
                        {"reset_stream": 0x10C, "stop_sending": 0x10C},
                    )
                peer.stdin.write(b"stop\n")
                await peer.stdin.drain()
                peer.stdin.close()
                await asyncio.wait_for(peer.wait(), 8)
                await client.close()
            finally:
                if socket is not None:
                    socket.abort()
                if waiting is not None and not waiting.done():
                    waiting.cancel()
                    await asyncio.gather(waiting, return_exceptions=True)
                if healthy is not None:
                    await healthy.aclose()
                if response is not None:
                    await response.aclose()
                peer.stdin.close()
                try:
                    await asyncio.wait_for(peer.wait(), 8)
                except asyncio.TimeoutError:
                    peer.kill()
                    await peer.wait()
                    self.fail("HTTP/3 WebSocket peer did not settle")
                finally:
                    if client is not None:
                        await client.abort()
                error = await peer.stderr.read()
                self.assertLessEqual(len(error), 65536)
                self.assertEqual(peer.returncode, 0, error.decode(errors="replace"))
                self.assertFalse((directory / "error.json").exists())
