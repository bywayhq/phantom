"""HTTP/3 reconnection, rejection and sibling ownership against aioquic."""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from phantom_http import AsyncClient, SseError, Trust


class HTTP3EventSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_backoff_and_reconnects_preserve_live_sibling(self):
        await self.check_source(None)

    async def test_initial_rejection_is_terminal_without_extra_send(self):
        await self.check_source("initial")

    async def test_reconnect_rejection_is_terminal_without_extra_send(self):
        await self.check_source("reconnect")

    async def check_source(self, reject):
        with tempfile.TemporaryDirectory(
            prefix="phantom-python-events-h3-"
        ) as temporary:
            directory = Path(temporary)
            peer = await asyncio.create_subprocess_exec(
                os.environ["PHANTOM_H3_PEER_PYTHON"],
                os.environ["PHANTOM_EVENTS_H3_PEER_SCRIPT"],
                "--directory",
                str(directory),
                *(["--reject", reject] if reject is not None else []),
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

            client = source = healthy = waiting = None
            primary = None
            try:
                await event("ready")
                ready = receipt("ready.json")
                client = AsyncClient(
                    profile="chrome-154-windows",
                    protocol="h3",
                    context="raw",
                    timeout_ms=10000,
                    trust=Trust(roots=(bytes(ready["root_der"]),)),
                )
                opening = client.event_source(
                    ready["url"] + "/events",
                    protocol="h3",
                    initial_retry=0,
                    min_retry=0.2,
                    max_reconnects=3,
                )
                if reject == "initial":
                    with self.assertRaises(SseError) as caught:
                        await opening
                    self.assertEqual(caught.exception.kind, "unexpected_status")
                    self.assertNotIn("private", str(caught.exception))
                else:
                    source = await opening
                    self.assertEqual((source.status, source.protocol), (200, "h3"))
                    first = await anext(source)
                    self.assertEqual((first.data, first.id), ("first", "7"))
                    if reject == "reconnect":
                        with self.assertRaises(SseError) as caught:
                            await anext(source)
                        self.assertEqual(caught.exception.kind, "unexpected_status")
                        self.assertNotIn("private", str(caught.exception))
                        with self.assertRaises(StopAsyncIteration):
                            await anext(source)
                        self.assertEqual(source.reconnects, 1)
                    else:
                        healthy = await client.get(ready["url"] + "/healthy")
                        await event("live")
                        waiting = asyncio.create_task(anext(source))
                        await asyncio.sleep(0.03)
                        self.assertFalse(waiting.done())
                        waiting.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await waiting
                        self.assertFalse(source.closed)
                        remaining = [item async for item in source]
                        self.assertEqual(
                            [(item.data, item.id) for item in remaining],
                            [("second", "9")],
                        )
                        self.assertEqual(
                            (source.last_event_id, source.reconnects), ("9", 2)
                        )
                        self.assertTrue(source.closed)
                        self.assertEqual(await healthy.read(max_bytes=7), b"healthy")
                if reject is not None:
                    await event("rejected")
                async with await client.get(ready["url"] + "/reuse") as reused:
                    self.assertEqual(await reused.read(max_bytes=2), b"ok")
                await event("complete")
                result = receipt("result.json")
                self.assertEqual(result["connections"], 1)
                expected = {
                    None: ["/events", "/healthy", "/events", "/events", "/reuse"],
                    "initial": ["/events", "/reuse"],
                    "reconnect": ["/events", "/events", "/reuse"],
                }[reject]
                requests = result["requests"]
                self.assertEqual([item["path"] for item in requests], expected)
                self.assertEqual(
                    len({item["stream"] for item in requests}), len(expected)
                )
                ids = [
                    [
                        value
                        for name, value in item["headers"]
                        if name == "last-event-id"
                    ]
                    for item in requests
                    if item["path"] == "/events"
                ]
                self.assertEqual(
                    ids,
                    {
                        None: [[], ["7"], ["9"]],
                        "initial": [[]],
                        "reconnect": [[], ["7"]],
                    }[reject],
                )
                self.assertEqual(result["healthy_released"], reject is None)
                peer.stdin.write(b"stop\n")
                await peer.stdin.drain()
                await asyncio.wait_for(peer.wait(), 8)
            except BaseException as error:
                primary = error
                raise
            finally:
                if waiting is not None and not waiting.done():
                    waiting.cancel()
                    await asyncio.gather(waiting, return_exceptions=True)
                if source is not None:
                    source.close()
                if healthy is not None:
                    await healthy.aclose()
                if client is not None:
                    await client.abort()
                peer.stdin.close()
                try:
                    await asyncio.wait_for(peer.wait(), 8)
                except asyncio.TimeoutError:
                    peer.kill()
                    await peer.wait()
                    if primary is None:
                        self.fail("HTTP/3 EventSource peer did not settle")
                error = await peer.stderr.read()
                if primary is None:
                    self.assertLessEqual(len(error), 65536)
                    self.assertEqual(peer.returncode, 0, error.decode(errors="replace"))
                    self.assertFalse((directory / "error.json").exists())
                elif error:
                    print(error[:65536].decode(errors="replace"), file=sys.stderr)
