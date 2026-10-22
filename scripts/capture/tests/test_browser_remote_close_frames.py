"""Literal wire endings distinguish a browser close from truncated messages."""

import asyncio
import json
import unittest

from scripts.capture import browser_remote as remote

DEADLINE = 3.0


class BrowserCloseFrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_reply_does_not_hide_an_observed_later_truncated_frame(self):
        case = self
        reply = b'\x81\x14{"id":1,"result":{}}'
        for ending in (b"\x81\x02", b"\x81\x7e"):
            with self.subTest(ending=ending):
                closed = []

                class Writer:
                    def __init__(self, observations):
                        self.transport = self
                        self.observations = observations

                    def abort(self):
                        self.observations.append(True)

                    async def wait_closed(self):
                        return None

                class Socket(remote.RemoteSocket):
                    def __init__(self, reader, writer, ending):
                        super().__init__(reader, writer)
                        self.ending = ending

                    async def send(self, text):
                        case.assertEqual(
                            json.loads(text),
                            {"id": 1, "method": "Browser.close", "params": {}},
                        )
                        self.reader.feed_data(reply + self.ending)
                        self.reader.feed_eof()

                connection = remote.RemoteConnection(
                    Socket(asyncio.StreamReader(), Writer(closed), ending)
                )

                async def ignore(_):
                    return None

                connection.start(ignore)
                try:
                    with self.assertRaises(asyncio.IncompleteReadError) as raised:
                        await asyncio.wait_for(
                            remote.request_browser_close(connection, "chrome"), DEADLINE
                        )
                    self.assertIs(raised.exception, connection.failure)
                    self.assertEqual(raised.exception.partial, b"")
                    self.assertEqual(raised.exception.expected, 2)
                finally:
                    await connection.close()
                    self.assertTrue(connection.reader.done())
                    self.assertEqual(closed, [True])

    async def observe(self, ending):
        writers = []
        tasks = []
        connection = None

        async def serve(reader, writer):
            _, opcode, payload = await asyncio.wait_for(
                remote.read_frame(reader), DEADLINE
            )
            self.assertEqual(opcode, 1)
            self.assertEqual(
                json.loads(payload), {"id": 1, "method": "Browser.close", "params": {}}
            )
            writer.write(ending)
            await writer.drain()
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), DEADLINE)

        def accepted(reader, writer):
            writers.append(writer)
            tasks.append(asyncio.create_task(serve(reader, writer)))

        listener = await asyncio.start_server(accepted, "127.0.0.1", 0)
        try:
            port = listener.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writers.append(writer)
            connection = remote.RemoteConnection(remote.RemoteSocket(reader, writer))

            async def ignore(_):
                return None

            connection.start(ignore)
            observed = None
            accepted = False
            try:
                observed = await asyncio.wait_for(
                    remote.request_browser_close(connection, "chrome"), DEADLINE
                )
                accepted = True
            except (ConnectionError, asyncio.IncompleteReadError) as error:
                observed = error

            self.assertIs(observed, connection.failure)
            for task in tasks:
                await asyncio.wait_for(task, DEADLINE)
            return observed, accepted
        finally:
            listener.close()
            await listener.wait_closed()
            if connection is not None:
                await connection.close()
                self.assertTrue(connection.reader.done())
            for writer in writers:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            for task in tasks:
                if not task.done():
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task

    async def test_empty_header_eof_and_close_control_frame_are_clean(self):
        for ending in (b"", b"\x88\x00"):
            with self.subTest(ending=ending):
                observed, accepted = await self.observe(ending)

                self.assertTrue(accepted)
                self.assertIs(type(observed), ConnectionError)
                self.assertEqual(str(observed), "remote protocol endpoint closed")
                if not ending:
                    self.assertIsInstance(
                        observed.__cause__, asyncio.IncompleteReadError
                    )
                    self.assertEqual(observed.__cause__.partial, b"")
                    self.assertEqual(observed.__cause__.expected, 2)

    async def test_eof_inside_frames_or_fragmented_messages_is_a_failure(self):
        for ending, partial, expected in (
            (b"\x81", b"\x81", 2),
            (b"\x81\x02", b"", 2),
            (b"\x81\x7e", b"", 2),
            (b"\x81\x82\x01", b"\x01", 4),
            (b"\x01\x01x", b"", 2),
            (b"\x01\x00", b"", 2),
        ):
            with self.subTest(ending=ending):
                observed, accepted = await self.observe(ending)

                self.assertFalse(accepted)
                self.assertIsInstance(observed, asyncio.IncompleteReadError)
                self.assertEqual(observed.partial, partial)
                self.assertEqual(observed.expected, expected)
