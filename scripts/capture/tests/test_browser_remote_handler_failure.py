import asyncio
import unittest

from scripts.capture.tests import test_browser_remote_lifecycle as lifecycle


class RemoteHandlerFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsolicited_handler_failure_is_observed_at_close(self) -> None:
        event = {"method": "Probe.unsolicited", "params": {"literal": 23}}
        peer = lifecycle.CommandPeer(
            {"Probe.ready": {"ready": "literal"}, "Page.navigate": {}}, event
        )
        self.addAsyncCleanup(peer.finish)
        failure = lifecycle.HandlerFailure("controlled unsolicited handler failure")
        peer.allowed = (failure,)
        invoked = asyncio.Event()
        connection = None

        async def failed_handler(actual):
            self.assertEqual(actual, event)
            self.assertEqual(connection.pending, {})
            invoked.set()
            raise failure

        port = await peer.listen()
        connection = await peer.connect(port, failed_handler)
        reply = await asyncio.wait_for(connection.call("Probe.ready", {}), 2.0)
        self.assertEqual(reply, {"ready": "literal"})

        reply = await asyncio.wait_for(
            connection.call("Page.navigate", {"url": "http://literal/unsolicited"}),
            2.0,
        )
        self.assertEqual(reply, {})
        await asyncio.wait_for(invoked.wait(), 2.0)
        self.assertEqual(
            peer.remote.commands,
            [
                {"id": 1, "method": "Probe.ready", "params": {}},
                {
                    "id": 2,
                    "method": "Page.navigate",
                    "params": {"url": "http://literal/unsolicited"},
                },
            ],
        )

        done, _ = await asyncio.wait([connection.reader], timeout=2.0)
        self.assertIn(connection.reader, done)
        reader_failure = connection.reader.exception()
        error = None
        try:
            await asyncio.wait_for(connection.close(), 2.0)
        except BaseException as actual:
            error = actual
        closed_before_backup = connection.socket.writer.is_closing()
        await peer.finish()

        self.assertIs(
            error, failure, "shutdown discarded its unsolicited handler fault"
        )
        self.assertIs(reader_failure, failure)
        self.assertTrue(closed_before_backup)


if __name__ == "__main__":
    unittest.main()
