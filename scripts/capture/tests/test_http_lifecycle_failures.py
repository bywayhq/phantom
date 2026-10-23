import asyncio
import contextlib
import json
import ssl
import unittest
from unittest.mock import Mock

import h2.config
import h2.connection
import h2.events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

from scripts.capture import http_lifecycle as lifecycle
from scripts.capture import http_lifecycle_resources_h3 as h3
from scripts.capture.http2_session import HOSTNAME
from scripts.capture.http_lifecycle_resources import ResourceCapture
from scripts.capture.tests.test_http_lifecycle_resources import fields
from scripts.capture.tests.test_http_lifecycle_resources_h3 import WireQuic


class FailureReportingTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_resource_connection_requires_its_observed_completion(
        self,
    ) -> None:
        for protocol in ("h2", "h3"):
            with self.subTest(protocol=protocol):
                run = lifecycle.Run("resources", "token", 100)
                run.resources = ResourceCapture("token", 12345, protocol)
                run.select(0, run.resources.target("/start"))
                target = run.resources.done_target("resources:ok")
                try:
                    with self.assertRaisesRegex(ValueError, "owned path and token"):
                        run.resources.observe(
                            1,
                            1,
                            fields(12345, target.replace("run=token", "run=other")),
                            None,
                        )
                    run.finish(target, 1)
                    self.assertIsNone(run.completion)
                    self.assertIsNone(run.page_result)

                    run.resources.observe(1, 1, fields(12345, target), None)
                    run.finish(target, 2)
                    run.finish(target.replace("run=token", "run=other"), 1)
                    self.assertIsNone(run.completion)
                    self.assertIsNone(run.page_result)

                    run.finish(target, 1)
                    self.assertEqual(run.page_result, "resources:ok")
                    with self.assertRaisesRegex(ValueError, "complete every"):
                        run.resources.check_complete(run.page_result)
                finally:
                    if run.completion is not None:
                        run.completion.cancel()

    async def test_h2_timeout_reports_received_request_and_written_response(
        self,
    ) -> None:
        certificate = lifecycle.generate_certificate()
        context = lifecycle.server_context(certificate)
        context.set_alpn_protocols(["h2"])
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(
            cadata=certificate.certificate_pem.decode()
        )
        client_context.set_alpn_protocols(["h2"])
        run = lifecycle.Run("resources", "PrivateToken", 100)
        owner = lifecycle.LifecycleServer(run)
        writer = None
        try:
            port = await owner.start("127.0.0.1", context, "main")
            run.resources = ResourceCapture(run.token, port)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", port, ssl=client_context, server_hostname=HOSTNAME
                ),
                5,
            )
            client = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=True)
            )
            client.initiate_connection()
            client.send_headers(
                1, fields(port, run.resources.target("/start")), end_stream=True
            )
            writer.write(client.data_to_send())
            await writer.drain()
            ended = False
            while not ended:
                data = await asyncio.wait_for(reader.read(65536), 5)
                if not data:
                    raise EOFError("controlled H2 peer closed before its response")
                ended = any(
                    isinstance(event, h2.events.StreamEnded)
                    for event in client.receive_data(data)
                )
            with self.assertRaises(asyncio.TimeoutError) as raised:
                await owner.wait_done(0)
            text = str(raised.exception)
            state = json.loads(text.split("; state=", 1)[1])
            self.assertEqual(state["connections"][0]["alpn"], "h2")
            self.assertGreater(state["connections"][0]["frames"], 0)
            self.assertGreater(state["connections"][0]["server_bytes"], 0)
            self.assertEqual(
                state["requests"],
                [
                    {
                        "connection": 0,
                        "stream": 1,
                        "path": "/start",
                        "status": 200,
                        "body_bytes": 0,
                    }
                ],
            )
            self.assertEqual(state["response_queued"], ["/start"])
            self.assertFalse(state["page_done"])
            self.assertFalse(state["completion_scheduled"])
            self.assertNotIn(run.token, text)
            self.assertNotIn(HOSTNAME, text)
            self.assertNotIn("synthetic-resource-test", text)
            with self.assertRaises(asyncio.TimeoutError) as closed:
                await owner.close(raised.exception)
            self.assertIs(closed.exception, raised.exception)
            self.assertFalse(owner.protocols)
        finally:
            await owner.close()
            if writer is not None:
                writer.close()
                with contextlib.suppress(ConnectionError, ssl.SSLError):
                    await asyncio.wait_for(writer.wait_closed(), 5)

    async def test_quic_callback_retains_error_frame_reason_and_aggregate_errors(
        self,
    ) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        protocol = h3.ResourceProtocol(WireQuic(), owner=owner)
        protocol.transmit = Mock()
        protocol.quic_event_received(
            ConnectionTerminated(
                error_code=1, frame_type=6, reason_phrase="controlled\nTLS failure"
            )
        )
        primary = owner.errors[0]
        retirement = OSError("controlled endpoint retirement failure")
        owner.failed(retirement)
        # The callback's enclosing aioquic event loop normally sets this event.
        protocol._closed.set()
        with self.assertRaises(ValueError) as raised:
            await owner.close(primary)
        self.assertIs(raised.exception, primary)
        self.assertIn("frame_type=6", str(primary))
        self.assertIn('reason="controlled\\nTLS failure"', str(primary))
        aggregate = primary.__cause__
        self.assertIsInstance(aggregate, lifecycle.LifecycleFailures)
        self.assertIs(aggregate.primary, primary)
        self.assertEqual(aggregate.cleanup, (retirement,))
        self.assertIn("ValueError", str(aggregate))
        self.assertIn("controlled endpoint retirement failure", str(aggregate))
        self.assertTrue(owner.cleanup.done())

    async def test_cleanup_message_bounds_each_error_without_changing_interruptions(
        self,
    ) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = lifecycle.LifecycleServer(run)
        primary = asyncio.CancelledError("controlled cancellation")
        cleanup = OSError("x" * 10000)
        owner.remember(cleanup)
        with self.assertRaises(asyncio.CancelledError) as raised:
            await owner.close(primary)
        self.assertIs(raised.exception, primary)
        aggregate = primary.__cause__
        self.assertIs(aggregate.primary, primary)
        self.assertIs(aggregate.cleanup[0], cleanup)
        self.assertIn("CancelledError", str(aggregate))
        self.assertIn("OSError", str(aggregate))
        self.assertIn("controlled cancellation", str(aggregate))
        self.assertLess(len(str(aggregate)), 2048)

    async def test_timeout_omits_unknown_paths_fields_and_completion_input(
        self,
    ) -> None:
        run = lifecycle.Run("resources", "PrivateToken", 100)
        run.requests.append(
            lifecycle.RequestRecord(
                0,
                1,
                0,
                "GET",
                "https://private.invalid/secret",
                [],
                {"cookie": "private-cookie", "authorization": "private-credential"},
            )
        )
        run.page_result = "private-result"
        owner = lifecycle.LifecycleServer(run)
        try:
            with self.assertRaises(asyncio.TimeoutError) as raised:
                await owner.wait_done(0)
            text = str(raised.exception)
            state = json.loads(text.split("; state=", 1)[1])
            self.assertEqual(state["requests"][0]["path"], "other")
            self.assertEqual(state["page_result"], "other")
            self.assertNotIn("private", text.lower())
        finally:
            await owner.close()


if __name__ == "__main__":
    unittest.main()
