import asyncio
import http.client
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.capture import safari_webdriver as safari


def response(value, status="200 OK", *, chunked=False):
    body = json.dumps({"value": value}).encode()
    if chunked:
        header = b"Transfer-Encoding: chunked\r\n"
        body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        header = f"Content-Length: {len(body)}\r\n".encode()
    return f"HTTP/1.1 {status}\r\n".encode() + header + b"\r\n" + body


class ResponseTests(unittest.TestCase):
    def test_standard_http_parser_preserves_chunked_values(self):
        self.assertEqual(
            safari.response_value(response({"ready": True}, chunked=True)),
            {"ready": True},
        )

    def test_protocol_error_retains_status_code_and_message(self):
        with self.assertRaises(safari.WebDriverError) as raised:
            safari.response_value(
                response(
                    {"error": "session not created", "message": "disabled"},
                    "500 Internal Server Error",
                )
            )
        self.assertEqual(raised.exception.status, 500)
        self.assertEqual(raised.exception.code, "session not created")
        self.assertIn("disabled", str(raised.exception))

    def test_malformed_duplicate_oversized_and_http_error_responses_fail(self):
        cases = [
            b"not HTTP",
            b'HTTP/1.1 200 OK\r\n\r\n{"value":1,"value":2}',
            response("x" * safari.MAX_OUTPUT),
            response(None, "302 Found"),
            b"x" * (safari.MAX_WIRE + 1),
            b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"value":null}',
        ]
        for wire in cases:
            with (
                self.subTest(length=len(wire)),
                self.assertRaises(
                    (ValueError, http.client.HTTPException, safari.WebDriverError)
                ),
            ):
                safari.response_value(wire)

    def test_capture_url_cannot_select_a_remote_host_or_credentials(self):
        for url in (
            "https://127.0.0.1:1234/",
            "http://example.com:1234/",
            "http://user@127.0.0.1:1234/",
            "http://127.0.0.1:1234/#x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                safari.SafariSession(url, {})

    def test_h2_requires_an_explicit_https_loopback_url(self):
        owner = safari.SafariSession(
            "https://127.0.0.1:1234/run/probe", {}, protocol="h2"
        )
        self.assertTrue(owner.accept_insecure_certificates)
        self.assertFalse(
            safari.SafariSession(
                "http://127.0.0.1:1234/", {}
            ).accept_insecure_certificates
        )
        for url in (
            "http://127.0.0.1:1234/",
            "https://server.phantom.test:1234/",
            "https://localhost:1234/",
            "https://127.0.0.2:1234/",
            "https://[::1]:1234/",
            "https://127.0.0.1/",
            "https://user@127.0.0.1:1234/",
            "https://@127.0.0.1:1234/",
            "https://127.0.0.1:1234/#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                safari.SafariSession(url, {}, protocol="h2")
        with self.assertRaises(ValueError):
            safari.SafariSession("https://127.0.0.1:1234/", {}, protocol="h3")

    def test_h2_success_requires_observed_alpn_and_decoded_streams(self):
        run = SimpleNamespace(
            requests=[
                SimpleNamespace(
                    kind="page", stream_id=1, decoded_headers=[(b":method", b"GET")]
                ),
                SimpleNamespace(
                    kind="sse",
                    attempt=0,
                    extra=False,
                    stream_id=3,
                    decoded_headers=[(b":method", b"GET")],
                ),
                SimpleNamespace(
                    kind="sse",
                    attempt=1,
                    extra=False,
                    stream_id=5,
                    decoded_headers=[(b":method", b"GET")],
                ),
            ],
            terminated=1,
            connections=[SimpleNamespace(protocol="h2")],
        )
        safari.check_run(run, "h2")
        for protocol in (None, "http/1.1", "h3"):
            run.connections[0].protocol = protocol
            with (
                self.subTest(protocol=protocol),
                self.assertRaisesRegex(RuntimeError, "verified H2"),
            ):
                safari.check_run(run, "h2")
        run.connections[0].protocol = "h2"
        run.requests[-1].decoded_headers = []
        with self.assertRaisesRegex(RuntimeError, "verified H2"):
            safari.check_run(run, "h2")
        run.requests[-1].decoded_headers = [(b":method", b"GET")]
        run.requests[-1].stream_id = None
        with self.assertRaisesRegex(RuntimeError, "verified H2"):
            safari.check_run(run, "h2")
        run.connections = []
        with self.assertRaisesRegex(RuntimeError, "verified H2"):
            safari.check_run(run, "h2")

    def test_h2_url_override_preserves_the_existing_peer_and_certificate(self):
        from scripts.capture.sse_multiplexed import H2ReconnectServer

        server = safari.capture_server("h2")
        self.assertIsInstance(server, H2ReconnectServer)
        self.assertIs(type(server).start, H2ReconnectServer.start)
        self.assertIs(type(server).handle, H2ReconnectServer.handle)
        self.assertIs(type(server).close, H2ReconnectServer.close)
        with self.assertRaises(RuntimeError):
            server.url(SimpleNamespace(page_path=lambda: "/run/probe"))
        server.address = ("127.0.0.1", 1234)
        self.assertEqual(
            server.url(SimpleNamespace(page_path=lambda: "/run/probe")),
            "https://127.0.0.1:1234/run/probe",
        )
        self.assertTrue(server.certificate.der)
        self.assertIs(type(safari.capture_server("h1")), safari.ReconnectServer)
        with self.assertRaises(ValueError):
            safari.capture_server("h3")

    def test_success_requires_page_both_attempts_and_terminal_observation(self):
        run = SimpleNamespace(
            requests=[
                SimpleNamespace(kind="page"),
                SimpleNamespace(kind="sse", attempt=0, extra=False),
                SimpleNamespace(kind="sse", attempt=1, extra=False),
            ],
            terminated=1,
        )
        safari.check_run(run)
        run.requests[-1].extra = True
        with self.assertRaises(RuntimeError):
            safari.check_run(run)
        run.requests[-1].extra = False
        run.terminated = None
        with self.assertRaises(RuntimeError):
            safari.check_run(run)


class RestTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_loopback_peer_receives_exact_request_and_closes(self):
        seen = asyncio.get_running_loop().create_future()
        finished = asyncio.Event()

        async def peer(reader, writer):
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                length = int(
                    next(
                        line.split(b":")[1]
                        for line in head.split(b"\r\n")
                        if line.startswith(b"Content-Length:")
                    )
                )
                body = await reader.readexactly(length)
                seen.set_result((head, json.loads(body)))
                writer.write(response({"ready": True}, chunked=True))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                finished.set()

        async with await asyncio.start_server(peer, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            value = await safari.request(port, "POST", "/session", {"a": 1})
            self.assertEqual(value, {"ready": True})
            head, body = await asyncio.wait_for(seen, 1)
            self.assertTrue(head.startswith(b"POST /session HTTP/1.1\r\n"))
            self.assertIn(b"Connection: close\r\n", head)
            self.assertEqual(body, {"a": 1})
            await asyncio.wait_for(finished.wait(), 1)

    async def test_total_response_deadline_closes_peer_without_blocking_loop(self):
        entered = asyncio.Event()
        closed = asyncio.Event()

        async def peer(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                entered.set()
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
                closed.set()

        async with await asyncio.start_server(peer, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            with mock.patch.object(safari, "COMMAND_SECONDS", 0.05):
                operation = asyncio.create_task(safari.request(port, "GET", "/status"))
                await asyncio.wait_for(entered.wait(), 1)
                self.assertFalse(operation.done())
                with self.assertRaises(asyncio.TimeoutError):
                    await operation
            await asyncio.wait_for(closed.wait(), 1)


class OwnedProcess:
    def __init__(self):
        self.pid = 12345
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_eof()
        self.terminated = False

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


class OwnershipTests(unittest.IsolatedAsyncioTestCase):
    def owner(self):
        return safari.SafariSession(
            "http://127.0.0.1:1234/run/probe", {"safari_version": "26.0"}
        )

    async def test_open_sequence_deletes_only_acquired_session(self):
        owner = self.owner()
        process = OwnedProcess()
        # Safari's native XPC service can own the listener under another PID.
        listener = "p54321\nn127.0.0.1:4567"
        port_socket = mock.MagicMock()
        port_socket.__enter__.return_value.getsockname.return_value = (
            "127.0.0.1",
            4567,
        )
        answers = [
            {"ready": True},
            {
                "sessionId": "owned-session",
                "capabilities": {
                    "browserName": "safari",
                    "browserVersion": "26.0",
                    "acceptInsecureCerts": False,
                },
            },
            None,
            "Safari test UA",
            None,
            None,
        ]
        with (
            mock.patch.object(
                safari,
                "socket",
                SimpleNamespace(socket=mock.Mock(return_value=port_socket)),
            ),
            mock.patch.object(
                safari.asyncio, "create_subprocess_exec", return_value=process
            ),
            mock.patch.object(safari, "command", return_value=(0, listener)),
            mock.patch.object(safari, "request", side_effect=answers) as rest,
        ):
            async with owner:
                self.assertEqual(owner.provenance["user_agent"], "Safari test UA")
            self.assertEqual(
                rest.call_args_list[-1],
                mock.call(4567, "DELETE", "/session/owned-session", None),
            )
            self.assertEqual(
                rest.call_args_list[1].args[3]["capabilities"]["alwaysMatch"][
                    "acceptInsecureCerts"
                ],
                False,
            )
            self.assertTrue(process.terminated)
            self.assertTrue(owner.provenance["session_delete_acknowledged"])
            self.assertEqual(owner.provenance["listener_observation"], listener)
            self.assertEqual(owner.provenance["cleanup_failures"], [])
            await owner.close()
            self.assertEqual(rest.call_count, 6)

    async def test_h2_requests_and_confirms_certificate_bypass_before_navigation(self):
        owner = safari.SafariSession(
            "https://127.0.0.1:1234/run/probe",
            {"safari_version": "26.0"},
            protocol="h2",
        )
        owner.process = OwnedProcess()
        with mock.patch.object(
            owner,
            "command",
            side_effect=[
                {"ready": True},
                {
                    "sessionId": "tls-session",
                    "capabilities": {
                        "browserName": "safari",
                        "browserVersion": "26.0",
                        "acceptInsecureCerts": True,
                    },
                },
                None,
                "Safari TLS UA",
                None,
                None,
            ],
        ) as rest:
            # Exercise the same post-listener sequence through the actual open.
            await self.open_with_owned_listener(owner)
        self.assertTrue(
            rest.call_args_list[1].args[2]["capabilities"]["alwaysMatch"][
                "acceptInsecureCerts"
            ]
        )
        self.assertEqual(
            rest.call_args_list[-2],
            mock.call("POST", "/session/tls-session/url", {"url": owner.url}),
        )
        self.assertTrue(owner.provenance["session_delete_acknowledged"])

    async def open_with_owned_listener(self, owner):
        process = owner.process
        reservation = mock.MagicMock()
        reservation.__enter__.return_value.getsockname.return_value = (
            "127.0.0.1",
            4567,
        )
        with (
            mock.patch.object(
                safari,
                "socket",
                SimpleNamespace(socket=mock.Mock(return_value=reservation)),
            ),
            mock.patch.object(
                safari.asyncio, "create_subprocess_exec", return_value=process
            ),
            mock.patch.object(
                safari, "command", return_value=(0, "p54321\nn127.0.0.1:4567")
            ),
        ):
            async with owner:
                pass

    async def test_missing_wrong_and_non_boolean_certificate_capabilities_fail_and_delete(
        self,
    ):
        for protocol, returned in (
            ("h2", None),
            ("h2", False),
            ("h2", 1),
            ("h2", "true"),
            ("h1", True),
            ("h1", None),
        ):
            with self.subTest(protocol=protocol, returned=returned):
                scheme = "https" if protocol == "h2" else "http"
                owner = safari.SafariSession(
                    f"{scheme}://127.0.0.1:1234/run/probe",
                    {"safari_version": "26.0"},
                    protocol=protocol,
                )
                owner.process = OwnedProcess()
                caps = {"browserName": "safari", "browserVersion": "26.0"}
                if returned is not None:
                    caps["acceptInsecureCerts"] = returned
                with (
                    mock.patch.object(
                        owner,
                        "command",
                        side_effect=[
                            {"ready": True},
                            {"sessionId": "rejected-capability", "capabilities": caps},
                            None,
                        ],
                    ) as rest,
                    self.assertRaisesRegex(ValueError, "certificate capability"),
                ):
                    await self.open_with_owned_listener(owner)
                self.assertEqual(rest.call_count, 3)
                self.assertEqual(
                    rest.call_args_list[-1],
                    mock.call("DELETE", "/session/rejected-capability"),
                )
                self.assertTrue(owner.process.terminated)
                self.assertEqual(owner.provenance["capabilities"], caps)

    async def test_h2_capture_cleanup_failure_keeps_protocol_certificate_and_primary(
        self,
    ):
        server = SimpleNamespace(
            certificate=SimpleNamespace(der=b"public test certificate"),
            address=("127.0.0.1", 1234),
            start=mock.AsyncMock(),
            close=mock.AsyncMock(side_effect=OSError("peer close")),
        )
        primary = ValueError("H2 observation failed")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture"
            with (
                mock.patch.object(
                    safari, "provenance", return_value={"safari_version": "26.0"}
                ),
                mock.patch.object(safari, "capture_server", return_value=server),
                mock.patch.object(safari, "capture_scenario", side_effect=primary),
                self.assertRaises(safari.SafariFailure) as raised,
            ):
                await safari.run(output, "h2")
            self.assertIs(raised.exception.primary, primary)
            self.assertEqual(str(raised.exception.cleanup[0]), "peer close")
            record = json.loads((output / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(record["requested_protocol"], "h2")
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["failure"]["message"], "H2 observation failed")
            self.assertEqual(
                record["final_cleanup_failures"][0]["message"], "peer close"
            )
            self.assertEqual(
                (output / "peer-certificate.der").read_bytes(), server.certificate.der
            )

    async def test_non_loopback_driver_listener_fails_before_rest_and_reaps_owner(self):
        owner = self.owner()
        process = OwnedProcess()
        port_socket = mock.MagicMock()
        port_socket.__enter__.return_value.getsockname.return_value = (
            "127.0.0.1",
            4567,
        )
        with (
            mock.patch.object(
                safari,
                "socket",
                SimpleNamespace(socket=mock.Mock(return_value=port_socket)),
            ),
            mock.patch.object(
                safari.asyncio, "create_subprocess_exec", return_value=process
            ),
            mock.patch.object(
                safari, "command", return_value=(0, f"p{process.pid}\nn*:4567")
            ),
            mock.patch.object(safari, "request") as rest,
            self.assertRaisesRegex(RuntimeError, "not loopback-only"),
        ):
            await owner.__aenter__()
        rest.assert_not_called()
        self.assertTrue(process.terminated)

    async def test_error_record_preserves_nested_failures_without_cycle_recursion(self):
        primary = ValueError("operation")
        cleanup = OSError("cleanup")
        combined = safari.SafariFailure(primary, [cleanup])
        primary.__cause__ = combined
        record = safari.error_record(combined)
        self.assertEqual(record["primary"]["type"], "ValueError")
        self.assertTrue(record["primary"]["cause"]["repeated_reference"])
        self.assertEqual(record["cleanup"][0]["type"], "OSError")

    async def test_failed_navigation_retains_acquired_session_for_cleanup(self):
        owner = self.owner()
        owner.process = OwnedProcess()
        primary = ValueError("navigation failed")

        async def open_failed():
            owner.session = "owned-session"
            raise primary

        with (
            mock.patch.object(owner, "open", side_effect=open_failed),
            mock.patch.object(owner, "command", return_value=None) as rest,
        ):
            with self.assertRaises(ValueError) as raised:
                await owner.__aenter__()
            self.assertIs(raised.exception, primary)
            rest.assert_awaited_once_with("DELETE", "/session/owned-session")
            self.assertTrue(owner.process.terminated)

    async def test_delete_failure_preserves_primary_and_still_reaps_driver(self):
        owner = self.owner()
        owner.process = OwnedProcess()
        owner.session = "owned-session"
        primary, failure = ValueError("capture failed"), OSError("delete failed")
        with (
            mock.patch.object(owner, "command", side_effect=failure),
            self.assertRaises(safari.SafariFailure) as raised,
        ):
            await owner.__aexit__(ValueError, primary, None)
        self.assertIs(raised.exception.primary, primary)
        self.assertIs(raised.exception.cleanup[0].cleanup[0], failure)
        self.assertTrue(owner.process.terminated)
        self.assertNotIn("session_delete_acknowledged", owner.provenance)

    async def test_cancelled_acquisition_waits_for_exact_session_then_cleans_it(self):
        owner = self.owner()
        owner.process = OwnedProcess()
        entered, release = asyncio.Event(), asyncio.Event()

        async def opening():
            entered.set()
            await release.wait()
            owner.session = "acquired-after-cancellation"

        with (
            mock.patch.object(owner, "open", side_effect=opening),
            mock.patch.object(owner, "command", return_value=None) as rest,
        ):
            task = asyncio.create_task(owner.__aenter__())
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
            rest.assert_awaited_once_with(
                "DELETE", "/session/acquired-after-cancellation"
            )
            self.assertTrue(owner.process.terminated)

    async def test_no_session_means_no_delete_on_missing_driver(self):
        owner = self.owner()
        missing = FileNotFoundError("safaridriver")
        with (
            mock.patch.object(owner, "open", side_effect=missing),
            mock.patch.object(owner, "command") as rest,
        ):
            with self.assertRaises(FileNotFoundError):
                await owner.__aenter__()
            rest.assert_not_called()
        self.assertEqual(
            owner.provenance["launch_failure"]["type"], "FileNotFoundError"
        )


if __name__ == "__main__":
    unittest.main()
