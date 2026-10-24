import asyncio
import contextlib
import io
import socket
import ssl
import struct
import sys
import unittest
from unittest.mock import patch

from scripts.capture import http_lifecycle as lifecycle
from scripts.capture.http2_session import HOSTNAME


def arguments(*extra: str) -> list[str]:
    return [
        "--browser",
        "edge",
        "--browser-path",
        "unused-browser.exe",
        "--client-version",
        "154.0",
        "--scenario",
        "revalidate",
        "--output-dir",
        "unused-output",
        *extra,
    ]


class CliLoopTests(unittest.TestCase):
    def test_windows_tcp_selects_and_restores_policy_on_every_outcome(self) -> None:
        original = object()
        selected = object()
        for protocol in ("h1", "h2"):
            for error in (None, ValueError("capture failed"), asyncio.CancelledError()):
                with self.subTest(protocol=protocol, error=type(error).__name__):
                    changes = []

                    def run(operation, changes=changes, error=error):
                        operation.close()
                        self.assertEqual(changes, [selected])
                        if error is not None:
                            raise error

                    with (
                        patch.object(lifecycle.sys, "platform", "win32"),
                        patch.object(
                            lifecycle.metadata, "version", lifecycle.SUPPORTED.get
                        ),
                        patch.object(
                            asyncio, "get_event_loop_policy", return_value=original
                        ),
                        patch.object(asyncio, "set_event_loop_policy", changes.append),
                        patch.object(
                            asyncio,
                            "WindowsSelectorEventLoopPolicy",
                            return_value=selected,
                            create=True,
                        ) as select,
                        patch.object(asyncio, "run", run),
                    ):
                        command = arguments(
                            "--scenario", "resources", "--resource-protocol", protocol
                        )
                        if error is None:
                            lifecycle.main(command)
                        else:
                            with self.assertRaises(type(error)) as raised:
                                lifecycle.main(command)
                            self.assertIs(raised.exception, error)
                        select.assert_called_once_with()
                    self.assertEqual(changes, [selected, original])

    def test_http3_and_non_windows_keep_the_existing_policy(self) -> None:
        for platform, protocol in (("win32", "h3"), ("linux", "h2")):
            with self.subTest(platform=platform, protocol=protocol):

                def run(operation):
                    operation.close()

                with (
                    patch.object(lifecycle.sys, "platform", platform),
                    patch.object(
                        lifecycle.metadata, "version", lifecycle.SUPPORTED.get
                    ),
                    patch.object(asyncio, "set_event_loop_policy") as change,
                    patch.object(asyncio, "run", run),
                ):
                    lifecycle.main(
                        arguments(
                            "--scenario", "resources", "--resource-protocol", protocol
                        )
                    )
                    change.assert_not_called()

    def test_invalid_options_and_dependencies_do_not_change_policy(self) -> None:
        for extra, version in (
            (("--idle", "nan"), lifecycle.SUPPORTED.get),
            ((), lambda _package: "wrong-version"),
        ):
            with self.subTest(extra=extra):
                with (
                    patch.object(lifecycle.sys, "platform", "win32"),
                    patch.object(lifecycle.metadata, "version", version),
                    patch.object(asyncio, "set_event_loop_policy") as change,
                    patch.object(asyncio, "run") as run,
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    lifecycle.main(arguments(*extra))
                change.assert_not_called()
                run.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "Windows Selector transport control")
class WindowsResetTests(unittest.TestCase):
    def test_verified_tls_reset_retires_original_listener_and_owned_stream(
        self,
    ) -> None:
        original = asyncio.get_event_loop_policy()
        observed = []

        async def capture(_args):
            loop = asyncio.get_running_loop()
            self.assertIsInstance(loop, asyncio.SelectorEventLoop)
            errors = []
            previous = loop.get_exception_handler()

            def record_error(loop, context):
                errors.append(context)
                if previous is not None:
                    previous(loop, context)
                else:
                    loop.default_exception_handler(context)

            loop.set_exception_handler(record_error)
            certificate = lifecycle.generate_certificate()
            context = lifecycle.server_context(certificate)
            context.set_alpn_protocols(["http/1.1"])
            run = lifecycle.Run("revalidate", "token", 100)
            owner = lifecycle.LifecycleServer(run)
            protocols = []
            native_sockets = []
            create = owner.new_protocol

            def protocol(context, name):
                created = create(context, name)
                protocols.append(created)
                return created

            def peer(port):
                trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                trust.load_verify_locations(cadata=certificate.certificate_pem.decode())
                trust.set_alpn_protocols(["http/1.1"])
                with (
                    socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
                    trust.wrap_socket(raw, server_hostname=HOSTNAME) as stream,
                ):
                    self.assertEqual(stream.selected_alpn_protocol(), "http/1.1")
                    stream.sendall(
                        b"GET /start?run=token HTTP/1.1\r\nHost: local\r\n\r\n"
                    )
                    response = bytearray()
                    while b"\r\n\r\n" not in response:
                        chunk = stream.recv(65536)
                        if not chunk:
                            raise EOFError("TLS peer ended before the response head")
                        response.extend(chunk)
                    head, body = response.split(b"\r\n\r\n", 1)
                    self.assertIn(b"200 OK", head)
                    fields = dict(
                        line.split(b": ", 1) for line in bytes(head).split(b"\r\n")[1:]
                    )
                    length = int(fields[b"content-length"])
                    while len(body) < length:
                        chunk = stream.recv(length - len(body))
                        if not chunk:
                            raise EOFError("TLS peer ended before the response body")
                        body.extend(chunk)
                    self.assertEqual(len(body), length)
                    self.assertGreater(length, 0)
                    stream.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0)
                    )

            primary = None
            try:
                with patch.object(owner, "new_protocol", protocol):
                    port = await owner.start("127.0.0.1", context, "main")
                    await asyncio.to_thread(peer, port)
                    await asyncio.wait_for(run.connection_ended.wait(), 5)
                    for accepted in protocols:
                        native_sockets.append(
                            accepted.transport.get_extra_info("socket")
                        )
                self.assertEqual(len(run.connections), 1)
                self.assertIsNotNone(run.connections[0].reset)
                self.assertTrue(run.connections[0].disconnects)
            except BaseException as error:
                primary = error
            try:
                await owner.close(primary)
                self.assertFalse(owner.protocols)
                self.assertFalse(owner.event_tasks)
                self.assertTrue(all(item.waiter.done() for item in owner.listeners))
                self.assertTrue(
                    all(not item.server.sockets for item in owner.listeners)
                )
                self.assertTrue(all(item.closed.done() for item in protocols))
                self.assertTrue(all(item.retired for item in protocols))
                self.assertTrue(all(item.fileno() == -1 for item in native_sockets))
                self.assertFalse(errors)
                observed.append(loop)
            finally:
                loop.set_exception_handler(previous)

        with patch.object(lifecycle, "capture", capture):
            lifecycle.main(arguments())
        self.assertIs(asyncio.get_event_loop_policy(), original)
        self.assertEqual(len(observed), 1)
        self.assertIsInstance(observed[0], asyncio.SelectorEventLoop)


if __name__ == "__main__":
    unittest.main()
