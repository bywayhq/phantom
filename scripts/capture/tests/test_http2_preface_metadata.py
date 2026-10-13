import argparse
import asyncio
import errno
import inspect
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import http2_preface_ping as preface
from scripts.capture.browser_launch import LaunchPlan
from scripts.capture.fixture_file import write_text_fixture


def capture_arguments():
    return argparse.Namespace(
        client="Chromium",
        client_version="154.0",
        operating_system="Windows",
        listen="127.0.0.1",
        idle=11.5,
        short=9.0,
    )


class MetadataTests(unittest.TestCase):
    def test_raw_metadata_fails_before_certificate_acquisition(self):
        for name in ("client", "client_version", "operating_system"):
            for value in (
                "x\nframe_0=forged",
                "x\rforged",
                "x\t",
                "x\x00",
                "x\x7f",
                "é",
            ):
                args = capture_arguments()
                setattr(args, name, value)
                with (
                    self.subTest(name=name, value=value),
                    mock.patch.object(
                        preface,
                        "generate_certificate",
                        side_effect=AssertionError("certificate acquisition crossed"),
                    ) as certificate,
                ):
                    with self.assertRaisesRegex(ValueError, name):
                        asyncio.run(preface.capture(args))
                    certificate.assert_not_called()

    def test_rendered_metadata_cannot_replace_a_valid_fixture(self):
        run = preface.Run("token", 11.5, 9.0)
        run.page_connection = preface.FrameLog()
        for name in (
            "client",
            "client_version",
            "operating_system",
            "launch_mode",
            "launch_arguments",
        ):
            for value in (
                "x\nframe_0=forged",
                "x\rforged",
                "x\t",
                "x\x00",
                "x\x7f",
                "é",
            ):
                args = capture_arguments()
                plan = mock.Mock(client_name="Chromium", launch_mode="automatic")
                arguments = "--headless"
                if name == "launch_mode":
                    plan.launch_mode = value
                elif name == "launch_arguments":
                    arguments = value
                else:
                    setattr(args, name, value)

                with (
                    self.subTest(name=name, value=value),
                    tempfile.TemporaryDirectory() as directory,
                    mock.patch.object(preface, "capture_tool", return_value="python"),
                ):
                    destination = Path(directory) / "preface-ping.txt"
                    destination.write_bytes(b"previous fixture\n")
                    with self.assertRaisesRegex(ValueError, name):
                        text = preface.fixture(args, plan, arguments, run, 0)
                        write_text_fixture(destination, text)
                    self.assertEqual(destination.read_bytes(), b"previous fixture\n")

    def test_printable_metadata_keeps_literal_records_and_empty_values(self):
        args = capture_arguments()
        args.client = ""
        args.client_version = ""
        args.operating_system = "Windows 11 !~"
        run = preface.Run("token", 11.5, 9.0)
        run.page_connection = preface.FrameLog()
        plan = LaunchPlan(
            browser="chrome", executable=Path("chrome.exe"), headless=True
        )

        with mock.patch.object(preface, "capture_tool", return_value="python"):
            text = preface.fixture(args, plan, "", run, 0)

        self.assertIn("client=Google Chrome\n", text)
        self.assertIn("client_version=\n", text)
        self.assertIn("operating_system=Windows 11 !~\n", text)
        self.assertIn("launch_arguments=\n", text)
        self.assertEqual(text.count("frame_count="), 1)


class FactoryOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_factory_failure_retires_the_actual_accepted_socket(self):
        for primary in (
            ValueError("original protocol construction failure"),
            OSError(errno.EIO, "original protocol construction I/O failure"),
            MemoryError("original protocol construction allocation failure"),
        ):
            with self.subTest(error=type(primary)):
                await self.check_factory_failure(primary)

    async def check_factory_failure(self, primary):
        run = preface.Run("token", 11.5, 9.0)
        owner = preface.PrefaceServer(run, None)
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        accepted_sockets = []
        unexpected = []
        client = None

        def observe_failure(_loop, context):
            if context.get("exception") is not primary:
                unexpected.append(context)

        def fail_factory(_owner):
            # Observe the actual accepted socket before the backend constructs
            # its transport. Test-only backup closes it after the EOF assertion.
            frame = inspect.currentframe()
            try:
                while frame is not None:
                    if frame.f_code.co_name in {"_accept_connection2", "loop"}:
                        accepted = frame.f_locals.get("conn")
                        if isinstance(accepted, socket.socket):
                            accepted_sockets.append(accepted)
                    frame = frame.f_back
            finally:
                del frame
            raise primary

        try:
            await owner.start("127.0.0.1")
            address = ("127.0.0.1", owner.port)
            loop.set_exception_handler(observe_failure)
            with mock.patch.object(
                preface, "PrefaceProtocol", side_effect=fail_factory
            ):
                client = await asyncio.open_connection(*address)
                await asyncio.wait_for(run.done.wait(), 2)
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                protocols = tuple(owner.protocols)
                with self.assertRaises(type(primary)) as raised:
                    await owner.close(primary)

            self.assertIs(raised.exception, primary)
            self.assertIs(run.failure, primary)
            self.assertEqual(await asyncio.wait_for(client[0].read(1), 0.5), b"")
            self.assertEqual(len(protocols), 1)
            self.assertTrue(protocols[0].retired)
            self.assertTrue(protocols[0].closed.done())
            self.assertFalse(owner.protocols)
            self.assertEqual(unexpected, [])
            self.assertEqual(len(accepted_sockets), 1)
            self.assertTrue(
                all(accepted.fileno() == -1 for accepted in accepted_sockets)
            )
            rebound = await asyncio.start_server(lambda _r, w: w.close(), *address)
            rebound.close()
            await rebound.wait_closed()
        finally:
            loop.set_exception_handler(previous_handler)
            for accepted in accepted_sockets:
                accepted.close()
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            with self.assertRaises(type(primary)):
                await owner.close(primary)
