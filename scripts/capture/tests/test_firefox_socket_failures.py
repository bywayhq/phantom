import asyncio
import errno
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks


class FailingWriter:
    def __init__(self, cause: BaseException) -> None:
        self.cause = cause
        self.closed = False

    def get_extra_info(self, name: str) -> tuple[str, int]:
        return ("127.0.0.1", 1)

    def write(self, _data: bytes) -> None:
        raise self.cause

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class OriginalFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_origin_callbacks_preserve_unexpected_write_failure(self) -> None:
        for name in ("handle_page", "handle_target"):
            with self.subTest(name=name):
                origin = hooks.Origins(hooks.SCENARIOS["http1-idle"])
                reader = asyncio.StreamReader()
                reader.feed_data(b"GET /fast HTTP/1.1\r\nHost: x\r\n\r\n")
                reader.feed_eof()
                cause = OSError(errno.EIO, "independent response failure")
                writer = FailingWriter(cause)

                with self.assertRaises(OSError) as observed:
                    await getattr(origin, name)(reader, writer)

                self.assertIs(observed.exception, cause)
                self.assertTrue(writer.closed)

    async def test_an_oversized_websocket_frame_is_rejected_before_payload(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x82\xff" + (2**63).to_bytes(8, "big"))
        cause = RuntimeError("must not read a payload")
        writer = FailingWriter(cause)
        writer.write = lambda _data: None

        with self.assertRaises(ValueError):
            await asyncio.wait_for(
                hooks.serve_websocket(
                    reader, writer, b"GET /ws HTTP/1.1\r\nSec-WebSocket-Key: x\r\n\r\n"
                ),
                1,
            )


class CaptureBoundaryTests(unittest.TestCase):
    def test_detach_preserves_original_failure(self) -> None:
        cause = OSError(errno.EIO, "independent detach failure")

        class Session:
            def detach(self) -> None:
                raise cause

        owner = hooks.Hooks(1, {})
        owner._session = Session()

        with self.assertRaises(OSError) as observed:
            owner.detach()

        self.assertIs(observed.exception, cause)
        self.assertIsInstance(owner._session, Session)

    def test_failed_process_listing_is_distinct_from_an_empty_listing(self) -> None:
        result = subprocess.CompletedProcess(
            ["powershell"], 1, stdout=b"", stderr=b"independent CIM failure"
        )
        with patch.object(hooks.subprocess, "run", return_value=result):
            with self.assertRaises(subprocess.CalledProcessError) as observed:
                hooks.profile_processes(Path("C:/Temp/profile"))

        self.assertEqual(observed.exception.returncode, 1)
        self.assertEqual(observed.exception.stderr, b"independent CIM failure")

    def test_fixture_metadata_cannot_create_an_extra_record(self) -> None:
        with self.assertRaises(ValueError):
            hooks.render_fixture(
                client_version="157.0",
                build_id="1",
                operating_system="Windows\nrun_0_hook_error_count=0",
                frida_version="17.9.10",
                launch_arguments="--x",
                scenario=hooks.SCENARIOS["h2"],
                runs=[],
            )


if __name__ == "__main__":
    unittest.main()
