import argparse
import asyncio
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from scripts.conformance import aioquic_versions as versions
from scripts.conformance.aioquic_versions import (
    WSAENOBUFS,
    main,
    serve_past_reserved_ports,
    version_report,
)
from scripts.conformance.loopback_tls import LoopbackCertificate


class RefusedAtReservedBlock(OSError):
    winerror = WSAENOBUFS


class AioquicVersionsTests(unittest.TestCase):
    def test_reports_a_connection_moved_from_version_1_to_version_2(self) -> None:
        self.assertEqual(
            version_report(1, 0x6B3343CF, 1, [0x1A2A3A4A, 0x6B3343CF, 1], False, False),
            "first_packet_version=0x00000001 negotiated_version=0x6b3343cf "
            "chosen_version=0x00000001 "
            "available_versions=0x1a2a3a4a,0x6b3343cf,0x00000001 "
            "resumed=false early_data_accepted=false",
        )

    def test_reports_a_client_without_version_information(self) -> None:
        self.assertEqual(
            version_report(None, 1, None, [], True, True),
            "first_packet_version=none negotiated_version=0x00000001 "
            "chosen_version=none available_versions=none "
            "resumed=true early_data_accepted=true",
        )

    def test_refuses_a_non_loopback_listener(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--root", "root.der", "--port-file", "port", "--listen", "192.0.2.1"])

    def test_refuses_invalid_request_counts_before_server_preparation(self) -> None:
        for value in ["0", "-1", "invalid"]:
            with (
                self.subTest(value=value),
                patch(
                    "scripts.conformance.aioquic_versions.run", new_callable=AsyncMock
                ) as run,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as failure:
                    main(
                        [
                            "--root",
                            "root.der",
                            "--port-file",
                            "port",
                            "--requests",
                            value,
                        ]
                    )
                self.assertEqual(failure.exception.code, 2)
                run.assert_not_called()

    def test_preserves_default_and_explicit_positive_request_counts(self) -> None:
        for arguments, expected in [
            ([], 3),
            (["--requests", "1"], 1),
            (["--requests", "7"], 7),
        ]:
            with (
                self.subTest(arguments=arguments),
                patch(
                    "scripts.conformance.aioquic_versions.run", new_callable=AsyncMock
                ) as run,
            ):
                main(["--root", "root.der", "--port-file", "port", *arguments])
                run.assert_awaited_once()
                self.assertEqual(run.call_args.args[0].requests, expected)

    def test_a_refused_bind_to_port_zero_is_retried_three_times(self) -> None:
        binds = []

        async def serve_at() -> str:
            binds.append(None)
            raise RefusedAtReservedBlock() if len(binds) < 4 else OSError("in use")

        with self.assertRaisesRegex(OSError, "in use"):
            asyncio.run(serve_past_reserved_ports(serve_at))
        self.assertEqual(len(binds), 4)

    def test_other_bind_errors_are_not_retried(self) -> None:
        binds = []

        async def serve_at() -> str:
            binds.append(None)
            raise OSError("in use")

        with self.assertRaises(OSError):
            asyncio.run(serve_past_reserved_ports(serve_at))
        self.assertEqual(len(binds), 1)


class ControlledServer:
    def __init__(self):
        self._transport = self
        self.close_calls = 0

    def get_extra_info(self, key):
        if key != "sockname":
            raise AssertionError(f"unexpected transport property: {key}")
        return ("127.0.0.1", 49123)

    def close(self):
        self.close_calls += 1


class AioquicOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="aioquic-ownership-test-")
        self.fixture = Path(temporary.name).resolve()
        self.fixture.relative_to(Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.internal = self.fixture / "cert-work"
        self.outputs = self.fixture / "published"
        self.outputs.mkdir()
        self.args = argparse.Namespace(
            root=self.outputs / "root.der",
            port_file=self.outputs / "port",
            listen="127.0.0.1",
            requests=1,
        )
        self.server = ControlledServer()
        self.cert_error = None
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)

        def scratch_directory(*_args, **_kwargs):
            self.internal.mkdir()
            return str(self.internal)

        def certificate(directory):
            self.assertEqual(directory, self.internal)
            if self.cert_error is not None:
                raise self.cert_error
            root = directory / "root.der"
            root.write_bytes(b"controlled root artifact, not a valid TLS certificate")
            return LoopbackCertificate(
                root, directory / "leaf.key", directory / "leaf.pem"
            )

        async def serve(host, port, **_options):
            self.assertEqual((host, port), ("127.0.0.1", 0))
            versions.ReportingProtocol.done.set()
            return self.server

        stack.enter_context(
            mock.patch.object(versions.tempfile, "mkdtemp", scratch_directory)
        )
        stack.enter_context(
            mock.patch.object(versions, "generate_loopback_certificate", certificate)
        )
        stack.enter_context(mock.patch.object(versions, "QuicConfiguration"))
        self.serve = stack.enter_context(
            mock.patch.object(versions, "serve", side_effect=serve)
        )
        stack.enter_context(
            mock.patch.object(versions.asyncio, "sleep", new_callable=mock.AsyncMock)
        )

    def test_success_closes_server_and_preserves_published_artifacts(self):
        asyncio.run(versions.run(self.args))
        self.assertEqual(self.server.close_calls, 1)
        self.assertEqual(self.args.port_file.read_text(encoding="utf-8"), "49123")
        self.assertEqual(
            self.args.root.read_bytes(),
            b"controlled root artifact, not a valid TLS certificate",
        )
        self.serve.assert_called_once()

    def test_success_releases_certificate_scratch_directory(self):
        asyncio.run(versions.run(self.args))
        self.assertEqual(self.server.close_calls, 1)
        self.assertTrue(self.args.root.is_file())
        self.assertFalse(
            self.internal.exists(),
            "certificate scratch directory leaked after normal shutdown",
        )

    def test_port_publication_failure_closes_acquired_server(self):
        self.args.port_file = self.outputs / "missing-parent" / "port"
        with self.assertRaises(FileNotFoundError):
            asyncio.run(versions.run(self.args))
        self.serve.assert_called_once()
        self.assertTrue(self.args.root.is_file())
        self.assertEqual(
            self.server.close_calls,
            1,
            "acquired server leaked before the close-finally scope",
        )

    def test_certificate_failure_releases_scratch_before_server_preparation(self):
        error = FileNotFoundError("controlled certificate preparation failure")
        self.cert_error = error
        with self.assertRaises(FileNotFoundError) as failed:
            asyncio.run(versions.run(self.args))
        self.assertIs(failed.exception, error)
        self.serve.assert_not_called()
        self.assertEqual(self.server.close_calls, 0)
        self.assertFalse(
            self.internal.exists(),
            "certificate scratch directory leaked after preparation failure",
        )


if __name__ == "__main__":
    unittest.main()
