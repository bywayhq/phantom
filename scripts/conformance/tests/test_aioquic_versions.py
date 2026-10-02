import asyncio
import unittest

from scripts.conformance.aioquic_versions import (
    WSAENOBUFS,
    main,
    serve_past_reserved_ports,
    version_report,
)


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


if __name__ == "__main__":
    unittest.main()
