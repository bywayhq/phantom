"""Controls that prevent incorrect work from becoming an accepted baseline."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from run import accepted, accepted_recovery, quantile, sha


class AcceptanceTests(unittest.TestCase):
    def test_binary_identity_hashes_the_file_bytes(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_incomplete_or_duplicate_peer_requests_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        for observed in (11, 13):
            self.assertFalse(
                accepted(
                    {"failures": 0},
                    config,
                    {"requests": observed, "failures": 0, "proxy_connections": 0},
                )
            )

    def test_client_and_peer_failures_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        self.assertFalse(
            accepted(
                {"failures": 1},
                config,
                {"requests": 12, "failures": 0, "proxy_connections": 0},
            )
        )
        self.assertFalse(
            accepted(
                {"failures": 0},
                config,
                {"requests": 12, "failures": 1, "proxy_connections": 0},
            )
        )

    def test_proxy_route_must_actually_open_a_proxy_connection(self):
        phase = {"requests": 12, "failures": 0, "proxy_connections": 0}
        config = {"protocol": "h2", "requests": 10, "warmup": 2, "route": "connect"}
        self.assertFalse(accepted({"failures": 0}, config, phase))
        phase["proxy_connections"] = 1
        self.assertTrue(accepted({"failures": 0}, config, phase))
        config["route"] = "direct"
        self.assertFalse(accepted({"failures": 0}, config, phase))

    def test_small_tail_uses_observed_maximum_without_interpolation(self):
        self.assertEqual(quantile([10, 20, 30, 40], 0.99), 40)
        self.assertIsNone(quantile([], 0.99))

    def test_idle_peer_failures_and_mixed_allocation_intervals_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        phase = {"requests": 12, "failures": 0, "proxy_connections": 0}
        self.assertTrue(accepted_recovery({"heap_instrumented": False}, config, phase))
        self.assertFalse(accepted_recovery({"heap_instrumented": True}, config, phase))
        phase["failures"] = 1
        self.assertFalse(accepted_recovery({"heap_instrumented": False}, config, phase))


if __name__ == "__main__":
    unittest.main()
