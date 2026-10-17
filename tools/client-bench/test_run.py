"""Controls that prevent incorrect work from becoming an accepted baseline."""

import unittest

from run import accepted, quantile


class AcceptanceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
