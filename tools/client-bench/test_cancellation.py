"""Cancellation remains separate from completed transfers and network errors."""

import copy
import unittest

from client_result import validate_result
from curl_cffi_client import cleanup_error
from workload_config import effective_config, validate_cancellation


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.config = effective_config(
            {
                "protocol": "h2",
                "requests": 2,
                "warmup": 1,
                "concurrency": 2,
                "bytes": 65536,
                "chunk_delay_ms": 1,
                "cancel_after_bytes": 1024,
            }
        )
        sample = {
            "id": 0,
            "scheduled_ns": 0,
            "started_ns": 0,
            "application_wait_ns": 0,
            "build_ns": 0,
            "head_ns": 1,
            "first_byte_ns": 2,
            "complete_ns": 3,
            "bytes": 1024,
            "cancelled": True,
            "error": None,
        }
        self.raw = {
            "config": self.config,
            "elapsed_ns": 10,
            "heap_instrumented": False,
            "observer_storage_bytes": 0,
            "samples": [sample, sample | {"id": 1, "bytes": 65536, "cancelled": False}],
        }

    def test_valid_cancellation_has_a_prefix_and_a_complete_sibling(self):
        validate_cancellation(self.config)
        validate_result(self.raw, self.config)

    def test_failed_cleanup_is_retained_as_failure(self):
        record = self.raw["samples"][0]
        cleanup_error(record, "response cleanup", OSError("close failed"))
        self.assertFalse(record["cancelled"])
        self.assertIn("close failed", record["error"])
        validate_result(self.raw, self.config)

    def test_invalid_phase_and_unsupported_protocol_fail_explicitly(self):
        for change in (
            {"protocol": "h3"},
            {"route": "connect"},
            {"warmup": 0},
            {"cold": True},
            {"origins": 2},
            {"consume": "collect"},
            {"requests": 3},
            {"cancel_after_bytes": 65536},
            {"cancel_after_bytes": True},
            {"chunk_delay_ms": 0},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_cancellation(self.config | change)

    def test_false_cancellations_and_completed_bodies_are_rejected(self):
        for change in (
            {"cancelled": False},
            {"cancelled": 1},
            {"bytes": 0},
            {"bytes": 65536},
            {"error": "reset"},
        ):
            raw = copy.deepcopy(self.raw)
            raw["samples"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_result(raw, self.config)
        raw = copy.deepcopy(self.raw)
        raw["samples"][1]["cancelled"] = True
        with self.assertRaises(ValueError):
            validate_result(raw, self.config)


if __name__ == "__main__":
    unittest.main()
