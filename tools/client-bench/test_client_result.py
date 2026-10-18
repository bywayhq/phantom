"""Malformed adapter output must never become an accepted speed result."""

import copy
import unittest

from client_result import validate_result


class ClientResultTests(unittest.TestCase):
    def setUp(self):
        self.config = {"requests": 1, "bytes": 2, "protocol": "h2"}
        self.raw = {
            "config": dict(self.config),
            "elapsed_ns": 10,
            "heap_instrumented": False,
            "observer_storage_bytes": 0,
            "samples": [
                {
                    "id": 0,
                    "scheduled_ns": 0,
                    "started_ns": 0,
                    "application_wait_ns": 0,
                    "build_ns": 0,
                    "head_ns": 1,
                    "first_byte_ns": 2,
                    "complete_ns": 3,
                    "bytes": 2,
                    "error": None,
                }
            ],
        }

    def test_valid_samples_preserve_null_first_byte_and_constructor_semantics(self):
        validate_result(self.raw, self.config)
        self.raw["samples"][0]["first_byte_ns"] = None
        with self.assertRaisesRegex(ValueError, "nonempty streams"):
            validate_result(self.raw, self.config)
        self.config["consume"] = "collect"
        self.raw["config"] = dict(self.config)
        validate_result(self.raw, self.config)
        self.config["protocol"] = "construct"
        self.raw["config"] = dict(self.config)
        self.raw["samples"][0].update(bytes=0, head_ns=0, build_ns=2)
        validate_result(self.raw, self.config)

    def test_negative_nonfinite_and_boolean_numeric_results_are_rejected(self):
        for value in (-1, 0, float("nan"), float("inf"), True):
            raw = copy.deepcopy(self.raw)
            raw["elapsed_ns"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_result(raw, self.config)
        for field in ("bytes", "head_ns", "complete_ns", "first_byte_ns"):
            for value in (-1, float("nan"), True):
                raw = copy.deepcopy(self.raw)
                raw["samples"][0][field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    validate_result(raw, self.config)

    def test_workload_changes_duplicate_ids_and_false_byte_totals_are_rejected(self):
        for mutate in (
            lambda raw: raw["config"].update(bytes=3),
            lambda raw: raw["samples"][0].update(bytes=3),
            lambda raw: raw["samples"].append(raw["samples"][0]),
            lambda raw: raw["samples"][0].update(id=1),
            lambda raw: raw["samples"][0].update(first_byte_ns=0),
            lambda raw: raw.update(heap_instrumented=0),
        ):
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.assertRaises(ValueError):
                validate_result(raw, self.config)


if __name__ == "__main__":
    unittest.main()
