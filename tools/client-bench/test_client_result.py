"""Malformed adapter output must never become an accepted speed result."""

import copy
import unittest

from client_result import validate_result
from run import accepted
from workload_config import effective_config


class ClientResultTests(unittest.TestCase):
    def setUp(self):
        self.config = {"requests": 1, "bytes": 2, "protocol": "h2"}
        self.raw = {
            "config": effective_config(self.config),
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
        self.raw["config"] = effective_config(self.config)
        validate_result(self.raw, self.config)
        self.config["protocol"] = "construct"
        self.raw["config"] = effective_config(self.config)
        self.raw["samples"][0].update(bytes=0, head_ns=0, build_ns=2)
        validate_result(self.raw, self.config)

    def test_unobservable_head_needs_a_reason_and_stays_null(self):
        self.raw["samples"][0]["head_ns"] = None
        with self.assertRaises(ValueError):
            validate_result(self.raw, self.config)
        self.raw["unavailable_timings"] = {
            "head_ns": "This public API returns after the first body chunk."
        }
        validate_result(self.raw, self.config)
        for declaration in ({"head_ns": ""}, {"complete_ns": "unknown"}, []):
            self.raw["unavailable_timings"] = declaration
            with self.assertRaises(ValueError):
                validate_result(self.raw, self.config)
        self.raw["unavailable_timings"] = {"head_ns": "Unavailable."}
        self.raw["samples"][0]["head_ns"] = 1
        with self.assertRaises(ValueError):
            validate_result(self.raw, self.config)

    def test_failed_before_head_samples_are_retained_but_not_accepted(self):
        self.config.update(requests=2, warmup=0)
        self.raw["config"] = effective_config(self.config)
        failed = copy.deepcopy(self.raw["samples"][0])
        failed.update(
            id=1, head_ns=None, first_byte_ns=None, bytes=0, error="connect failed"
        )
        self.raw["samples"].append(failed)
        validate_result(self.raw, self.config)
        self.assertFalse(
            accepted(
                {"failures": 1},
                self.config,
                {"requests": 1, "failures": 0, "proxy_connections": 0},
            )
        )
        for error in (None, False, 1, {}):
            failed["error"] = error
            with self.subTest(error=error), self.assertRaises(ValueError):
                validate_result(self.raw, self.config)
        failed["error"] = "connect failed"
        del failed["head_ns"]
        with self.assertRaisesRegex(ValueError, "declare head"):
            validate_result(self.raw, self.config)

    def test_omitted_defaults_and_out_of_phase_samples_are_rejected(self):
        for change in ({"cold": True}, {"workers": 16}, {"consume": "collect"}):
            raw = copy.deepcopy(self.raw)
            raw["config"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_result(raw, self.config)
        raw = copy.deepcopy(self.raw)
        del raw["config"]["cold"]
        with self.assertRaises(ValueError):
            validate_result(raw, self.config)
        for started in (8, 11):
            raw = copy.deepcopy(self.raw)
            raw["samples"][0].update(started_ns=started, application_wait_ns=started)
            with self.subTest(started=started), self.assertRaises(ValueError):
                validate_result(raw, self.config)

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
