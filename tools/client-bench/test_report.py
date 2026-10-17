"""Keep diagnostic instrumentation out of accepted timing comparisons."""

import json
import tempfile
import unittest
from pathlib import Path

from report import aggregate


class ReportTests(unittest.TestCase):
    def test_failed_trial_remains_visible_without_becoming_a_speed_result(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "results.json").write_text("[]")
            (folder / "failures.json").write_text(json.dumps([{"name": "case"}]))
            self.assertEqual(
                aggregate(folder),
                [{"name": "case", "accepted_trials": 0, "failed_trials": 1}],
            )

    def test_allocation_profile_is_rejected_as_a_speed_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "results.json").write_text(
                json.dumps([{"name": "case", "summary": {"heap_instrumented": True}}])
            )
            (folder / "failures.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "allocation-profiler timings"):
                aggregate(folder)

    def test_external_profiler_is_rejected_even_without_allocation_instrumentation(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "identity.json").write_text(
                json.dumps({"external_profiler": True})
            )
            with self.assertRaisesRegex(ValueError, "profiler timings"):
                aggregate(folder)


if __name__ == "__main__":
    unittest.main()
