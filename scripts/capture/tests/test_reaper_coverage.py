import copy
import tempfile
import unittest
from pathlib import Path

from scripts.capture.reaper_coverage import (
    COVERAGE_SCHEMA,
    EXPECTED_PROBE_IDS,
    SNAPSHOT_DATE,
    SOURCE_MANIFEST_SHA256,
    SOURCE_SCHEMA,
    CoverageError,
    load_coverage,
    validate_coverage,
)


class ReaperCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repo_root = Path(self.temporary_directory.name)
        source = self.repo_root / "crates" / "probe" / "tests.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            "\n".join(
                f"#[test]\nfn {self.regression_test_name(probe_id)}() {{}}"
                for probe_id in EXPECTED_PROBE_IDS
            ),
            encoding="utf-8",
        )
        self.document = {
            "schema": COVERAGE_SCHEMA,
            "source": {
                "schema": SOURCE_SCHEMA,
                "snapshot_date": SNAPSHOT_DATE,
                "manifest_sha256": SOURCE_MANIFEST_SHA256,
            },
            "probes": [
                {
                    "id": probe_id,
                    "regressions": [
                        {
                            "file": "crates/probe/tests.rs",
                            "test": self.regression_test_name(probe_id),
                        }
                    ],
                }
                for probe_id in EXPECTED_PROBE_IDS
            ],
        }

    @staticmethod
    def regression_test_name(probe_id: str) -> str:
        return f"covers_{probe_id.replace('-', '_')}"

    def assert_invalid(self, document: object, message: str) -> None:
        with self.assertRaisesRegex(CoverageError, message):
            validate_coverage(document, self.repo_root)

    def test_accepts_complete_snapshot_deterministically(self) -> None:
        first = validate_coverage(self.document, self.repo_root)
        second = validate_coverage(copy.deepcopy(self.document), self.repo_root)

        self.assertEqual(first, len(EXPECTED_PROBE_IDS))
        self.assertEqual(second, first)

    def test_rejects_duplicate_probe(self) -> None:
        document = copy.deepcopy(self.document)
        document["probes"].append(copy.deepcopy(document["probes"][0]))

        self.assert_invalid(document, "duplicate probe IDs")

    def test_rejects_missing_probe(self) -> None:
        document = copy.deepcopy(self.document)
        document["probes"].pop()

        self.assert_invalid(document, "missing probe IDs: h3-retry")

    def test_rejects_passive_probe(self) -> None:
        document = copy.deepcopy(self.document)
        document["probes"][0]["id"] = "passive"

        self.assert_invalid(document, "passive is not an active adversarial probe")

    def test_rejects_stale_source_file(self) -> None:
        document = copy.deepcopy(self.document)
        document["probes"][0]["regressions"][0]["file"] = "crates/missing.rs"

        self.assert_invalid(document, "source file .* does not exist")

    def test_rejects_stale_test_name(self) -> None:
        document = copy.deepcopy(self.document)
        document["probes"][0]["regressions"][0]["test"] = "missing_test"

        self.assert_invalid(document, "annotated Rust test .* does not exist")

    def test_rejects_unannotated_function(self) -> None:
        source = self.repo_root / "crates" / "probe" / "tests.rs"
        source.write_text("fn helper_only() {}\n", encoding="utf-8")
        document = copy.deepcopy(self.document)
        document["probes"][0]["regressions"][0]["test"] = "helper_only"

        self.assert_invalid(document, "annotated Rust test .* does not exist")

    def test_repository_snapshot_maps_to_existing_tests(self) -> None:
        repository = Path(__file__).resolve().parents[3]
        coverage = (
            repository
            / "fixtures"
            / "adversarial"
            / "reaper"
            / SNAPSHOT_DATE
            / "coverage.json"
        )

        self.assertEqual(validate_coverage(load_coverage(coverage), repository), 22)


if __name__ == "__main__":
    unittest.main()
