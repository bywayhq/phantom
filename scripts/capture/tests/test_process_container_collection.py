"""Keep exited snapshot members distinct from uncollected live members."""

import contextlib
import time
import unittest
from unittest import mock

from scripts.capture import process_container


class WindowsJobCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.owner = object.__new__(process_container.ProcessContainer)
        self.owner.job = 17
        self.owner._windows_snapshot_complete = False
        self.owner._windows_snapshot_error = None
        self.owner._native_handles = []
        self.owner._windows_members = []
        self.owner._lost_failures = []
        self.deadline = time.monotonic() + 20
        self.failures = []
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        self.stop = patches.enter_context(
            mock.patch.object(process_container, "_windows_stop_admission")
        )
        self.members = patches.enter_context(
            mock.patch.object(process_container, "_windows_process_ids")
        )
        self.open = patches.enter_context(
            mock.patch.object(process_container, "_windows_open_process")
        )
        self.in_job = patches.enter_context(
            mock.patch.object(process_container, "_windows_in_job", return_value=True)
        )

    def collect(self) -> None:
        self.owner._collect_windows_job(self.failures, self.deadline)
        self.stop.assert_called_once_with(17)

    @staticmethod
    def windows_error(code: int) -> OSError:
        error = OSError("controlled OpenProcess failure")
        error.winerror = code
        return error

    def test_exited_snapshot_member_does_not_hide_a_remaining_member(self) -> None:
        self.members.side_effect = [[41, 42], [42]]
        self.open.side_effect = [self.windows_error(87), 420]

        self.collect()

        self.assertEqual(self.failures, [])
        self.assertTrue(self.owner._windows_snapshot_complete)
        self.assertEqual(self.owner._windows_members, [420])
        self.assertEqual(self.owner._native_handles, [])
        self.assertEqual(
            self.members.call_args_list,
            [mock.call(17, self.deadline), mock.call(17, self.deadline)],
        )
        self.in_job.assert_called_once_with(420, 17)

    def test_open_failure_for_a_current_member_remains_permanent(self) -> None:
        error = self.windows_error(87)
        self.members.side_effect = [[41], [41]]
        self.open.side_effect = error

        self.collect()

        self.assertFalse(self.owner._windows_snapshot_complete)
        self.assertIs(self.owner._windows_snapshot_error, error)
        self.assertEqual(self.failures, [("collect capture job members", error)])
        self.assertEqual(
            self.owner._lost_failures, [("capture job snapshot incomplete", error)]
        )

    def test_other_open_failures_are_not_reclassified_as_exited(self) -> None:
        for error in [self.windows_error(5), OSError(87, "unqualified error")]:
            with self.subTest(error=error):
                self.owner._windows_snapshot_error = None
                self.owner._lost_failures.clear()
                self.failures.clear()
                self.members.reset_mock(side_effect=True)
                self.members.return_value = [41]
                self.open.side_effect = error
                self.stop.reset_mock()

                self.collect()

                self.assertIs(self.owner._windows_snapshot_error, error)
                self.members.assert_called_once_with(17, self.deadline)

    def test_failed_membership_refresh_does_not_certify_cleanup(self) -> None:
        open_error = self.windows_error(87)
        query_error = OSError("controlled membership query failure")
        self.members.side_effect = [[41], query_error]
        self.open.side_effect = open_error

        self.collect()

        self.assertFalse(self.owner._windows_snapshot_complete)
        self.assertIs(self.owner._windows_snapshot_error, query_error)
        self.assertIs(query_error.__context__, open_error)
        self.assertEqual(self.failures, [("collect capture job members", query_error)])

    def test_a_handle_outside_the_job_is_not_treated_as_an_exited_member(self) -> None:
        self.members.return_value = [41]
        self.open.return_value = 410
        self.in_job.return_value = False

        self.collect()

        self.assertFalse(self.owner._windows_snapshot_complete)
        self.assertEqual(self.owner._native_handles, [410])
        self.assertIn("identity changed", str(self.owner._windows_snapshot_error))
        self.members.assert_called_once_with(17, self.deadline)


if __name__ == "__main__":
    unittest.main()
