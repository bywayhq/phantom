import subprocess
import sys
import unittest

from scripts.capture.process_container import ProcessContainer, popen_options


class ProcessContainerTests(unittest.TestCase):
    def test_containment_is_still_reported_after_close(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], **popen_options()
        )
        container = ProcessContainer(process)
        try:
            self.assertTrue(container.contained)
        finally:
            container.close()

        self.assertTrue(container.contained)
        self.assertIsNotNone(process.poll())

    def test_close_is_safe_after_the_process_exits(self) -> None:
        process = subprocess.Popen([sys.executable, "-c", "pass"], **popen_options())
        container = ProcessContainer(process)
        process.wait(timeout=30)
        container.close()
        container.close()

        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
