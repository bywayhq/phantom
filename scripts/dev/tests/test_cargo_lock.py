import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BASH = shutil.which("bash")
if BASH is not None and "system32" in BASH.lower():
    BASH = None

WAIT_COMMAND = """\
touch "$STARTED"
while [[ ! -e $RELEASE ]]; do sleep 0.05; done
touch "$FINISHED"
"""
RUN_HELPER = """\
sleep() {
  if [[ $1 == 5 ]]; then
    touch "$WAITING"
    command sleep 0.05
  else
    command sleep "$@"
  fi
}
export -f sleep
printf '%s\\n' "$$" > "$WRAPPER_PID"
if [[ ${DENIED_PROBE:-false} == true ]]; then
  kill() { echo 'kill: Operation not permitted' >&2; return 1; }
  export -f kill
fi
exec bash "$1" bash -c "$2"
"""


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class CargoLockTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.helper = self.root / "scripts/dev/with-cargo-lock.sh"
        self.helper.parent.mkdir(parents=True)
        shutil.copyfile(REPO / "scripts/dev/with-cargo-lock.sh", self.helper)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        self.lock = self.root / ".git/phantom-cargo-lock"
        self.environment = {**os.environ, "PHANTOM_CARGO_SLOTS": "1"}

    def git(self, *arguments: str) -> None:
        subprocess.run(["git", "-C", str(self.root), *arguments], check=True)

    def start(self, name: str, command: str, *, slots: int = 1):
        paths = {
            key: self.root / f"{name}-{key.lower()}"
            for key in ("STARTED", "RELEASE", "FINISHED", "WAITING", "WRAPPER_PID")
        }
        env = {**self.environment, **{k: str(v) for k, v in paths.items()}}
        env["PHANTOM_CARGO_SLOTS"] = str(slots)
        process = subprocess.Popen(
            [BASH, "-c", RUN_HELPER, "lock-test", str(self.helper), command],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def stop() -> None:
            paths["RELEASE"].touch()
            if process.poll() is None:
                self.signal(process, "TERM", paths["WRAPPER_PID"])
            process.communicate(timeout=15)

        self.addCleanup(stop)
        return process, paths

    def wait_for(self, path: Path) -> None:
        deadline = time.monotonic() + 15
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"timed out waiting for {path}")
            time.sleep(0.01)

    def signal(self, process: subprocess.Popen, name: str, pid_file: Path) -> None:
        if pid_file.exists():
            pid = pid_file.read_text().strip()
            subprocess.run(
                [BASH, "-c", 'kill -"$1" "$2"', "signal", name, pid], check=False
            )
        else:
            process.terminate()

    def finish(self, process: subprocess.Popen, expected: int = 0) -> str:
        output, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, expected, output + error)
        return error

    def test_a_dead_holder_is_preserved_without_starting_another_command(self) -> None:
        self.lock.mkdir()
        (self.lock / "pid").write_text("2147483647\n")
        (self.lock / "owner").write_text("crashed wrapper with possible live child\n")
        before = {p.name: p.read_bytes() for p in self.lock.iterdir()}
        process, paths = self.start("stale", 'touch "$STARTED"')
        error = self.finish(process, 75)

        self.assertIn("surviving child processes", error)
        self.assertIn("manually removing", error)
        self.assertFalse(paths["STARTED"].exists())
        self.assertEqual({p.name: p.read_bytes() for p in self.lock.iterdir()}, before)
        self.assertEqual(
            list(self.lock.parent.glob("phantom-cargo-lock*")), [self.lock]
        )

    def test_live_contention_starts_the_waiter_after_the_holder_finishes(self) -> None:
        first, first_paths = self.start("first", WAIT_COMMAND)
        self.wait_for(first_paths["STARTED"])
        self.environment["FINISHED_BEFORE"] = str(first_paths["FINISHED"])
        second, second_paths = self.start(
            "second", '[[ -e $FINISHED_BEFORE ]] || exit 23; touch "$STARTED"'
        )
        self.wait_for(second_paths["WAITING"])
        self.assertFalse(second_paths["STARTED"].exists())
        first_paths["RELEASE"].touch()
        self.finish(first)
        self.finish(second)

        self.assertTrue(first_paths["FINISHED"].exists())
        self.assertTrue(second_paths["STARTED"].exists())
        self.assertFalse(self.lock.exists())

    def test_two_slots_admit_two_holders_and_keep_a_third_waiting(self) -> None:
        first, first_paths = self.start("first", WAIT_COMMAND, slots=2)
        self.wait_for(first_paths["STARTED"])
        second, second_paths = self.start("second", WAIT_COMMAND, slots=2)
        self.wait_for(second_paths["STARTED"])
        self.environment["FINISHED_BEFORE"] = str(first_paths["FINISHED"])
        third, third_paths = self.start(
            "third", '[[ -e $FINISHED_BEFORE ]] || exit 23; touch "$STARTED"', slots=2
        )
        self.wait_for(third_paths["WAITING"])
        self.assertFalse(third_paths["STARTED"].exists())
        first_paths["RELEASE"].touch()
        self.finish(first)
        self.finish(third)

        self.assertIsNone(second.poll())
        self.assertTrue((self.root / ".git/phantom-cargo-lock.1").exists())
        second_paths["RELEASE"].touch()
        self.finish(second)

    def test_sibling_worktrees_contend_for_the_same_common_directory_slot(self) -> None:
        self.git("add", "scripts/dev/with-cargo-lock.sh")
        self.git(
            "-c",
            "user.name=Arya Alikhani",
            "-c",
            "user.email=AryaAlikhani@icloud.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        )
        sibling = self.root / "sibling"
        self.git("worktree", "add", "--detach", str(sibling))
        first, first_paths = self.start("original", WAIT_COMMAND)
        self.wait_for(first_paths["STARTED"])
        self.helper = sibling / "scripts/dev/with-cargo-lock.sh"
        self.environment["FINISHED_BEFORE"] = str(first_paths["FINISHED"])
        second, second_paths = self.start(
            "sibling", '[[ -e $FINISHED_BEFORE ]] || exit 23; touch "$STARTED"'
        )
        self.wait_for(second_paths["WAITING"])
        self.assertFalse(second_paths["STARTED"].exists())
        first_paths["RELEASE"].touch()
        self.finish(first)
        self.finish(second)
        self.assertFalse(self.lock.exists())

    def test_command_failure_releases_its_slot_and_returns_its_status(self) -> None:
        process, _ = self.start("failure", "exit 37")
        self.finish(process, 37)
        self.assertFalse(self.lock.exists())

    def test_signal_cleanup_waits_for_the_command_to_finish(self) -> None:
        for signal, status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal):
                process, paths = self.start(signal.lower(), WAIT_COMMAND)
                self.wait_for(paths["STARTED"])
                self.signal(process, signal, paths["WRAPPER_PID"])
                self.assertTrue(self.lock.exists())
                paths["RELEASE"].touch()
                self.finish(process, status)
                self.assertFalse(self.lock.exists())

    def test_unknown_holder_metadata_keeps_waiters_blocked(self) -> None:
        for pid in (None, "not-a-pid\n", "0\n"):
            with self.subTest(pid=pid):
                self.lock.mkdir()
                if pid is not None:
                    (self.lock / "pid").write_text(pid)
                process, paths = self.start("unknown", 'touch "$STARTED"')
                self.wait_for(paths["WAITING"])
                self.assertIsNone(process.poll())
                self.assertFalse(paths["STARTED"].exists())
                shutil.rmtree(self.lock)
                self.finish(process)
                paths["STARTED"].unlink()
                paths["WAITING"].unlink()

    def test_a_denied_process_probe_does_not_report_a_dead_holder(self) -> None:
        self.lock.mkdir()
        (self.lock / "pid").write_text("2147483647\n")
        self.environment["DENIED_PROBE"] = "true"
        process, paths = self.start("denied", 'touch "$STARTED"')
        self.wait_for(paths["WAITING"])
        self.assertIsNone(process.poll())
        self.assertTrue(self.lock.exists())
        self.assertFalse(paths["STARTED"].exists())
        shutil.rmtree(self.lock)
        self.finish(process)


if __name__ == "__main__":
    unittest.main()
