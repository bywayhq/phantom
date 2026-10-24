"""Resolver ownership controls use temporary directories, never host settings."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import mac_native_dns_guard as guard

NONCE = "ab" * 16
SOURCE = Path(guard.__file__).resolve()


class InputTests(unittest.TestCase):
    def test_only_fixed_nonce_and_high_port_are_accepted(self) -> None:
        self.assertEqual(guard.resolver_name(NONCE, 1024), f"n-{NONCE}.phantom.test")
        for nonce, port in (
            ("../elsewhere", 1234),
            ("A" * 32, 1234),
            (NONCE, True),
            (NONCE, 53),
            (NONCE, 65536),
        ):
            with self.subTest(nonce=nonce, port=port), self.assertRaises(ValueError):
                guard.resolver_name(nonce, port)

    def test_production_cli_has_no_path_or_lifetime_override(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(SOURCE), "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--nonce", result.stdout)
        self.assertNotIn("--directory", result.stdout)
        self.assertNotIn("--seconds", result.stdout)


@unittest.skipUnless(
    os.name == "posix", "actual guard requires POSIX file identities and pipes"
)
class FileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "resolver"
        self.owner = guard.ResolverFile(self.directory, NONCE, 1053, protected=False)

    def test_file_is_closed_before_no_replace_publication_and_restore_is_idempotent(
        self,
    ) -> None:
        original_close, original_link = os.close, os.link
        closed = []

        def close(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        def link(source: Path, target: Path) -> None:
            self.assertTrue(closed)
            with self.assertRaises(OSError):
                os.fstat(closed[-1])
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(), self.owner.content)
            original_link(source, target)

        with (
            patch.object(guard.os, "close", side_effect=close),
            patch.object(guard.os, "link", side_effect=link),
        ):
            receipt = self.owner.install()
        self.assertEqual(receipt["event"], "installed")
        self.assertEqual(
            self.owner.target.read_bytes(),
            b"domain n-"
            + NONCE.encode()
            + b".phantom.test\nnameserver 127.0.0.1\nport 1053\n",
        )
        self.assertFalse(self.owner.staging.exists())
        self.owner.restore()
        self.owner.restore()
        self.assertFalse(self.directory.exists())

    def test_existing_resolver_and_existing_directory_are_preserved(self) -> None:
        self.directory.mkdir()
        self.owner.target.write_bytes(b"previous resolver")
        with self.assertRaises(FileExistsError):
            self.owner.install()
        self.owner.restore()
        self.assertEqual(self.owner.target.read_bytes(), b"previous resolver")
        self.assertFalse(self.owner.staging.exists())

    def test_modified_content_and_replaced_inode_are_never_removed(self) -> None:
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                owner = guard.ResolverFile(self.directory, NONCE, 1053, protected=False)
                owner.install()
                if replacement:
                    other = self.directory / "replacement"
                    other.write_bytes(owner.content)
                    other.replace(owner.target)
                else:
                    owner.target.write_bytes(b"modified")
                with self.assertRaisesRegex(RuntimeError, "replacement retained"):
                    owner.restore()
                self.assertTrue(owner.target.exists())
                owner.target.unlink()
                self.directory.rmdir()

    def test_changed_directory_and_unrelated_files_are_retained(self) -> None:
        self.owner.install()
        other = self.directory / "unrelated"
        other.write_bytes(b"keep")
        with self.assertRaises(OSError):
            self.owner.restore()
        self.assertEqual(other.read_bytes(), b"keep")
        self.assertFalse(self.owner.target.exists())
        other.unlink()
        self.owner.restore()
        self.assertFalse(self.directory.exists())

    def test_symlink_parent_is_rejected_before_publication(self) -> None:
        destination = Path(self.temporary.name) / "elsewhere"
        destination.mkdir()
        self.directory.symlink_to(destination, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "real directory"):
            self.owner.install()
        self.assertEqual(list(destination.iterdir()), [])


@unittest.skipUnless(
    os.name == "posix", "actual owner control pipe uses POSIX select/signals"
)
class OwnerProcessTests(unittest.TestCase):
    @staticmethod
    def command(directory: Path, seconds: float = 2.0) -> list[str]:
        code = (
            "import runpy,sys; from pathlib import Path; "
            "owner=runpy.run_path(sys.argv[1])['_own']; "
            "sys.exit(owner(Path(sys.argv[2]),sys.argv[3],1053,seconds=float(sys.argv[4]),protected=False))"
        )
        return [
            sys.executable,
            "-I",
            "-c",
            code,
            str(SOURCE),
            str(directory),
            NONCE,
            str(seconds),
        ]

    def start(
        self, directory: Path, seconds: float = 2.0, *, control: int = subprocess.PIPE
    ) -> subprocess.Popen:
        child = subprocess.Popen(
            self.command(directory, seconds),
            stdin=control,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.collect, child)
        readable, _, _ = select.select([child.stdout], [], [], 3)
        self.assertTrue(readable, "guard did not acknowledge installation")
        first = json.loads(child.stdout.readline())
        self.assertEqual(first["event"], "installed")
        self.assertTrue((directory / f"n-{NONCE}.phantom.test").exists())
        return child

    @staticmethod
    def collect(child: subprocess.Popen) -> None:
        if child.poll() is None:
            child.communicate(
                timeout=4
            )  # EOF is the owner's normal restoration trigger.
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    def finish(
        self, child: subprocess.Popen, directory: Path, data: bytes | None = None
    ) -> dict:
        stdout, stderr = child.communicate(data, timeout=4)
        self.assertEqual(child.returncode, 0, stderr.decode())
        final = json.loads(stdout.splitlines()[-1])
        self.assertEqual(final["event"], "restored")
        self.assertFalse(directory.exists())
        return final

    def test_explicit_stop_and_pipe_eof_restore(self) -> None:
        for data, reason in ((b"STOP\n", "stop"), (None, "eof")):
            with (
                self.subTest(reason=reason),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary) / "resolver"
                final = self.finish(self.start(directory), directory, data)
                self.assertEqual(final["reason"], reason)

    def test_deadline_restores_while_control_writer_remains_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "resolver"
            child = self.start(directory, seconds=0.25)
            child.wait(timeout=3)  # Do not close stdin: this must be the deadline path.
            final = self.finish(child, directory)
            self.assertEqual(final["reason"], "deadline")

    def test_catchable_signal_restores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "resolver"
            child = self.start(directory)
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=3)
            final = self.finish(child, directory)
            self.assertEqual(final["reason"], f"signal-{signal.SIGTERM}")

    def test_changed_file_is_retained_and_reported_as_failed_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "resolver"
            child = self.start(directory)
            target = directory / f"n-{NONCE}.phantom.test"
            target.write_bytes(b"changed")
            stdout, _ = child.communicate(b"STOP\n", timeout=4)
            self.assertEqual(child.returncode, 1)
            final = json.loads(stdout.splitlines()[-1])
            self.assertEqual(final["event"], "restoration-failed")
            self.assertIn("replacement retained", final["cleanup"])
            self.assertEqual(target.read_bytes(), b"changed")

    def test_failed_install_restores_staging_and_keeps_the_existing_resolver(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "resolver"
            directory.mkdir()
            target = directory / f"n-{NONCE}.phantom.test"
            target.write_bytes(b"existing")
            result = subprocess.run(
                self.command(directory), input=b"STOP\n", capture_output=True, timeout=4
            )
            self.assertEqual(result.returncode, 1, result.stderr.decode())
            final = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual(final["event"], "restored")
            self.assertIn("FileExistsError", final["primary"])
            self.assertIsNone(final["cleanup"])
            self.assertEqual(target.read_bytes(), b"existing")
            self.assertEqual(list(Path(temporary).iterdir()), [directory])

    def test_control_writer_process_loss_restores_without_a_stop_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "resolver"
            reader, writer = os.pipe()
            try:
                owner = self.start(directory, control=reader)
                holder = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "import time; print('ready',flush=True); time.sleep(5)",
                    ],
                    pass_fds=(writer,),
                    stdout=subprocess.PIPE,
                )
            finally:
                os.close(reader)
                os.close(writer)
            try:
                self.assertEqual(holder.stdout.readline(), b"ready\n")
                self.assertIsNone(owner.poll())
                holder.terminate()
                holder.wait(timeout=2)
                final = self.finish(owner, directory)
                self.assertEqual(final["reason"], "eof")
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.wait(timeout=2)
                holder.stdout.close()


if __name__ == "__main__":
    unittest.main()
