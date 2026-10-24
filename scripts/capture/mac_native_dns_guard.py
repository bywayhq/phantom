"""Own one finite, no-overwrite macOS resolver-file intervention.

The production CLI accepts no filesystem paths. Its stdout is the ownership
receipt: retain it even on failure. SIGKILL or host loss cannot run restoration;
the receipt identifies leftovers without authorizing deletion of replacements.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path

OWNER_SECONDS = 120.0
RESOLVER_DIRECTORY = Path("/private/etc/resolver")


def resolver_name(nonce: str, port: int) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("nonce must contain exactly 32 lowercase hexadecimal digits")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("DNS port must be in 1024..65535")
    return f"n-{nonce}.phantom.test"


def identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode)


def directory_identity(path: Path, *, protected: bool) -> tuple[int, int, int, int]:
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode):
        raise RuntimeError("resolver parent is not a real directory")
    if protected and (value.st_uid != 0 or value.st_mode & 0o022):
        raise RuntimeError("resolver parent is not protected and root-owned")
    return identity(value)


class ResolverFile:
    """Own the file and optional directory; the private path seam is for tests."""

    def __init__(
        self, directory: Path, nonce: str, port: int, *, protected: bool = True
    ) -> None:
        self.name = resolver_name(nonce, port)
        self.port = port
        self.directory = directory
        self.target = directory / self.name
        self.staging = directory.parent / f".phantom-native-dns-{nonce}"
        self.protected = protected
        self.content = (
            f"domain {self.name}\nnameserver 127.0.0.1\nport {port}\n"
        ).encode("ascii")
        self.parent: tuple[int, int, int, int] | None = None
        self.created_directory = False
        self.directory_id: tuple[int, int, int, int] | None = None
        self.file_id: tuple[int, int, int, int] | None = None
        self.staging_id: tuple[int, int, int, int] | None = None
        self.restored = False

    def check_directory(self) -> None:
        if (
            directory_identity(self.directory.parent, protected=self.protected)
            != self.parent
            or directory_identity(self.directory, protected=self.protected)
            != self.directory_id
        ):
            raise RuntimeError("owned resolver directory identity changed")

    def install(self) -> dict:
        # All ancestors must be protected; /etc's documented alias is avoided.
        if self.protected:
            for ancestor in reversed(self.directory.parent.parents):
                directory_identity(ancestor, protected=True)
        self.parent = directory_identity(
            self.directory.parent, protected=self.protected
        )
        try:
            self.directory.mkdir(mode=0o755)
            self.created_directory = True
        except FileExistsError:
            pass
        self.directory_id = directory_identity(self.directory, protected=self.protected)
        self.check_directory()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.staging, flags, 0o644)
        try:
            os.fchmod(descriptor, 0o644)
            self.staging_id = identity(os.fstat(descriptor))
            if self.protected and self.staging_id[2] != 0:
                raise RuntimeError("resolver staging file is not root-owned")
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(self.content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        self.check_directory()
        # Only closed, complete bytes become visible to the resolver scanner.
        os.link(self.staging, self.target)
        self.file_id = self.staging_id
        self.remove_staging()
        return {
            "event": "installed",
            "pid": os.getpid(),
            "domain": self.name,
            "port": self.port,
            "identity": self.file_id,
            "sha256": hashlib.sha256(self.content).hexdigest(),
            "created_directory": self.created_directory,
            "directory_identity": self.directory_id,
            "parent_identity": self.parent,
        }

    def remove_staging(self) -> None:
        if self.staging_id is not None:
            if identity(self.staging.lstat()) != self.staging_id:
                raise RuntimeError("owned staging file identity changed")
            self.staging.unlink()
            self.staging_id = None

    def restore(self) -> None:
        if self.restored or self.directory_id is None:
            return
        self.check_directory()
        if self.file_id is not None:
            try:
                before = self.target.lstat()
                if not stat.S_ISREG(before.st_mode) or identity(before) != self.file_id:
                    raise RuntimeError("resolver file changed; replacement retained")
                descriptor = os.open(
                    self.target,
                    os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
                )
            except FileNotFoundError:
                pass
            else:
                try:
                    value = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(value.st_mode)
                        or identity(value) != self.file_id
                        or os.read(descriptor, len(self.content) + 1) != self.content
                        or identity(self.target.lstat()) != self.file_id
                    ):
                        raise RuntimeError(
                            "resolver file changed; replacement retained"
                        )
                    self.target.unlink()
                finally:
                    os.close(descriptor)
        self.remove_staging()
        if self.created_directory:
            self.directory.rmdir()  # Refuse unrelated files, including replacements.
        self.restored = True


def emit(record: dict) -> None:
    print(json.dumps(record, sort_keys=True), flush=True)


def _own(
    directory: Path,
    nonce: str,
    port: int,
    *,
    seconds: float = OWNER_SECONDS,
    protected: bool = True,
    report: Callable[[dict], None] = emit,
) -> int:
    """Private temp-directory/time seam; the CLI cannot select these inputs."""
    if not math.isfinite(seconds) or not 0 < seconds <= OWNER_SECONDS:
        raise ValueError("guard lifetime must be finite and within 0..120 seconds")
    owner = ResolverFile(directory, nonce, port, protected=protected)
    primary: BaseException | None = None
    cleanup: BaseException | None = None
    stopped = None
    previous = {}

    def stop(signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = f"signal-{signum}"

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", None)):
            if signum is not None:
                previous[signum] = signal.signal(signum, stop)
        os.set_inheritable(sys.stdin.fileno(), False)
        deadline = time.monotonic() + seconds
        deadline_unix_ns = time.time_ns() + int(seconds * 1_000_000_000)
        installed = owner.install()
        installed["lifetime_seconds"] = seconds
        installed["deadline_unix_ns"] = deadline_unix_ns
        report(installed)
        command = b""
        while stopped is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stopped = "deadline"
                break
            if not select.select([sys.stdin], [], [], min(remaining, 0.1))[0]:
                continue
            if stopped is not None:
                break
            chunk = os.read(sys.stdin.fileno(), 6)
            if not chunk:
                stopped = "eof"
                break
            command += chunk
            if command == b"STOP\n":
                stopped = "stop"
            elif len(command) >= 5 or not b"STOP\n".startswith(command):
                raise ValueError("guard accepts only STOP followed by newline")
    except BaseException as error:
        primary = error
    finally:
        try:
            owner.restore()
        except BaseException as error:
            cleanup = error
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    report(
        {
            "event": "restored" if cleanup is None else "restoration-failed",
            "domain": owner.name,
            "identity": owner.file_id,
            "directory_identity": owner.directory_id,
            "parent_identity": owner.parent,
            "staging_identity": owner.staging_id,
            "created_directory": owner.created_directory,
            "sha256": hashlib.sha256(owner.content).hexdigest(),
            "reason": stopped,
            "primary": None
            if primary is None
            else f"{type(primary).__name__}: {primary}",
            "cleanup": None
            if cleanup is None
            else f"{type(cleanup).__name__}: {cleanup}",
        }
    )
    return int(primary is not None or cleanup is not None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    resolver_name(args.nonce, args.port)
    if sys.platform != "darwin" or os.geteuid() != 0:
        parser.error("guard requires macOS root; browser must remain unprivileged")
    return _own(RESOLVER_DIRECTORY, args.nonce, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
