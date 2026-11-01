"""Byte hashes and command receipts retained with capture provenance."""

import hashlib
import subprocess
from collections.abc import Iterable
from pathlib import Path


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def file_digests(paths: Iterable[str], *, root: Path = Path(".")) -> dict[str, str]:
    """Hash the caller's source inventory, retaining its names and order."""
    return {name: file_digest(root / name) for name in paths}


def command_output(record: dict, *args: str, timeout: float = 10) -> str:
    """Retain command output even when metadata collection fails or times out."""
    receipt = {
        "argv": list(args),
        "timeout_seconds": timeout,
        "exit": None,
        "stdout": "",
        "stderr": "",
    }
    record["metadata_commands"].append(receipt)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, subprocess.TimeoutExpired):
            for name in ("stdout", "stderr"):
                output = getattr(error, name)
                if output is not None:
                    receipt[name] = (
                        output.decode("utf-8", errors="replace")
                        if isinstance(output, bytes)
                        else output
                    )
        raise
    receipt.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
    result.check_returncode()
    return result.stdout.strip()
