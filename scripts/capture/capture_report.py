"""Byte hashes and command receipts retained with capture provenance."""

import hashlib
import subprocess
from pathlib import Path


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def command_output(record: dict, *args: str) -> str:
    """Retain command output even when metadata collection fails or times out."""
    receipt = {"argv": list(args), "exit": None, "stdout": "", "stderr": ""}
    record["metadata_commands"].append(receipt)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
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
