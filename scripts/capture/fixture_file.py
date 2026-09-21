"""Atomic writers for retained capture fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_atomically(path: Path, text: str, *, encoding: str) -> None:
    """Replace `path` with `text` only after the complete file is durable.

    An encoding failure or interrupted write leaves any previous fixture intact.
    """
    path = path.resolve()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding=encoding, dir=path.parent, delete=False
        ) as output:
            temporary_path = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_text_fixture(path: Path, fixture: str) -> None:
    """Write an ASCII `key=value` fixture atomically."""
    write_atomically(path, fixture, encoding="ascii")
