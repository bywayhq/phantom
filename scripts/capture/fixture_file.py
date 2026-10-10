"""Atomic writers for retained capture fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


class _FixtureCleanupError(RuntimeError):
    def __init__(
        self,
        temporary_path: Path,
        cleanup_error: BaseException,
        *,
        replacement_completed: bool,
        primary: BaseException | None,
    ) -> None:
        self.temporary_path = temporary_path
        self.cleanup_error = cleanup_error
        self.replacement_completed = replacement_completed
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        super().__init__(
            f"could not remove staged fixture {temporary_path}: {cleanup_error}"
        )


def write_atomically(path: Path, text: str, *, encoding: str) -> None:
    """Replace `path` with `text` only after the complete file is durable.

    Text is written byte-for-byte: newline translation would change retained
    fixture digests on Windows. An encoding failure or interrupted write leaves
    any previous fixture intact.

    If removing the staged file also fails, the original exception stays primary.
    Its cause retains the cleanup error, staged path and whether replace returned.
    """
    path = path.resolve()
    temporary_path: Path | None = None
    replacement_completed = False
    primary: BaseException | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding=encoding, newline="", dir=path.parent, delete=False
        ) as output:
            temporary_path = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        replacement_completed = True
    except BaseException as error:
        primary = error
        raise
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except BaseException as cleanup_error:
                failure = _FixtureCleanupError(
                    temporary_path,
                    cleanup_error,
                    replacement_completed=replacement_completed,
                    primary=primary,
                )
                if primary is not None:
                    raise primary from failure
                raise failure from cleanup_error


def write_text_fixture(path: Path, fixture: str) -> None:
    """Write an ASCII `key=value` fixture atomically."""
    write_atomically(path, fixture, encoding="ascii")
