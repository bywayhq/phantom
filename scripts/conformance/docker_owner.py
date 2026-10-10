"""Verify a run's Docker container identity before removing it."""

from __future__ import annotations

import json
import math
import subprocess
from collections.abc import Mapping


def verified_container_id(
    name: str,
    owner_label: str,
    owner: str,
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Return the full ID with the expected label, or None for a missing name."""

    _require_deadline(timeout)

    result = subprocess.run(
        [
            "docker",
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Id}}\n{{json .Config.Labels}}",
            name,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )
    if result.returncode == 1 and result.stderr.strip() in {
        f"Error: No such object: {name}",
        f"Error response from daemon: No such container: {name}",
    }:
        return None

    _require_success(result, "container ownership inspection")

    lines = result.stdout.splitlines()
    if len(lines) != 2 or not _is_full_id(lines[0]):
        raise ValueError("container ownership inspection returned an invalid ID")

    try:
        labels = json.loads(lines[1])
    except json.JSONDecodeError as error:
        raise ValueError(
            "container ownership inspection returned invalid labels"
        ) from error

    if not isinstance(labels, dict) or labels.get(owner_label) != owner:
        raise RuntimeError(
            "container ownership did not match; left the container untouched"
        )

    return lines[0]


def remove_container(
    container_id: str, *, timeout: float, env: Mapping[str, str] | None = None
) -> None:
    """Remove a previously verified immutable ID within a finite deadline."""

    _require_deadline(timeout)
    if not _is_full_id(container_id):
        raise ValueError("container removal requires a full immutable ID")

    result = subprocess.run(
        ["docker", "rm", "--force", container_id],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )
    _require_success(result, "container removal")


def _require_deadline(timeout: float) -> None:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("container command timeout must be finite and positive")


def _is_full_id(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _require_success(result: subprocess.CompletedProcess[str], operation: str) -> None:
    try:
        result.check_returncode()
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"{operation} exited with status {result.returncode}: {result.stderr.strip()}"
        ) from error
