"""Pin an external client's command and declared build artifacts."""

import json
import re
from pathlib import Path


def load_client(path, sha):
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "name",
        "version",
        "command",
        "artifacts",
    }:
        raise ValueError("client descriptor needs name, version, command and artifacts")
    name, version = descriptor["name"], descriptor["version"]
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name)
        or not isinstance(version, str)
        or not version.strip()
        or len(version) > 120
    ):
        raise ValueError("client name and version must identify the selected build")
    command = descriptor["command"]
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 32
        or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
    ):
        raise ValueError("client command must be a nonempty argv array")
    executable = Path(command[0])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("client executable must be an existing absolute file")
    artifacts = descriptor["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 256:
        raise ValueError("client artifacts must be a bounded nonempty list")
    hashes = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise ValueError("each client artifact needs path and sha256")
        if not isinstance(artifact["path"], str):
            raise ValueError("client artifact path must be an absolute file")
        source = Path(artifact["path"])
        digest = artifact["sha256"]
        if (
            not source.is_absolute()
            or not source.is_file()
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError(
                "client artifact needs an existing absolute file and SHA256"
            )
        source = source.resolve()
        if str(source) in hashes:
            raise ValueError("duplicate client artifact")
        if sha(source) != digest:
            raise ValueError(f"client artifact hash mismatch: {source}")
        hashes[str(source)] = digest
    # Python adapters need both the interpreter and script pinned. Native shared
    # libraries, wheels and module locks must be listed by the adapter's author.
    for argument in command:
        source = Path(argument)
        if source.is_file() and (
            not source.is_absolute() or str(source.resolve()) not in hashes
        ):
            raise ValueError("every file in client command must be absolute and pinned")
    return {
        "name": name,
        "version": version,
        "command": command,
        "artifact_sha256": hashes,
        "descriptor": descriptor,
        "descriptor_sha256": sha(path),
    }


def verified_client_build(client, receipt):
    """Require the selected executable and every declared input in the receipt."""
    return (
        isinstance(receipt, dict)
        and receipt.get("native_optimization_verified") is True
        and receipt.get("binary_sha256")
        == client["artifact_sha256"][str(Path(client["command"][0]).resolve())]
        and receipt.get("artifact_sha256") == client["artifact_sha256"]
    )
