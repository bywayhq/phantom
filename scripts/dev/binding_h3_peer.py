"""Stage the HTTP/3 binding peers and their isolated pinned runtime."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

PEER_FILES = (
    "binding_upload_h3.py",
    "binding_headers_h3.py",
    "aioquic_versions.py",
    "loopback_tls.py",
)


def peer_environment(root, directory, environment=None):
    environment = dict(os.environ if environment is None else environment)
    selected = environment.get("PHANTOM_H3_PEER_PYTHON")
    if selected:
        python = Path(selected).absolute()
        if not python.is_file():
            raise ValueError("HTTP/3 peer interpreter is missing")
    else:
        runtime = directory / "h3-runtime"
        subprocess.run(
            ["uv", "venv", "--python", "3.12.10", str(runtime)],
            check=True,
            timeout=180,
        )
        python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), "aioquic==1.3.0"],
            check=True,
            timeout=180,
        )
    identity = json.loads(
        subprocess.check_output(
            [
                str(python),
                "-I",
                "-c",
                "import aioquic,json,sys; print(json.dumps({'python':list(sys.version_info[:3]),'aioquic':aioquic.__version__}))",
            ],
            timeout=30,
        )
    )
    if tuple(identity["python"]) < (3, 12, 3) or identity["aioquic"] != "1.3.0":
        raise ValueError("HTTP/3 peer requires Python >=3.12.3 and aioquic 1.3.0")
    peer = directory / "h3-peer"
    peer.mkdir()
    for name in PEER_FILES:
        source = root / "scripts/conformance" / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("HTTP/3 peer fixture is missing or nonregular")
        shutil.copyfile(source, peer / name)
    environment["PHANTOM_H3_PEER_PYTHON"] = str(python)
    environment["PHANTOM_H3_PEER_SCRIPT"] = str(peer / PEER_FILES[0])
    environment["PHANTOM_HEADER_H3_PEER_SCRIPT"] = str(peer / "binding_headers_h3.py")
    return environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a test command is required")
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="phantom-h3-peer-") as temporary:
        environment = peer_environment(root, Path(temporary))
        subprocess.run(command, check=True, env=environment)


if __name__ == "__main__":
    main()
