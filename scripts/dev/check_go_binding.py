"""Build the native Go adapter and exercise its public Go API."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def h3_peer_environment(root, directory, environment=None):
    spec = importlib.util.spec_from_file_location(
        "binding_h3_peer", root / "scripts/dev/binding_h3_peer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.peer_environment(root, directory, environment)


def run(*command: str, **options) -> None:
    print("+", *command, flush=True)
    subprocess.run(command, check=True, **options)


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    run("go", "version")
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            text=True,
        )
    )
    run("cargo", "build", "--locked", "-p", "phantom-go")
    library = Path(metadata["target_directory"]) / "debug"
    environment = os.environ.copy()
    name = {
        "win32": "phantom_go.dll",
        "darwin": "libphantom_go.dylib",
        "linux": "libphantom_go.so",
    }[sys.platform]
    environment["CGO_ENABLED"] = "0"
    environment["PHANTOM_GO_LIBRARY"] = str((library / name).resolve())
    module = root / "bindings" / "go"
    sources = [str(path) for path in sorted(module.glob("*.go"))]
    unformatted = subprocess.check_output(["gofmt", "-l", *sources], text=True)
    if unformatted:
        raise RuntimeError("Go files need formatting:\n" + unformatted)
    with tempfile.TemporaryDirectory(prefix="phantom-go-h3-peer-") as temporary:
        environment = h3_peer_environment(root, Path(temporary), environment)
        run(
            "go",
            "test",
            "-count=1",
            "-timeout=5m",
            "-v",
            ".",
            cwd=module,
            env=environment,
        )


if __name__ == "__main__":
    main()
