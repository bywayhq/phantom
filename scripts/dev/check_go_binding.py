"""Build the native Go adapter and exercise its public Go API."""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


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
    if sys.platform == "win32":
        environment["PHANTOM_GO_LIBRARY"] = str(library / "phantom_go.dll")
    else:
        environment["CGO_ENABLED"] = "1"
        environment["CGO_LDFLAGS"] = (
            environment.get("CGO_LDFLAGS", "") + " -L" + shlex.quote(str(library))
        )
        loader = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        environment[loader] = str(library) + os.pathsep + environment.get(loader, "")
    module = root / "bindings" / "go"
    sources = [str(path) for path in sorted(module.glob("*.go"))]
    unformatted = subprocess.check_output(["gofmt", "-l", *sources], text=True)
    if unformatted:
        raise RuntimeError("Go files need formatting:\n" + unformatted)
    run("go", "test", "-count=1", "-timeout=5m", "-v", ".", cwd=module, env=environment)


if __name__ == "__main__":
    main()
