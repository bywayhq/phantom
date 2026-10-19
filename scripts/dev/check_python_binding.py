"""Build, install and exercise the Python wheel with this interpreter."""

import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def run(*command: str) -> None:
    print("+", *command, flush=True)
    subprocess.run(command, check=True)


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    output = root / "target" / "python-binding"
    environment = output / f"python-{sys.version_info.major}.{sys.version_info.minor}"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(
        str(python),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "maturin==1.9.6",
        "h2==4.4.1",
        "hpack==4.2.0",
        "hyperframe==6.1.0",
    )
    wheels = Path(tempfile.mkdtemp(prefix="wheels-", dir=output))
    run(
        str(python),
        "-m",
        "maturin",
        "build",
        "--locked",
        "--profile",
        "dev",
        "--manifest-path",
        "bindings/python/Cargo.toml",
        "--interpreter",
        str(python),
        "--out",
        str(wheels),
    )
    built = list(wheels.glob("*.whl"))
    if len(built) != 1:
        raise RuntimeError(f"expected one built wheel, found {len(built)}")
    run(
        str(python),
        "-m",
        "pip",
        "install",
        "--no-deps",
        "--force-reinstall",
        str(built[0]),
    )
    run(str(python), "-m", "unittest", "discover", "-s", "bindings/python/tests", "-v")


if __name__ == "__main__":
    main()
