"""Build, install and exercise the Python wheel with this interpreter."""

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import venv
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
MATURIN = "1.9.6"
TEST_DEPENDENCIES = ("h2==4.4.1", "hpack==4.2.0", "hyperframe==6.1.0")
MAX_WHEEL_BYTES = 256 * 1024 * 1024


def artifact_tools():
    spec = importlib.util.spec_from_file_location(
        "phantom_cli_artifact", ROOT / "scripts/release/cli_artifact.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def python_in(environment):
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def wheel_files(archive):
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(infos) > 10_000 or sum(info.file_size for info in infos) > MAX_WHEEL_BYTES:
        raise ValueError("wheel exceeds inspection bounds")
    if len(names) != len({name.casefold() for name in names}):
        raise ValueError("duplicate wheel path")
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or ":" in name
            or str(path) != name.rstrip("/")
            or info.orig_filename != name
            or stat.S_ISLNK(info.external_attr >> 16)
        ):
            raise ValueError("unsafe wheel path")
    return [info for info in infos if not info.is_dir()]


def record_row(name, data):
    checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return [name, "sha256=" + checksum.decode("ascii"), str(len(data))]


def inspect_wheel(wheel, target, version):
    """Check the native ABI3 wheel's metadata and every RECORD payload hash."""
    with zipfile.ZipFile(wheel) as archive:
        names = {info.filename for info in wheel_files(archive)}
        dist = [
            name.removesuffix("/WHEEL")
            for name in names
            if name.endswith(".dist-info/WHEEL")
        ]
        if len(dist) != 1:
            raise ValueError("expected one wheel metadata directory")
        dist = dist[0]
        if dist != f"phantom_http-{version}.dist-info":
            raise ValueError("wheel metadata directory differs from package identity")
        required = {f"{dist}/{name}" for name in ("WHEEL", "METADATA", "RECORD")}
        if not required <= names or "phantom_http/__init__.py" not in names:
            raise ValueError("missing wheel payload or metadata")
        if names & {f"{dist}/RECORD.jws", f"{dist}/RECORD.p7s"}:
            raise ValueError("signed wheel cannot be rewritten")
        metadata = BytesParser().parsebytes(archive.read(f"{dist}/METADATA"))
        if (
            metadata["Name"] != "phantom-http"
            or metadata["Version"] != version
            or metadata["Requires-Python"] != ">=3.10"
            or metadata["License-Expression"] != "MIT OR Apache-2.0"
        ):
            raise ValueError("unexpected Python package metadata")
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            path = f"{dist}/licenses/{name}"
            if (
                path not in names
                or archive.read(path) != (ROOT / "bindings/python" / name).read_bytes()
            ):
                raise ValueError("missing or changed project license")
        licenses = {
            name.removeprefix(f"{dist}/licenses/")
            for name in names
            if name.startswith(f"{dist}/licenses/")
        }
        if set(metadata.get_all("License-File", [])) != licenses:
            raise ValueError("license metadata does not match included files")
        info = BytesParser().parsebytes(archive.read(f"{dist}/WHEEL"))
        tags = info.get_all("Tag", [])
        fields = wheel.stem.split("-")
        if (
            fields[:2] != ["phantom_http", version]
            or len(fields) != 5
            or tags != ["-".join(fields[2:])]
            or fields[2:4] != ["cp310", "abi3"]
            or info["Root-Is-Purelib"] != "false"
        ):
            raise ValueError("unexpected wheel ABI or filename tags")
        platform_tag = fields[-1]
        accepted = {
            "x86_64-unknown-linux-gnu": platform_tag == "linux_x86_64",
            "x86_64-pc-windows-msvc": platform_tag == "win_amd64",
            "aarch64-apple-darwin": re.fullmatch(r"macosx_\d+_\d+_arm64", platform_tag)
            is not None,
        }
        if not accepted.get(target, False):
            raise ValueError("wheel platform tag does not match native target")
        primary = [
            name
            for name in names
            if re.fullmatch(r"phantom_http/_native(?:\.abi3)?\.(?:so|pyd)", name)
        ]
        if len(primary) != 1:
            raise ValueError("expected one native Python extension")
        record = f"{dist}/RECORD"
        rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
        if any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(
            rows
        ):
            raise ValueError("invalid or duplicate wheel RECORD row")
        if {row[0] for row in rows} != names:
            raise ValueError("wheel RECORD does not cover exactly its payload")
        for row in rows:
            expected = (
                [record, "", ""]
                if row[0] == record
                else record_row(row[0], archive.read(row[0]))
            )
            if row != expected:
                raise ValueError("wheel RECORD hash or size differs")
        return {
            "dist_info": dist,
            "version": version,
            "tags": tags,
            "native": primary[0],
        }


def add_notices(original, candidate, notices, dist):
    """Retain the original wheel and rebuild RECORD after adding offline notices."""
    record = f"{dist}/RECORD"
    metadata_path = f"{dist}/METADATA"
    rows = []
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(candidate, "x", compression=zipfile.ZIP_DEFLATED) as output,
    ):
        names = {info.filename for info in wheel_files(source)}
        folded = {name.casefold() for name in names}
        extra = [
            (
                path,
                f"{dist}/licenses/third-party/{path.relative_to(notices).as_posix()}",
            )
            for path in sorted(notices.rglob("*"))
            if path.is_file()
        ]
        metadata = BytesParser(policy=policy.default).parsebytes(
            source.read(metadata_path)
        )
        for _, name in extra:
            if name.casefold() in folded:
                raise ValueError("third-party notice conflicts with wheel payload")
            names.add(name)
            folded.add(name.casefold())
            metadata["License-File"] = name.removeprefix(f"{dist}/licenses/")
        for info in wheel_files(source):
            if info.filename == record:
                continue
            data = (
                metadata.as_bytes(
                    policy=policy.default.clone(utf8=True, max_line_length=0)
                )
                if info.filename == metadata_path
                else source.read(info.filename)
            )
            output.writestr(info, data)
            rows.append(record_row(info.filename, data))
        for path, name in extra:
            data = path.read_bytes()
            output.writestr(name, data)
            rows.append(record_row(name, data))
        rows.append([record, "", ""])
        receipt = io.StringIO(newline="")
        csv.writer(receipt, lineterminator="\n").writerows(rows)
        output.writestr(record, receipt.getvalue())


def dependency_closure(metadata):
    packages = [
        package
        for package in metadata["packages"]
        if package["name"] == "phantom-python"
    ]
    if len(packages) != 1:
        raise ValueError("expected one Python adapter in Cargo metadata")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending = [packages[0]["id"]]
    selected = set()
    while pending:
        package = pending.pop()
        if package in selected:
            continue
        selected.add(package)
        pending.extend(
            dep["pkg"]
            for dep in nodes[package]["deps"]
            if any(kind["kind"] in (None, "build") for kind in dep["dep_kinds"])
        )
    return packages[0], selected


def run(*command: str) -> None:
    print("+", *command, flush=True)
    subprocess.run(command, check=True)


def check_development() -> None:
    root = ROOT
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
        f"maturin=={MATURIN}",
        *TEST_DEPENDENCIES,
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


def installed_checks(wheel, commands):
    with tempfile.TemporaryDirectory(prefix="phantom-python-wheel-") as temporary:
        directory = Path(temporary).resolve()
        if directory.is_relative_to(ROOT):
            raise ValueError("wheel installation check must run outside checkout")
        environment = directory / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = python_in(environment)
        commands.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--disable-pip-version-check",
                *TEST_DEPENDENCIES,
            ],
            cwd=directory,
            timeout=180,
        )
        commands.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--no-cache-dir",
                "--disable-pip-version-check",
                str(wheel),
            ],
            cwd=directory,
        )
        commands.run([str(python), "-I", "-m", "pip", "check"], cwd=directory)
        identity = json.loads(
            commands.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import importlib.metadata,json,platform,sys,phantom_http,phantom_http._native as n; "
                    "print(json.dumps({'python':sys.version,'implementation':platform.python_implementation(),"
                    "'version':importlib.metadata.version('phantom-http'),"
                    "'package':phantom_http.__file__,'extension':n.__file__}))",
                ],
                cwd=directory,
            )
        )
        for name in ("package", "extension"):
            path = Path(identity[name]).resolve()
            if not path.is_relative_to(environment.resolve()) or path.is_relative_to(
                ROOT
            ):
                raise ValueError(
                    "Python imported a package outside the clean installation"
                )
        # Keep tests outside the checkout too, with Python's isolated import mode.
        shutil.copytree(
            ROOT / "bindings/python/tests",
            directory / "tests",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        checks = json.loads(
            commands.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import json,sys,unittest; "
                    "suite=unittest.defaultTestLoader.discover('tests'); "
                    "r=unittest.TextTestRunner(verbosity=2).run(suite); "
                    "print(json.dumps({'tests':r.testsRun,'skipped':len(r.skipped)})); "
                    "sys.exit(0 if r.wasSuccessful() and r.testsRun>=12 and not r.skipped else 1)",
                ],
                cwd=directory,
                timeout=300,
            )
        )
        return {"installation": identity, "loopback_checks": checks}


def verify_candidate(target, output):
    tools = artifact_tools()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    if commands.run(["git", "status", "--porcelain"]).strip():
        raise ValueError("wheel candidates require a clean checkout")
    if (
        sys.implementation.name != "cpython"
        or sys.version_info < (3, 10)
        or sys.maxsize <= 2**32
    ):
        raise ValueError("wheel candidates require 64-bit CPython 3.10 or newer")
    if any(
        key.startswith(("BORING_BSSL_", "CARGO_PROFILE_RELEASE_"))
        or key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")
        for key in os.environ
    ):
        raise ValueError(
            "remove native TLS and release optimization overrides before building candidates"
        )
    revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    lock = tools.digest(ROOT / "Cargo.lock")
    rustc = commands.run(["rustc", "-vV"]).decode()
    host = tools.host_identity(target, rustc)
    cargo = commands.run(["cargo", "-V"]).decode().strip()
    metadata = json.loads(
        commands.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ],
            timeout=180,
        )
    )
    package, package_ids = dependency_closure(metadata)
    build_environment = output / "build-environment"
    venv.EnvBuilder(with_pip=True).create(build_environment)
    python = python_in(build_environment)
    commands.run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            "--disable-pip-version-check",
            f"maturin=={MATURIN}",
        ],
        timeout=180,
    )
    maturin = (
        commands.run([str(python), "-I", "-m", "maturin", "--version"]).decode().strip()
    )
    wheels = output / "original"
    jobs = tools.build_jobs()
    command = [
        str(python),
        "-I",
        "-m",
        "maturin",
        "build",
        "--locked",
        "--release",
        "--config",
        "profile.release.opt-level=3",
        "--target",
        target,
        "--jobs",
        jobs,
        "--manifest-path",
        "bindings/python/Cargo.toml",
        "--interpreter",
        str(python),
        "--out",
        str(wheels),
    ]
    if target.endswith("linux-gnu"):
        # A native-host candidate does not establish a manylinux runtime floor.
        command.extend(["--compatibility", "linux", "--auditwheel", "check"])
    commands.run(command, timeout=1800)
    built = list(wheels.glob("*.whl"))
    if len(built) != 1:
        raise ValueError(f"expected one built wheel, found {len(built)}")
    original = built[0]
    info = inspect_wheel(original, target, package["version"])
    notices = output / "notices"
    inventory = tools.copy_notices(metadata, package_ids, notices)
    for entry in inventory:
        entry["scope"] = (
            "potential normal/build input; conservative feature-unified metadata graph, not linked-code attribution"
        )
    sysroot = Path(commands.run(["rustc", "--print", "sysroot"]).decode().strip())
    tools.copy_rust_notices(sysroot, notices / "rust-runtime")
    tools.write_json(notices / "inventory.json", inventory)
    candidate = output / "candidate" / original.name
    candidate.parent.mkdir()
    add_notices(original, candidate, notices, info["dist_info"])
    checked = inspect_wheel(candidate, target, package["version"])
    native = output / "native"
    native.mkdir()
    with zipfile.ZipFile(candidate) as archive:
        binary = native / PurePosixPath(checked["native"]).name
        binary.write_bytes(archive.read(checked["native"]))
    linkage = tools.dependency_inspection(binary, target, commands)
    installed = installed_checks(candidate, commands)
    if installed["installation"]["version"] != package["version"]:
        raise ValueError("installed wheel version differs from source metadata")
    if (
        commands.run(["git", "status", "--porcelain"]).strip()
        or commands.run(["git", "rev-parse", "HEAD"]).decode().strip() != revision
        or tools.digest(ROOT / "Cargo.lock") != lock
    ):
        raise ValueError("checkout identity changed during wheel verification")
    identity = {
        "schema": 1,
        "source_revision": revision,
        "cargo_lock_sha256": lock,
        "target": target,
        "profile": "release",
        "rustc": rustc,
        "cargo": cargo,
        "maturin": maturin,
        "build_jobs": jobs,
        "build_environment": {
            key: os.environ[key]
            for key in ("MACOSX_DEPLOYMENT_TARGET", "CC", "CXX", "CFLAGS", "CXXFLAGS")
            if key in os.environ
        },
        "tested_host": host,
        "original_wheel_sha256": tools.digest(original),
        "wheel_sha256": tools.digest(candidate),
        "wheel": checked,
        "notices": inventory,
        "native_linkage": linkage,
        **installed,
        "runtime_boundary": "Tested on the recorded host and CPython only. No older OS/libc, manylinux, or PyPI compatibility established; SDK/OS runtime licenses are separate.",
    }
    # The uploadable directory is created only after install and all controls pass.
    verified = output / "verified"
    verified.mkdir()
    shutil.copyfile(candidate, verified / candidate.name)
    tools.write_json(verified / "verification.json", identity)
    (verified / "SHA256SUMS").write_text(
        f"{identity['wheel_sha256']}  {candidate.name}\n", encoding="utf-8"
    )
    print(f"Verified native Python wheel candidate: {verified / candidate.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-candidate", action="store_true")
    parser.add_argument(
        "--target",
        choices=(
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin",
        ),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.release_candidate:
        if args.target is None or args.output is None:
            parser.error("--release-candidate requires --target and --output")
        verify_candidate(args.target, args.output)
    elif args.target is not None or args.output is not None:
        parser.error("--target and --output require --release-candidate")
    else:
        check_development()


if __name__ == "__main__":
    main()
