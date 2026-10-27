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
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
MATURIN = "1.15.0"
TEST_DEPENDENCIES = (
    "h2==4.4.1",
    "hpack==4.2.0",
    "hyperframe==6.1.0",
    "mypy==1.19.1",
)
MAX_WHEEL_BYTES = 256 * 1024 * 1024


def h3_peer_environment(root, directory, environment=None):
    spec = importlib.util.spec_from_file_location(
        "binding_h3_peer", root / "scripts/dev/binding_h3_peer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.peer_environment(root, directory, environment)


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


def inspect_wheel(wheel, target, version, *, manylinux=False, project_licenses=None):
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
        required.update(
            f"phantom_http/{name}"
            for name in ("__init__.py", "py.typed", "_native.pyi")
        )
        if not required <= names:
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
        if project_licenses is None:
            project_licenses = {
                name: hashlib.sha256(
                    (ROOT / "bindings/python" / name).read_bytes()
                ).hexdigest()
                for name in ("LICENSE-MIT", "LICENSE-APACHE")
            }
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            path = f"{dist}/licenses/{name}"
            if path not in names or hashlib.sha256(
                archive.read(path)
            ).hexdigest() != project_licenses.get(name):
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
            "x86_64-unknown-linux-gnu": platform_tag
            == ("manylinux_2_28_x86_64" if manylinux else "linux_x86_64"),
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


def inspect_source(archive, receipt_path, revision, original_lock):
    """Inspect the producer's exact bounded archive without importing Python 3.11 TOML."""
    if (
        archive.stat().st_size > 512 * 1024 * 1024
        or receipt_path.stat().st_size > 4 * 1024 * 1024
    ):
        raise ValueError("source archive or receipt exceeds inspection bounds")
    receipt = json.loads(receipt_path.read_bytes())
    if (
        receipt["source_revision"] != revision
        or receipt["maturin"] != MATURIN
        or receipt["archive_sha256"] != hashlib.sha256(archive.read_bytes()).hexdigest()
        or receipt["original_cargo_lock_sha256"] != original_lock
    ):
        raise ValueError("source archive identity differs from the checkout or receipt")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > 30_000 or sum(m.size for m in members) > 512 * 1024 * 1024:
            raise ValueError("source archive exceeds inspection bounds")
        names = set()
        roots = set()
        files = {}
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or len(path.parts) < 2
                or ".." in path.parts
                or "\\" in member.name
                or ":" in member.name
                or str(path) != member.name
                or member.name.casefold() in names
            ):
                raise ValueError("unsafe or duplicate source archive member")
            names.add(member.name.casefold())
            roots.add(path.parts[0])
            files[PurePosixPath(*path.parts[1:]).as_posix()] = member
        if len(roots) != 1:
            raise ValueError("expected exactly one source tree")
        metadata = BytesParser().parsebytes(
            source.extractfile(files["PKG-INFO"]).read()
        )
        version = metadata["Version"]
        if metadata["Name"] != "phantom-http" or roots != {f"phantom_http-{version}"}:
            raise ValueError("unexpected source package identity")
        lock = source.extractfile(files["Cargo.lock"]).read()
        if hashlib.sha256(lock).hexdigest() != receipt["cargo_lock_sha256"]:
            raise ValueError("source closure lock differs from receipt")
        licenses = {
            name: hashlib.sha256(source.extractfile(member).read()).hexdigest()
            for name, member in files.items()
            if name in ("LICENSE-MIT", "LICENSE-APACHE")
            or name.startswith("third-party-notices/")
        }
        if set(metadata.get_all("License-File", [])) != licenses.keys():
            raise ValueError("source license metadata differs from payload")
        if not any(
            name.startswith("third-party-notices/rust-runtime/") for name in licenses
        ):
            raise ValueError("source archive lacks Rust runtime notices")
        inventory = json.loads(
            source.extractfile(files["third-party-notices/inventory.json"]).read()
        )
        if inventory != receipt["notices"]:
            raise ValueError("source notice inventory differs from receipt")
        for package in inventory:
            for notice in package["notices"]:
                if (
                    licenses.get("third-party-notices/" + notice["file"])
                    != notice["sha256"]
                ):
                    raise ValueError("source dependency notice differs from inventory")
    return {"receipt": receipt, "version": version, "licenses": licenses}


def inspect_source_notices(wheel, dist, source):
    """Require the source notice closure byte-for-byte, without a second notice rewrite."""
    prefix = f"{dist}/licenses/"
    with zipfile.ZipFile(wheel) as archive:
        actual = {
            name.removeprefix(prefix): hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith(prefix) and not name.endswith("/")
        }
    if actual != source["licenses"]:
        raise ValueError("wheel license payload differs from the source archive")


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


def run(*command: str, **options) -> None:
    print("+", *command, flush=True)
    subprocess.run(command, check=True, **options)


def check_development() -> None:
    root = ROOT
    os.chdir(root)
    output = root / "target" / "python-binding"
    output.mkdir(parents=True, exist_ok=True)
    # Cargo caches can restore incomplete virtualenvs; never cache this environment.
    with tempfile.TemporaryDirectory(prefix="phantom-python-binding-") as temporary:
        environment = Path(temporary) / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
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
            "--force-reinstall",
            str(built[0]),
        )
        peer_environment = h3_peer_environment(root, Path(temporary))
        run(
            str(python),
            "-m",
            "unittest",
            "discover",
            "-s",
            "bindings/python/tests",
            "-v",
            env=peer_environment,
        )


def installed_checks(wheel, commands, interpreter=None):
    with tempfile.TemporaryDirectory(prefix="phantom-python-wheel-") as temporary:
        directory = Path(temporary).resolve()
        if directory.is_relative_to(ROOT):
            raise ValueError("wheel installation check must run outside checkout")
        environment = directory / "environment"
        if interpreter is None:
            venv.EnvBuilder(with_pip=True).create(environment)
        else:
            commands.run(
                [str(interpreter), "-I", "-m", "venv", str(environment)], cwd=directory
            )
        python = python_in(environment)
        if interpreter is None:
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
        wheelhouse = directory / "dependency-wheels"
        commands.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "download",
                "--only-binary=:all:",
                "--dest",
                str(wheelhouse),
                str(wheel),
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
                "--find-links",
                str(wheelhouse),
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
        peer_environment = (
            h3_peer_environment(ROOT, directory) if interpreter is None else None
        )
        checks = json.loads(
            commands.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import json,sys,unittest; "
                    + (
                        "suite=unittest.defaultTestLoader.discover('tests'); "
                        if interpreter is None
                        else "suite=unittest.defaultTestLoader.discover('tests',pattern='test_client.py'); "
                    )
                    + "r=unittest.TextTestRunner(verbosity=2).run(suite); "
                    "print(json.dumps({'tests':r.testsRun,'skipped':len(r.skipped)})); "
                    "sys.exit(0 if r.wasSuccessful() and r.testsRun>=12 and not r.skipped else 1)",
                ],
                cwd=directory,
                timeout=300,
                env=peer_environment,
            )
        )
        return {
            "installation": identity,
            "dependency_wheels": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(wheelhouse.glob("*.whl"))
            },
            "loopback_checks": checks,
            "coverage": "full installed suite and typing"
            if interpreter is None
            else "stdlib test_client loopback module only; no typing or other modules",
        }


def source_build_directory():
    # MSBuild's nested tracking logs can exceed MAX_PATH under the user temp path.
    parent = None
    if sys.platform == "win32" and "RUNNER_TEMP" in os.environ:
        parent = Path(os.environ["RUNNER_TEMP"])
        if not parent.is_absolute() or not parent.is_dir():
            raise ValueError("RUNNER_TEMP must be an absolute existing directory")
        parent = parent.resolve()
        if parent.is_relative_to(ROOT.resolve()):
            raise ValueError("RUNNER_TEMP must be outside checkout")
    try:
        return tempfile.TemporaryDirectory(prefix="pw-", dir=parent)
    except OSError as error:
        if parent is not None:
            raise ValueError("RUNNER_TEMP must be writable") from error
        raise


def verify_candidate(
    target, output, source_archive, source_receipt, additional_python=None
):
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
    original_lock = hashlib.sha256(
        commands.run(["git", "show", f"{revision}:Cargo.lock"])
    ).hexdigest()
    source = inspect_source(source_archive, source_receipt, revision, original_lock)
    if (
        f"release: {source['receipt']['source_builder_toolchain']}"
        not in rustc.splitlines()
    ):
        raise ValueError("consumer compiler differs from source notice toolchain")
    package = {"version": source["version"]}
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
    manylinux = target.endswith("linux-gnu")
    # pip extracts and builds only this archive in its isolated PEP 517 environment.
    # No checkout path is a compiler input, and the backend pin comes from the archive.
    build_args = [
        "--locked",
        "--profile",
        "release",
        "--config",
        "profile.release.opt-level=3",
        "--target",
        target,
        "--jobs",
        jobs,
    ]
    if manylinux:
        build_args.extend(
            ["--compatibility", "manylinux_2_28", "--auditwheel", "check"]
        )
    build_env = dict(os.environ, MATURIN_NO_INSTALL_RUST="1")
    with source_build_directory() as temporary:
        directory = Path(temporary).resolve()
        if directory.is_relative_to(ROOT):
            raise ValueError("source wheel build must run outside checkout")
        build_env.update(
            TMPDIR=str(directory),
            TEMP=str(directory),
            TMP=str(directory),
            CARGO_TARGET_DIR=str(directory / "t"),
        )
        commands.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "--use-pep517",
                "--wheel-dir",
                str(wheels),
                "--config-settings=maturin.build-args=" + shlex.join(build_args),
                str(source_archive.resolve()),
            ],
            cwd=directory,
            env=build_env,
            timeout=1800,
        )
    built = list(wheels.glob("*.whl"))
    if len(built) != 1:
        raise ValueError(f"expected one built wheel, found {len(built)}")
    original = built[0]
    info = inspect_wheel(
        original,
        target,
        package["version"],
        manylinux=manylinux,
        project_licenses=source["licenses"],
    )
    candidate = output / "candidate" / original.name
    candidate.parent.mkdir()
    inspect_source_notices(original, info["dist_info"], source)
    inventory = source["receipt"]["notices"]
    shutil.copyfile(original, candidate)
    checked = inspect_wheel(
        candidate,
        target,
        package["version"],
        manylinux=manylinux,
        project_licenses=source["licenses"],
    )
    native = output / "native"
    native.mkdir()
    with zipfile.ZipFile(candidate) as archive:
        binary = native / PurePosixPath(checked["native"]).name
        binary.write_bytes(archive.read(checked["native"]))
    linkage = tools.dependency_inspection(binary, target, commands)
    installed = installed_checks(candidate, commands)
    installations = [installed]
    if additional_python is not None:
        installations.append(installed_checks(candidate, commands, additional_python))
    if any(
        result["installation"]["version"] != package["version"]
        for result in installations
    ):
        raise ValueError("installed wheel version differs from source metadata")
    if (
        source is not None
        and tools.digest(source_archive) != source["receipt"]["archive_sha256"]
    ):
        raise ValueError("source archive changed during wheel verification")
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
            for key in (
                "MACOSX_DEPLOYMENT_TARGET",
                "CC",
                "CXX",
                "CFLAGS",
                "CXXFLAGS",
                "PHANTOM_MANYLINUX_IMAGE",
            )
            if key in os.environ
        },
        "tested_host": host,
        "original_wheel_sha256": tools.digest(original),
        "wheel_sha256": tools.digest(candidate),
        "wheel": checked,
        "notices": inventory,
        "native_linkage": linkage,
        **installed,
        "additional_installations": installations[1:],
        "source_distribution": source["receipt"],
        "runtime_boundary": (
            "Built and audited for manylinux_2_28; installed on the recorded host and interpreters only. SDK/OS runtime licenses are separate."
            if manylinux
            else "Tested on the recorded host and interpreters only; older OS compatibility is not established. SDK/OS runtime licenses are separate."
        ),
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


def assemble_candidates(source_directory, wheel_directories, output):
    """Compose one exact source and three installed consumer receipts; never publish."""
    tools = artifact_tools()
    source_receipt = source_directory / "receipt.json"
    receipt = json.loads(source_receipt.read_bytes())
    archives = list(source_directory.glob("*.tar.gz"))
    if len(archives) != 1:
        raise ValueError("expected exactly one source archive")
    source = inspect_source(
        archives[0],
        source_receipt,
        receipt["source_revision"],
        receipt["original_cargo_lock_sha256"],
    )
    targets = {
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-apple-darwin",
    }
    receipts = []
    payloads = [archives[0]]
    for directory in wheel_directories:
        consumer = json.loads((directory / "verification.json").read_bytes())
        if (
            consumer["target"] not in targets
            or consumer["source_distribution"] != receipt
        ):
            raise ValueError(
                "consumer does not verify this exact source or has a duplicate target"
            )
        targets.remove(consumer["target"])
        wheels = list(directory.glob("*.whl"))
        if len(wheels) != 1 or tools.digest(wheels[0]) != consumer["wheel_sha256"]:
            raise ValueError("consumer wheel identity differs from receipt")
        info = inspect_wheel(
            wheels[0],
            consumer["target"],
            source["version"],
            manylinux=consumer["target"].endswith("linux-gnu"),
            project_licenses=source["licenses"],
        )
        inspect_source_notices(wheels[0], info["dist_info"], source)
        if (
            consumer["loopback_checks"]["tests"] < 12
            or consumer["loopback_checks"]["skipped"]
        ):
            raise ValueError("consumer installed checks are incomplete")
        additional = consumer["additional_installations"]
        if (
            len(additional) != 1
            or additional[0]["loopback_checks"]["tests"] < 12
            or additional[0]["loopback_checks"]["skipped"]
        ):
            raise ValueError(
                "consumer current-stable installation checks are incomplete"
            )
        receipts.append(consumer)
        payloads.append(wheels[0])
    if targets:
        raise ValueError("all three native source consumers must pass before promotion")
    output.mkdir(parents=True, exist_ok=False)
    for path in payloads:
        shutil.copyfile(path, output / path.name)
    tools.write_json(
        output / "verification.json",
        {
            "source": receipt,
            "consumers": receipts,
            "validation": "same source built and installed on all three recorded native hosts; publication is separate",
        },
    )
    (output / "SHA256SUMS").write_text(
        "".join(f"{tools.digest(p)}  {p.name}\n" for p in payloads), encoding="utf-8"
    )


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
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--additional-python", type=Path)
    parser.add_argument("--assemble-source", type=Path)
    parser.add_argument("--consumer", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.assemble_source is not None:
        if (
            args.output is None
            or len(args.consumer) != 3
            or args.release_candidate
            or args.target is not None
            or any(
                v is not None
                for v in (
                    args.source_archive,
                    args.source_receipt,
                    args.additional_python,
                )
            )
        ):
            parser.error(
                "--assemble-source requires --output and exactly three --consumer directories"
            )
        assemble_candidates(args.assemble_source, args.consumer, args.output)
    elif args.consumer:
        parser.error("--consumer requires --assemble-source")
    elif args.release_candidate:
        if args.target is None or args.output is None:
            parser.error("--release-candidate requires --target and --output")
        if args.source_archive is None or args.source_receipt is None:
            parser.error(
                "--release-candidate requires --source-archive and --source-receipt"
            )
        verify_candidate(
            args.target,
            args.output,
            args.source_archive,
            args.source_receipt,
            args.additional_python,
        )
    elif any(
        value is not None
        for value in (
            args.target,
            args.output,
            args.source_archive,
            args.source_receipt,
            args.additional_python,
        )
    ):
        parser.error("--target and --output require --release-candidate")
    else:
        check_development()


if __name__ == "__main__":
    main()
