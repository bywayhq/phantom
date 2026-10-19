"""Build and verify one host-native Phantom CLI archive; never publish it."""

import argparse
import contextlib
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"
TARGETS = {
    "x86_64-pc-windows-msvc": ("Windows", {"amd64", "x86_64"}),
    "x86_64-unknown-linux-gnu": ("Linux", {"x86_64"}),
    "aarch64-apple-darwin": ("Darwin", {"arm64", "aarch64"}),
}
ALLOC_STDLIB_LICENSE_SOURCE = (
    "https://raw.githubusercontent.com/dropbox/rust-alloc-no-stdlib/"
    "0a81fd6928ea3b33c8cd484aa4575d50ffb98012/LICENSE"
)
ALLOC_STDLIB_LICENSE_SHA256 = (
    "c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae"
)
ALLOC_STDLIB_LICENSE_PATH = "scripts/release/notices/alloc-stdlib-0.3.0.LICENSE"
NAPI_RS_LICENSE_REVISIONS = {
    ("napi", "3.14.2"): "8bab46ee5dfd48a7b51e8bad3d09aed315ada4df",
    ("napi-build", "2.6.0"): "a94cef33f62e74682963dd085e283f52dcec2600",
    ("napi-derive", "3.6.12"): "8bab46ee5dfd48a7b51e8bad3d09aed315ada4df",
    ("napi-derive-backend", "6.1.5"): "4694e6d7c7d7eb2ac6b9a634374c3519a9e5851f",
    ("napi-sys", "3.4.0"): "37109f133043aff379a38edfb8b1548e7e9309e5",
}
NAPI_RS_LICENSE_SHA256 = (
    "3f1ce66533302df3a32edbfdfc0b78f0dd34659e4c1f5817162e5ea3c2297215"
)
NAPI_RS_LICENSE_PATH = "scripts/release/notices/napi-rs.LICENSE"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build_jobs():
    value = os.environ.get("CARGO_BUILD_JOBS", "2")
    if not value.isascii() or not value.isdigit() or int(value) == 0:
        raise ValueError("CARGO_BUILD_JOBS must be a positive integer")
    return value


class Commands:
    def __init__(self, logs):
        self.logs = logs
        self.logs.mkdir(parents=True)
        self.count = 0

    def run(self, args, *, cwd=ROOT, expected=0, timeout=60, env=None):
        self.count += 1
        stem = self.logs / f"{self.count:02d}-{Path(str(args[0])).stem}"
        write_json(stem.with_suffix(".command.json"), [str(arg) for arg in args])
        try:
            result = subprocess.run(
                args,
                cwd=cwd,
                env=env,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            stem.with_suffix(".stdout").write_bytes(error.stdout or b"")
            stem.with_suffix(".stderr").write_bytes(error.stderr or b"")
            write_json(stem.with_suffix(".exit.json"), {"timeout_seconds": timeout})
            raise
        stem.with_suffix(".stdout").write_bytes(result.stdout)
        stem.with_suffix(".stderr").write_bytes(result.stderr)
        write_json(stem.with_suffix(".exit.json"), {"returncode": result.returncode})
        if result.returncode != expected:
            raise ValueError(f"command failed ({result.returncode}); see {stem}")
        return result.stdout


def host_identity(target, rustc):
    system, machines = TARGETS[target]
    if platform.system() != system or platform.machine().lower() not in machines:
        raise ValueError(
            "artifact target must match this host; cross builds are unsupported"
        )
    if f"host: {target}" not in rustc.splitlines():
        raise ValueError("Rust host must match the artifact target")
    return {
        "system": system,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "libc": list(platform.libc_ver()),
        "macos": platform.mac_ver()[0],
        "windows": list(platform.win32_ver()),
        "runner_image": os.environ.get("ImageOS"),  # noqa: SIM112 - runner key
        "runner_image_version": os.environ.get("ImageVersion"),  # noqa: SIM112 - runner key
        "linux_distribution": Path("/etc/os-release").read_text(encoding="utf-8")
        if system == "Linux"
        else None,
        "compatibility": "Tested on this runtime only; no older runtime floor established.",
    }


def build_records(raw):
    """Use actual build inputs, rather than metadata's workspace-wide feature union."""
    packages = set()
    executables = []
    finished = False
    for line in raw.splitlines():
        record = json.loads(line)
        if record.get("reason") in {"compiler-artifact", "build-script-executed"}:
            packages.add(record["package_id"])
        if (
            record.get("reason") == "compiler-artifact"
            and record.get("target", {}).get("name") == "phantom"
            and "bin" in record["target"]["kind"]
            and not record["profile"]["test"]
            and record.get("executable")
        ):
            if record["profile"]["opt_level"] != "3":
                raise ValueError(
                    "CLI was not built with the release optimization level"
                )
            executables.append(Path(record["executable"]))
        if record.get("reason") == "build-finished":
            finished = record["success"]
    if not finished or len(executables) != 1 or not packages:
        raise ValueError("Cargo did not report exactly one successful release CLI")
    return packages, executables[0]


def notice_files(directory):
    files = []
    for entry in directory.iterdir():
        if entry.name.upper().startswith(
            ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")
        ):
            files.extend([entry] if entry.is_file() else entry.rglob("*"))
    return sorted(path for path in files if path.is_file())


def package_notices(package, root):
    directory = Path(package["manifest_path"]).parent.resolve()
    files = notice_files(directory)
    license_file = package.get("license_file")
    if license_file:
        path = (directory / license_file).resolve()
        if not path.is_file():
            raise ValueError(f"missing declared license: {package['name']}")
        files.append(path)
    # Local workspace and nested vendor packages can inherit their repository's
    # licenses. Do not search outside this checkout or a registry package.
    if not files and directory.is_relative_to(root):
        parent = directory.parent
        while parent.is_relative_to(root):
            files = notice_files(parent)
            if files or parent == root:
                break
            parent = parent.parent
    if not files and (
        package["name"],
        package.get("version"),
        package.get("license"),
    ) == ("alloc-stdlib", "0.3.0", "BSD-3-Clause"):
        # This published subcrate omits its repository-root license. Retain the
        # exact upstream notice at its own .cargo_vcs_info.json revision offline.
        pinned = root / ALLOC_STDLIB_LICENSE_PATH
        if not pinned.is_file() or digest(pinned) != ALLOC_STDLIB_LICENSE_SHA256:
            raise ValueError("missing or modified pinned alloc-stdlib license")
        files = [pinned]
    if (
        not files
        and package.get("license") == "MIT"
        and (package["name"], package.get("version")) in NAPI_RS_LICENSE_REVISIONS
    ):
        # These published subcrates omit the same repository-root license.
        # Retain each exact upstream revision in the resulting inventory.
        pinned = root / NAPI_RS_LICENSE_PATH
        if not pinned.is_file() or digest(pinned) != NAPI_RS_LICENSE_SHA256:
            raise ValueError("missing or modified pinned napi-rs license")
        files = [pinned]
    if not files:
        raise ValueError(f"no retained license/notice text for {package['name']}")
    return sorted(set(files))


def copy_notices(metadata, package_ids, destination, root=ROOT):
    packages = {package["id"]: package for package in metadata["packages"]}
    if missing := package_ids - packages.keys():
        raise ValueError(f"build inputs absent from Cargo metadata: {sorted(missing)}")
    inventory = []
    for package_id in sorted(package_ids):
        package = packages[package_id]
        name = package["name"]
        version = package["version"]
        folder = destination / f"{name}-{version}"
        if folder.exists():
            raise ValueError(f"ambiguous package name/version: {name}-{version}")
        folder.mkdir(parents=True)
        files = package_notices(package, root)
        # Preserve distinct same-named notices, including license directories.
        texts = []
        for index, path in enumerate(files):
            output = folder / f"{index:02d}-{path.name}"
            shutil.copyfile(path, output)
            texts.append(
                {
                    "file": output.relative_to(destination).as_posix(),
                    "sha256": digest(output),
                }
            )
        inventory.append(
            {
                "name": name,
                "version": version,
                "license": package.get("license"),
                "source": package.get("source") or "checkout",
                "repository": package.get("repository"),
                "notices": texts,
                "scope": "compiler input (includes build tools and procedural macros)",
            }
        )
        if files == [root / ALLOC_STDLIB_LICENSE_PATH]:
            inventory[-1]["supplementary_notice"] = {
                "source": ALLOC_STDLIB_LICENSE_SOURCE,
                "sha256": ALLOC_STDLIB_LICENSE_SHA256,
            }
        if files == [root / NAPI_RS_LICENSE_PATH]:
            revision = NAPI_RS_LICENSE_REVISIONS[name, version]
            inventory[-1]["supplementary_notice"] = {
                "source": f"https://raw.githubusercontent.com/napi-rs/napi-rs/{revision}/LICENSE",
                "sha256": NAPI_RS_LICENSE_SHA256,
            }
        if name == "phantom-btls-sys":
            native = Path(package["manifest_path"]).parent / "deps/boringssl"
            native_files = [
                native / "LICENSE",
                *sorted((native / "third_party").glob("*/LICENSE*")),
            ]
            for path in native_files:
                output = folder / "boringssl" / path.relative_to(native)
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, output)
                texts.append(
                    {
                        "file": output.relative_to(destination).as_posix(),
                        "sha256": digest(output),
                    }
                )
    return inventory


def copy_rust_notices(sysroot, destination):
    docs = sysroot / "share/doc/rust"
    copyright_file = docs / "COPYRIGHT-library.html"
    if not copyright_file.exists():
        copyright_file = docs / "COPYRIGHT"
    if not copyright_file.is_file():
        raise ValueError("Rust toolchain is missing runtime copyright notices")
    destination.mkdir()
    shutil.copyfile(copyright_file, destination / copyright_file.name)
    licenses = docs / "licenses"
    if licenses.is_dir():
        if (
            not (licenses / "MIT.txt").is_file()
            or not (licenses / "Apache-2.0.txt").is_file()
        ):
            raise ValueError("Rust toolchain is missing MIT/Apache license texts")
        shutil.copytree(licenses, destination / "licenses")
    else:
        files = list(docs.glob("LICENSE*"))
        if not files:
            raise ValueError("Rust toolchain is missing license texts")
        for path in files:
            shutil.copyfile(path, destination / path.name)


def dependency_inspection(binary, target, commands):
    if target.endswith("linux-gnu"):
        tools = [
            ["readelf", "-h", "-d", "-V", str(binary)],
            ["ldd", str(binary)],
            ["ldd", "--version"],
        ]
    elif target.endswith("apple-darwin"):
        tools = [
            ["otool", "-L", str(binary)],
            ["otool", "-l", str(binary)],
            ["sw_vers"],
        ]
    else:
        dumpbin = shutil.which("dumpbin")
        if not dumpbin:
            vswhere = (
                Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)"))
                / "Microsoft Visual Studio/Installer/vswhere.exe"
            )
            found = (
                commands.run(
                    [
                        str(vswhere),
                        "-latest",
                        "-products",
                        "*",
                        "-requires",
                        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                        "-find",
                        "VC/Tools/MSVC/**/bin/Hostx64/x64/dumpbin.exe",
                    ]
                )
                .decode()
                .splitlines()
            )
            if not found:
                raise ValueError("MSVC dumpbin is required for dependency inspection")
            dumpbin = found[0]
        tools = [[dumpbin, "/HEADERS", "/DEPENDENTS", str(binary)]]
    return [
        {
            "tool": Path(args[0]).name,
            "arguments": args[1:],
            "output": commands.run(args).decode("utf-8", errors="replace"),
        }
        for args in tools
    ]


def create_archive(folder, archive):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in sorted(folder.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(folder.parent).as_posix())
    else:
        with tarfile.open(archive, "w:gz") as output:
            output.add(folder, arcname=folder.name)


def extract_archive(archive, destination):
    """Extract only regular files/directories, preserving executable permissions."""
    destination = destination.resolve()
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            entries = [
                (entry.filename, entry.is_dir(), entry) for entry in source.infolist()
            ]
            for name, is_dir, entry in entries:
                output = archive_path(destination, name)
                if is_dir:
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(entry) as data, output.open("xb") as target:
                        shutil.copyfileobj(data, target)
    else:
        with tarfile.open(archive, "r:gz") as source:
            for entry in source.getmembers():
                output = archive_path(destination, entry.name)
                if entry.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(entry) as data, output.open("xb") as target:
                        shutil.copyfileobj(data, target)
                    output.chmod(entry.mode & 0o777)
                else:
                    raise ValueError("archive contains a non-file entry")


def archive_path(destination, name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError("unsafe archive path")
    return destination.joinpath(*path.parts)


def read_head(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        byte = stream.recv(1)
        if not byte:
            raise ValueError("peer closed before a complete request")
        result.extend(byte)
        if len(result) > 16384:
            raise ValueError("oversized request head")
    return bytes(result)


@contextlib.contextmanager
def peer(handler):
    """One bounded loopback connection, like phantom-cli/tests/commands.rs."""
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)

        def serve():
            try:
                with listener.accept()[0] as stream:
                    stream.settimeout(10)
                    handler(stream, read_head(stream))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{listener.getsockname()[1]}/artifact"
        finally:
            thread.join(12)
        if thread.is_alive():
            raise ValueError("controlled peer did not finish")
        if errors:
            raise errors[0]


def smoke(binary, directory, commands, version):
    environment = os.environ.copy()
    # Run with ordinary system loader search, not checkout/native build paths.
    for key in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"):
        environment.pop(key, None)

    def run(args, **options):
        return commands.run(
            [str(binary), *args], cwd=directory, env=environment, **options
        )

    if run(["--version"]).decode().strip() != f"phantom {version}":
        raise ValueError("extracted CLI version differs from Cargo metadata")
    if PROFILE not in run(["profiles", "list"]).decode().splitlines():
        raise ValueError("expected exact profile absent from extracted CLI")
    profile = run(["profiles", "export", PROFILE])
    profile_file = directory / "profile.json"
    profile_file.write_bytes(profile)
    if json.loads(run(["profiles", "import", str(profile_file)])) != json.loads(
        profile
    ):
        raise ValueError("extracted CLI profile round trip changed settings")

    def request(url, timeout="5000"):
        return [
            "request",
            url,
            "--profile",
            PROFILE,
            "--protocol",
            "h1",
            "--timeout-ms",
            timeout,
        ]

    def get(stream, head):
        if not head.startswith(b"GET /artifact HTTP/1.1\r\n"):
            raise ValueError("unexpected request target")
        if b"X-Artifact: first\r\nX-Artifact: second\r\n" not in head:
            raise ValueError("caller header ordering changed")
        stream.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        )

    with peer(get) as url:
        if (
            run(
                [
                    *request(url),
                    "--header",
                    "X-Artifact: first",
                    "--header",
                    "X-Artifact: second",
                ]
            )
            != b"hello"
        ):
            raise ValueError("extracted request body mismatch")

    payload = bytes(range(251)) * 256
    upload = directory / "upload.bin"
    download = directory / "download.bin"
    upload.write_bytes(payload)

    def transfer(stream, head):
        if (
            not head.startswith(b"PUT /artifact HTTP/1.1\r\n")
            or f"content-length: {len(payload)}\r\n".encode() not in head.lower()
        ):
            raise ValueError("unexpected file upload framing")
        received = bytearray()
        while len(received) < len(payload):
            chunk = stream.recv(min(4096, len(payload) - len(received)))
            if not chunk:
                raise ValueError("incomplete upload")
            received.extend(chunk)
        if received != payload:
            raise ValueError("uploaded bytes changed")
        stream.sendall(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        for index in range(0, len(payload), 4096):
            chunk = payload[index : index + 4096]
            stream.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        stream.sendall(b"0\r\n\r\n")

    with peer(transfer) as url:
        run(
            [
                *request(url),
                "--method",
                "PUT",
                "--upload",
                str(upload),
                "--output",
                str(download),
            ]
        )
    if download.read_bytes() != payload:
        raise ValueError("downloaded bytes changed")

    def stalled(stream, _head):
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\na")
        try:
            if stream.recv(1):
                raise ValueError("unexpected bytes after incomplete response")
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    report = directory / "deadline.json"
    with peer(stalled) as url:
        body = run([*request(url, "1000"), "--diagnostics", str(report)], expected=1)
    if body != b"a":
        raise ValueError("deadline check did not reach the response body")
    events = json.loads(report.read_text(encoding="utf-8"))["events"]
    if not any(
        event["phase"] == "response_body" and event["outcome"] != "completed"
        for event in events
    ):
        raise ValueError("deadline diagnostics omitted incomplete body")
    return [
        "version",
        "profile-list",
        "profile-round-trip",
        "ordered-headers",
        "request",
        "file-upload",
        "chunked-download",
        "deadline-cancellation-disconnect",
    ]


def verify(args):
    jobs = build_jobs()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = Commands(output / "logs")
    if commands.run(["git", "status", "--porcelain"]).strip():
        raise ValueError("CLI artifacts require a clean checkout")
    revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    lock_hash = digest(ROOT / "Cargo.lock")
    if any(key.startswith("BORING_BSSL_") for key in os.environ):
        raise ValueError(
            "remove prebuilt native TLS overrides before building artifacts"
        )
    rustc = commands.run(["rustc", "-vV"]).decode()
    runtime = host_identity(args.target, rustc)
    cargo_version = commands.run(["cargo", "-V"]).decode().strip()
    metadata = json.loads(
        commands.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                args.target,
            ]
        )
    )
    raw = commands.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            args.target,
            "-p",
            "phantom-cli",
            "--jobs",
            jobs,
            "--message-format=json-render-diagnostics",
        ],
        timeout=1800,
    )
    package_ids, binary = build_records(raw)
    package = next(
        package for package in metadata["packages"] if package["name"] == "phantom-cli"
    )
    name = f"phantom-{package['version']}-{args.target}"
    staging = output / "staging" / name
    staging.mkdir(parents=True)
    executable = "phantom.exe" if args.target.endswith("windows-msvc") else "phantom"
    shutil.copy2(binary, staging / executable)
    for filename in ("LICENSE-APACHE", "LICENSE-MIT"):
        shutil.copyfile(ROOT / filename, staging / filename)
    (staging / "README.md").write_text(
        "# Phantom CLI\n\n"
        "Put this directory's phantom executable on your path. Keep the licenses\n"
        "and notices when redistributing it. Run `phantom --help` to get started.\n\n"
        "See artifact.json for the exact source, compiler, tested runtime and\n"
        "native dependencies. Older runtimes and fully static linkage are not\n"
        "verified. This candidate is unsigned and is not a published release.\n\n"
        + (
            "Windows requires the [Microsoft x64 Visual C++ v14 runtime]"
            "(https://aka.ms/vc14/vc_redist.x64.exe), at least as recent as the\n"
            "archive's MSVC build tools. Runtime DLLs are not bundled.\n\n"
            if executable.endswith(".exe")
            else ""
        )
        + f"[CLI guide](https://github.com/bywayhq/phantom/blob/{revision}/crates/phantom-cli/README.md)\n",
        encoding="utf-8",
    )
    inventory = copy_notices(metadata, package_ids, staging / "notices")
    sysroot = Path(commands.run(["rustc", "--print", "sysroot"]).decode().strip())
    copy_rust_notices(sysroot, staging / "notices/rust-runtime")
    inspection = dependency_inspection(staging / executable, args.target, commands)
    identity = {
        "schema": 1,
        "package": "phantom-cli",
        "version": package["version"],
        "source_revision": revision,
        "cargo_lock_sha256": lock_hash,
        "target": args.target,
        "rustc": rustc,
        "cargo": cargo_version,
        "build_jobs": jobs,
        "build_environment": {
            key: os.environ[key]
            for key in (
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "MACOSX_DEPLOYMENT_TARGET",
                "CC",
                "CXX",
                "CFLAGS",
                "CXXFLAGS",
            )
            if key in os.environ
        },
        "tested_runtime": runtime,
        "binary_sha256": digest(staging / executable),
        "dependencies": inventory,
        "native_inspection": inspection,
    }
    write_json(staging / "artifact.json", identity)
    extension = ".zip" if executable.endswith(".exe") else ".tar.gz"
    archive = output / f"{name}{extension}"
    create_archive(staging, archive)
    with tempfile.TemporaryDirectory(prefix="phantom-cli-artifact-") as temporary:
        extracted = Path(temporary).resolve()
        if extracted.is_relative_to(ROOT):
            raise ValueError("extracted installation check must run outside checkout")
        extract_archive(archive, extracted)
        installed = extracted / name / executable
        if digest(installed) != identity["binary_sha256"]:
            raise ValueError("extracted binary checksum mismatch")
        checks = smoke(installed, extracted, commands, package["version"])
    if (
        commands.run(["git", "status", "--porcelain"]).strip()
        or commands.run(["git", "rev-parse", "HEAD"]).decode().strip() != revision
        or digest(ROOT / "Cargo.lock") != lock_hash
    ):
        raise ValueError("checkout identity changed during artifact verification")
    # No uploadable directory exists until every verification step succeeds.
    verified = output / "verified"
    verified.mkdir()
    archive_hash = digest(archive)
    shutil.move(str(archive), verified / archive.name)
    (verified / "SHA256SUMS").write_text(
        f"{archive_hash}  {archive.name}\n", encoding="utf-8"
    )
    write_json(
        verified / "verification.json",
        {
            "archive": archive.name,
            "sha256": archive_hash,
            "identity": identity,
            "checks": checks,
        },
    )
    print(f"Verified CLI archive: {verified / archive.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="new evidence directory"
    )
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
