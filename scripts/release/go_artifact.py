"""Build and verify a paired Go module/native library archive; never publish it."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
MODULE = "github.com/bywayhq/phantom/bindings/go"
LIBRARIES = {
    "x86_64-pc-windows-msvc": "phantom_go.dll",
    "x86_64-unknown-linux-gnu": "libphantom_go.so",
    "aarch64-apple-darwin": "libphantom_go.dylib",
}


def h3_peer_environment(root, directory, environment=None):
    spec = importlib.util.spec_from_file_location(
        "binding_h3_peer", root / "scripts/dev/binding_h3_peer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.peer_environment(root, directory, environment)


def checked_module_version(source, native_version):
    declaration = re.search(
        rb'^const nativePackageVersion = "([^"]+)"\r?$',
        (source / "version.go").read_bytes(),
        re.MULTILINE,
    )
    if declaration is None or declaration[1].decode() != native_version:
        raise ValueError("Go module version differs from native Cargo package version")
    version = f"v{native_version}"
    if not re.fullmatch(r"v[01]\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("Go candidates require a stable v0 or v1 module version")
    return version


def committed_module_files(commands, revision):
    tree = commands.run(["git", "ls-tree", "-r", "-z", revision, "--", "bindings/go"])
    blobs = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if mode not in {"100644", "100755"} or kind != "blob":
            continue
        path = PurePosixPath(raw_path.decode())
        if path.parts[:2] != ("bindings", "go") or ".." in path.parts:
            raise ValueError("Git module inventory contains an unexpected path")
        relative = PurePosixPath(*path.parts[2:])
        if "vendor" in relative.parts[:-1]:
            continue
        blobs[relative.as_posix()] = blob
    nested = {
        str(PurePosixPath(path).parent) + "/"
        for path in blobs
        if path != "go.mod" and PurePosixPath(path).name == "go.mod"
    }
    return {
        path: commands.run(["git", "cat-file", "blob", blob])
        for path, blob in sorted(blobs.items())
        if not any(path.startswith(directory) for directory in nested)
    }


def stage_module_proxy(destination, revision, version, commands):
    files = committed_module_files(commands, revision)
    if files.get("go.mod", b"").splitlines()[:1] != [f"module {MODULE}".encode()]:
        raise ValueError("committed Go module has an unexpected identity")
    for required in ("version.go", "native.h", "LICENSE-MIT", "LICENSE-APACHE"):
        if required not in files:
            raise ValueError(f"committed Go module is missing {required}")
    folder = destination / MODULE / "@v"
    folder.mkdir(parents=True)
    (folder / f"{version}.mod").write_bytes(files["go.mod"])
    timestamp = (
        commands.run(["git", "show", "-s", "--format=%cI", revision]).decode().strip()
    )
    (folder / f"{version}.info").write_text(
        json.dumps({"Version": version, "Time": timestamp}), encoding="utf-8"
    )
    (folder / "list").write_text(version + "\n", encoding="utf-8")
    archive = folder / f"{version}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path, data in files.items():
            entry = zipfile.ZipInfo(f"{MODULE}@{version}/{path}")
            entry.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(entry, data)
    return {
        "path": MODULE,
        "version": version,
        "tag": f"bindings/go/{version}",
        "source_revision": revision,
        "zip_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "mod_sha256": hashlib.sha256(files["go.mod"]).hexdigest(),
        "files_sha256": {
            path: hashlib.sha256(data).hexdigest() for path, data in files.items()
        },
    }


def artifact_tools():
    spec = importlib.util.spec_from_file_location(
        "phantom_cli_artifact", ROOT / "scripts/release/cli_artifact.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_records(raw, target):
    packages, libraries = set(), []
    finished = False
    for line in raw.splitlines():
        record = json.loads(line)
        if record.get("reason") in {"compiler-artifact", "build-script-executed"}:
            packages.add(record["package_id"])
        if (
            record.get("reason") == "compiler-artifact"
            and record.get("target", {}).get("name") == "phantom_go"
            and "cdylib" in record["target"]["kind"]
            and not record["profile"]["test"]
        ):
            if record["profile"]["opt_level"] != "3":
                raise ValueError("Go native library is not optimized at level 3")
            libraries.extend(
                Path(path)
                for path in record["filenames"]
                if Path(path).name == LIBRARIES[target]
            )
        if record.get("reason") == "build-finished":
            finished = record["success"]
    if not finished or len(libraries) != 1 or not packages:
        raise ValueError(
            "Cargo did not report exactly one successful release Go library"
        )
    return packages, libraries[0]


def copy_module(source, destination):
    destination.mkdir()
    files = sorted(source.glob("*.go")) + [
        source / name
        for name in (
            "go.mod",
            "go.sum",
            "native.h",
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
        )
    ]
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or nonregular Go module file: {path.name}")
        shutil.copyfile(path, destination / path.name)
    if (destination / "go.mod").read_text().splitlines()[0] != f"module {MODULE}":
        raise ValueError("unexpected Go module identity")
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        if (destination / name).read_bytes() != (ROOT / name).read_bytes():
            raise ValueError("Go module license differs from project license")


def installation_environment(directory, library, target):
    environment = os.environ.copy()
    for name in ("GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE", "GOVCS"):
        environment.pop(name, None)
    go_os, go_arch = {
        "x86_64-pc-windows-msvc": ("windows", "amd64"),
        "x86_64-unknown-linux-gnu": ("linux", "amd64"),
        "aarch64-apple-darwin": ("darwin", "arm64"),
    }[target]
    environment.update(
        GOWORK="off",
        GOENV="off",
        GOFLAGS="",
        GOTOOLCHAIN="local",
        GOOS=go_os,
        GOARCH=go_arch,
        GOPROXY="off",
        GOSUMDB="off",
        GOVCS="off",
        GOPATH=str(directory / "gopath"),
        GOMODCACHE=str(directory / "module-cache"),
        GOCACHE=str(directory / "build-cache"),
    )
    for variable in ("CGO_LDFLAGS", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        environment.pop(variable, None)
    environment["CGO_ENABLED"] = "0"
    environment["PHANTOM_GO_LIBRARY"] = str(library.resolve())
    return environment


def stage_go_dependencies(source, proxy, notices, commands, environment):
    """Retain checksum-verified module downloads for offline consumer checks."""
    sums = (source / "go.sum").read_bytes()
    expected = {tuple(line.split()) for line in sums.decode().splitlines()}
    download_environment = {
        **environment,
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
    }
    modules = (
        commands.run(
            [
                "go",
                "list",
                "-mod=readonly",
                "-m",
                "-f",
                "{{if not .Main}}{{.Path}}@{{.Version}}{{end}}",
                "all",
            ],
            cwd=source,
            env=download_environment,
            timeout=180,
        )
        .decode()
        .split()
    )
    records = []
    for module in modules:
        record = json.loads(
            commands.run(
                ["go", "mod", "download", "-json", module],
                cwd=source,
                env=download_environment,
                timeout=180,
            )
        )
        path, version = module.rsplit("@", 1)
        if (
            record.get("Error")
            or record.get("Path") != path
            or record.get("Version") != version
            or (path, version, record.get("Sum")) not in expected
            or (path, version + "/go.mod", record.get("GoModSum")) not in expected
        ):
            raise ValueError(f"Go dependency differs from pinned checksums: {module}")
        # The downloaded cache already uses Go's escaped module-path spelling.
        cached = Path(record["Zip"])
        cache = Path(environment["GOMODCACHE"]) / "cache/download"
        destination = proxy / cached.relative_to(cache).parent
        destination.mkdir(parents=True, exist_ok=True)
        for key in ("Zip", "GoMod", "Info"):
            shutil.copyfile(record[key], destination / Path(record[key]).name)
        license_file = Path(record["Dir"]) / "LICENSE"
        notice = notices / path / version / "LICENSE"
        notice.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(license_file, notice)
        # purego records its copied Go-runtime code attribution in its README.
        shutil.copyfile(
            Path(record["Dir"]) / "README.md", notice.with_name("README.md")
        )
        records.append(
            {
                "module": module,
                "sum": record["Sum"],
                "go_mod_sum": record["GoModSum"],
                "license_sha256": hashlib.sha256(license_file.read_bytes()).hexdigest(),
            }
        )
    if (source / "go.sum").read_bytes() != sums:
        raise ValueError("Go dependency download changed the pinned checksums")
    if records:
        go_root = Path(
            commands.run(["go", "env", "GOROOT"], env=environment).decode().strip()
        )
        runtime_notice = notices / "go-runtime/LICENSE"
        runtime_notice.parent.mkdir(parents=True)
        shutil.copyfile(go_root / "LICENSE", runtime_notice)
    return records


def completed_tests(raw):
    passed, package_passed = set(), False
    for line in raw.splitlines():
        event = json.loads(line)
        if event.get("Action") in {"skip", "fail"}:
            raise ValueError("extracted Go tests failed or skipped a control")
        if event.get("Action") == "pass":
            name = event.get("Test")
            if name and "/" not in name:
                passed.add(name)
            elif name is None and event.get("Package") == MODULE:
                package_passed = True
    if (
        not package_passed
        or len(passed) < 11
        or "TestHTTP3UploadCancellation" not in passed
    ):
        raise ValueError(
            "extracted Go tests did not complete all controls including HTTP/3"
        )
    return sorted(passed)


CONSUMER = r"""package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "time"

    phantom "github.com/bywayhq/phantom/bindings/go"
)

func run() error {
    peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "PUT" || strings.Join(r.Header.Values("X-Duplicate"), ",") != "one,two" {
            http.Error(w, "unexpected request", http.StatusBadRequest)
            return
        }
        _, _ = io.Copy(w, r.Body)
    }))
    defer peer.Close()
    client, err := phantom.New(phantom.Config{
        Profile: "chrome/154.0.8037.97/windows-11-26200/r1",
        Protocol: "h1", Timeout: 5 * time.Second,
    })
    if err != nil { return err }
    response, err := client.Do(context.Background(), phantom.Request{
        Method: "PUT", URL: peer.URL, Body: []byte("external-consumer"),
        Headers: []phantom.Header{{Name: "X-Duplicate", Value: []byte("one")}, {Name: "X-Duplicate", Value: []byte("two")}},
    })
    if err != nil { _ = client.Close(); return err }
    body, err := response.Body.ReadAll(1024)
    if err != nil { _ = client.Close(); return err }
    if response.Status != 200 || response.Protocol != "h1" || string(body) != "external-consumer" {
        _ = client.Close()
        return fmt.Errorf("unexpected response")
    }
    return client.Close()
}

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    fmt.Println("external-consumer-ok")
}
"""


def installed_checks(extracted, name, target, identity, commands, tools, proxy=None):
    folder = extracted / name
    payload = identity["payload_sha256"]
    files = {
        path.relative_to(folder).as_posix()
        for path in folder.rglob("*")
        if path.is_file()
    }
    if files != set(payload) | {"artifact.json"}:
        raise ValueError("extracted archive payload differs from its inventory")
    if json.loads((folder / "artifact.json").read_text()) != identity:
        raise ValueError("extracted artifact identity differs")
    for path, expected in payload.items():
        if tools.digest(folder / path) != expected:
            raise ValueError(f"extracted payload checksum mismatch: {path}")
    module = folder / "module"
    library = folder / "lib" / LIBRARIES[target]
    environment = installation_environment(extracted, library, target)
    if proxy is not None:
        environment["GOPROXY"] = proxy.resolve().as_uri()
    go_environment = json.loads(
        commands.run(
            [
                "go",
                "env",
                "-json",
                "GOVERSION",
                "GOOS",
                "GOARCH",
                "GOHOSTOS",
                "GOHOSTARCH",
                "CGO_ENABLED",
                "CC",
            ],
            cwd=extracted,
            env=environment,
        )
    )
    if any(
        go_environment.get(f"GOHOST{part}") != environment[f"GO{part}"]
        for part in ("OS", "ARCH")
    ):
        raise ValueError("Go toolchain host differs from the native archive target")
    consumer = extracted / "consumer"
    consumer.mkdir()
    replacement = os.path.relpath(module, consumer).replace(os.sep, "/")
    (consumer / "go.mod").write_text(
        "module example.test/phantom-install\n\ngo 1.26\n\n"
        f"require {MODULE} v0.0.0\nreplace {MODULE} => {json.dumps(replacement)}\n",
        encoding="utf-8",
    )
    (consumer / "main.go").write_text(CONSUMER, encoding="utf-8")
    resolution = json.loads(
        commands.run(
            ["go", "list", "-mod=readonly", "-m", "-json", MODULE],
            cwd=consumer,
            env=environment,
        )
    )
    if (
        resolution.get("Path") != MODULE
        or Path(resolution.get("Dir", "")).resolve() != module.resolve()
        or Path(resolution.get("Replace", {}).get("Dir", "")).resolve()
        != module.resolve()
    ):
        raise ValueError("consumer did not resolve the extracted Go module")
    executable = consumer / (
        "consumer.exe" if target.endswith("windows-msvc") else "consumer"
    )
    commands.run(["go", "mod", "tidy"], cwd=consumer, env=environment, timeout=180)
    commands.run(
        ["go", "build", "-mod=readonly", "-o", str(executable), "."],
        cwd=consumer,
        env=environment,
        timeout=300,
    )
    result = commands.run([str(executable)], cwd=consumer, env=environment)
    if result.strip() != b"external-consumer-ok":
        raise ValueError("external Go consumer omitted success marker")
    environment = h3_peer_environment(ROOT, extracted, environment)
    tests = completed_tests(
        commands.run(
            ["go", "test", "-mod=readonly", "-count=1", "-json", "-timeout=5m", "."],
            cwd=module,
            env=environment,
            timeout=360,
        )
    )
    return {
        "external_consumer": "passed",
        "module_resolution": resolution,
        "go_environment": go_environment,
        "tests": tests,
        "loader_environment": {
            key: environment[key]
            for key in (
                "PHANTOM_GO_LIBRARY",
                "CGO_LDFLAGS",
                "LD_LIBRARY_PATH",
                "DYLD_LIBRARY_PATH",
            )
            if key in environment
        },
    }


def module_proxy_checks(extracted, library, target, proxy, module, commands, tools):
    version = module["version"]
    first_sums = None
    first_download = None
    resolutions = []
    for index in range(2):
        directory = extracted / f"registry-consumer-{index}"
        directory.mkdir()
        environment = installation_environment(directory, library, target)
        environment["GOPROXY"] = proxy.resolve().as_uri()
        consumer_mod = directory / "go.mod"
        consumer_mod.write_text(
            "module example.test/phantom-registry\n\ngo 1.26\n\n"
            f"require {MODULE} {version}\n",
            encoding="utf-8",
        )
        (directory / "main.go").write_text(CONSUMER, encoding="utf-8")
        if index == 0:
            commands.run(
                ["go", "get", f"{MODULE}@{version}"],
                cwd=directory,
                env=environment,
                timeout=180,
            )
        else:
            (directory / "go.sum").write_bytes(first_sums)
        commands.run(["go", "mod", "tidy"], cwd=directory, env=environment, timeout=180)
        download = json.loads(
            commands.run(
                ["go", "mod", "download", "-json", f"{MODULE}@{version}"],
                cwd=directory,
                env=environment,
                timeout=180,
            )
        )
        cache = Path(environment["GOMODCACHE"])
        if (
            download.get("Error")
            or download.get("Path") != MODULE
            or download.get("Version") != version
            or not download.get("Sum", "").startswith("h1:")
            or not download.get("GoModSum", "").startswith("h1:")
        ):
            raise ValueError(
                "Go module proxy download did not verify the exact version"
            )
        for key in ("Dir", "Zip", "GoMod"):
            if not Path(download.get(key, "")).resolve().is_relative_to(cache):
                raise ValueError("Go module proxy download escaped its fresh cache")
        if (
            tools.digest(Path(download["Zip"])) != module["zip_sha256"]
            or tools.digest(Path(download["GoMod"])) != module["mod_sha256"]
        ):
            raise ValueError("Go module proxy download differs from committed source")
        downloaded = Path(download["Dir"])
        actual_files = {
            path.relative_to(downloaded).as_posix(): tools.digest(path)
            for path in downloaded.rglob("*")
            if path.is_file()
        }
        if actual_files != module["files_sha256"]:
            raise ValueError("Go module cache differs from the committed module tree")
        resolution = json.loads(
            commands.run(
                ["go", "list", "-mod=readonly", "-m", "-json", MODULE],
                cwd=directory,
                env=environment,
            )
        )
        if (
            resolution.get("Path") != MODULE
            or resolution.get("Version") != version
            or resolution.get("Replace") is not None
            or Path(resolution.get("Dir", "")).resolve() != downloaded.resolve()
        ):
            raise ValueError("Go registry consumer did not resolve the cached module")
        sums = (directory / "go.sum").read_bytes()
        if index == 0:
            first_sums, first_download = sums, download
            executable = directory / (
                "consumer.exe" if target.endswith("windows-msvc") else "consumer"
            )
            commands.run(
                ["go", "build", "-mod=readonly", "-o", str(executable), "."],
                cwd=directory,
                env=environment,
                timeout=300,
            )
            if (
                commands.run([str(executable)], cwd=directory, env=environment).strip()
                != b"external-consumer-ok"
            ):
                raise ValueError("Go registry consumer omitted success marker")
        elif sums != first_sums or any(
            download[key] != first_download[key] for key in ("Sum", "GoModSum")
        ):
            raise ValueError("fresh Go module cache changed the recorded checksums")
        verified = commands.run(["go", "mod", "verify"], cwd=directory, env=environment)
        if verified.strip() != b"all modules verified":
            raise ValueError("Go module cache verification did not complete")
        resolutions.append(resolution)
    return {
        "external_consumer": "passed",
        "fresh_caches": 2,
        "resolutions": resolutions,
        "go_sum": first_sums.decode(),
        "module_sum": first_download["Sum"],
        "go_mod_sum": first_download["GoModSum"],
        "source": module,
        "scope": "isolated file proxy; no public tag or checksum database claim",
    }


def verify(target, output):
    tools = artifact_tools()
    jobs = tools.build_jobs()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    if commands.run(["git", "status", "--porcelain"]).strip():
        raise ValueError("Go artifacts require a clean checkout")
    if any(
        key.startswith(("BORING_BSSL_", "CARGO_PROFILE_RELEASE_"))
        or key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}
        for key in os.environ
    ):
        raise ValueError(
            "remove native TLS and Rust release overrides before building artifacts"
        )
    revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    lock = tools.digest(ROOT / "Cargo.lock")
    rustc = commands.run(["rustc", "-vV"]).decode()
    host = tools.host_identity(target, rustc)
    cargo = commands.run(["cargo", "-V"]).decode().strip()
    go = (
        commands.run(["go", "version"], env={**os.environ, "GOTOOLCHAIN": "local"})
        .decode()
        .strip()
    )
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
    packages = [
        package for package in metadata["packages"] if package["name"] == "phantom-go"
    ]
    if len(packages) != 1:
        raise ValueError("expected one native Go adapter in Cargo metadata")
    package = packages[0]
    version = checked_module_version(ROOT / "bindings/go", package["version"])
    proxy = output / "module-proxy"
    module = stage_module_proxy(proxy, revision, version, commands)
    raw = commands.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--config",
            "profile.release.opt-level=3",
            "-p",
            "phantom-go",
            "--jobs",
            jobs,
            "--message-format=json-render-diagnostics",
        ],
        timeout=1800,
    )
    package_ids, library = build_records(raw, target)
    name = f"phantom-go-{package['version']}-{target}"
    staging = output / "staging" / name
    (staging / "lib").mkdir(parents=True)
    shutil.copy2(library, staging / "lib" / library.name)
    copy_module(ROOT / "bindings/go", staging / "module")
    for filename in ("LICENSE-APACHE", "LICENSE-MIT"):
        shutil.copyfile(ROOT / filename, staging / filename)
    (staging / "README.md").write_text(
        "# Phantom Go native candidate\n\n"
        "Keep module/ and lib/ from this archive together. The module source and\n"
        "native library are paired at the revision in artifact.json. Keep all\n"
        "licenses and notices when redistributing them.\n\n"
        "In your Go module, require github.com/bywayhq/phantom/bindings/go at\n"
        "v0.0.0 and add a local replace to this archive's module/ directory.\n"
        "No module tag or registry release is provided. Go 1.26 or newer is required.\n\n"
        + f"Set PHANTOM_GO_LIBRARY to the absolute path of lib/{library.name},\n"
        "or put that native library beside your executable. cgo is not required.\n"
        "The Go module downloads its pinned purego dependency through Go modules.\n\n"
        + (
            "Install the Microsoft x64 Visual C++ v14 runtime, at least as recent\n"
            "as the recorded MSVC build tools.\n\n"
            if target.endswith("windows-msvc")
            else ""
        )
        + "See module/README.md for the API and the receipt for tested hosts.\n"
        "This candidate is unsigned. SDK/OS runtimes are not bundled.\n",
        encoding="utf-8",
    )
    inventory = tools.copy_notices(metadata, package_ids, staging / "notices")
    go_dependencies = stage_go_dependencies(
        ROOT / "bindings/go",
        proxy,
        staging / "notices/go",
        commands,
        installation_environment(output / "dependency-download", library, target),
    )
    sysroot = Path(commands.run(["rustc", "--print", "sysroot"]).decode().strip())
    tools.copy_rust_notices(sysroot, staging / "notices/rust-runtime")
    inspection = tools.dependency_inspection(
        staging / "lib" / library.name, target, commands
    )
    identity = {
        "schema": 1,
        "package": "phantom-go",
        "version": package["version"],
        "source_revision": revision,
        "cargo_lock_sha256": lock,
        "target": target,
        "profile": "release",
        "optimization": "3",
        "rustc": rustc,
        "cargo": cargo,
        "go": go,
        "build_jobs": jobs,
        "tested_host": host,
        "native_sha256": tools.digest(staging / "lib" / library.name),
        "dependencies": inventory,
        "go_dependencies": go_dependencies,
        "native_inspection": inspection,
        "build_environment": {
            key: os.environ[key]
            for key in ("MACOSX_DEPLOYMENT_TARGET", "CC", "CXX", "CFLAGS", "CXXFLAGS")
            if key in os.environ
        },
        "payload_sha256": {
            path.relative_to(staging).as_posix(): tools.digest(path)
            for path in sorted(staging.rglob("*"))
            if path.is_file()
        },
    }
    tools.write_json(staging / "artifact.json", identity)
    suffix = ".zip" if target.endswith("windows-msvc") else ".tar.gz"
    archive = output / f"{name}{suffix}"
    tools.create_archive(staging, archive)
    with tempfile.TemporaryDirectory(prefix="phantom-go-install-") as temporary:
        extracted = Path(temporary).resolve()
        if extracted.is_relative_to(ROOT):
            raise ValueError("Go installation checks must run outside checkout")
        tools.extract_archive(archive, extracted)
        checks = installed_checks(
            extracted, name, target, identity, commands, tools, proxy=proxy
        )
        checks["module_proxy"] = module_proxy_checks(
            extracted,
            extracted / name / "lib" / library.name,
            target,
            proxy,
            module,
            commands,
            tools,
        )
    if (
        commands.run(["git", "status", "--porcelain"]).strip()
        or commands.run(["git", "rev-parse", "HEAD"]).decode().strip() != revision
        or tools.digest(ROOT / "Cargo.lock") != lock
    ):
        raise ValueError("checkout identity changed during Go artifact verification")
    verified = output / "verified"
    verified.mkdir()
    archive_hash = tools.digest(archive)
    shutil.move(str(archive), verified / archive.name)
    (verified / "SHA256SUMS").write_text(
        f"{archive_hash}  {archive.name}\n", encoding="utf-8"
    )
    tools.write_json(
        verified / "verification.json",
        {
            "archive": archive.name,
            "sha256": archive_hash,
            "identity": identity,
            "checks": checks,
        },
    )
    print(f"Verified Go installation candidate: {verified / archive.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=LIBRARIES, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="new evidence directory"
    )
    args = parser.parse_args()
    verify(args.target, args.output)


if __name__ == "__main__":
    main()
