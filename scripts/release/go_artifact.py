"""Build and verify a paired Go module/native library archive; never publish it."""

import argparse
import importlib.util
import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = "github.com/bywayhq/phantom/bindings/go"
LIBRARIES = {
    "x86_64-pc-windows-msvc": "phantom_go.dll",
    "x86_64-unknown-linux-gnu": "libphantom_go.so",
    "aarch64-apple-darwin": "libphantom_go.dylib",
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
        for name in ("go.mod", "native.h", "README.md", "LICENSE-MIT", "LICENSE-APACHE")
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
        GOPATH=str(directory / "gopath"),
        GOMODCACHE=str(directory / "module-cache"),
        GOCACHE=str(directory / "build-cache"),
    )
    if target.endswith("windows-msvc"):
        environment["CGO_ENABLED"] = "0"
        environment["PHANTOM_GO_LIBRARY"] = str(library.resolve())
    else:
        environment["CGO_ENABLED"] = "1"
        environment["CGO_LDFLAGS"] = "-L" + shlex.quote(str(library.parent))
        loader = (
            "DYLD_LIBRARY_PATH"
            if target.endswith("apple-darwin")
            else "LD_LIBRARY_PATH"
        )
        environment[loader] = str(library.parent)
    return environment


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
    if not package_passed or len(passed) < 10:
        raise ValueError("extracted Go tests did not complete all ten controls")
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


def installed_checks(extracted, name, target, identity, commands, tools):
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
    commands.run(
        ["go", "build", "-mod=readonly", "-o", str(executable), "."],
        cwd=consumer,
        env=environment,
        timeout=300,
    )
    result = commands.run([str(executable)], cwd=consumer, env=environment)
    if result.strip() != b"external-consumer-ok":
        raise ValueError("external Go consumer omitted success marker")
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
        + (
            "Set PHANTOM_GO_LIBRARY to the absolute path of lib/phantom_go.dll.\n"
            "Windows does not need cgo. Install the Microsoft x64 Visual C++ v14\n"
            "runtime, at least as recent as the recorded MSVC build tools.\n\n"
            if target.endswith("windows-msvc")
            else "Enable cgo and a C compiler. Set CGO_LDFLAGS to -L followed by\n"
            "the quoted absolute lib/ directory. Set "
            + (
                "DYLD_LIBRARY_PATH"
                if target.endswith("apple-darwin")
                else "LD_LIBRARY_PATH"
            )
            + " to that directory before running your program.\n\n"
        )
        + "See module/README.md for the API. This candidate is unsigned and\n"
        "verified only on its recorded native host. Older OS/libc versions and\n"
        "other architectures are unverified. SDK/OS runtimes are not bundled.\n",
        encoding="utf-8",
    )
    inventory = tools.copy_notices(metadata, package_ids, staging / "notices")
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
        checks = installed_checks(extracted, name, target, identity, commands, tools)
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
