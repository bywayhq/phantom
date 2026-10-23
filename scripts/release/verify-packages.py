#!/usr/bin/env python3
"""Build exact release archives through a non-publishing loopback registry."""

import argparse
import functools
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import tarfile
import threading
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]
CRATES_IO = "https://github.com/rust-lang/crates.io-index"


def index_path(name):
    name = name.lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def index_record(manifest, checksum, local_names):
    dependencies = []

    def add(table, target=None):
        for key, kind in (
            ("dependencies", "normal"),
            ("dev-dependencies", "dev"),
            ("build-dependencies", "build"),
        ):
            for alias, settings in table.get(key, {}).items():
                if isinstance(settings, str):
                    settings = {"version": settings}
                package = settings.get("package", alias)
                if "git" in settings or "path" in settings:
                    raise ValueError(f"unpackaged dependency: {alias}")
                dependencies.append(
                    {
                        "name": alias,
                        "package": settings.get("package"),
                        "req": settings["version"],
                        "features": settings.get("features", []),
                        "optional": settings.get("optional", False),
                        "default_features": settings.get("default-features", True),
                        "target": target,
                        "kind": kind,
                        "registry": None if package in local_names else CRATES_IO,
                    }
                )

    add(manifest)
    for target, table in manifest.get("target", {}).items():
        add(table, target)
    package = manifest["package"]
    return {
        "name": package["name"],
        "vers": package["version"],
        "deps": dependencies,
        "cksum": checksum,
        "features": {},
        "features2": manifest.get("features", {}),
        "yanked": False,
        "links": package.get("links"),
        "rust_version": package.get("rust-version"),
        "v": 2,
    }


def install_registry_config(base, manifest, versions):
    # cargo install resolves the downloaded root manifest rather than its index
    # dependency records. Redirect only its staged direct dependencies; ordinary
    # external dependencies must continue to come from crates.io.
    dependencies = index_record(manifest, "", versions)["deps"]
    staged = {
        dependency.get("package") or dependency["name"]
        for dependency in dependencies
        if dependency["kind"] != "dev" and dependency["registry"] is None
    }
    return (
        "[registries.phantom-staging]\nindex = "
        + json.dumps("sparse+" + base + "/")
        + "\n\n[patch.crates-io]\n"
        + "".join(
            f"{json.dumps(name)} = {{ version = {json.dumps('=' + versions[name])}, "
            'registry = "phantom-staging" }\n'
            for name in sorted(staged)
        )
    )


def installed_package_sources(log, base, versions):
    selected = {}
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("reason") != "compiler-artifact":
            continue
        identity = record["package_id"]
        name = identity.rsplit("#", 1)[-1].split("@", 1)[0]
        if name not in versions:
            continue
        expected = f"sparse+{base}/#{name}@{versions[name]}"
        if identity != expected:
            raise ValueError(f"installed package bypassed staging archive: {identity}")
        selected[name] = identity
    if not {"phantom-cli", "phantom-http"} <= selected.keys():
        raise ValueError("CLI install omitted staged root or client source receipts")
    return selected


def consumer_manifest(text: str, versions: dict[str, str]) -> str:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))[
        "workspace"
    ]["package"]
    text = text.replace(
        'path = "../../../crates/phantom"',
        f'version = "={versions["phantom-http"]}", registry = "phantom-staging"',
    ).replace(
        'path = "../../../crates/phantom-testkit"',
        f'version = "={versions["phantom-testkit"]}", registry = "phantom-staging"',
    )
    text = text.replace(
        'edition = "2024"',
        f'edition = "2024"\nrust-version = {json.dumps(workspace["rust-version"])}',
    )
    return text.replace(
        "https-records = [",
        'full = ["phantom/full"]\n'
        'diagnostics = ["phantom/diagnostics"]\nhttps-records = [',
    )


class RegistryHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def run(command, cwd, log, *, stdout=None):
    print("+", " ".join(map(str, command)), flush=True)
    with log.open("w", encoding="utf-8") as output:
        if stdout is None:
            result = subprocess.run(
                command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT
            )
        else:
            with stdout.open("w", encoding="utf-8") as payload:
                result = subprocess.run(command, cwd=cwd, stdout=payload, stderr=output)
    if result.returncode:
        print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
        raise RuntimeError(f"command failed ({result.returncode}); see {log}")


def verify(args):
    destination = args.output.resolve()
    # A new run cannot accidentally use an old package or consumer lockfile.
    destination.mkdir(parents=True, exist_ok=False)
    logs = destination / "logs"
    logs.mkdir()
    registry = destination / "registry"
    archives = registry / "archives"
    archives.mkdir(parents=True)
    manifests = (
        (ROOT / "scripts/release/packages.txt").read_text(encoding="utf-8").splitlines()
    )
    records = []
    package_target = destination / "package-target"
    for number, manifest in enumerate(manifests):
        command = [
            "cargo",
            "package",
            "--no-verify",
            "--exclude-lockfile",
            "--manifest-path",
            str(ROOT / manifest),
            "--target-dir",
            str(package_target),
        ]
        if args.allow_dirty:
            command.append("--allow-dirty")
        run(command, ROOT, logs / f"package-{number:02}.log")
    identities = []
    for archive in sorted((package_target / "package").glob("*.crate")):
        with tarfile.open(archive) as source:
            prefix = source.getnames()[0].split("/")[0]
            metadata = tomllib.loads(
                source.extractfile(f"{prefix}/Cargo.toml").read().decode()
            )
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        if archive.stat().st_size > 10 * 1024 * 1024:
            raise ValueError(f"crate exceeds registry size limit: {archive}")
        shutil.copyfile(archive, archives / archive.name)
        records.append((metadata, checksum))
        identities.append({"archive": archive.name, "sha256": checksum})
    if len(records) != len(manifests):
        raise ValueError("package inventory differs from release plan")
    local_names = {manifest["package"]["name"] for manifest, _ in records}
    handler = functools.partial(RegistryHandler, directory=str(registry))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    base = f"http://127.0.0.1:{server.server_port}"
    (registry / "config.json").write_text(
        json.dumps({"dl": f"{base}/archives/{{crate}}-{{version}}.crate"}),
        encoding="utf-8",
    )
    for manifest, checksum in records:
        record = index_record(manifest, checksum, local_names)
        path = registry / index_path(record["name"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    identities_path = destination / "archives.json"
    identities_path.write_text(
        json.dumps(identities, indent=2) + "\n", encoding="utf-8"
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        consumer = destination / "consumer"
        source = ROOT / "tests/downstream/public-api"
        shutil.copytree(source / "src", consumer / "src")
        shutil.copytree(source / "fixtures", consumer / "fixtures")
        text = (source / "Cargo.toml").read_text(encoding="utf-8")
        versions = {
            manifest["package"]["name"]: manifest["package"]["version"]
            for manifest, _ in records
        }
        (consumer / "Cargo.toml").write_text(
            consumer_manifest(text, versions), encoding="utf-8"
        )
        config = consumer / ".cargo"
        config.mkdir()
        (config / "config.toml").write_text(
            '[registries.phantom-staging]\nindex = "sparse+' + base + '/"\n',
            encoding="utf-8",
        )
        # The registry consumer must not inherit a checkout's prebuilt native TLS.
        inherited = [key for key in os.environ if key.startswith("BORING_BSSL_")]
        if inherited:
            raise ValueError(
                f"remove native build overrides for release check: {inherited}"
            )
        toolchain = [f"+{args.toolchain}"] if args.toolchain else []
        cargo = ["cargo", *toolchain]
        for suffix, extra in (("minimal", []), ("full", ["--all-features"])):
            run([*cargo, "test", *extra], consumer, logs / f"consumer-{suffix}.log")
        run(
            [*cargo, "metadata", "--all-features", "--locked", "--format-version", "1"],
            consumer,
            logs / "metadata.log",
            stdout=destination / "metadata.json",
        )
        packages = json.loads(
            (destination / "metadata.json").read_text(encoding="utf-8")
        )["packages"]
        for package in packages:
            name, source = package["name"], package["source"]
            if name == "phantom-public-api-check":
                continue
            if not source or source.startswith("git+"):
                raise ValueError(f"non-registry dependency: {name} {source}")
            if name in local_names and not source.startswith("sparse+" + base):
                raise ValueError(f"package bypassed staging archive: {name} {source}")

        # Install the CLI from the same archives, without checkout path overrides.
        install = destination / "cli-install"
        cli_manifest = next(
            manifest
            for manifest, _ in records
            if manifest["package"]["name"] == "phantom-cli"
        )
        install_config = destination / "cli-registry.toml"
        install_config.write_text(
            install_registry_config(base, cli_manifest, versions), encoding="utf-8"
        )
        install_log = logs / "cli-install.log"
        run(
            [
                *cargo,
                "install",
                "phantom-cli",
                "--version",
                "=" + versions["phantom-cli"],
                "--registry",
                "phantom-staging",
                # cargo install ignores the current directory's configuration.
                "--config",
                str(install_config),
                "--message-format=json-render-diagnostics",
                "--debug",
                "--root",
                str(install),
                "--target-dir",
                os.environ.get("CARGO_TARGET_DIR", str(consumer / "target")),
            ],
            consumer,
            install_log,
        )
        (logs / "cli-packages.json").write_text(
            json.dumps(installed_package_sources(install_log, base, versions), indent=2)
            + "\n",
            encoding="utf-8",
        )
        executable = install / "bin" / ("phantom.exe" if os.name == "nt" else "phantom")
        run([str(executable), "--version"], consumer, logs / "cli-version.log")
        run([str(executable), "profiles", "list"], consumer, logs / "cli-profiles.log")
        print(f"Verified {len(records)} archives; evidence: {destination}", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--toolchain")
    verify(parser.parse_args())
