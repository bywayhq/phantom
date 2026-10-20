"""Assemble four npm candidates with Python 3.11+; never build or publish."""

import argparse
import base64
import contextlib
import hashlib
import http.server
import importlib.util
import json
import re
import shutil
import tarfile
import tempfile
import threading
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = {
    "x86_64-pc-windows-msvc": "@byway/phantom-win32-x64-msvc",
    "x86_64-unknown-linux-gnu": "@byway/phantom-linux-x64-gnu",
    "aarch64-apple-darwin": "@byway/phantom-darwin-arm64",
}
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_payload(path, maximum):
    require(path.stat().st_size <= maximum, "npm archive exceeds bounds")
    with tarfile.open(path, "r:gz") as archive:
        entries = archive.getmembers()
        require(
            len(entries) <= 10_000 and sum(e.size for e in entries) <= maximum,
            "npm archive exceeds bounds",
        )
        result = {}
        names = set()
        for entry in entries:
            name = PurePosixPath(entry.name)
            require(
                entry.isfile()
                and len(name.parts) >= 2
                and name.parts[0] == "package"
                and str(name) == entry.name
                and not name.is_absolute()
                and ".." not in name.parts
                and "\\" not in entry.name
                and ":" not in entry.name
                and entry.name.casefold() not in names
                and all(
                    not part.endswith((".", " "))
                    and part.split(".", 1)[0].upper() not in RESERVED
                    for part in name.parts
                ),
                "unsafe or duplicate npm archive member",
            )
            names.add(entry.name.casefold())
            result[entry.name.removeprefix("package/")] = archive.extractfile(
                entry
            ).read()
        return result


def source_bytes(actual, canonical, target):
    return actual == canonical or (
        target == "x86_64-pc-windows-msvc"
        and b"\r" not in canonical
        and actual == canonical.replace(b"\n", b"\r\n")
    )


def read_candidate(directory, revision, version, git_files, node, promotion):
    receipt_path = directory / "verification.json"
    require(
        receipt_path.is_file()
        and not receipt_path.is_symlink()
        and receipt_path.stat().st_size <= 8 * 1024**2,
        "missing or oversized Node receipt",
    )
    receipt_raw = receipt_path.read_bytes()
    receipt = promotion.decode_json(receipt_raw)
    target = receipt["target"]
    require(target in PACKAGES, "unsupported Node candidate target")
    filename = f"byway-phantom-{version}.tgz"
    require(
        {p.name for p in directory.iterdir()}
        == {filename, "verification.json", "SHA256SUMS"}
        and all(p.is_file() and not p.is_symlink() for p in directory.iterdir()),
        "Node candidate must contain exactly its three verified files",
    )
    archive = directory / filename
    require(
        archive.stat().st_size <= node.MAX_ARCHIVE_BYTES,
        "Node archive exceeds bounds",
    )
    archive_hash = sha256(archive.read_bytes())
    checksum = directory / "SHA256SUMS"
    require(checksum.stat().st_size <= 512, "oversized Node checksum")
    require(
        checksum.read_bytes()
        in (
            f"{archive_hash}  {filename}\n".encode(),
            f"{archive_hash}  {filename}\r\n".encode(),
        ),
        "Node candidate checksum differs",
    )
    lock_identity = promotion.validate_receipt(
        "node",
        target,
        version,
        revision,
        git_files["Cargo.lock"],
        git_files["bindings/node/package-lock.json"],
        receipt,
        filename,
        archive_hash,
    )
    payload = archive_payload(archive, node.MAX_ARCHIVE_BYTES)
    require(
        {"package/" + name: sha256(raw) for name, raw in payload.items()}
        == receipt["payload_sha256"],
        "Node candidate payload differs from receipt",
    )
    source_package = promotion.decode_json(git_files["bindings/node/package.json"])
    require(
        promotion.decode_json(payload["package.json"])
        == node.package_metadata(source_package, version, target),
        "Node candidate package metadata differs",
    )
    fixed = {
        *node.SOURCES,
        "package.json",
        "phantom.node",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    }
    require(
        fixed <= payload.keys()
        and all(name in fixed or name.startswith("notices/") for name in payload),
        "unexpected Node candidate payload",
    )
    for name in [*node.SOURCES, "LICENSE-MIT", "LICENSE-APACHE"]:
        git_name = "bindings/node/" + name if name in node.SOURCES else name
        require(
            source_bytes(payload[name], git_files[git_name], target),
            "Node candidate source differs from selected Git revision",
        )
    require(
        sha256(payload["phantom.node"]) == receipt["native_sha256"],
        "Node candidate addon differs",
    )
    require(
        promotion.decode_json(payload["notices/inventory.json"]) == receipt["notices"]
        and any(name.startswith("notices/rust-runtime/") for name in payload),
        "Node candidate notice inventory differs or runtime notices are missing",
    )
    for package in receipt["notices"]:
        for notice in package["notices"]:
            require(
                sha256(payload["notices/" + notice["file"]]) == notice["sha256"],
                "Node candidate notice text differs",
            )
    return (
        target,
        payload,
        {
            "target": target,
            "archive_sha256": archive_hash,
            "receipt_sha256": sha256(receipt_raw),
            "lock_identity": lock_identity,
        },
        receipt_raw,
    )


def manifests(source, version, node):
    common = {
        "version": version,
        "license": source["license"],
        "repository": {
            "type": "git",
            "url": "https://github.com/bywayhq/phantom.git",
            "directory": "bindings/node",
        },
        "engines": source["engines"],
        "publishConfig": {"access": "public"},
    }
    facade = {
        **common,
        "name": node.PACKAGE,
        "description": source["description"],
        **{name: source[name] for name in ("main", "types", "exports")},
        "files": [*node.SOURCES, "LICENSE-MIT", "LICENSE-APACHE"],
        "optionalDependencies": dict.fromkeys(PACKAGES.values(), version),
    }
    result = {node.PACKAGE: facade}
    for target, name in PACKAGES.items():
        result[name] = {
            **common,
            "name": name,
            "os": [node.TARGETS[target][0]],
            "cpu": [node.TARGETS[target][1]],
            "main": "phantom.node",
            "exports": {".": "./phantom.node", "./package.json": "./package.json"},
            "files": [
                "phantom.node",
                "LICENSE-MIT",
                "LICENSE-APACHE",
                "notices",
                "provenance.json",
            ],
        }
        if target == "x86_64-unknown-linux-gnu":
            result[name]["libc"] = ["glibc"]
    return result


def pack_package(
    staging, packed, metadata, node_exe, npm_cli, commands, node, tools, environment
):
    tools.write_json(staging / "package.json", metadata)
    records = json.loads(
        commands.run(
            [
                str(node_exe),
                str(npm_cli),
                "pack",
                "--ignore-scripts",
                "--json",
                "--pack-destination",
                str(packed),
            ],
            cwd=staging,
            env=environment,
            timeout=120,
        )
    )
    filename = (
        metadata["name"].removeprefix("@").replace("/", "-")
        + "-"
        + metadata["version"]
        + ".tgz"
    )
    require(
        len(records) == 1 and records[0]["filename"] == filename,
        "npm pack returned an unexpected archive",
    )
    archive = packed / filename
    payload = node.inspect_archive(archive, staging, tools)
    return {
        "name": metadata["name"],
        "version": metadata["version"],
        "archive": filename,
        "sha256": tools.digest(archive),
        "payload_sha256": payload,
    }


def assemble(args):
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.source_revision), "expected exact source SHA"
    )
    require(len(args.candidate) == 3, "expected exactly three native candidates")
    node = load_module(
        "registry_node_artifact", ROOT / "scripts/release/node_artifact.py"
    )
    promotion = load_module(
        "registry_promotion", ROOT / "scripts/release/promote_prebuilds.py"
    )
    tools = node.artifact_tools()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    revision = args.source_revision
    require(
        commands.run(["git", "rev-parse", "--verify", revision + "^{commit}"])
        .decode()
        .strip()
        == revision,
        "source revision differs",
    )
    paths = [
        "Cargo.lock",
        "bindings/node/package-lock.json",
        "bindings/node/package.json",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        *("bindings/node/" + name for name in node.SOURCES),
    ]
    git_files = {
        path: commands.run(["git", "show", revision + ":" + path]) for path in paths
    }
    source = promotion.decode_json(git_files["bindings/node/package.json"])
    version = source["version"]
    require(
        re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version
        ),
        "expected stable npm version",
    )
    candidates = {}
    for directory in args.candidate:
        target, payload, identity, receipt = read_candidate(
            directory.resolve(), revision, version, git_files, node, promotion
        )
        require(target not in candidates, "duplicate Node candidate target")
        candidates[target] = (payload, identity, receipt)
    require(candidates.keys() == PACKAGES.keys(), "missing Node candidate target")
    # Packing JavaScript/native bytes needs npm, not a compiler or addon execution.
    node_exe = args.node.resolve(strict=True)
    npm_cli = args.npm_cli.resolve(strict=True)
    configuration = output / "npm-configuration"
    configuration.mkdir()
    environment = node.npm_environment(configuration, node_exe)
    metadata = manifests(source, version, node)
    packed = output / "candidate"
    packed.mkdir()
    results = []
    for name, package in metadata.items():
        staging = output / "staging" / name.removeprefix("@").replace("/", "-")
        staging.mkdir(parents=True)
        if name == node.PACKAGE:
            files = {file: git_files["bindings/node/" + file] for file in node.SOURCES}
            files.update(
                {file: git_files[file] for file in ("LICENSE-MIT", "LICENSE-APACHE")}
            )
        else:
            target = next(
                target
                for target, package_name in PACKAGES.items()
                if package_name == name
            )
            payload, identity, receipt = candidates[target]
            files = {
                file: raw
                for file, raw in payload.items()
                if file in {"phantom.node", "LICENSE-MIT", "LICENSE-APACHE"}
                or file.startswith("notices/")
            }
            files["provenance.json"] = receipt
        for file, raw in files.items():
            destination = staging / file
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        results.append(
            pack_package(
                staging,
                packed,
                package,
                node_exe,
                npm_cli,
                commands,
                node,
                tools,
                environment,
            )
        )
    manifest = {
        "schema": 1,
        "source_revision": revision,
        "cargo_lock_sha256": sha256(git_files["Cargo.lock"]),
        "npm_lock_sha256": sha256(git_files["bindings/node/package-lock.json"]),
        "inputs": [candidates[target][1] for target in PACKAGES],
        "packages": results,
        "validation": "exact native candidates repackaged; registry resolution/install proof pending; no publication",
    }
    tools.write_json(packed / "manifest.json", manifest)
    (packed / "SHA256SUMS").write_text(
        "".join(f"{p['sha256']}  {p['archive']}\n" for p in results),
        encoding="utf-8",
        newline="\n",
    )
    packed.rename(output / "assembled")
    return output / "assembled"


@contextlib.contextmanager
def registry_fixture(packages, directory):
    """Serve only these four package identities while an installation runs."""
    require(len(packages) == 4, "temporary registry requires exactly four packages")
    routes, requests = {}, []

    class Server(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append({"path": self.path, "status": 405})
            self.send_error(405)

        def do_GET(self):
            path = unquote(urlsplit(self.path).path)
            found = routes.get(path) if not urlsplit(self.path).query else None
            requests.append({"path": path, "status": 200 if found else 404})
            if found is None:
                self.send_error(404)
                return
            kind, raw = found
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            # npm can abandon an incompatible optional package download.
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = Server(("127.0.0.1", 0), Handler)
    address = f"http://127.0.0.1:{server.server_port}"
    for package in packages:
        raw = (directory / package["archive"]).read_bytes()
        metadata = package["metadata"]
        tarball_path = "/tarballs/" + package["archive"]
        routes[tarball_path] = ("application/octet-stream", raw)
        version = {
            **metadata,
            "dist": {
                "tarball": address + tarball_path,
                "integrity": "sha512-"
                + base64.b64encode(hashlib.sha512(raw).digest()).decode(),
                "shasum": hashlib.sha1(raw).hexdigest(),
            },
        }
        routes["/" + metadata["name"]] = (
            "application/json",
            json.dumps(
                {
                    "name": metadata["name"],
                    "dist-tags": {"latest": metadata["version"]},
                    "versions": {metadata["version"]: version},
                }
            ).encode(),
        )
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    worker.start()
    try:
        yield address, requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)
        require(not worker.is_alive(), "temporary npm fixture failed to stop")


def read_assembly(directory, revision, node, promotion):
    manifest_path = directory / "manifest.json"
    require(
        manifest_path.stat().st_size <= 8 * 1024**2, "oversized npm assembly manifest"
    )
    manifest = promotion.decode_json(manifest_path.read_bytes())
    require(
        manifest["schema"] == 1 and manifest["source_revision"] == revision,
        "npm assembly source identity differs",
    )
    packages = manifest["packages"]
    require(
        len(packages) == 4
        and {p["name"] for p in packages} == {node.PACKAGE, *PACKAGES.values()},
        "npm assembly must contain exactly four package identities",
    )
    require(len({p["version"] for p in packages}) == 1, "npm package versions differ")
    for package in packages:
        filename = (
            package["name"].removeprefix("@").replace("/", "-")
            + "-"
            + package["version"]
            + ".tgz"
        )
        require(
            package["archive"] == filename
            and re.fullmatch(r"[a-z0-9.-]+\.tgz", filename),
            "unexpected npm archive name",
        )
        archive = directory / filename
        require(
            archive.stat().st_size <= node.MAX_ARCHIVE_BYTES,
            "npm assembly archive exceeds bounds",
        )
        require(
            sha256(archive.read_bytes()) == package["sha256"],
            "npm assembly archive hash differs",
        )
        payload = archive_payload(archive, node.MAX_ARCHIVE_BYTES)
        require(
            {"package/" + name: sha256(raw) for name, raw in payload.items()}
            == package["payload_sha256"],
            "npm assembly payload differs",
        )
        metadata = promotion.decode_json(payload["package.json"])
        require(
            metadata["name"] == package["name"]
            and metadata["version"] == package["version"],
            "npm assembly package metadata differs",
        )
        package["metadata"] = metadata
    return manifest


def installed_payloads(consumer, packages, selected, tools):
    scope = consumer / "node_modules/@byway"
    require(
        {p.name for p in scope.iterdir()}
        == {"phantom", selected.removeprefix("@byway/")},
        "npm installed missing or incompatible native packages",
    )
    for package in packages:
        if package["name"] not in {"@byway/phantom", selected}:
            continue
        directory = consumer / "node_modules" / package["name"]
        actual = {
            "package/" + p.relative_to(directory).as_posix(): tools.digest(p)
            for p in directory.rglob("*")
            if p.is_file()
        }
        require(
            actual == package["payload_sha256"], "installed npm package payload differs"
        )


def check_install(args):
    node = load_module(
        "registry_install_node", ROOT / "scripts/release/node_artifact.py"
    )
    promotion = load_module(
        "registry_install_promotion", ROOT / "scripts/release/promote_prebuilds.py"
    )
    tools = node.artifact_tools()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    directory = args.assembly.resolve()
    manifest = read_assembly(directory, revision, node, promotion)
    source = promotion.decode_json(
        commands.run(["git", "show", revision + ":bindings/node/package.json"])
    )
    expected = manifests(source, source["version"], node)
    require(
        all(
            package["metadata"] == expected[package["name"]]
            for package in manifest["packages"]
        ),
        "npm registry manifests differ from selected source/platform contract",
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="phantom-npm-registry-") as temporary:
        outside = Path(temporary).resolve()
        require(
            not outside.is_relative_to(ROOT),
            "registry install must run outside checkout",
        )
        with registry_fixture(manifest["packages"], directory) as (address, requests):
            for major, executable in ((22, args.node22), (24, args.node24)):
                node_exe, cli, identity = node.runtime(
                    executable, major, args.target, commands
                )
                consumer = outside / f"node-{major}"
                consumer.mkdir()
                environment = node.npm_environment(consumer, node_exe)
                configs = {
                    key: environment[key]
                    for key in ("NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG")
                }
                environment = {
                    k: v
                    for k, v in environment.items()
                    if not k.upper().startswith("NPM_CONFIG_")
                }
                environment.update(configs)
                environment["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
                environment["NO_PROXY"] = "127.0.0.1,localhost"
                cache = consumer / "npm-cache"
                tools.write_json(
                    consumer / "package.json",
                    {
                        "name": "phantom-registry-consumer",
                        "private": True,
                        "version": "1.0.0",
                    },
                )
                version = manifest["packages"][0]["version"]
                base = [str(node_exe), str(cli)]
                flags = [
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    "--registry",
                    address,
                ]
                commands.run(
                    [
                        *base,
                        "install",
                        *flags,
                        "--cache",
                        str(cache),
                        f"@byway/phantom@{version}",
                    ],
                    cwd=consumer,
                    env=environment,
                    timeout=180,
                )
                installed_payloads(
                    consumer, manifest["packages"], PACKAGES[args.target], tools
                )
                repeated = outside / f"node-{major}-ci"
                repeated.mkdir()
                for name in ("package.json", "package-lock.json"):
                    shutil.copyfile(consumer / name, repeated / name)
                    shutil.copyfile(consumer / name, output / f"node-{major}-{name}")
                commands.run(
                    [*base, "ci", *flags, "--cache", str(repeated / "npm-cache")],
                    cwd=repeated,
                    env=environment,
                    timeout=180,
                )
                installed_payloads(
                    repeated, manifest["packages"], PACKAGES[args.target], tools
                )
                checked = node.public_checks(
                    consumer,
                    node_exe,
                    cli,
                    version,
                    commands,
                    tools,
                    environment,
                    cache,
                    PACKAGES[args.target],
                )
                results.append(
                    {
                        "runtime": identity,
                        "resolver_installation": "name/version and fresh-cache lockfile install passed",
                        **checked,
                    }
                )
            require(
                requests and all(request["status"] == 200 for request in requests),
                "unexpected request to temporary npm fixture",
            )
    tools.write_json(
        output / "verification.json",
        {
            "source_revision": revision,
            "assembly_manifest_sha256": tools.digest(directory / "manifest.json"),
            "target": args.target,
            "checks": results,
            "registry_requests": requests,
            "scope": "temporary local npm resolver and installed public API proof; no public registry publication",
        },
    )
    return output / "verification.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assembly = commands.add_parser("assemble")
    assembly.add_argument("--candidate", action="append", type=Path, required=True)
    assembly.add_argument("--source-revision", required=True)
    assembly.add_argument("--node", type=Path, required=True)
    assembly.add_argument("--npm-cli", type=Path, required=True)
    assembly.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check-install")
    check.add_argument("--assembly", type=Path, required=True)
    check.add_argument("--target", choices=PACKAGES, required=True)
    check.add_argument("--node22", type=Path, required=True)
    check.add_argument("--node24", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(assemble(args) if args.command == "assemble" else check_install(args))


if __name__ == "__main__":
    main()
