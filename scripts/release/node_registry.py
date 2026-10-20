"""Assemble four npm candidates with Python 3.11+; never build or publish."""

import argparse
import hashlib
import importlib.util
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", action="append", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--npm-cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    print(assemble(parser.parse_args()))


if __name__ == "__main__":
    main()
