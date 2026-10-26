#!/usr/bin/env python3
"""Check registry advisories, fork lineage and reviewed native backports."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import tomllib

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ADVISORIES = {
    "CVE-2026-35189",
    "GHSA-53rm-773f-4q8c",
    "GHSA-wppq-2f6r-wfvm",
}
UDP_ADVISORY = "GHSA-6pp4-4cxf-xf88"


def fork_packages() -> dict[str, dict[str, Any]]:
    """Include unchanged forks as well as packages selected for publication."""
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    forks = {}
    for dependency in workspace["workspace"]["dependencies"].values():
        if not isinstance(dependency, dict) or "path" not in dependency:
            continue
        manifest = ROOT / dependency["path"] / "Cargo.toml"
        package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
        if package.get("metadata", {}).get("phantom"):
            forks[package["name"]] = package
    return forks


def upstream_identities() -> dict[str, tuple[str, str]]:
    return {
        name: (metadata["upstream-package"], metadata["upstream-version"])
        for name, package in fork_packages().items()
        for metadata in [package["metadata"]["phantom"]]
    }


def verify_files(files: dict[str, str]) -> None:
    if not files:
        raise RuntimeError("backport or lineage evidence is empty")
    for name, expected in files.items():
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"reviewed advisory evidence changed: {name}")


def verify_backport(fix: dict[str, Any]) -> None:
    verify_files(fix["files"])
    verify_files(fix["patches"])
    for name in fix["patches"]:
        patch = Path(name)
        series = (
            (ROOT / patch.parent / "series").read_text(encoding="utf-8").splitlines()
        )
        if series.count(patch.name) != 1:
            raise RuntimeError(f"backport must occur once in patches/series: {patch}")


def audit_inputs(
    config: dict[str, Any],
) -> tuple[set[tuple[str, str]], dict[str, tuple[str, str]], list[dict[str, Any]]]:
    forks = fork_packages()
    identities = upstream_identities()
    locked = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    packages = set()
    registry_packages = set()
    versions: dict[str, set[str]] = {}
    for package in locked:
        name, version = package["name"], package["version"]
        versions.setdefault(name, set()).add(version)
        if name in identities:
            if version != forks[name]["version"]:
                raise RuntimeError(f"locked fork version differs from manifest: {name}")
            packages.add(identities[name])
        elif package.get("source", "").startswith("registry+"):
            registry_packages.add((name, version))
            packages.add((name, version))

    lineage = config["lineage"]
    if not any(
        entry["fork"] == "phantom-http2" and entry["identity"][0] == "h2"
        for entry in lineage
    ):
        raise RuntimeError("missing HTTP/2 h2 advisory lineage")
    for entry in lineage:
        fork = entry["fork"]
        if fork not in versions or identities[fork] != tuple(entry["upstream"]):
            raise RuntimeError(f"reviewed fork lineage changed: {fork}")
        verify_files(entry["files"])
        packages.add(tuple(entry["identity"]))

    backports = []
    for advisory, fix in config["rust-fixes"].items():
        identity = tuple(fix["identity"])
        if not any(
            entry["fork"] == fix["fork"] and tuple(entry["identity"]) == identity
            for entry in lineage
        ):
            raise RuntimeError(f"backport has no reviewed lineage: {advisory}")
        if identity in registry_packages:
            raise RuntimeError(
                f"backport cannot exempt a registry dependency: {advisory}"
            )
        verify_backport(fix)
        backports.append({"advisory": advisory, "status": "reviewed-backport", **fix})

    source_fixes = config["source-fixes"]
    if missing := SOURCE_ADVISORIES - source_fixes.keys():
        raise RuntimeError(f"source advisory reviews are missing: {sorted(missing)}")
    for advisory, fix in source_fixes.items():
        fork = fix["fork"]
        package = forks[fork]
        if (
            versions.get(fork) != {fix["version"]}
            or package["version"] != fix["version"]
        ):
            raise RuntimeError(f"reviewed backport package version changed: {fork}")
        if identities[fork] != tuple(fix["upstream"]):
            raise RuntimeError(f"reviewed backport upstream changed: {fork}")
        if advisory == "CVE-2026-35189":
            revision = package["metadata"]["phantom"]["boringssl-revision"]
            if revision != fix["boringssl-revision"]:
                raise RuntimeError(f"reviewed BoringSSL revision changed: {revision}")
        verify_backport(fix)
        backports.append({"advisory": advisory, "status": "reviewed-backport", **fix})
    udp = config["registry-fixes"][UDP_ADVISORY]
    name, version = udp["identity"]
    if versions.get(name) != {version} or (name, version) not in registry_packages:
        raise RuntimeError(f"reviewed registry fix version changed: {name}")
    backports.append(
        {"advisory": UDP_ADVISORY, "status": "fixed-registry-version", **udp}
    )
    return packages, identities, backports


def review_audit(data: dict[str, Any], status: int, config: dict[str, Any]) -> None:
    findings = data["vulnerabilities"]["list"]
    if data["vulnerabilities"]["count"] != len(findings):
        raise RuntimeError("inconsistent vulnerability count in audit report")
    if any(data["warnings"].values()):
        raise RuntimeError("audit warnings require review; see audit.json")
    if data.get("error") or status not in (0, 1) or (status == 1 and not findings):
        raise RuntimeError("advisory audit failed; see audit.json and audit.log")
    for finding in findings:
        advisory, package = finding["advisory"], finding["package"]
        fix = config["rust-fixes"].get(advisory["id"])
        if not fix or tuple(fix["identity"]) != (package["name"], package["version"]):
            raise RuntimeError(f"unresolved advisory: {advisory['id']}")
        print(f"Retained backport: {advisory['id']}; {', '.join(fix['patches'])}")


def check(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads(
        (ROOT / "scripts/release/advisory-fixes.json").read_text(encoding="utf-8")
    )
    packages, identities, backports = audit_inputs(config)
    lock = output / "upstream-identities.lock"
    text = "version = 3\n"
    for name, version in sorted(packages):
        text += (
            f"\n[[package]]\nname = {json.dumps(name)}\n"
            f"version = {json.dumps(version)}\n"
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
    lock.write_text(text, encoding="utf-8")
    (output / "identity-map.json").write_text(
        json.dumps({"direct": identities, "lineage": config["lineage"]}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (output / "retained-backports.json").write_text(
        json.dumps(backports, indent=2) + "\n", encoding="utf-8"
    )
    with (
        (output / "audit.json").open("w", encoding="utf-8") as result,
        (output / "audit.log").open("w", encoding="utf-8") as log,
    ):
        status = subprocess.run(
            ["cargo", "audit", "--file", str(lock), "--json"],
            cwd=ROOT,
            stdout=result,
            stderr=log,
            check=False,
        )
    data = json.loads((output / "audit.json").read_text(encoding="utf-8"))
    review_audit(data, status.returncode, config)
    print(
        f"Checked {len(packages)} upstream identities and reviewed source fixes: {output}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    check(parser.parse_args().output.resolve())
