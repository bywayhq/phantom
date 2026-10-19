#!/usr/bin/env python3
"""Check resolved dependencies under their upstream registry identities."""

import argparse
import json
import subprocess
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]


def upstream_identities():
    """Include unchanged forks as well as packages selected for publication."""
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    identities = {}
    for dependency in workspace["workspace"]["dependencies"].values():
        if not isinstance(dependency, dict) or "path" not in dependency:
            continue
        manifest = ROOT / dependency["path"] / "Cargo.toml"
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        upstream = data["package"].get("metadata", {}).get("phantom")
        if upstream:
            identities[data["package"]["name"]] = (
                upstream["upstream-package"],
                upstream["upstream-version"],
            )
    return identities


def check(output):
    output.mkdir(parents=True, exist_ok=True)
    identities = upstream_identities()
    packages = set()
    for package in tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))[
        "package"
    ]:
        if package["name"] in identities:
            packages.add(identities[package["name"]])
        elif package.get("source", "").startswith("registry+"):
            packages.add((package["name"], package["version"]))
    lock = output / "upstream-identities.lock"
    text = "version = 3\n"
    for name, version in sorted(packages):
        text += (
            f"\n[[package]]\nname = {json.dumps(name)}\n"
            f"version = {json.dumps(version)}\n"
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
    lock.write_text(text)
    (output / "identity-map.json").write_text(json.dumps(identities, indent=2) + "\n")
    with (
        (output / "audit.json").open("w") as result,
        (output / "audit.log").open("w") as log,
    ):
        status = subprocess.run(
            ["cargo", "audit", "--file", str(lock), "--json"],
            cwd=ROOT,
            stdout=result,
            stderr=log,
        )
    data = json.loads((output / "audit.json").read_text(encoding="utf-8"))
    fixes = json.loads(
        (ROOT / "scripts/release/advisory-fixes.json").read_text(encoding="utf-8")
    )
    unresolved = []
    for finding in data["vulnerabilities"]["list"]:
        advisory, package = finding["advisory"], finding["package"]
        fix = fixes.get(advisory["id"])
        if not fix or (fix["package"], fix["version"]) != (
            package["name"],
            package["version"],
        ):
            unresolved.append(finding)
        else:
            print(f"Retained backport: {advisory['id']}; {fix['evidence']}")
    if unresolved or (status.returncode and not data["vulnerabilities"]["list"]):
        raise RuntimeError(f"unresolved advisory or audit failure; see {output}")
    print(f"Checked {len(packages)} upstream identities; raw report: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    check(parser.parse_args().output.resolve())
