#!/usr/bin/env python3
"""Publish the reviewed release in order, requiring Byway team ownership."""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]
OWNER = "github:bywayhq:staff"
PUBLISHER = "0xARYA"


def fetch(url, missing_ok=False):
    request = urllib.request.Request(url, headers={"User-Agent": "phantom-release/1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise


def api(path, missing_ok=False):
    data = fetch("https://crates.io/api/v1/" + path, missing_ok)
    return json.loads(data) if data is not None else None


def owners(name):
    data = api(f"crates/{name}/owners", missing_ok=True)
    return {entry["login"] for entry in data["users"]} if data else set()


def plan():
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))[
        "workspace"
    ]["package"]
    packages = []
    for manifest in (
        (ROOT / "scripts/release/packages.txt").read_text(encoding="utf-8").splitlines()
    ):
        package = tomllib.loads((ROOT / manifest).read_text(encoding="utf-8"))[
            "package"
        ]
        version = package["version"]
        if isinstance(version, dict):
            version = workspace["version"]
        packages.append((package["name"], version, manifest))
    return packages


def published_from_commit(name, version, record, commit):
    archive = fetch(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")
    if hashlib.sha256(archive).hexdigest() != record["version"]["checksum"]:
        raise RuntimeError(f"registry archive checksum differs: {name} {version}")
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        info = json.load(source.extractfile(f"{name}-{version}/.cargo_vcs_info.json"))
    if info["git"]["sha1"] != commit or info["git"].get("dirty", False):
        raise RuntimeError(f"existing {name} {version} was not published from {commit}")


def ensure_owner(name):
    if OWNER not in owners(name):
        subprocess.run(["cargo", "owner", "--add", OWNER, name], check=True, cwd=ROOT)
    if OWNER not in owners(name):
        raise RuntimeError(f"Byway ownership was not established for {name}")


def release(publish):
    packages = plan()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    # Check every name before uploading any package. Existing names must be
    # controlled by Byway or the named maintainer who can add its team.
    for name, version, _manifest in packages:
        existing = api(f"crates/{name}", missing_ok=True)
        current_owners = owners(name) if existing else set()
        if existing and not ({OWNER, PUBLISHER} & current_owners):
            raise RuntimeError(f"package name is owned by another publisher: {name}")
        record = api(f"crates/{name}/{version}", missing_ok=True)
        if record:
            published_from_commit(name, version, record, commit)
        state = "same-commit version exists" if record else "new version"
        print(f"{name} {version}: {state}; owners={sorted(current_owners)}", flush=True)
    if not publish:
        print(f"Required team owner: {OWNER}; no packages published", flush=True)
        return
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise RuntimeError("refusing to publish a dirty checkout")
    for name, version, manifest in packages:
        if not api(f"crates/{name}/{version}", missing_ok=True):
            # This can resolve each unpublished predecessor only after it has
            # reached the real registry. The staged archive gate runs earlier.
            for extra in (["--dry-run"], []):
                subprocess.run(
                    [
                        "cargo",
                        "publish",
                        "--locked",
                        "--manifest-path",
                        manifest,
                        *extra,
                    ],
                    check=True,
                    cwd=ROOT,
                )
            for _attempt in range(30):
                if api(f"crates/{name}/{version}", missing_ok=True):
                    break
                time.sleep(2)
            else:
                raise RuntimeError(f"registry did not expose {name} {version}")
        # Also repair ownership if an earlier run stopped after uploading.
        ensure_owner(name)
        print(f"Verified {name} {version}; owner={OWNER}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    release(parser.parse_args().publish)
