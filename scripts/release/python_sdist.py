"""Repair and verify a pinned Maturin source archive; never build or publish it.

Run with Python 3.11+ through scripts/dev/with-cargo-lock.sh. The input must be
the unmodified Maturin 1.15.0 sdist from --source-revision. Native wheel builds
and installed tests remain a separate release check.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import re
import shutil
import tarfile
import tempfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

import tomllib

ROOT = Path(__file__).resolve().parents[2]
MATURIN = "1.15.0"
SUPPORTED_TARGETS = (
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
)
MAX_FILES = 30_000
MAX_BYTES = 512 * 1024 * 1024
H3_LICENSES = {
    f"vendor/h3/{member}/LICENSE" for member in ("h3", "h3-quinn", "h3-datagram")
}
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_source(archive, destination, license_text, executables=None):
    """Accept only one bounded source tree, materializing known H3 licenses."""
    with tarfile.open(archive, "r:gz") as source:
        entries = source.getmembers()
        if len(entries) > MAX_FILES or sum(e.size for e in entries) > MAX_BYTES:
            raise ValueError("source archive exceeds inspection bounds")
        names = set()
        roots = set()
        licenses = set()
        for entry in entries:
            path = PurePosixPath(entry.name)
            if (
                not path.parts
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in entry.name
                or ":" in entry.name
                or str(path) != entry.name.rstrip("/")
                or entry.name.casefold() in names
                or any(
                    part.endswith((".", " "))
                    or part.split(".", 1)[0].upper() in WINDOWS_RESERVED
                    for part in path.parts
                )
            ):
                raise ValueError("unsafe or duplicate source archive path")
            names.add(entry.name.casefold())
            roots.add(path.parts[0])
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            output = destination.joinpath(*path.parts)
            if entry.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if len(path.parts) < 2:
                raise ValueError("source files must be inside the source directory")
            if relative in H3_LICENSES:
                if entry.issym():
                    if entry.linkname != "../LICENSE":
                        raise ValueError("unexpected H3 license link")
                elif not entry.isfile() or source.extractfile(entry).read() not in (
                    b"../LICENSE",
                    license_text,
                ):
                    raise ValueError("unexpected H3 license contents")
                data = license_text
                licenses.add(relative)
            elif entry.isfile():
                data = source.extractfile(entry).read()
            else:
                raise ValueError("source archive contains unsupported link or entry")
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as target:
                target.write(data)
            output.chmod(0o755 if entry.mode & 0o111 else 0o644)
            if executables is not None and entry.mode & 0o111:
                executables.add(relative)
        if len(roots) != 1 or licenses != H3_LICENSES:
            raise ValueError("expected one source tree with all three H3 licenses")
    return destination / roots.pop()


def rewrite_pyproject(text, notices):
    """Select notice files and prove that all other TOML data survives."""
    original = tomllib.loads(text)
    if (
        original["build-system"]["requires"] != [f"maturin=={MATURIN}"]
        or original["tool"]["maturin"].get("manifest-path")
        != "bindings/python/Cargo.toml"
    ):
        raise ValueError("expected pinned Maturin source with portable manifest path")
    changes = {
        ("project", "license-files"): [
            "LICENSE-MIT",
            "LICENSE-APACHE",
            *(["third-party-notices/**/*"] if notices else []),
        ],
    }
    expected = tomllib.loads(text)
    for (table, key), value in changes.items():
        node = expected
        for component in table.split("."):
            node = node[component]
        node[key] = value
    lines = []
    section = None
    seen = set()
    for line in text.splitlines():
        if line.startswith("["):
            section = line.strip()[1:-1]
        match = re.match(r"^([A-Za-z-]+)\s*=", line)
        field = (section, match.group(1)) if match else None
        if field in changes:
            if field in seen:
                raise ValueError("duplicate source packaging field")
            lines.append(f"{field[1]} = {json.dumps(changes[field])}")
            seen.add(field)
        else:
            lines.append(line)
    result = "\n".join(lines) + "\n"
    if seen != changes.keys() or tomllib.loads(result) != expected:
        raise ValueError("unsupported multiline source packaging fields")
    if original["project"]["name"] != "phantom-http":
        raise ValueError("unexpected source project")
    return result


def package_key(package):
    return package["name"], package["version"], package.get("source")


def validate_description(source, expected_readme):
    """Require the binding README in both source layout and package metadata."""
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
    if project["project"].get("readme") != "README.md":
        raise ValueError("source description must select the binding README")
    expected = expected_readme.decode("utf-8").replace("\r\n", "\n")
    if any(
        path.read_text(encoding="utf-8") != expected
        for path in (source / "README.md", source / "bindings/python/README.md")
    ):
        raise ValueError("source description differs from the tracked binding README")
    metadata = BytesParser().parsebytes((source / "PKG-INFO").read_bytes())
    description = metadata.get_payload(decode=True)
    if (
        metadata.get("Description-Content-Type", "").split(";", 1)[0].strip()
        != "text/markdown"
        or not isinstance(description, bytes)
        or description.decode("utf-8").replace("\r\n", "\n").rstrip("\n")
        != expected.rstrip("\n")
    ):
        raise ValueError("source metadata differs from the binding README")


def dependency_keys(package, packages):
    result = set()
    for dependency in package.get("dependencies", []):
        parts = dependency.split(" ", 2)
        matches = {
            key
            for key in packages
            if key[0] == parts[0]
            and (len(parts) == 1 or key[1] == parts[1])
            and (
                len(parts) < 3 or key[2] == parts[2].removeprefix("(").removesuffix(")")
            )
        }
        if len(matches) != 1:
            raise ValueError("ambiguous source lock dependency")
        result.update(matches)
    return result


def verify_lock_pruning(before, after):
    original = tomllib.loads(before)
    updated = tomllib.loads(after)
    original_packages = original.pop("package")
    updated_packages = updated.pop("package")
    old = {package_key(p): p for p in original_packages}
    new = {package_key(p): p for p in updated_packages}
    if len(old) != len(original_packages) or len(new) != len(updated_packages):
        raise ValueError("duplicate source lock package identity")
    if original != updated or not new or not new.keys() <= old.keys():
        raise ValueError("source lock resolution added or changed package identities")
    for key, package in new.items():
        fields = {k: v for k, v in package.items() if k != "dependencies"}
        old_fields = {k: v for k, v in old[key].items() if k != "dependencies"}
        if fields != old_fields or not dependency_keys(package, new) <= dependency_keys(
            old[key], old
        ):
            raise ValueError("source lock resolution changed package contents or edges")
    return {"before": len(old), "after": len(new), "removed": len(old) - len(new)}


def canonical_archive(source, destination, executables=()):
    with (
        destination.open("xb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("staged source contains a symlink")
            if not path.is_file():
                continue
            info = tarfile.TarInfo(path.relative_to(source.parent).as_posix())
            data = path.read_bytes()
            info.size = len(data)
            info.mode = (
                0o755 if path.relative_to(source).as_posix() in executables else 0o644
            )
            archive.addfile(info, io.BytesIO(data))


def repair(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        raise ValueError("source revision must be an exact lowercase commit SHA")
    tools = load_module(
        "python_sdist_artifacts", ROOT / "scripts/release/cli_artifact.py"
    )
    binding = load_module(
        "python_sdist_binding", ROOT / "scripts/dev/check_python_binding.py"
    )
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    revision = (
        commands.run(
            ["git", "rev-parse", "--verify", f"{args.source_revision}^{{commit}}"]
        )
        .decode()
        .strip()
    )
    helper_revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    license_text = commands.run(["git", "show", f"{revision}:vendor/h3/LICENSE"])
    if len(license_text) < 1000 or b"MIT" not in license_text:
        raise ValueError("missing actual tracked H3 license text")
    source_lock = commands.run(["git", "show", f"{revision}:Cargo.lock"]).decode()
    toolchain = tomllib.loads(
        commands.run(["git", "show", f"{revision}:rust-toolchain.toml"]).decode()
    )["toolchain"]["channel"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain):
        raise ValueError("source distribution requires an exact stable Rust toolchain")
    tracked_modes = commands.run(["git", "ls-tree", "-rz", revision])
    tracked_executables = {
        entry.split(b"\t", 1)[1].decode("utf-8")
        for entry in tracked_modes.split(b"\0")
        if entry.startswith(b"100755 ")
    }
    with tempfile.TemporaryDirectory(prefix="phantom-python-source-") as temporary:
        executables = set()
        source = extract_source(
            args.source_archive, Path(temporary), license_text, executables
        )
        validate_description(
            source,
            commands.run(["git", "show", f"{revision}:bindings/python/README.md"]),
        )
        # Windows-produced tar entries lose executable bits. Git retains the
        # source's mode independently of the packager's host filesystem.
        executables.update(tracked_executables)
        (source / "rust-toolchain.toml").write_text(
            f'[toolchain]\nchannel = "{toolchain}"\nprofile = "minimal"\n',
            encoding="utf-8",
        )
        rustc = commands.run(["rustc", "-vV"], cwd=source, timeout=180).decode()
        if f"release: {toolchain}" not in rustc.splitlines():
            raise ValueError(
                "notice-producing rustc differs from the source toolchain pin"
            )
        lock = source / "Cargo.lock"
        original_lock = lock.read_text(encoding="utf-8")
        if tomllib.loads(original_lock) != tomllib.loads(source_lock):
            raise ValueError("input source lock differs from declared source revision")
        project = source / "pyproject.toml"
        project.write_text(
            rewrite_pyproject(project.read_text(encoding="utf-8"), []), encoding="utf-8"
        )
        metadata_command = ["cargo", "metadata", "--offline", "--format-version", "1"]
        commands.run(metadata_command, cwd=source, timeout=180)
        pruning = verify_lock_pruning(original_lock, lock.read_text(encoding="utf-8"))
        metadata = json.loads(
            commands.run([*metadata_command, "--locked"], cwd=source, timeout=180)
        )
        selected = set()
        for target in SUPPORTED_TARGETS:
            target_metadata = json.loads(
                commands.run(
                    [*metadata_command, "--locked", "--filter-platform", target],
                    cwd=source,
                    timeout=180,
                )
            )
            package, target_inputs = binding.dependency_closure(target_metadata)
            selected.update(target_inputs)
        # The shared collector's one pinned supplemental notice is not supplied
        # by its published crate. Keep the exact checked-in fallback available.
        supplemental = source / tools.ALLOC_STDLIB_LICENSE_PATH
        supplemental.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / tools.ALLOC_STDLIB_LICENSE_PATH, supplemental)
        notices = source / "third-party-notices"
        inventory = tools.copy_notices(metadata, selected, notices, root=source)
        for item in inventory:
            item["scope"] = (
                "potential normal/build input for supported target union; not linked-code attribution"
            )
        sysroot = Path(
            commands.run(["rustc", "--print", "sysroot"], cwd=source).decode().strip()
        )
        tools.copy_rust_notices(sysroot, notices / "rust-runtime")
        tools.write_json(notices / "inventory.json", inventory)
        notice_paths = sorted(
            p.relative_to(source).as_posix() for p in notices.rglob("*") if p.is_file()
        )
        project.write_text(
            rewrite_pyproject(project.read_text(encoding="utf-8"), notice_paths),
            encoding="utf-8",
        )
        version = tomllib.loads(project.read_text(encoding="utf-8"))["project"][
            "version"
        ]
        if source.name != f"phantom_http-{version}" or version != package["version"]:
            raise ValueError("source archive identity differs from package version")
        pkg_info = source / "PKG-INFO"
        metadata_fields = BytesParser(policy=policy.default).parsebytes(
            pkg_info.read_bytes()
        )
        if (
            metadata_fields["Name"] != "phantom-http"
            or metadata_fields["Version"] != version
        ):
            raise ValueError("source metadata differs from package identity")
        del metadata_fields["License-File"]
        for path in ["LICENSE-MIT", "LICENSE-APACHE", *notice_paths]:
            metadata_fields["License-File"] = path
        pkg_info.write_bytes(
            metadata_fields.as_bytes(
                policy=policy.default.clone(linesep="\n", max_line_length=0)
            )
        )
        staging = output / "candidate"
        staging.mkdir()
        candidate = staging / (source.name + ".tar.gz")
        canonical_archive(source, candidate, executables)
        tools.write_json(
            staging / "receipt.json",
            {
                "source_revision": revision,
                "source_revision_scope": "caller-declared archive revision; original lock, binding README, H3 license and executable modes checked against Git",
                "helper_revision": helper_revision,
                "input_sha256": tools.digest(args.source_archive),
                "archive_sha256": tools.digest(candidate),
                "cargo_lock_sha256": tools.digest(lock),
                "original_cargo_lock_sha256": hashlib.sha256(
                    source_lock.encode()
                ).hexdigest(),
                "maturin": MATURIN,
                "source_builder_toolchain": toolchain,
                "supported_targets": list(SUPPORTED_TARGETS),
                "toolchain_scope": "pinned archive compiler only; deliberate consumer overrides are outside this notice closure",
                "lock_pruning": pruning,
                "notices": inventory,
                "rustc": rustc,
                "validation": "offline locked dependency resolution only; source-built wheel/install not yet verified",
            },
        )
        staging.rename(output / "verified")
    return output / "verified" / candidate.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    print(repair(parser.parse_args()))


if __name__ == "__main__":
    main()
