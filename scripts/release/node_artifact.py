"""Build and install-check one native Node package candidate; never publish it."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "@byway/phantom"
SOURCES = (
    "index.cjs",
    "index.mjs",
    "index.d.ts",
    "index.d.cts",
    "index.d.mts",
    "README.md",
    "lib/bytes.cjs",
    "lib/bytes.d.cts",
    "lib/client.cjs",
    "lib/client-native.d.cts",
    "lib/controls.cjs",
    "lib/errors.cjs",
    "lib/events.cjs",
    "lib/native.cjs",
    "lib/network.cjs",
    "lib/prepared-body.cjs",
    "lib/profile.cjs",
    "lib/request-options.cjs",
    "lib/request-preparation.cjs",
    "lib/response.cjs",
    "lib/session.cjs",
    "lib/tls.cjs",
    "lib/upload.cjs",
    "lib/validation.cjs",
    "lib/websocket.cjs",
)
TARGETS = {
    "x86_64-pc-windows-msvc": ("win32", "x64", "phantom_node.dll"),
    "x86_64-unknown-linux-gnu": ("linux", "x64", "libphantom_node.so"),
    "aarch64-apple-darwin": ("darwin", "arm64", "libphantom_node.dylib"),
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def h3_peer_environment(root, directory, environment=None):
    spec = importlib.util.spec_from_file_location(
        "binding_h3_peer", root / "scripts/dev/binding_h3_peer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.peer_environment(root, directory, environment)


def artifact_tools():
    spec = importlib.util.spec_from_file_location(
        "cli_artifact", ROOT / "scripts/release/cli_artifact.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_records(raw, target):
    """Select the real optimized cdylib and inputs from Cargo's build receipt."""
    packages = set()
    binaries = []
    finished = False
    for line in raw.splitlines():
        record = json.loads(line)
        if record.get("reason") in {"compiler-artifact", "build-script-executed"}:
            packages.add(record["package_id"])
        if (
            record.get("reason") == "compiler-artifact"
            and record.get("target", {}).get("name") == "phantom_node"
            and "cdylib" in record["target"]["kind"]
            and not record["profile"]["test"]
        ):
            if record["profile"]["opt_level"] != "3":
                raise ValueError("Node addon was not built with release optimization")
            binaries.extend(
                Path(name)
                for name in record["filenames"]
                if Path(name).name == TARGETS[target][2]
            )
        if record.get("reason") == "build-finished":
            finished = record["success"]
    if not finished or len(binaries) != 1 or not packages:
        raise ValueError(
            "Cargo did not report exactly one successful release Node addon"
        )
    return packages, binaries[0]


def package_metadata(source, version, target):
    if (
        source["name"] != PACKAGE
        or source["version"] != version
        or source.get("private") is not True
    ):
        raise ValueError(
            "Node source package identity differs from Cargo or is not private"
        )
    if any(
        source.get(name)
        for name in (
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "bundledDependencies",
            "bundleDependencies",
        )
    ):
        raise ValueError(
            "native package candidates currently require no runtime npm dependencies"
        )
    fields = (
        "name",
        "version",
        "private",
        "description",
        "license",
        "main",
        "types",
        "exports",
        "engines",
    )
    package = {name: source[name] for name in fields}
    package["os"] = [TARGETS[target][0]]
    package["cpu"] = [TARGETS[target][1]]
    package["files"] = [
        *SOURCES,
        "phantom.node",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "notices",
    ]
    return package


def inspect_archive(archive, staging, tools):
    """Compare npm's complete regular-file payload with the staged inputs."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Node archive exceeds inspection bounds")
    expected = {
        "package/" + path.relative_to(staging).as_posix(): tools.digest(path)
        for path in staging.rglob("*")
        if path.is_file()
    }
    with tarfile.open(archive, "r:gz") as source:
        entries = source.getmembers()
        if (
            len(entries) > 10_000
            or sum(entry.size for entry in entries) > MAX_ARCHIVE_BYTES
        ):
            raise ValueError("Node archive exceeds inspection bounds")
        names = [entry.name for entry in entries]
        if len(names) != len({name.casefold() for name in names}):
            raise ValueError("duplicate Node archive path")
        found = {}
        for entry in entries:
            path = PurePosixPath(entry.name)
            if (
                not entry.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in entry.name
                or ":" in entry.name
                or str(path) != entry.name
                or not entry.name.startswith("package/")
            ):
                raise ValueError("unsafe Node archive path or entry")
            with source.extractfile(entry) as payload:
                found[entry.name] = hashlib.sha256(payload.read()).hexdigest()
        if found != expected:
            raise ValueError("Node archive differs from the exact staged payload")
    return found


def copied_tests(destination, native_package=None):
    """Run existing peers against installed public entry points, with checked edits."""
    shutil.copytree(
        ROOT / "bindings/node/tests",
        destination,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    replacements = {
        "client.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
            ("import('../index.mjs')", "import('@byway/phantom')", 1),
            ("path.resolve(__dirname, '..')", "require.resolve('@byway/phantom')", 3),
            (
                "require('../phantom.node')",
                ("require(" + json.dumps(native_package) + ")")
                if native_package
                else "require(path.join(path.dirname(require.resolve('@byway/phantom')), 'phantom.node'))",
                2,
            ),
        ),
        "http2.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "pipeline.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "configuration.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "profiles.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "compact-profiles.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "session-sharing.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "session-snapshots.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "transfer.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "transfer-http2.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "request-controls.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "prepared-bodies.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "multipart.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "socks4.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "pool.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "pool-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "socks4-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "network.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "unix-socket.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "network-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "response-headers.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "multipart-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "server-pins.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "response-trailers.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "response-trailers-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "client-certificates.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
            ("import('../index.mjs')", "import('@byway/phantom')", 1),
        ),
        "client-certificates-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "server-pins-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "diagnostics.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "diagnostics-http2.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "diagnostics-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "transfer-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "prepared-bodies-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "request-controls-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "session-snapshot-facade.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "upload-pump.test.cjs": (
            (
                "path.resolve(__dirname, '../index.cjs')",
                "require.resolve('@byway/phantom')",
                1,
            ),
        ),
        "content-decoding.test.cjs": (
            ("require('..')", "require('@byway/phantom')", 1),
        ),
        "redirects.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "retries.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "uploads.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "upload-http3.test.cjs": (("require('..')", "require('@byway/phantom')", 1),),
        "native-loader.test.cjs": (
            (
                "path.join(__dirname, '../lib/native.cjs')",
                "path.join(path.dirname(require.resolve('@byway/phantom')), 'lib/native.cjs')",
                1,
            ),
        ),
        "types.cts": (("from '../index.cjs'", "from '@byway/phantom'", 1),),
        "types.mts": (("from '../index.mjs'", "from '@byway/phantom'", 1),),
    }
    for name, edits in replacements.items():
        path = destination / name
        text = path.read_text(encoding="utf-8")
        for before, after, count in edits:
            if text.count(before) != count:
                raise ValueError(f"installed Node test import changed: {name}")
            text = text.replace(before, after)
        path.write_text(text, encoding="utf-8")


def tap_summary(raw):
    counts = {}
    for label in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        values = re.findall(rf"^# {label} (\d+)\r?$", raw.decode("utf-8"), re.MULTILINE)
        if len(values) != 1:
            raise ValueError("missing or ambiguous Node test summary")
        counts[label] = int(values[0])
    if (
        counts["tests"] < 19
        or counts["pass"] != counts["tests"]
        or any(counts[name] for name in ("fail", "cancelled", "skipped", "todo"))
    ):
        raise ValueError("installed Node loopback controls did not all pass")
    return counts


def runtime(node, major, target, commands):
    node = node.resolve(strict=True)
    identity = json.loads(
        commands.run(
            [
                str(node),
                "-p",
                "JSON.stringify({executable:process.execPath,versions:process.versions,platform:process.platform,architecture:process.arch})",
            ]
        )
    )
    if (
        identity["versions"]["node"].split(".")[0] != str(major)
        or (identity["platform"], identity["architecture"]) != TARGETS[target][:2]
    ):
        raise ValueError(
            "Node executable must match the requested major and native host"
        )
    candidates = (
        node.parent / "node_modules/npm/bin/npm-cli.js",
        node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js",
    )
    cli = next((path for path in candidates if path.is_file()), None)
    if cli is None:
        raise ValueError(
            "the selected Node executable needs its adjacent bundled npm CLI"
        )
    identity["npm"] = commands.run([str(node), str(cli), "--version"]).decode().strip()
    return node, cli, identity


def npm_environment(consumer, node):
    environment = os.environ.copy()
    for key in (
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
    ):
        environment.pop(key, None)
    environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
    # npm rejects loading one path as both its user and global configuration.
    for kind in ("user", "global"):
        config = consumer / f"npm-{kind}.npmrc"
        config.write_bytes(b"")
        environment[f"NPM_CONFIG_{kind.upper()}CONFIG"] = str(config)
    return environment


def public_checks(
    consumer,
    node,
    cli,
    version,
    commands,
    tools,
    environment,
    cache,
    native_package=None,
):
    package = consumer / "node_modules/@byway/phantom"
    base = [str(node), str(cli)]
    probe = (
        "const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');"
        "const c=require('@byway/phantom'),entry=require.resolve('@byway/phantom');"
        "const metadata=JSON.parse(fs.readFileSync(path.join(path.dirname(entry),'package.json'),'utf8'));"
        "assert.equal(metadata.version," + json.dumps(version) + ");"
        "import('@byway/phantom').then(e=>{assert.equal(c.Client,e.Client);assert.equal(c.Profile,e.Profile);"
        "assert.equal(typeof c.PreparedBody,'function');assert.equal(c.PreparedBody,e.PreparedBody);"
        "assert.equal(typeof c.AttemptBudget,'function');assert.ok(c.profiles().length);"
        "console.log(JSON.stringify({entry,version:metadata.version,profiles:c.profiles().length}));});"
    )
    observed = json.loads(
        commands.run([str(node), "-e", probe], cwd=consumer, env=environment)
    )
    if Path(observed["entry"]).resolve() != (package / "index.cjs").resolve():
        raise ValueError("Node resolved a package outside the clean consumer")
    environment = h3_peer_environment(ROOT, consumer, environment)
    copied_tests(consumer / "tests", native_package)
    checked = tap_summary(
        commands.run(
            [
                str(node),
                "--test",
                "--test-concurrency=1",
                "--test-reporter=tap",
                "tests/client.test.cjs",
                "tests/http2.test.cjs",
                "tests/pipeline.test.cjs",
                "tests/configuration.test.cjs",
                "tests/profiles.test.cjs",
                "tests/compact-profiles.test.cjs",
                "tests/session-sharing.test.cjs",
                "tests/session-snapshots.test.cjs",
                "tests/transfer.test.cjs",
                "tests/transfer-http2.test.cjs",
                "tests/request-controls.test.cjs",
                "tests/prepared-bodies.test.cjs",
                "tests/multipart.test.cjs",
                "tests/response-headers.test.cjs",
                "tests/socks4.test.cjs",
                "tests/pool.test.cjs",
                "tests/pool-facade.test.cjs",
                "tests/socks4-facade.test.cjs",
                "tests/network.test.cjs",
                "tests/unix-socket.test.cjs",
                "tests/network-facade.test.cjs",
                "tests/multipart-facade.test.cjs",
                "tests/response-trailers.test.cjs",
                "tests/response-trailers-facade.test.cjs",
                "tests/server-pins.test.cjs",
                "tests/server-pins-facade.test.cjs",
                "tests/client-certificates.test.cjs",
                "tests/client-certificates-facade.test.cjs",
                "tests/diagnostics.test.cjs",
                "tests/diagnostics-http2.test.cjs",
                "tests/diagnostics-facade.test.cjs",
                "tests/transfer-facade.test.cjs",
                "tests/prepared-bodies-facade.test.cjs",
                "tests/request-controls-facade.test.cjs",
                "tests/session-snapshot-facade.test.cjs",
                "tests/upload-pump.test.cjs",
                "tests/content-decoding.test.cjs",
                "tests/redirects.test.cjs",
                "tests/retries.test.cjs",
                "tests/uploads.test.cjs",
                "tests/upload-http3.test.cjs",
                "tests/native-loader.test.cjs",
            ],
            cwd=consumer,
            env=environment,
            timeout=300,
        )
    )
    # Install only the already locked development compiler in a separate project.
    compiler = consumer / "compiler"
    compiler.mkdir()
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(ROOT / "bindings/node" / name, compiler / name)
    commands.run(
        [
            *base,
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--cache",
            str(cache),
        ],
        cwd=compiler,
        env=environment,
        timeout=180,
    )
    commands.run(
        [
            str(node),
            str(compiler / "node_modules/typescript/bin/tsc"),
            "--noEmit",
            "--strict",
            "--module",
            "NodeNext",
            "--target",
            "ES2022",
            "--lib",
            "ES2022,ESNext.Disposable",
            "--typeRoots",
            str(compiler / "node_modules/@types"),
            "tests/types.cts",
            "tests/types.mts",
        ],
        cwd=consumer,
        env=environment,
        timeout=60,
    )
    return {
        "installation": observed,
        "loopback_checks": checked,
        "typescript": "locked compiler; CJS and ESM consumers passed",
    }


def installed_checks(archive, runtimes, version, files, commands, tools):
    results = []
    with tempfile.TemporaryDirectory(prefix="phantom-node-package-") as temporary:
        directory = Path(temporary).resolve()
        if directory.is_relative_to(ROOT):
            raise ValueError("Node installation checks must run outside checkout")
        for node, cli, identity in runtimes:
            major = identity["versions"]["node"].split(".")[0]
            consumer = directory / f"node-{major}"
            consumer.mkdir()
            tools.write_json(
                consumer / "package.json",
                {
                    "name": "phantom-install-control",
                    "version": "1.0.0",
                    "private": True,
                },
            )
            environment = npm_environment(consumer, node)
            cache = consumer / "npm-cache"
            base = [str(node), str(cli)]
            commands.run(
                [
                    *base,
                    "install",
                    "--ignore-scripts",
                    "--offline",
                    "--no-audit",
                    "--no-fund",
                    "--cache",
                    str(cache),
                    str(archive),
                ],
                cwd=consumer,
                env=environment,
                timeout=180,
            )
            package = consumer / "node_modules/@byway/phantom"
            actual = {
                "package/" + path.relative_to(package).as_posix(): tools.digest(path)
                for path in package.rglob("*")
                if path.is_file()
            }
            if actual != files:
                raise ValueError("installed Node package differs from verified archive")
            checked = public_checks(
                consumer, node, cli, version, commands, tools, environment, cache
            )
            results.append(
                {
                    "runtime": identity,
                    **checked,
                }
            )
    return results


def verify(args):
    tools = artifact_tools()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = tools.Commands(output / "logs")
    if commands.run(["git", "status", "--porcelain"]).strip():
        raise ValueError("Node package candidates require a clean checkout")
    if any(
        key.startswith(("BORING_BSSL_", "CARGO_PROFILE_RELEASE_"))
        or key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "NODE_OPTIONS", "NODE_PATH")
        for key in os.environ
    ):
        raise ValueError("remove native TLS, Node and release optimization overrides")
    revision = commands.run(["git", "rev-parse", "HEAD"]).decode().strip()
    lock = tools.digest(ROOT / "Cargo.lock")
    npm_lock = tools.digest(ROOT / "bindings/node/package-lock.json")
    rustc = commands.run(["rustc", "-vV"]).decode()
    host = tools.host_identity(args.target, rustc)
    cargo = commands.run(["cargo", "-V"]).decode().strip()
    runtimes = [
        runtime(args.node22, 22, args.target, commands),
        runtime(args.node24, 24, args.target, commands),
    ]
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
            ],
            timeout=180,
        )
    )
    jobs = tools.build_jobs()
    packages, binary = build_records(
        commands.run(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--config",
                "profile.release.opt-level=3",
                "--target",
                args.target,
                "-p",
                "phantom-node",
                "--jobs",
                jobs,
                "--message-format=json-render-diagnostics",
            ],
            timeout=1800,
        ),
        args.target,
    )
    selected = [
        package for package in metadata["packages"] if package["name"] == "phantom-node"
    ]
    if len(selected) != 1:
        raise ValueError("expected one Node adapter in Cargo metadata")
    version = selected[0]["version"]
    source_package = json.loads(
        (ROOT / "bindings/node/package.json").read_text(encoding="utf-8")
    )
    staging = output / "staging"
    staging.mkdir()
    tools.write_json(
        staging / "package.json", package_metadata(source_package, version, args.target)
    )
    for name in SOURCES:
        destination = staging / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "bindings/node" / name, destination)
    shutil.copyfile(binary, staging / "phantom.node")
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        shutil.copyfile(ROOT / name, staging / name)
    inventory = tools.copy_notices(metadata, packages, staging / "notices")
    sysroot = Path(commands.run(["rustc", "--print", "sysroot"]).decode().strip())
    tools.copy_rust_notices(sysroot, staging / "notices/rust-runtime")
    tools.write_json(staging / "notices/inventory.json", inventory)
    linkage = tools.dependency_inspection(
        staging / "phantom.node", args.target, commands
    )
    packed = output / "candidate"
    packed.mkdir()
    node, cli, _ = runtimes[0]
    records = json.loads(
        commands.run(
            [
                str(node),
                str(cli),
                "pack",
                "--ignore-scripts",
                "--json",
                "--pack-destination",
                str(packed),
            ],
            cwd=staging,
            timeout=120,
        )
    )
    filename = f"byway-phantom-{version}.tgz"
    if len(records) != 1 or records[0]["filename"] != filename:
        raise ValueError("npm did not report exactly one expected package archive")
    archive = packed / filename
    files = inspect_archive(archive, staging, tools)
    tests = installed_checks(archive, runtimes, version, files, commands, tools)
    if (
        commands.run(["git", "status", "--porcelain"]).strip()
        or commands.run(["git", "rev-parse", "HEAD"]).decode().strip() != revision
        or tools.digest(ROOT / "Cargo.lock") != lock
        or tools.digest(ROOT / "bindings/node/package-lock.json") != npm_lock
    ):
        raise ValueError("checkout identity changed during Node package verification")
    identity = {
        "schema": 1,
        "source_revision": revision,
        "cargo_lock_sha256": lock,
        "npm_lock_sha256": npm_lock,
        "target": args.target,
        "profile": "release",
        "rustc": rustc,
        "cargo": cargo,
        "build_jobs": jobs,
        "build_environment": {
            name: os.environ[name]
            for name in ("MACOSX_DEPLOYMENT_TARGET", "CC", "CXX", "CFLAGS", "CXXFLAGS")
            if name in os.environ
        },
        "tested_host": host,
        "package": PACKAGE,
        "version": version,
        "native_sha256": tools.digest(binary),
        "archive_sha256": tools.digest(archive),
        "payload_sha256": files,
        "notices": inventory,
        "native_linkage": linkage,
        "installation_checks": tests,
        "runtime_boundary": "Tested only on the recorded native host and Node runtimes. No older OS/libc or fully static compatibility established. SDK/OS runtime licenses are separate; no registry publication.",
    }
    verified = output / "verified"
    verified.mkdir()
    shutil.copyfile(archive, verified / filename)
    tools.write_json(verified / "verification.json", identity)
    (verified / "SHA256SUMS").write_text(
        f"{identity['archive_sha256']}  {filename}\n", encoding="utf-8"
    )
    print(f"Verified native Node package candidate: {verified / filename}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--node22", required=True, type=Path)
    parser.add_argument("--node24", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
