"""Validate native candidates for an existing Release; publish only with --publish."""

import argparse
import base64
import hashlib
import json
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import quote

import tomllib

REPOSITORY = "bywayhq/phantom"
WORKFLOWS = {
    "cli": ".github/workflows/cli-artifacts.yml",
    "python": ".github/workflows/python-wheels.yml",
    "node": ".github/workflows/node-packages.yml",
    "go": ".github/workflows/go-artifacts.yml",
}
TARGETS = {
    "x86_64-pc-windows-msvc": ("Windows", {"amd64", "x86_64"}),
    "x86_64-unknown-linux-gnu": ("Linux", {"x86_64"}),
    "aarch64-apple-darwin": ("Darwin", {"arm64", "aarch64"}),
}
SHA256 = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")
MAX_ARCHIVE = 2 * 1024**3
MAX_RECEIPT = 8 * 1024**2
CLI_CHECKS = {
    "version",
    "profile-list",
    "profile-round-trip",
    "ordered-headers",
    "request",
    "file-upload",
    "chunked-download",
    "deadline-cancellation-disconnect",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def positive_id(value):
    require(type(value) is int and value > 0, "invalid GitHub object ID")
    return value


class GitHub:
    """Use the runner's gh credentials without passing tokens in command arguments."""

    def __init__(self, logs):
        self.logs = logs
        logs.mkdir()
        self.count = 0

    def command(self, args, *, destination=None, timeout=120):
        self.count += 1
        stem = self.logs / f"{self.count:03d}"
        stem.with_suffix(".command.json").write_text(json.dumps(args), encoding="utf-8")
        with stem.with_suffix(".stderr").open("wb") as errors:
            output = destination or stem.with_suffix(".stdout")
            with output.open("wb") as stream:
                result = subprocess.run(
                    args, stdout=stream, stderr=errors, timeout=timeout, check=False
                )
        require(result.returncode == 0, f"GitHub command failed; see {stem}.stderr")
        return output

    def api(self, endpoint):
        path = self.command(
            ["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/{endpoint}"]
        )
        require(
            path.stat().st_size <= MAX_RECEIPT,
            "GitHub metadata exceeds processing limit",
        )
        return decode_json(path.read_bytes())

    def pages(self, endpoint, field=None):
        result = []
        for page in range(1, 21):
            data = self.api(f"{endpoint}?per_page=100&page={page}")
            values = data[field] if field else data
            require(isinstance(values, list), "invalid GitHub list response")
            result.extend(values)
            if len(values) < 100:
                if field:
                    require(
                        data["total_count"] == len(result),
                        "GitHub list changed during validation",
                    )
                return result
        raise ValueError("GitHub list exceeds processing limit")

    def source(self, filename, revision):
        data = self.api(f"contents/{filename}?ref={revision}")
        require(
            data["type"] == "file" and data["encoding"] == "base64",
            "source file unavailable",
        )
        return base64.b64decode(data["content"], validate=False)

    def download(self, artifact, path):
        self.command(
            [
                "gh",
                "api",
                "--hostname",
                "github.com",
                f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip",
            ],
            destination=path,
            timeout=600,
        )
        require(
            path.stat().st_size == artifact["size_in_bytes"],
            "downloaded artifact size differs",
        )
        require(
            f"sha256:{digest(path)}" == artifact["digest"],
            "downloaded artifact digest differs",
        )

    def upload(self, tag, paths):
        # No --clobber: a concurrent collision must fail rather than replace bytes.
        self.command(
            [
                "gh",
                "release",
                "upload",
                tag,
                "--repo",
                f"github.com/{REPOSITORY}",
                *map(str, paths),
            ],
            timeout=600,
        )


def release_identity(api, tag):
    require(
        re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag),
        "select a stable vX.Y.Z Release tag",
    )
    release = api.api(f"releases/tags/{quote(tag, safe='')}")
    require(release["tag_name"] == tag, "Release tag differs")
    positive_id(release["id"])
    require(not release.get("immutable", False), "Release is immutable")
    reference = api.api(f"git/ref/tags/{quote(tag, safe='')}")["object"]
    for _ in range(6):
        require(SHA1.fullmatch(reference["sha"]), "invalid tag object SHA")
        if reference["type"] == "commit":
            return release, reference["sha"]
        require(reference["type"] == "tag", "Release tag does not resolve to a commit")
        reference = api.api(f"git/tags/{reference['sha']}")["object"]
    raise ValueError("Release tag nesting exceeds processing limit")


def checked_run(api, family, run_id, revision):
    run = api.api(f"actions/runs/{run_id}")
    require(run["id"] == run_id, "candidate run ID differs")
    for key in ("repository", "head_repository"):
        require(
            run[key]["full_name"] == REPOSITORY,
            "candidate run belongs to another repository",
        )
        positive_id(run[key]["id"])
    require(
        run["repository"]["id"] == run["head_repository"]["id"],
        "candidate is from a fork",
    )
    require(run["head_sha"] == revision, "candidate source differs from Release tag")
    require(
        run["event"] == "workflow_dispatch", "candidate must be manually dispatched"
    )
    require(
        run["status"] == "completed" and run["conclusion"] == "success",
        "candidate workflow did not complete successfully",
    )
    workflow = api.api(f"actions/workflows/{positive_id(run['workflow_id'])}")
    require(
        workflow["path"] == WORKFLOWS[family]
        and run["path"].split("@", 1)[0] == WORKFLOWS[family],
        "candidate workflow differs",
    )
    artifacts = api.pages(f"actions/runs/{run_id}/artifacts", "artifacts")
    names = [item["name"] for item in artifacts]
    require(len(names) == len(set(names)), "duplicate candidate artifact name")
    selected = {}
    expected = {f"phantom-{family}-{target}" for target in TARGETS}
    allowed = expected | {f"phantom-{family}-logs-{target}" for target in TARGETS}
    require(
        set(names) <= allowed and expected <= set(names),
        "candidate platform artifacts are incomplete or unexpected",
    )
    ids = set()
    for artifact in artifacts:
        require(
            positive_id(artifact["id"]) not in ids, "duplicate candidate artifact ID"
        )
        ids.add(artifact["id"])
        if artifact["name"] not in expected:
            continue
        require(
            artifact["expired"] is False,
            "candidate artifact has expired; build a new candidate",
        )
        require(
            type(artifact["size_in_bytes"]) is int
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE,
            "candidate archive exceeds processing limit",
        )
        require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", "")),
            "candidate lacks a GitHub SHA-256 digest; build a new candidate",
        )
        owner = artifact["workflow_run"]
        require(
            owner["id"] == run_id
            and owner["head_sha"] == revision
            and owner["repository_id"] == run["repository"]["id"]
            and owner["head_repository_id"] == run["repository"]["id"],
            "artifact run identity differs",
        )
        target = artifact["name"].removeprefix(f"phantom-{family}-")
        selected[target] = artifact
    return run, selected


def passed_tests(value, *, minimum, node=False):
    require(
        type(value["tests"]) is int
        and value["tests"] >= minimum
        and value["skipped"] == 0,
        "installed candidate tests are incomplete",
    )
    if node:
        require(
            value["pass"] == value["tests"]
            and all(value[key] == 0 for key in ("fail", "cancelled", "todo")),
            "Node candidate tests did not all pass",
        )


def checkout_lock(actual, source, target):
    canonical = hashlib.sha256(source).hexdigest()
    if actual == canonical:
        representation = "git-blob"
    elif (
        target == "x86_64-pc-windows-msvc"
        and b"\r" not in source
        and actual == hashlib.sha256(source.replace(b"\n", b"\r\n")).hexdigest()
    ):
        # Existing Windows candidate receipts hash the exact Git checkout bytes.
        representation = "windows-crlf-checkout"
    else:
        raise ValueError("candidate lockfile hash differs from exact source bytes")
    return {
        "git_sha256": canonical,
        "receipt_sha256": actual,
        "representation": representation,
    }


def validate_receipt(
    family, target, version, revision, lock, npm_lock, receipt, filename, payload_hash
):
    identity = receipt["identity"] if family in {"cli", "go"} else receipt
    require(
        identity["schema"] == 1
        and identity["source_revision"] == revision
        and identity["target"] == target,
        "candidate receipt identity differs",
    )
    locks = {"cargo_lock": checkout_lock(identity["cargo_lock_sha256"], lock, target)}
    host = identity["tested_runtime" if family == "cli" else "tested_host"]
    system, machines = TARGETS[target]
    require(
        host["system"] == system and host["machine"].lower() in machines,
        "candidate native host differs",
    )
    require(
        identity["rustc"] and identity["cargo"],
        "candidate toolchain identity is missing",
    )
    notices = identity["dependencies" if family in {"cli", "go"} else "notices"]
    require(
        isinstance(notices, list) and notices, "candidate notice inventory is missing"
    )
    for package_notice in notices:
        require(
            package_notice["name"]
            and package_notice["version"]
            and package_notice["notices"],
            "candidate package notices are incomplete",
        )
        for notice in package_notice["notices"]:
            require(
                notice["file"] and SHA256.fullmatch(notice["sha256"]),
                "candidate notice hash is missing",
            )
    require(
        identity["native_inspection" if family in {"cli", "go"} else "native_linkage"],
        "candidate native linkage inspection is missing",
    )
    if family == "python":
        wheel = identity["wheel"]
        require(
            wheel["version"] == version
            and identity["installation"]["version"] == version,
            "Python candidate version differs",
        )
        platform = {
            "Windows": "win_amd64",
            "Linux": "linux_x86_64",
            "Darwin": r"macosx_[0-9]+_[0-9]+_arm64",
        }[system]
        require(
            re.fullmatch(
                rf"phantom_http-{re.escape(version)}-cp310-abi3-{platform}\.whl",
                filename,
            ),
            "Python wheel filename differs",
        )
        require(
            wheel["tags"]
            == [filename.removeprefix(f"phantom_http-{version}-").removesuffix(".whl")],
            "Python wheel tags differ",
        )
        require(
            identity["wheel_sha256"] == payload_hash
            and identity["profile"] == "release",
            "Python wheel hash or profile differs",
        )
        passed_tests(identity["loopback_checks"], minimum=12)
    else:
        package = {"cli": "phantom-cli", "go": "phantom-go", "node": "@byway/phantom"}[
            family
        ]
        require(
            identity["package"] == package and identity["version"] == version,
            "candidate package or version differs",
        )
        if family == "node":
            require(
                filename == f"byway-phantom-{version}.tgz"
                and identity["archive_sha256"] == payload_hash
                and identity["profile"] == "release",
                "Node archive identity differs",
            )
            locks["npm_lock"] = checkout_lock(
                identity["npm_lock_sha256"], npm_lock, target
            )
            runtimes = set()
            checks = identity["installation_checks"]
            require(
                len(checks) == 2,
                "Node candidate must cover both supported runtime lines",
            )
            for check in checks:
                major = check["runtime"]["versions"]["node"].split(".")[0]
                require(major not in runtimes, "duplicate Node runtime check")
                runtimes.add(major)
                require(
                    check["installation"]["version"] == version
                    and check["typescript"]
                    == "locked compiler; CJS and ESM consumers passed",
                    "Node installed version or type checks differ",
                )
                passed_tests(check["loopback_checks"], minimum=19, node=True)
            require(runtimes == {"22", "24"}, "Node runtime checks are incomplete")
        else:
            prefix = "phantom" if family == "cli" else "phantom-go"
            suffix = ".zip" if system == "Windows" else ".tar.gz"
            require(
                filename == f"{prefix}-{version}-{target}{suffix}"
                and receipt["archive"] == filename
                and receipt["sha256"] == payload_hash,
                "native archive identity differs",
            )
            if family == "cli":
                require(
                    set(receipt["checks"]) == CLI_CHECKS
                    and len(receipt["checks"]) == len(CLI_CHECKS),
                    "CLI installation checks are incomplete",
                )
            else:
                checks = receipt["checks"]
                require(
                    identity["profile"] == "release"
                    and checks["external_consumer"] == "passed",
                    "Go external installation check is incomplete",
                )
                require(
                    len(checks["tests"]) >= 10
                    and len(checks["tests"]) == len(set(checks["tests"]))
                    and all(
                        isinstance(item, str) and item.startswith("Test")
                        for item in checks["tests"]
                    ),
                    "Go installed tests are incomplete",
                )
    return locks


def unpack_candidate(path, destination):
    destination.mkdir()
    with zipfile.ZipFile(path) as archive:
        items = archive.infolist()
        names = [item.filename for item in items]
        require(
            len(items) == 3 and len({name.casefold() for name in names}) == 3,
            "candidate must contain exactly three distinct files",
        )
        require(
            {"verification.json", "SHA256SUMS"} <= set(names),
            "candidate receipt or checksum is missing",
        )
        payload_name = next(
            name for name in names if name not in {"verification.json", "SHA256SUMS"}
        )
        require(
            re.fullmatch(
                r"(?:phantom|byway-phantom)[A-Za-z0-9._-]{1,200}", payload_name
            ),
            "candidate payload filename is invalid",
        )
        for item in items:
            mode = item.external_attr >> 16
            require(
                item.filename not in {".", ".."}
                and "/" not in item.filename
                and "\\" not in item.filename
                and ":" not in item.filename
                and not item.is_dir()
                and (not stat.S_IFMT(mode) or stat.S_ISREG(mode)),
                "candidate contains an invalid archive entry",
            )
            limit = (
                MAX_RECEIPT
                if item.filename == "verification.json"
                else 1024
                if item.filename == "SHA256SUMS"
                else MAX_ARCHIVE
            )
            require(item.file_size <= limit, "candidate file exceeds processing limit")
            with (
                archive.open(item) as source,
                (destination / item.filename).open("xb") as output,
            ):
                shutil.copyfileobj(source, output, length=65536)
    filename = next(
        name for name in names if name not in {"verification.json", "SHA256SUMS"}
    )
    payload_hash = digest(destination / filename)
    checksum_line = f"{payload_hash}  {filename}".encode()
    require(
        (destination / "SHA256SUMS").read_bytes()
        in {checksum_line + b"\n", checksum_line + b"\r\n"},
        "candidate checksum differs",
    )
    return (
        filename,
        payload_hash,
        decode_json((destination / "verification.json").read_bytes()),
    )


def no_collisions(api, release_id, names):
    assets = api.pages(f"releases/{release_id}/assets")
    existing = [item["name"].casefold() for item in assets]
    require(
        len(existing) == len(set(existing)), "Release contains ambiguous asset names"
    )
    require(
        not set(existing) & {name.casefold() for name in names},
        "Release asset name already exists; overwrite is forbidden",
    )


def unchanged_release(api, tag, release_id, revision):
    current, current_revision = release_identity(api, tag)
    require(
        current["id"] == release_id and current_revision == revision,
        "Release identity changed during validation or upload",
    )


def uploaded_assets(api, release_id, ready, names):
    assets = api.pages(f"releases/{release_id}/assets")
    observed = {item["name"]: item for item in assets}
    for name in names:
        require(
            name in observed
            and observed[name]["size"] == (ready / name).stat().st_size
            and observed[name].get("digest") == f"sha256:{digest(ready / name)}",
            "uploaded Release asset verification failed; retain logs and inspect partial publication",
        )


def promote(api, tag, runs, output, *, publish=False):
    require(
        set(runs) == set(WORKFLOWS) and len(set(runs.values())) == 4,
        "select four distinct candidate run IDs",
    )
    for run_id in runs.values():
        positive_id(run_id)
    release, revision = release_identity(api, tag)
    version = tag[1:]
    source = tomllib.loads(api.source("Cargo.toml", revision).decode())
    require(
        source["workspace"]["package"]["version"] == version,
        "Release version differs from source workspace",
    )
    lock = api.source("Cargo.lock", revision)
    npm_lock = api.source("bindings/node/package-lock.json", revision)
    candidates = []
    downloads = output / "downloads"
    downloads.mkdir()
    for family in WORKFLOWS:
        run, artifacts = checked_run(api, family, runs[family], revision)
        for target, artifact in artifacts.items():
            stem = f"{family}-{target}"
            archive = downloads / f"{stem}.zip"
            api.download(artifact, archive)
            extracted = downloads / stem
            filename, payload_hash, receipt = unpack_candidate(archive, extracted)
            locks = validate_receipt(
                family,
                target,
                version,
                revision,
                lock,
                npm_lock,
                receipt,
                filename,
                payload_hash,
            )
            asset = (
                f"byway-phantom-{version}-{target}.tgz"
                if family == "node"
                else filename
            )
            candidates.append(
                {
                    "family": family,
                    "target": target,
                    "run_id": run["id"],
                    "run_attempt": run["run_attempt"],
                    "artifact_id": artifact["id"],
                    "artifact_digest": artifact["digest"],
                    "candidate_filename": filename,
                    "asset": asset,
                    "sha256": payload_hash,
                    "receipt": f"phantom-{family}-{version}-{target}.verification.json",
                    "receipt_sha256": digest(extracted / "verification.json"),
                    **locks,
                }
            )
    manifest_name = f"phantom-prebuilds-{version}.json"
    checksums_name = f"phantom-prebuilds-{version}-SHA256SUMS.txt"
    names = [
        name for item in candidates for name in (item["asset"], item["receipt"])
    ] + [manifest_name, checksums_name]
    require(
        len(names) == len({name.casefold() for name in names}),
        "promotion asset names collide",
    )
    no_collisions(api, release["id"], names)
    unchanged_release(api, tag, release["id"], revision)
    ready = output / "verified"
    ready.mkdir()
    checksums = []
    for item in candidates:
        extracted = downloads / f"{item['family']}-{item['target']}"
        for source_name, asset_name in (
            (item["candidate_filename"], item["asset"]),
            ("verification.json", item["receipt"]),
        ):
            shutil.copyfile(extracted / source_name, ready / asset_name)
            copied_hash = digest(ready / asset_name)
            require(
                copied_hash
                == item[
                    "sha256" if source_name != "verification.json" else "receipt_sha256"
                ],
                "staged candidate bytes differ",
            )
            checksums.append(f"{copied_hash}  {asset_name}\n")
    manifest = {
        "schema": 1,
        "repository": REPOSITORY,
        "release_id": release["id"],
        "tag": tag,
        "version": version,
        "source_revision": revision,
        "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "npm_lock_sha256": hashlib.sha256(npm_lock).hexdigest(),
        "candidates": candidates,
        "compatibility": "Only the native hosts and runtimes recorded in the unchanged candidate receipts were tested. No older OS/libc, manylinux, or registry publication claim.",
    }
    manifest_path = ready / manifest_name
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    checksums.append(f"{digest(manifest_path)}  {manifest_name}\n")
    (ready / checksums_name).write_text(
        "".join(sorted(checksums)), encoding="utf-8", newline="\n"
    )
    if publish:
        unchanged_release(api, tag, release["id"], revision)
        no_collisions(api, release["id"], names)
        # Upload the manifest last. Partial uploads are retained on failure; never delete assets.
        data_names = [name for name in names if name != manifest_name]
        api.upload(tag, [ready / name for name in data_names])
        uploaded_assets(api, release["id"], ready, data_names)
        unchanged_release(api, tag, release["id"], revision)
        api.upload(tag, [manifest_path])
        uploaded_assets(api, release["id"], ready, names)
        unchanged_release(api, tag, release["id"], revision)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    for family in WORKFLOWS:
        parser.add_argument(f"--{family}-run", required=True, type=int)
    parser.add_argument(
        "--output", required=True, type=Path, help="new evidence directory"
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="upload validated bytes without overwrite",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    api = GitHub(args.output / "logs")
    try:
        promote(
            api,
            args.tag,
            {family: getattr(args, f"{family}_run") for family in WORKFLOWS},
            args.output,
            publish=args.publish,
        )
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        zipfile.BadZipFile,
        subprocess.TimeoutExpired,
    ) as error:
        parser.exit(
            1,
            f"Promotion failed: {error}. Evidence retained in {args.output}. Uploads, if started, may be partial; no assets were overwritten or removed.\n",
        )
    print(
        f"{'Published' if args.publish else 'Validated only; no Release changed'}: {args.output / 'verified'}"
    )


if __name__ == "__main__":
    main()
