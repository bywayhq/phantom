import copy
import hashlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "promote_prebuilds", Path(__file__).parents[1] / "promote_prebuilds.py"
)
promotion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(promotion)
REVISION = "a" * 40
LOCK = b"locked dependency bytes\n"
NPM_LOCK = b"locked npm dependency bytes\n"
VERSION = "0.3.0"
RUNS = {family: index for index, family in enumerate(promotion.WORKFLOWS, 11)}


def hashed(raw):
    return hashlib.sha256(raw).hexdigest()


def candidate(family, target):
    system, machines = promotion.TARGETS[target]
    host = {"system": system, "machine": sorted(machines)[0]}
    identity = {
        "schema": 1,
        "source_revision": REVISION,
        "cargo_lock_sha256": hashed(LOCK),
        "target": target,
        "profile": "release",
        "version": VERSION,
        "rustc": f"rustc receipt\nhost: {target}",
        "cargo": "cargo receipt",
    }
    notices = [
        {
            "name": "phantom",
            "version": VERSION,
            "notices": [{"file": "LICENSE-MIT", "sha256": hashed(b"license")}],
        }
    ]
    payload = f"opaque {family} {target} payload; never executed".encode()
    payload_hash = hashed(payload)
    suffix = ".zip" if system == "Windows" else ".tar.gz"
    if family in {"cli", "go"}:
        identity["package"] = "phantom-cli" if family == "cli" else "phantom-go"
        identity["tested_runtime" if family == "cli" else "tested_host"] = host
        identity["dependencies"] = notices
        identity["native_inspection"] = [
            {"tool": "native tool", "output": "recorded output"}
        ]
        prefix = "phantom" if family == "cli" else "phantom-go"
        filename = f"{prefix}-{VERSION}-{target}{suffix}"
        receipt = {
            "identity": identity,
            "archive": filename,
            "sha256": payload_hash,
            "checks": sorted(promotion.CLI_CHECKS)
            if family == "cli"
            else {
                "external_consumer": "passed",
                "tests": [f"TestControl{index}" for index in range(10)],
            },
        }
    else:
        identity.update(
            tested_host=host,
            notices=notices,
            native_linkage=[{"tool": "native tool", "output": "recorded output"}],
        )
        if family == "python":
            platform = {
                "Windows": "win_amd64",
                "Linux": "linux_x86_64",
                "Darwin": "macosx_11_0_arm64",
            }[system]
            filename = f"phantom_http-{VERSION}-cp310-abi3-{platform}.whl"
            identity.update(
                wheel={"version": VERSION, "tags": [f"cp310-abi3-{platform}"]},
                installation={"version": VERSION},
                wheel_sha256=payload_hash,
                loopback_checks={"tests": 12, "skipped": 0},
            )
        else:
            filename = f"byway-phantom-{VERSION}.tgz"
            identity.update(
                package="@byway/phantom",
                archive_sha256=payload_hash,
                npm_lock_sha256=hashed(NPM_LOCK),
                installation_checks=[
                    {
                        "runtime": {"versions": {"node": f"{major}.0.0"}},
                        "installation": {"version": VERSION},
                        "typescript": "locked compiler; CJS and ESM consumers passed",
                        "loopback_checks": {
                            "tests": 19,
                            "pass": 19,
                            "skipped": 0,
                            "fail": 0,
                            "cancelled": 0,
                            "todo": 0,
                        },
                    }
                    for major in (22, 24)
                ],
            )
        receipt = identity
    return filename, payload, receipt


def zipped(filename, payload, receipt, *, checksum=None, extra=None):
    name = filename.filename if isinstance(filename, zipfile.ZipInfo) else filename
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(filename, payload)
        archive.writestr("verification.json", json.dumps(receipt))
        archive.writestr("SHA256SUMS", checksum or f"{hashed(payload)}  {name}\n")
        if extra:
            archive.writestr(*extra)
    return output.getvalue()


class FakeGitHub:
    def __init__(self):
        self.release = {"id": 42, "tag_name": f"v{VERSION}", "immutable": False}
        self.reference = {"type": "commit", "sha": REVISION}
        self.runs = {}
        self.artifacts = {}
        self.files = {}
        self.assets = []
        self.uploads = []
        self.fail_upload = None
        self.mutate_uploaded_digest = False
        for family, run_id in RUNS.items():
            self.runs[run_id] = {
                "id": run_id,
                "run_attempt": 1,
                "head_sha": REVISION,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "repository": {"id": 7, "full_name": promotion.REPOSITORY},
                "head_repository": {"id": 7, "full_name": promotion.REPOSITORY},
                "path": promotion.WORKFLOWS[family] + "@main",
                "workflow_id": run_id + 100,
            }
            self.artifacts[run_id] = []
            for offset, target in enumerate(promotion.TARGETS):
                filename, payload, receipt = candidate(family, target)
                raw = zipped(filename, payload, receipt)
                artifact_id = run_id * 10 + offset
                self.files[artifact_id] = raw
                self.artifacts[run_id].append(
                    {
                        "id": artifact_id,
                        "name": f"phantom-{family}-{target}",
                        "expired": False,
                        "size_in_bytes": len(raw),
                        "digest": "sha256:" + hashed(raw),
                        "workflow_run": {
                            "id": run_id,
                            "head_sha": REVISION,
                            "repository_id": 7,
                            "head_repository_id": 7,
                        },
                    }
                )

    def api(self, endpoint):
        if endpoint.startswith("releases/tags/"):
            return copy.deepcopy(self.release)
        if endpoint.startswith("git/ref/tags/"):
            return {"object": copy.deepcopy(self.reference)}
        if endpoint.startswith("git/tags/"):
            return {"object": {"type": "commit", "sha": REVISION}}
        if endpoint.startswith("actions/runs/"):
            return copy.deepcopy(self.runs[int(endpoint.split("/")[-1])])
        if endpoint.startswith("actions/workflows/"):
            run_id = int(endpoint.split("/")[-1]) - 100
            return {"path": self.runs[run_id]["path"].split("@")[0]}
        raise AssertionError(endpoint)

    def pages(self, endpoint, field=None):
        if endpoint.startswith("releases/"):
            return copy.deepcopy(self.assets)
        return copy.deepcopy(self.artifacts[int(endpoint.split("/")[2])])

    def source(self, filename, revision):
        if revision != REVISION:
            raise AssertionError("source read is not pinned")
        return {
            "Cargo.toml": f'[workspace.package]\nversion = "{VERSION}"\n'.encode(),
            "Cargo.lock": LOCK,
            "bindings/node/package-lock.json": NPM_LOCK,
        }[filename]

    def command(self, args, *, destination, timeout):
        artifact_id = int(args[-1].split("/")[-2])
        destination.write_bytes(self.files[artifact_id])

    def download(self, artifact, path):
        promotion.GitHub.download(self, artifact, path)

    def upload(self, tag, paths):
        self.uploads.append([path.name for path in paths])
        if self.fail_upload == len(self.uploads):
            raise ValueError("controlled upload failure")
        for path in paths:
            self.assets.append(
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "digest": "sha256:"
                    + (
                        "0" * 64
                        if self.mutate_uploaded_digest
                        else promotion.digest(path)
                    ),
                }
            )


class PromotionTests(unittest.TestCase):
    def run_promotion(self, api, root, *, publish=False):
        return promotion.promote(api, f"v{VERSION}", RUNS, root, publish=publish)

    def test_default_validation_preserves_all_twelve_payloads_and_receipt_bytes(self):
        api = FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.run_promotion(api, root)
            self.assertEqual(api.uploads, [])
            self.assertEqual(len(manifest["candidates"]), 12)
            self.assertEqual(len(list((root / "verified").iterdir())), 26)
            for item in manifest["candidates"]:
                with zipfile.ZipFile(
                    io.BytesIO(api.files[item["artifact_id"]])
                ) as original:
                    self.assertEqual(
                        (root / "verified" / item["asset"]).read_bytes(),
                        original.read(item["candidate_filename"]),
                    )
                    self.assertEqual(
                        (root / "verified" / item["receipt"]).read_bytes(),
                        original.read("verification.json"),
                    )
            node_names = [
                item["asset"]
                for item in manifest["candidates"]
                if item["family"] == "node"
            ]
            self.assertEqual(len(set(node_names)), 3)
            checksums = (
                (root / "verified" / f"phantom-prebuilds-{VERSION}-SHA256SUMS.txt")
                .read_text()
                .splitlines()
            )
            self.assertEqual(len(checksums), 25)
            for line in checksums:
                sha, filename = line.split("  ")
                self.assertEqual(promotion.digest(root / "verified" / filename), sha)

    def test_publish_checks_all_uploaded_bytes_and_commits_manifest_last(self):
        api = FakeGitHub()
        api.reference = {"type": "tag", "sha": "b" * 40}
        with tempfile.TemporaryDirectory() as directory:
            self.run_promotion(api, Path(directory), publish=True)
        self.assertEqual(len(api.uploads), 2)
        self.assertEqual(len(api.uploads[0]), 25)
        self.assertEqual(api.uploads[1], [f"phantom-prebuilds-{VERSION}.json"])

    def test_windows_checksum_crlf_is_accepted_without_changing_candidate_bytes(self):
        api = FakeGitHub()
        artifact = api.artifacts[11][0]
        filename, payload, receipt = candidate("cli", next(iter(promotion.TARGETS)))
        raw = zipped(
            filename, payload, receipt, checksum=f"{hashed(payload)}  {filename}\r\n"
        )
        api.files[artifact["id"]] = raw
        artifact.update(size_in_bytes=len(raw), digest="sha256:" + hashed(raw))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_promotion(api, root)
            self.assertEqual((root / "verified" / filename).read_bytes(), payload)

    def test_lock_checkout_representation_is_exact_and_windows_only(self):
        source = b"first lock line\nsecond lock line\n"
        crlf = source.replace(b"\n", b"\r\n")
        windows = "x86_64-pc-windows-msvc"
        for target in promotion.TARGETS:
            self.assertEqual(
                promotion.checkout_lock(hashed(source), source, target)[
                    "representation"
                ],
                "git-blob",
            )
        self.assertEqual(
            promotion.checkout_lock(hashed(crlf), source, windows),
            {
                "git_sha256": hashed(source),
                "receipt_sha256": hashed(crlf),
                "representation": "windows-crlf-checkout",
            },
        )
        for invalid in (
            source + b"edit",
            crlf.replace(b"\r\n", b"\r\r\n"),
            source.replace(b"\n", b"\r\n", 1),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                promotion.checkout_lock(hashed(invalid), source, windows)
        for target in ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                promotion.checkout_lock(hashed(crlf), source, target)
        with self.assertRaises(ValueError):
            promotion.checkout_lock(hashed(crlf.replace(b"\n", b"\r\n")), crlf, windows)

    def test_manifest_keeps_actual_cargo_and_npm_checkout_hashes(self):
        api = FakeGitHub()
        target = "x86_64-pc-windows-msvc"
        artifact = api.artifacts[RUNS["node"]][0]
        filename, payload, receipt = candidate("node", target)
        receipt["cargo_lock_sha256"] = hashed(LOCK.replace(b"\n", b"\r\n"))
        receipt["npm_lock_sha256"] = hashed(NPM_LOCK.replace(b"\n", b"\r\n"))
        raw = zipped(filename, payload, receipt)
        api.files[artifact["id"]] = raw
        artifact.update(size_in_bytes=len(raw), digest="sha256:" + hashed(raw))
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.run_promotion(api, Path(directory))
        self.assertEqual(manifest["cargo_lock_sha256"], hashed(LOCK))
        self.assertEqual(manifest["npm_lock_sha256"], hashed(NPM_LOCK))
        item = next(
            item
            for item in manifest["candidates"]
            if item["family"] == "node" and item["target"] == target
        )
        for key in ("cargo_lock", "npm_lock"):
            self.assertEqual(item[key]["representation"], "windows-crlf-checkout")
            self.assertEqual(item[key]["receipt_sha256"], receipt[f"{key}_sha256"])

    def test_untrusted_or_unfinished_runs_and_incomplete_artifacts_fail_closed(self):
        changes = [
            lambda api: api.runs[11].update(event="pull_request"),
            lambda api: api.runs[11].update(status="in_progress"),
            lambda api: api.runs[11].update(conclusion="failure"),
            lambda api: api.runs[11].update(head_sha="b" * 40),
            lambda api: api.runs[11]["head_repository"].update(
                full_name="other/phantom"
            ),
            lambda api: api.runs[11].update(path=".github/workflows/other.yml"),
            lambda api: api.artifacts[11].pop(),
            lambda api: api.artifacts[11].append(copy.deepcopy(api.artifacts[11][0])),
            lambda api: api.artifacts[11][0].update(expired=True),
            lambda api: api.artifacts[11][0].update(digest=None),
            lambda api: api.artifacts[11][0]["workflow_run"].update(head_sha="b" * 40),
            lambda api: api.artifacts[11][0].update(
                size_in_bytes=promotion.MAX_ARCHIVE + 1
            ),
        ]
        for change in changes:
            with (
                self.subTest(change=changes.index(change)),
                tempfile.TemporaryDirectory() as directory,
            ):
                api = FakeGitHub()
                change(api)
                with self.assertRaises((ValueError, TypeError)):
                    self.run_promotion(api, Path(directory), publish=True)
                self.assertEqual(api.uploads, [])
                self.assertFalse((Path(directory) / "verified").exists())

    def test_archive_digest_size_checksum_and_framing_tampering_are_rejected(self):
        for mode in (
            "digest",
            "size",
            "checksum",
            "extra",
            "link",
            "duplicate",
            "traversal",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                api = FakeGitHub()
                item = api.artifacts[11][0]
                filename, payload, receipt = candidate(
                    "cli", next(iter(promotion.TARGETS))
                )
                if mode == "digest":
                    api.files[item["id"]] += b"tampered"
                    item["size_in_bytes"] = len(api.files[item["id"]])
                elif mode == "size":
                    item["size_in_bytes"] += 1
                else:
                    extra = None
                    checksum = None
                    if mode == "checksum":
                        checksum = "0" * 64 + f"  {filename}\n"
                    elif mode in {"extra", "duplicate"}:
                        extra = ("extra" if mode == "extra" else "SHA256SUMS", b"extra")
                    elif mode == "link":
                        info = zipfile.ZipInfo(filename)
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        filename = info
                    else:
                        filename = "../escape"
                    with patch("warnings.warn"):
                        raw = zipped(
                            filename, payload, receipt, checksum=checksum, extra=extra
                        )
                    api.files[item["id"]] = raw
                    item.update(size_in_bytes=len(raw), digest="sha256:" + hashed(raw))
                with self.assertRaises(ValueError):
                    self.run_promotion(api, Path(directory), publish=True)
                self.assertEqual(api.uploads, [])

    def test_every_receipt_identity_and_completion_boundary_is_checked(self):
        mutations = {
            "cli": [
                lambda r: r["identity"].update(source_revision="b" * 40),
                lambda r: r["identity"].update(cargo_lock_sha256="0" * 64),
                lambda r: r["identity"].update(target="other"),
                lambda r: r["identity"].update(version="0.2.0"),
                lambda r: r.update(checks=[]),
                lambda r: r["identity"].update(dependencies=[]),
            ],
            "python": [
                lambda r: r["wheel"].update(version="0.2.0"),
                lambda r: r["loopback_checks"].update(skipped=1),
                lambda r: r["wheel"].update(tags=["cp310-abi3-win_arm64"]),
                lambda r: r.update(wheel_sha256="0" * 64),
            ],
            "node": [
                lambda r: r.update(npm_lock_sha256="0" * 64),
                lambda r: r["installation_checks"].pop(),
                lambda r: r["installation_checks"][0]["loopback_checks"].update(
                    cancelled=1
                ),
                lambda r: r["installation_checks"][0].update(typescript="not checked"),
            ],
            "go": [
                lambda r: r["checks"].update(external_consumer="failed"),
                lambda r: r["checks"].update(tests=[]),
                lambda r: r["identity"]["tested_host"].update(system="other"),
            ],
        }
        for family, changes in mutations.items():
            for index, change in enumerate(changes):
                with (
                    self.subTest(family=family, index=index),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    api = FakeGitHub()
                    artifact = api.artifacts[RUNS[family]][0]
                    filename, payload, receipt = candidate(
                        family, next(iter(promotion.TARGETS))
                    )
                    change(receipt)
                    raw = zipped(filename, payload, receipt)
                    api.files[artifact["id"]] = raw
                    artifact.update(
                        size_in_bytes=len(raw), digest="sha256:" + hashed(raw)
                    )
                    with self.assertRaises(ValueError):
                        self.run_promotion(api, Path(directory), publish=True)
                    self.assertEqual(api.uploads, [])

    def test_release_collisions_and_changed_tag_never_overwrite_assets(self):
        for mode in ("collision", "changed_tag", "immutable", "wrong_version"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                api = FakeGitHub()
                if mode == "collision":
                    api.assets.append({"name": f"PHANTOM-PREBUILDS-{VERSION}.JSON"})
                elif mode == "immutable":
                    api.release["immutable"] = True
                elif mode == "wrong_version":
                    api.source = lambda *_: b'[workspace.package]\nversion="0.2.0"'
                else:
                    original = api.api
                    calls = 0

                    def moved(endpoint, original=original):
                        nonlocal calls
                        if endpoint.startswith("git/ref/"):
                            calls += 1
                            if calls == 2:
                                return {"object": {"type": "commit", "sha": "b" * 40}}
                        return original(endpoint)

                    api.api = moved
                with self.assertRaises(ValueError):
                    self.run_promotion(api, Path(directory), publish=True)
                self.assertEqual(api.uploads, [])

    def test_upload_failure_or_digest_mismatch_does_not_publish_manifest(self):
        for mode in ("upload", "digest"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                api = FakeGitHub()
                api.fail_upload = 1 if mode == "upload" else None
                api.mutate_uploaded_digest = mode == "digest"
                with self.assertRaises(ValueError):
                    self.run_promotion(api, Path(directory), publish=True)
                self.assertEqual(len(api.uploads), 1)
                self.assertNotIn(
                    f"phantom-prebuilds-{VERSION}.json",
                    [asset["name"] for asset in api.assets],
                )

    def test_gh_upload_arguments_never_enable_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            api = promotion.GitHub(Path(directory) / "logs")
            with patch.object(api, "command") as command:
                api.upload(f"v{VERSION}", [Path("asset.zip")])
            args = command.call_args.args[0]
            self.assertEqual(args[:3], ["gh", "release", "upload"])
            self.assertNotIn("--clobber", args)
            self.assertNotIn("--skip-existing", args)

    def test_duplicate_receipt_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            promotion.decode_json(b'{"schema":1,"schema":2}')


if __name__ == "__main__":
    unittest.main()
