"""Run headed Chrome captures on the workflow's disposable macOS runners."""

import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from scripts.capture import run_matrix
from scripts.capture.browser_failures import raise_browser_failures
from scripts.capture.capture_report import command_output, file_digest

PROFILE_VERSION = "156.0.8078.48"
CHROME_DMG = "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"
# Chromium chrome/updater/branding.gni names Google's signing team.
CHROME_REQUIREMENT = (
    'anchor apple generic and identifier "com.google.Chrome" '
    'and certificate leaf[subject.OU] = "EQHXZ8M8AV"'
)


@contextmanager
def staged_chrome(
    output: Path, record: dict, *, parent: Path = Path("/tmp")
) -> Iterator[tuple[Path, Path]]:
    """Keep an owned mount/app until cleanup succeeds, including on interruption."""
    directory = Path(tempfile.mkdtemp(prefix="ph-", dir=parent)).resolve()
    if directory.parent != parent.resolve():
        raise RuntimeError("Chrome staging directory is outside its parent")
    record["staging_directory"] = str(directory)
    image = directory / "chrome.dmg"
    mount = directory / "mount"
    app = directory / "Google Chrome.app"
    primary = None
    cleanup = []
    attached = False
    try:
        args = [
            "/usr/bin/curl",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--max-time",
            "120",
            "--dump-header",
            str(output / "download.headers"),
            "--output",
            str(image),
            CHROME_DMG,
        ]
        record["download_argv"] = args
        with (output / "download.log").open("wb") as log:
            download = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
        record["download_exit"] = download.returncode
        download.check_returncode()
        record["package"] = {
            "url": CHROME_DMG,
            "sha256": file_digest(image),
            "bytes": image.stat().st_size,
        }
        mount.mkdir()
        # Even an interrupted attach may have mounted the image.
        attached = True
        command_output(
            record,
            "/usr/bin/hdiutil",
            "attach",
            "-readonly",
            "-nobrowse",
            "-mountpoint",
            str(mount),
            str(image),
        )
        command_output(record, "/usr/bin/ditto", str(mount / app.name), str(app))
        yield app / "Contents/MacOS/Google Chrome", directory
    except BaseException as error:
        primary = error
    finally:
        if attached:
            try:
                command_output(record, "/usr/bin/hdiutil", "detach", str(mount))
            except BaseException as error:
                cleanup.append(error)
        retain = record.get("capture_started", False) and (
            primary is not None or record.get("capture_exit") != 0
        )
        if not cleanup and not retain:
            try:
                shutil.rmtree(directory)
            except BaseException as error:
                cleanup.append(error)
        record["staging_retained"] = bool(cleanup) or retain
        record["staging_cleanup_failures"] = [
            {"type": type(error).__name__, "message": str(error)} for error in cleanup
        ]
        raise_browser_failures(primary, tuple(cleanup))


def verify_profile_browser(record: dict, chrome: Path) -> None:
    command_output(
        record,
        "/usr/bin/codesign",
        "--verify",
        "--deep",
        "--strict",
        "-R",
        CHROME_REQUIREMENT,
        str(chrome.parents[2]),
    )
    command_output(
        record,
        "/usr/sbin/spctl",
        "--assess",
        "--type",
        "execute",
        "--verbose=4",
        str(chrome.parents[2]),
    )
    architectures = command_output(record, "/usr/bin/lipo", "-archs", str(chrome))
    record["browser_architectures"] = architectures.split()
    if set(record["browser_architectures"]) != {"arm64", "x86_64"}:
        raise RuntimeError("Chrome download does not contain both native architectures")


def capture_profile(output: Path, chrome: Path, work: Path, record: dict) -> None:
    """Run independent existing tools once each; retain every cell's result."""
    record["cells"] = []
    operating_system = " ".join(record["os"].split()) + " " + record["architecture"]
    for name in ("snapshot", "h1", "h2", "h3"):
        cell = output / name
        cell.mkdir()
        capture = {
            "tool": "snapshot" if name == "snapshot" else "http_lifecycle",
            "browsers": ["chrome"],
            "output_dir": str(cell / "fixtures"),
            "args": ["--headful"],
            "timeout": 180,
        }
        if name == "snapshot":
            capture["args"].extend(["--run-timeout", "60"])
        else:
            capture["scenarios"] = ["resources"]
            capture["args"].extend(["--resource-protocol", name])
        manifest = cell / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "operating_system": operating_system,
                    "repeat": 1,
                    "browsers": {
                        "chrome": {"path": str(chrome), "version": PROFILE_VERSION}
                    },
                    "captures": [capture],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        results = cell / "results.json"
        args = [
            str(manifest),
            "--jobs",
            "1",
            "--retries",
            "0",
            "--work-dir",
            str(work / name),
            "--results",
            str(results),
        ]
        receipt = {
            "name": name,
            "entry_point": "scripts.capture.run_matrix.main",
            "argv": args,
            "exit": None,
        }
        record["cells"].append(receipt)
        try:
            with (
                (cell / "stdout.log").open("w", encoding="utf-8") as stdout,
                (cell / "stderr.log").open("w", encoding="utf-8") as stderr,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                receipt["exit"] = run_matrix.main(args)
        finally:
            # Preserve short-path attempt logs even when no result was written.
            for kind in ("logs", "completed"):
                retained = work / name / kind
                if retained.is_dir():
                    shutil.copytree(retained, cell / kind)
        if receipt["exit"] == 130:
            raise KeyboardInterrupt("profile capture interrupted")
        if results.is_file():
            document = json.loads(results.read_text(encoding="utf-8"))
            jobs = document.get("jobs", [])
            receipt["complete"] = (
                document.get("concurrency") == 1
                and document.get("interrupted") is False
                and len(jobs) == 1
                and jobs[0].get("status") == "ok"
                and len(jobs[0].get("attempts", [])) == 1
                and jobs[0]["attempts"][0].get("ok") is True
                and (
                    cell
                    / "fixtures"
                    / ("snapshot-1.txt" if name == "snapshot" else "resources.txt")
                ).is_file()
            )
        else:
            receipt["complete"] = False
    record["capture_exit"] = int(
        any(cell["exit"] != 0 or not cell["complete"] for cell in record["cells"])
    )


def source_hashes(record):
    names = command_output(record, "git", "ls-files", "-z", "scripts/capture").split(
        "\0"
    )
    names = [name for name in names if name.endswith(".py")]
    names.extend(
        [".github/workflows/macos-headful-capture.yml", "scripts/requirements.txt"]
    )
    return {name: file_digest(Path(name)) for name in sorted(names)}


def capture_sse(output: Path, chrome: Path, version: str, record: dict) -> None:
    args = [
        sys.executable,
        "-m",
        "scripts.capture.sse_reconnect",
        "--browser",
        "chrome",
        "--browser-path",
        str(chrome),
        "--headful",
        "--protocol",
        "h1",
        "--scenario",
        "reconnect-204",
        "--repeat",
        "1",
        "--run-timeout",
        "120",
        "--listen",
        "127.0.0.1:0",
        "--client",
        "chrome",
        "--client-version",
        version,
        "--operating-system",
        " ".join(record["os"].split()) + " " + platform.machine(),
        "--output-dir",
        str(output / "fixtures"),
    ]
    record["phase"] = "capture"
    record["capture_argv"] = args
    record["capture_started"] = True
    with (
        (output / "capture.stdout.log").open("wb") as stdout,
        (output / "capture.stderr.log").open("wb") as stderr,
    ):
        record["capture_exit"] = subprocess.run(
            args, stdout=stdout, stderr=stderr
        ).returncode
    record["phase"] = "fixture"
    fixture = output / "fixtures/reconnect-204.txt"
    record["fixture_present"] = fixture.is_file()
    if fixture.is_file():
        record["fixture_sha256"] = file_digest(fixture)
        fields = dict(
            line.split("=", 1)
            for line in fixture.read_text(encoding="utf-8").splitlines()
        )
        if (
            fields["launch_mode"] != "headful"
            or fields["repeat_count"] != "1"
            or fields["run_0_terminated_ms"] == "none"
        ):
            raise RuntimeError("fixture lacks the selected headed terminal observation")
        attempts, agents, page_count = [], [], 0
        for index in range(int(fields["run_0_request_count"])):
            key = f"run_0_request_{index}"
            request = dict(item.split(":", 1) for item in fields[key].split(","))
            page_count += request["kind"] == "page"
            if request["kind"] == "sse":
                attempts.append((request["attempt"], request["extra"]))
            for header in range(int(fields[f"{key}_header_count"])):
                name, _, value = bytes.fromhex(
                    fields[f"{key}_header_{header}"]
                ).partition(b":")
                if name.lower() == b"user-agent":
                    agents.append(value.hex())
        record["observed_user_agent_values_hex"] = agents
        if attempts != [("0", "false"), ("1", "false")] or not page_count or not agents:
            raise RuntimeError(
                "fixture lacks the real page, two SSE attempts or User-Agent bytes"
            )


def run_capture(
    output=Path("target/macos-headful-capture"),
    chrome=Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    *,
    mode="sse",
):
    if mode not in {"sse", "profile"}:
        raise ValueError("capture mode must be sse or profile")
    if mode == "profile":
        output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {
        "status": "failed",
        "capture_exit": None,
        "capture_started": False,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "runner_label": os.environ["CAPTURE_RUNNER_LABEL"],
        "architecture": platform.machine(),
        "python": sys.version,
        "image_os": os.environ.get("ImageOS"),  # noqa: SIM112 - runner key
        "image_version": os.environ.get("ImageVersion"),  # noqa: SIM112 - runner key
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "mode": mode,
        "launch_mode": "headful",
        "protocol": "h1",
        "scenario": "reconnect-204",
        "repeat": 1,
        "retries": 0,
        "run_timeout_seconds": 120,
        "metadata_commands": [],
    }

    try:
        with ExitStack() as stack:
            record["phase"] = "host_identity"
            if (
                sys.platform != "darwin"
                or platform.machine() != os.environ["CAPTURE_EXPECTED_ARCH"]
            ):
                raise RuntimeError(
                    "runner OS or architecture differs from the selected attempt"
                )
            record["phase"] = "source_identity"
            record["source_head"] = command_output(record, "git", "rev-parse", "HEAD")
            if record["source_head"] != os.environ["GITHUB_SHA"]:
                raise RuntimeError("checkout does not match the dispatched source")
            if command_output(
                record, "git", "status", "--porcelain", "--untracked-files=all"
            ):
                raise RuntimeError("capture requires a clean source checkout")
            record["source_before"] = source_hashes(record)
            if mode == "profile":
                record["phase"] = "stage_browser"
                chrome, work = stack.enter_context(staged_chrome(output, record))
                verify_profile_browser(record, chrome)
                record["scenario"] = "profile"
                record["protocol"] = "h1,h2,h3"
                del record["run_timeout_seconds"]
                record["cell_timeout_seconds"] = 180
            record["phase"] = "browser_identity"
            info = chrome.parents[1] / "Info.plist"
            record["os"] = command_output(record, "/usr/bin/sw_vers")
            with info.open("rb") as stream:
                installed = plistlib.load(stream)
            version = installed["CFBundleShortVersionString"]
            if mode == "profile" and (
                version != PROFILE_VERSION
                or installed.get("CFBundleIdentifier") != "com.google.Chrome"
            ):
                raise RuntimeError(
                    "profile capture requires ordinary Google Chrome " + PROFILE_VERSION
                )
            record["browser_version"] = version
            record["browser_build"] = installed["CFBundleVersion"]
            record["chrome_launcher_path"] = str(chrome)
            record["chrome_launcher_sha256"] = file_digest(chrome)
            record["chrome_info_sha256"] = file_digest(info)
            record["browser_version_output"] = command_output(
                record, str(chrome), "--version"
            )
            if (
                not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version)
                or record["browser_version_output"] != f"Google Chrome {version}"
            ):
                raise RuntimeError("installed browser version witnesses disagree")
            if mode == "profile":
                record["phase"] = "capture"
                record["capture_started"] = True
                capture_profile(output, chrome, work, record)
                record["fixture_present"] = all(
                    cell["complete"] for cell in record["cells"]
                )
            else:
                capture_sse(output, chrome, version, record)
            record["phase"] = "unchanged_inputs"
            record["source_after"] = source_hashes(record)
            record["source_head_after"] = command_output(
                record, "git", "rev-parse", "HEAD"
            )
            record["chrome_launcher_sha256_after"] = file_digest(chrome)
            record["chrome_info_sha256_after"] = file_digest(info)
            if (
                record["source_before"] != record["source_after"]
                or record["source_head"] != record["source_head_after"]
                or record["chrome_launcher_sha256_after"]
                != record["chrome_launcher_sha256"]
                or record["chrome_info_sha256_after"] != record["chrome_info_sha256"]
            ):
                raise RuntimeError(
                    "capture source or installed browser changed during the attempt"
                )
            if mode == "profile":
                verify_profile_browser(record, chrome)
            record["phase"] = "capture_result"
            if record["capture_exit"] != 0 or not record["fixture_present"]:
                raise RuntimeError(
                    "capture command failed or emitted no fixture; inspect both logs"
                )
            record["status"] = "success"
            record["phase"] = "complete"
    except BaseException as error:
        record["status"] = "failed"
        record["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
            "phase": record["phase"],
        }
        raise
    finally:
        record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        if mode == "profile":
            record["output_hashes"] = {
                path.relative_to(output).as_posix(): file_digest(path)
                for path in sorted(output.rglob("*"))
                if path.is_file()
            }
        (output / "provenance.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    run_capture(mode=os.environ.get("CAPTURE_MODE", "sse"))
