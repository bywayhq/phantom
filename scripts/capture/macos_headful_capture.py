"""Run the headed Chrome SSE attempt used by the macOS capture workflow."""

import json
import os
import platform
import plistlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.capture.capture_report import command_output, file_digest


def source_hashes(record):
    names = command_output(record, "git", "ls-files", "-z", "scripts/capture").split(
        "\0"
    )
    names = [name for name in names if name.endswith(".py")]
    names.extend(
        [".github/workflows/macos-headful-capture.yml", "scripts/requirements.txt"]
    )
    return {name: file_digest(Path(name)) for name in sorted(names)}


def run_capture(
    output=Path("target/macos-headful-capture"),
    chrome=Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
):
    output.mkdir(parents=True, exist_ok=False)
    info = chrome.parents[1] / "Info.plist"
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
        "launch_mode": "headful",
        "protocol": "h1",
        "scenario": "reconnect-204",
        "repeat": 1,
        "retries": 0,
        "run_timeout_seconds": 120,
        "metadata_commands": [],
    }

    try:
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
        record["phase"] = "browser_identity"
        record["os"] = command_output(record, "/usr/bin/sw_vers")
        with info.open("rb") as stream:
            installed = plistlib.load(stream)
        version = installed["CFBundleShortVersionString"]
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
                raise RuntimeError(
                    "fixture lacks the selected headed terminal observation"
                )
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
            if (
                attempts != [("0", "false"), ("1", "false")]
                or not page_count
                or not agents
            ):
                raise RuntimeError(
                    "fixture lacks the real page, two SSE attempts or User-Agent bytes"
                )
        record["phase"] = "unchanged_inputs"
        record["source_after"] = source_hashes(record)
        record["source_head_after"] = command_output(record, "git", "rev-parse", "HEAD")
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
        record["phase"] = "capture_result"
        if record["capture_exit"] != 0 or not record["fixture_present"]:
            raise RuntimeError(
                "capture command failed or emitted no fixture; inspect both logs"
            )
        record["status"] = "success"
        record["phase"] = "complete"
    except BaseException as error:
        record["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
            "phase": record["phase"],
        }
        raise
    finally:
        record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "provenance.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    run_capture()
