"""Record a Chromium browser's ClientHellos when an HTTPS record carries ECH.

Chrome reads HTTPS records from its own DNS client or from DNS over HTTPS;
`--host-resolver-rules` cannot produce one. This tool therefore points the
browser at the loopback DNS-over-HTTPS server that the
`capture_ech_client_hello` example runs. It writes the `dns_over_https.mode`
and `dns_over_https.templates` preferences into the `Local State` file of the
run's disposable user-data directory, the same preferences the Secure DNS
setting writes, so no setting outside that directory changes. Chrome ignores
these preferences on a managed or parental-controlled Windows host.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from .browser_launch import CHROMIUM_BROWSERS, LaunchedBrowser, LaunchPlan
from .fixture_file import write_text_fixture

HOSTNAME = "server.phantom.test"
URL = f"https://{HOSTNAME}/"
DEFAULT_ORIGIN = "127.0.0.1:443"
LOCAL_STATE = "Local State"
DNS_CONFIGURATION = (
    "Local State dns_over_https.mode=secure dns_over_https.templates=<doh_template>"
)
# The origin's certificate is self-signed; QUIC stays off so every
# ClientHello arrives over TCP.
EXTRA_ARGUMENTS = ("--ignore-certificate-errors", "--disable-quic")
READY_PREFIX = "ready doh_template="
CAPTURE_TIMEOUT_SECONDS = 180


def local_state(template: str) -> str:
    """A `Local State` file that sends every lookup to `template`."""
    return json.dumps({"dns_over_https": {"mode": "secure", "templates": template}})


def parse_ready_line(line: str) -> tuple[str, str] | None:
    """Return the DoH template and origin from the example's ready line."""
    if not line.startswith(READY_PREFIX):
        return None
    template, separator, origin = (
        line[len(READY_PREFIX) :].strip().partition(" origin=")
    )
    if not separator or not template.startswith("https://127.") or not origin:
        return None
    return template, origin


@dataclass(frozen=True)
class CaptureRun:
    browser: str
    browser_path: Path
    client_version: str
    operating_system: str
    scenario: str
    origin: str
    capture_binary: Path
    headless: bool


def launch_plan(run: CaptureRun) -> LaunchPlan:
    return LaunchPlan(
        browser=run.browser,
        executable=run.browser_path,
        headless=run.headless,
        extra_arguments=EXTRA_ARGUMENTS,
    )


def capture_arguments(run: CaptureRun, plan: LaunchPlan) -> list[str]:
    """Arguments for the `capture_ech_client_hello` example."""
    return [
        str(run.capture_binary),
        run.scenario,
        run.origin,
        plan.client_name,
        run.client_version,
        run.operating_system,
        DNS_CONFIGURATION,
        plan.launch_mode,
        plan.recorded_arguments(URL),
    ]


def capture(
    run: CaptureRun,
    report: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
) -> str:
    """Run one capture and return the fixture text."""
    plan = launch_plan(run)
    process = subprocess.Popen(
        capture_arguments(run, plan),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="ascii",
    )
    try:
        assert process.stderr is not None
        ready = None
        for line in process.stderr:
            ready = parse_ready_line(line)
            if ready is not None:
                break
            report(line.rstrip())
        if ready is None:
            raise RuntimeError("the capture server exited before it was ready")
        template, _origin = ready
        threading.Thread(
            target=lambda: [report(line.rstrip()) for line in process.stderr or ()],
            daemon=True,
        ).start()
        chunks: list[str] = []
        reader = threading.Thread(
            target=lambda: chunks.append(
                process.stdout.read() if process.stdout else ""
            ),
            daemon=True,
        )
        reader.start()
        configured = replace(
            plan, profile_files=((LOCAL_STATE, local_state(template)),)
        )
        with LaunchedBrowser(configured, URL):
            process.wait(timeout=CAPTURE_TIMEOUT_SECONDS)
        reader.join(timeout=10)
        if process.returncode != 0:
            raise RuntimeError(
                f"capture server failed with exit code {process.returncode}"
            )
        return "".join(chunks)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--browser", choices=CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", required=True)
    parser.add_argument("--scenario", choices=("accept", "reject"), required=True)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--capture-binary", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    fixture = capture(
        CaptureRun(
            browser=arguments.browser,
            browser_path=arguments.browser_path,
            client_version=arguments.client_version,
            operating_system=arguments.operating_system,
            scenario=arguments.scenario,
            origin=arguments.origin,
            capture_binary=arguments.capture_binary,
            headless=not arguments.headful,
        )
    )
    write_text_fixture(arguments.output, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
