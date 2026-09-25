"""Record a Chromium browser's ClientHellos when an HTTPS record carries ECH.

Chrome reads HTTPS records from its own DNS client or from DNS over HTTPS;
`--host-resolver-rules` cannot produce one. This tool therefore points the
browser at the loopback DNS-over-HTTPS server that the
`capture_ech_client_hello` example runs. It writes the `dns_over_https.mode`
and `dns_over_https.templates` preferences into the `Local State` file of the
run's disposable user-data directory, the same preferences the Secure DNS
setting writes, so no setting outside that directory changes. Chrome ignores
these preferences on a managed or parental-controlled Windows host.

Edge 153 sent no DNS-over-HTTPS query with those preferences. With
`--dns-from-policy` the tool writes no preferences; the browser must already
have the `DnsOverHttpsMode` and `DnsOverHttpsTemplates` machine policies,
which the tool reads with `reg query` and checks before it launches anything.
The policy names a fixed template, so the server listens on `--doh-port`.
"""

from __future__ import annotations

import argparse
import json
import re
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
POLICY_KEYS = {"edge": r"HKLM\SOFTWARE\Policies\Microsoft\Edge"}
POLICY_DNS_CONFIGURATION = (
    "policy {key} DnsOverHttpsMode=secure DnsOverHttpsTemplates=<doh_template>"
)
READY_PREFIX = "ready doh_template="
CAPTURE_TIMEOUT_SECONDS = 180


def local_state(template: str) -> str:
    """A `Local State` file that sends every lookup to `template`."""
    return json.dumps({"dns_over_https": {"mode": "secure", "templates": template}})


def doh_template(origin: str, port: int) -> str:
    """The template the capture server listens on for `origin` and `port`."""
    host, _separator, _origin_port = origin.rpartition(":")
    return f"https://{host}:{port}/dns-query"


def parse_reg_query(output: str) -> dict[str, str]:
    """Return the `REG_SZ` values that `reg query <key>` lists."""
    values = {}
    for line in output.splitlines():
        match = re.fullmatch(r"\s+(\S+)\s+REG_SZ(?:\s+(.*))?", line.rstrip())
        if match:
            values[match.group(1)] = match.group(2) or ""
    return values


def read_policy(
    key: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    """Read, never write, the policy values under `key` from the 64-bit view."""
    result = run(
        ["reg", "query", key, "/reg:64"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return {}
    return parse_reg_query(result.stdout)


def policy_problem(key: str, values: dict[str, str], template: str) -> str | None:
    """Explain why the policy under `key` would not send lookups to `template`."""
    expected = {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": template}
    wrong = [
        f"{name} is {values[name]!r}" if name in values else f"{name} is absent"
        for name, value in expected.items()
        if values.get(name) != value
    ]
    if not wrong:
        return None
    return (
        f"{key} does not send DNS to the capture server: {'; '.join(wrong)}. "
        f"Expected DnsOverHttpsMode=secure and DnsOverHttpsTemplates={template}"
    )


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
    doh_port: int | None = None
    dns_from_policy: bool = False


def launch_plan(run: CaptureRun) -> LaunchPlan:
    return LaunchPlan(
        browser=run.browser,
        executable=run.browser_path,
        headless=run.headless,
        extra_arguments=EXTRA_ARGUMENTS,
    )


def capture_arguments(run: CaptureRun, plan: LaunchPlan) -> list[str]:
    """Arguments for the `capture_ech_client_hello` example."""
    port = [] if run.doh_port is None else ["--doh-port", str(run.doh_port)]
    dns_configuration = (
        POLICY_DNS_CONFIGURATION.format(key=POLICY_KEYS[run.browser])
        if run.dns_from_policy
        else DNS_CONFIGURATION
    )
    return [
        str(run.capture_binary),
        *port,
        run.scenario,
        run.origin,
        plan.client_name,
        run.client_version,
        run.operating_system,
        dns_configuration,
        plan.launch_mode,
        plan.recorded_arguments(URL),
    ]


def check_policy(
    run: CaptureRun,
    read: Callable[[str], dict[str, str]] = read_policy,
) -> None:
    """Fail unless the browser's machine policy names this run's template."""
    if run.browser not in POLICY_KEYS:
        raise ValueError(f"--dns-from-policy is not supported for {run.browser}")
    if run.doh_port is None:
        raise ValueError("--dns-from-policy needs --doh-port")
    key = POLICY_KEYS[run.browser]
    problem = policy_problem(key, read(key), doh_template(run.origin, run.doh_port))
    if problem is not None:
        raise RuntimeError(problem)


def capture(
    run: CaptureRun,
    report: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
) -> str:
    """Run one capture and return the fixture text."""
    if run.dns_from_policy:
        check_policy(run)
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
        if run.doh_port is not None and template != doh_template(
            run.origin, run.doh_port
        ):
            raise RuntimeError(f"the capture server listens on {template}")
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
        configured = (
            plan
            if run.dns_from_policy
            else replace(plan, profile_files=((LOCAL_STATE, local_state(template)),))
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


def port_number(text: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{text} is not a TCP port")
    return port


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
    parser.add_argument("--doh-port", type=port_number)
    parser.add_argument("--dns-from-policy", action="store_true")
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
            doh_port=arguments.doh_port,
            dns_from_policy=arguments.dns_from_policy,
        )
    )
    write_text_fixture(arguments.output, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
