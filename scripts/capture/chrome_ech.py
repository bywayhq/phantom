"""Record a Chromium browser's ClientHellos when an HTTPS record carries ECH.

Chrome reads HTTPS records from its own DNS client or from DNS over HTTPS;
`--host-resolver-rules` cannot produce one. This tool therefore points the
browser at the loopback DNS-over-HTTPS server that the
`capture_ech_client_hello` example runs. It writes the `dns_over_https.mode`
and `dns_over_https.templates` preferences into the `Local State` file of the
run's disposable user-data directory, the same preferences the Secure DNS
setting writes, so no setting outside that directory changes. Chrome ignores
these preferences on a managed or parental-controlled Windows host.

Opera 136 overrides Chromium's two preferences at startup with its own, so for
`--browser opera` the file also sets `dns_over_https.opera.doh_mode` to
`custom` and `dns_over_https.opera.custom_servers` to the template.

Edge 153 sent no DNS-over-HTTPS query with those preferences. With
`--dns-from-policy` the tool writes no preferences; the browser must already
have the `DnsOverHttpsMode` and `DnsOverHttpsTemplates` machine policies,
which the tool reads with `reg query` and checks before it launches anything.
The policy names a fixed template, so the server listens on `--doh-port`.

With `--quic`, the HTTPS record lists `h3` and `h2`, the origin also serves
HTTP/3 from a BoringSSL QUIC server that decrypts ECH, and the browser runs
with QUIC enabled. Chromium's QUIC client accepts a certificate from an
unknown root only for a host named in `--origin-to-force-quic-on`, so the
origin's host is named there with a decoy port that is never requested, and
the certificate's public key is trusted through
`--ignore-certificate-errors-spki-list`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO

from .browser_launch import DESKTOP_CHROMIUM_BROWSERS, LaunchedBrowser, LaunchPlan
from .fixture_file import write_text_fixture
from .process_container import ProcessCleanupError, ProcessContainer

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
# Never requested: naming the origin's host here lets QUIC accept its
# certificate (`ProofVerifierChromium::Job::ShouldAllowUnknownRootForHost`)
# without forcing the origin itself onto QUIC, which would skip the HTTPS
# record's `alpn` (`HttpStreamFactory::JobController::DoCreateJobs`).
DECOY_FORCE_QUIC_PORT = 9
SPKI_PLACEHOLDER = "<certificate-spki>"
POLICY_KEYS = {"edge": r"HKLM\SOFTWARE\Policies\Microsoft\Edge"}
POLICY_DNS_CONFIGURATION = (
    "policy {key} DnsOverHttpsMode=secure DnsOverHttpsTemplates=<doh_template>"
)
READY_PREFIX = "ready doh_template="
# Opera's own Secure DNS preferences beside Chromium's, which Opera overrides
# with them at startup (`dns_over_https_prefs_observer.cc` in opera_browser.dll).
OPERA_DNS_SETTINGS = {"enabled_version": 1, "doh_mode": "custom"}
OPERA_DNS_CONFIGURATION = (
    " dns_over_https.opera.enabled_version=1 dns_over_https.opera.doh_mode=custom"
    " dns_over_https.opera.custom_servers=<doh_template>"
)
CAPTURE_TIMEOUT_SECONDS = 180
MAX_CAPTURE_OUTPUT = 16 * 1024 * 1024
MAX_CAPTURE_DIAGNOSTICS = 1024 * 1024
MAX_DIAGNOSTIC_LINE = 16 * 1024
POLL_SECONDS = 0.02
POLICY_TIMEOUT_SECONDS = 5


def local_state(template: str, browser: str = "chrome") -> str:
    """A `Local State` file that sends every lookup to `template`."""
    settings: dict[str, object] = {"mode": "secure", "templates": template}
    if browser == "opera":
        settings["opera"] = dict(OPERA_DNS_SETTINGS, custom_servers=template)
    return json.dumps({"dns_over_https": settings})


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
        timeout=POLICY_TIMEOUT_SECONDS,
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


def parse_ready_line(line: str) -> tuple[str, str, str | None] | None:
    """Return the DoH template, origin, and certificate SPKI hash, if any,
    from the example's ready line."""
    if not line.startswith(READY_PREFIX):
        return None
    template, separator, rest = line[len(READY_PREFIX) :].strip().partition(" origin=")
    origin, spki_separator, spki = rest.partition(" spki=")
    if not separator or not template.startswith("https://127.") or not origin:
        return None
    if spki_separator and not re.fullmatch(r"[A-Za-z0-9+/]{43}=", spki):
        return None
    return template, origin, spki if spki_separator else None


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
    quic: bool = False


def quic_arguments(spki: str) -> tuple[str, ...]:
    """Chromium switches that let QUIC reach the loopback origin."""
    return (
        "--enable-quic",
        f"--origin-to-force-quic-on={HOSTNAME}:{DECOY_FORCE_QUIC_PORT}",
        f"--ignore-certificate-errors-spki-list={spki}",
    )


def launch_plan(run: CaptureRun, spki: str = SPKI_PLACEHOLDER) -> LaunchPlan:
    """The browser launch; with QUIC, `spki` trusts the origin's key."""
    return LaunchPlan(
        browser=run.browser,
        executable=run.browser_path,
        headless=run.headless,
        extra_arguments=quic_arguments(spki) if run.quic else EXTRA_ARGUMENTS,
    )


def capture_arguments(run: CaptureRun, plan: LaunchPlan) -> list[str]:
    """Arguments for the `capture_ech_client_hello` example."""
    port = [] if run.doh_port is None else ["--doh-port", str(run.doh_port)]
    quic = ["--quic"] if run.quic else []
    if run.dns_from_policy:
        dns_configuration = POLICY_DNS_CONFIGURATION.format(
            key=POLICY_KEYS[run.browser]
        )
    elif run.browser == "opera":
        dns_configuration = DNS_CONFIGURATION + OPERA_DNS_CONFIGURATION
    else:
        dns_configuration = DNS_CONFIGURATION
    return [
        str(run.capture_binary),
        *port,
        *quic,
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
    command = capture_arguments(run, plan)
    deadline = time.monotonic() + CAPTURE_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="phantom-ech-output-") as directory:
        output_path = Path(directory) / "fixture"
        diagnostics_path = Path(directory) / "diagnostics"
        # Readers need separate open descriptions: seeking a descriptor shared
        # with the child would change the child's next write position.
        with (
            output_path.open("wb") as output,
            diagnostics_path.open("wb") as diagnostics,
            output_path.open("rb") as output_reader,
            diagnostics_path.open("rb") as diagnostics_reader,
        ):
            process = ProcessContainer(command, stdout=output, stderr=diagnostics)
            observer = _CaptureOutput(output_reader, diagnostics_reader, report)
            try:
                if not process.start():
                    raise RuntimeError("the capture server stopped before launch")
                while observer.ready is None:
                    code = process.poll()
                    observer.poll(final=code is not None)
                    if observer.ready is not None:
                        break
                    if code is not None:
                        raise RuntimeError(
                            "the capture server exited before it was ready"
                        )
                    _wait_for_capture(deadline, command)

                template, _origin, spki = observer.ready
                if run.doh_port is not None and template != doh_template(
                    run.origin, run.doh_port
                ):
                    raise RuntimeError(f"the capture server listens on {template}")
                if run.quic != (spki is not None):
                    raise RuntimeError(
                        "the capture server's QUIC mode does not match the run"
                    )
                if spki is not None:
                    plan = launch_plan(run, spki)
                configured = (
                    plan
                    if run.dns_from_policy
                    else replace(
                        plan,
                        profile_files=(
                            (LOCAL_STATE, local_state(template, run.browser)),
                        ),
                    )
                )
                _check_capture_deadline(deadline, command)
                with LaunchedBrowser(configured, URL):
                    while True:
                        _check_capture_deadline(deadline, command)
                        code = process.poll()
                        observer.poll()
                        if code is not None:
                            break
                        _wait_for_capture(deadline, command)
                if code != 0:
                    raise RuntimeError(f"capture server failed with exit code {code}")
            except BaseException as primary:
                try:
                    process.close()
                except BaseException as cleanup:
                    raise primary from ProcessCleanupError(
                        (("close ECH capture server", cleanup),),
                        container=process,
                        primary=primary,
                    )
                raise
            else:
                # Stop descendants before the final read. Inherited output
                # handles cannot keep a reader waiting for pipe EOF.
                process.close()
                observer.poll(final=True)
                fixture = output_reader.read(MAX_CAPTURE_OUTPUT + 1)
                if len(fixture) > MAX_CAPTURE_OUTPUT:
                    raise ValueError("ECH fixture exceeds the capture output limit")
                return fixture.decode("ascii")


def _check_capture_deadline(deadline: float, command: Sequence[str]) -> None:
    if time.monotonic() >= deadline:
        raise subprocess.TimeoutExpired(command, CAPTURE_TIMEOUT_SECONDS)


def _wait_for_capture(deadline: float, command: Sequence[str]) -> None:
    _check_capture_deadline(deadline, command)
    time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))


class _CaptureOutput:
    """Read finite output snapshots without background reader tasks."""

    def __init__(
        self,
        output: BinaryIO,
        diagnostics: BinaryIO,
        report: Callable[[str], None],
    ) -> None:
        self.output = output
        self.diagnostics = diagnostics
        self.report = report
        self.ready: tuple[str, str, str | None] | None = None
        self.pending = bytearray()
        self.diagnostic_bytes = 0

    def poll(self, *, final: bool = False) -> None:
        self.output.seek(0, 2)
        if self.output.tell() > MAX_CAPTURE_OUTPUT:
            raise ValueError("ECH fixture exceeds the capture output limit")
        self.output.seek(0)
        while True:
            chunk = self.diagnostics.read(4096)
            if not chunk:
                break
            self.diagnostic_bytes += len(chunk)
            if self.diagnostic_bytes > MAX_CAPTURE_DIAGNOSTICS:
                raise ValueError("ECH diagnostics exceed the capture output limit")
            self.pending.extend(chunk)
            while b"\n" in self.pending:
                line, _, remainder = self.pending.partition(b"\n")
                self.pending = bytearray(remainder)
                self._line(line)
            if len(self.pending) > MAX_DIAGNOSTIC_LINE:
                raise ValueError("ECH diagnostic line exceeds the capture limit")
        if final and self.pending:
            self._line(bytes(self.pending))
            self.pending.clear()

    def _line(self, line: bytes) -> None:
        if len(line) > MAX_DIAGNOSTIC_LINE:
            raise ValueError("ECH diagnostic line exceeds the capture limit")
        text = line.decode("ascii").rstrip()
        ready = parse_ready_line(text) if self.ready is None else None
        if ready is not None:
            self.ready = ready
        else:
            self.report(text)


def port_number(text: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{text} is not a TCP port")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # The DoH preferences go into a desktop profile's `Local State` file.
    parser.add_argument("--browser", choices=DESKTOP_CHROMIUM_BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", required=True)
    parser.add_argument("--scenario", choices=("accept", "reject"), required=True)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--capture-binary", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--doh-port", type=port_number)
    parser.add_argument("--dns-from-policy", action="store_true")
    parser.add_argument("--quic", action="store_true")
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
            quic=arguments.quic,
        )
    )
    write_text_fixture(arguments.output, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
