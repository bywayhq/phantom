"""Record browser ClientHellos when an HTTPS record carries ECH.

Firefox uses explicit TRR-only profile preferences and a supplied NSS cert9.db
for normal certificate verification. Its captures use TCP.

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
import codecs
import hashlib
import io
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

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
MAX_IDENTITY_BYTES = 128 * 1024
MAX_CERT9_BYTES = 4 * 1024 * 1024
RESUMPTION_SEQUENCES = ("early-accept", "early-reject", "ech-retry")
FIREFOX_DNS_CONFIGURATION = (
    "user.js network.trr.mode=3 network.trr.uri=<doh_template> "
    "network.trr.allow-rfc1918=true network.http.http3.enable=false"
)


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
    if not separator:
        return None
    try:
        parsed = urlsplit(template)
        host, _, port = origin.rpartition(":")
        if (
            parsed.scheme != "https"
            or (
                parsed.hostname is None
                or not ipaddress.ip_address(parsed.hostname).is_loopback
            )
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/dns-query"
            or parsed.query
            or parsed.fragment
            or parsed.port is None
            or not 1 <= parsed.port <= 65535
            or not ipaddress.ip_address(host).is_loopback
            or not 1 <= int(port) <= 65535
        ):
            return None
    except ValueError:
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
    certificate: Path | None = None
    private_key: Path | None = None
    certificate_sha256: str | None = None
    cert9_db: Path | None = None
    cert9_sha256: str | None = None
    resumption: str | None = None


def quic_arguments(spki: str) -> tuple[str, ...]:
    """Chromium switches that let QUIC reach the loopback origin."""
    return (
        "--enable-quic",
        f"--origin-to-force-quic-on={HOSTNAME}:{DECOY_FORCE_QUIC_PORT}",
        f"--ignore-certificate-errors-spki-list={spki}",
    )


def origin_url(origin: str) -> str:
    host, separator, port = origin.rpartition(":")
    if (
        not separator
        or host != "127.0.0.1"
        or not port.isdecimal()
        or not 0 <= int(port) <= 65535
    ):
        raise ValueError("Firefox ECH origin must be 127.0.0.1:<port>")
    suffix = "" if int(port) == 443 else f":{port if int(port) else '<origin-port>'}"
    return f"https://{HOSTNAME}{suffix}/"


def capture_url(run: CaptureRun, origin: str) -> str:
    url = origin_url(origin)
    return url + "seed" if run.resumption is not None else url


def checked_input(path: Path, limit: int, digest: str | None = None) -> bytes:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("ECH identity input exceeds its size limit")
    if digest is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("ECH input SHA-256 must contain 64 hex digits")
        if hashlib.sha256(data).hexdigest() != digest.lower():
            raise ValueError("ECH input SHA-256 mismatch")
    return data


def capture_inputs(run: CaptureRun) -> tuple[bytes, bytes, bytes] | None:
    if run.resumption is not None and (
        run.resumption not in RESUMPTION_SEQUENCES
        or run.browser != "firefox"
        or run.quic
        or run.scenario != "accept"
    ):
        raise ValueError("ECH resumption requires Firefox TCP with --scenario accept")
    if run.browser != "firefox":
        if any(
            (
                run.certificate,
                run.private_key,
                run.certificate_sha256,
                run.cert9_db,
                run.cert9_sha256,
            )
        ):
            raise ValueError("PEM and NSS inputs require --browser firefox")
        return None
    origin_url(run.origin)
    if run.quic or run.dns_from_policy:
        raise ValueError("Firefox ECH capture supports TCP and profile DoH only")
    if not all(
        (
            run.certificate,
            run.private_key,
            run.certificate_sha256,
            run.cert9_db,
            run.cert9_sha256,
        )
    ):
        raise ValueError(
            "Firefox ECH capture requires PEM identity and hash-bound NSS inputs"
        )
    assert (
        run.certificate is not None
        and run.private_key is not None
        and run.cert9_db is not None
    )
    certificate = checked_input(
        run.certificate, MAX_IDENTITY_BYTES, run.certificate_sha256
    )
    key = checked_input(run.private_key, MAX_IDENTITY_BYTES)
    if any(
        marker in key
        for marker in (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            b"Proc-Type: 4,ENCRYPTED",
        )
    ):
        raise ValueError("ECH private key must be unencrypted PEM")
    database = checked_input(run.cert9_db, MAX_CERT9_BYTES, run.cert9_sha256)
    if not database.startswith(b"SQLite format 3\x00"):
        raise ValueError("cert9.db must be an NSS SQL database")
    return certificate, key, database


class _TrustedFirefox(LaunchedBrowser):
    def __init__(self, plan: LaunchPlan, url: str, database: bytes) -> None:
        super().__init__(plan, url)
        self.database = database

    def _start(self, profile: Path) -> subprocess.Popen[bytes] | ProcessContainer:
        (profile / "cert9.db").write_bytes(self.database)
        return super()._start(profile)


def launch_plan(
    run: CaptureRun, spki: str = SPKI_PLACEHOLDER, *, template: str = "<doh_template>"
) -> LaunchPlan:
    """The browser launch; with QUIC, `spki` trusts the origin's key."""
    if run.browser == "firefox":
        return LaunchPlan(
            browser="firefox",
            executable=run.browser_path,
            headless=run.headless,
            firefox_preferences=(
                ("network.trr.mode", 3),
                ("network.trr.uri", template),
                ("network.trr.allow-rfc1918", True),
                ("network.http.http3.enable", False),
            ),
        )
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
    if run.browser == "firefox":
        dns_configuration = FIREFOX_DNS_CONFIGURATION
    elif run.dns_from_policy:
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
        *(
            ["--identity", str(run.certificate), str(run.private_key)]
            if run.browser == "firefox"
            else []
        ),
        *(["--resumption", run.resumption] if run.resumption is not None else []),
        run.scenario,
        run.origin,
        plan.client_name,
        run.client_version,
        run.operating_system,
        dns_configuration,
        plan.launch_mode,
        plan.recorded_arguments(
            capture_url(run, run.origin) if run.browser == "firefox" else URL
        ),
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
    inputs = capture_inputs(run)
    if run.dns_from_policy:
        check_policy(run)
    plan = launch_plan(run)
    deadline = time.monotonic() + CAPTURE_TIMEOUT_SECONDS
    with _output_directory() as directory:
        if inputs is not None:
            certificate, key, _database = inputs
            staged_certificate = directory / "certificate.pem"
            staged_key = directory / "key.pem"
            staged_certificate.write_bytes(certificate)
            staged_key.write_bytes(key)
            run = replace(run, certificate=staged_certificate, private_key=staged_key)
        command = capture_arguments(run, plan)
        output_path = directory / "fixture"
        diagnostics_path = directory / "diagnostics"
        # Readers need separate open descriptions: seeking a descriptor shared
        # with the child would change the child's next write position.
        with (
            output_path.open("wb") as output,
            diagnostics_path.open("wb") as diagnostics,
            output_path.open("rb") as output_reader,
            diagnostics_path.open("rb") as diagnostics_reader,
        ):
            process = ProcessContainer(command, stdout=output, stderr=diagnostics)
            try:
                observer = _CaptureOutput(output_reader, diagnostics_reader, report)
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

                template, actual_origin, spki = observer.ready
                if run.browser == "firefox":
                    requested_port = int(run.origin.rsplit(":", 1)[1])
                    actual_port = int(actual_origin.rsplit(":", 1)[1])
                    if actual_origin.rsplit(":", 1)[0] != "127.0.0.1" or (
                        requested_port and requested_port != actual_port
                    ):
                        raise RuntimeError(
                            "the capture server origin does not match the run"
                        )
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
                if inputs is not None:
                    if urlsplit(template).hostname != "127.0.0.1":
                        raise RuntimeError("Firefox DoH listener must use 127.0.0.1")
                    configured = launch_plan(run, template=template)
                elif run.dns_from_policy:
                    configured = plan
                else:
                    configured = replace(
                        plan,
                        profile_files=(
                            (LOCAL_STATE, local_state(template, run.browser)),
                        ),
                    )
                _check_capture_deadline(deadline, command)
                browser = (
                    _TrustedFirefox(
                        configured, capture_url(run, actual_origin), inputs[2]
                    )
                    if inputs is not None
                    else LaunchedBrowser(configured, URL)
                )
                with browser:
                    while True:
                        _check_capture_deadline(deadline, command)
                        code = process.poll()
                        observer.poll()
                        if code is not None:
                            if code != 0:
                                raise RuntimeError(
                                    f"capture server failed with exit code {code}"
                                )
                            break
                        _wait_for_capture(deadline, command)
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
                with io.TextIOWrapper(io.BytesIO(fixture), encoding="ascii") as text:
                    result = text.read()
                if inputs is not None:
                    result += f"cert9_sha256={run.cert9_sha256.lower()}\n"
                    result += (
                        f"certificate_pem_sha256={run.certificate_sha256.lower()}\n"
                    )
                if len(result) > MAX_CAPTURE_OUTPUT:
                    raise ValueError("ECH fixture exceeds the capture output limit")
                return result


@contextmanager
def _output_directory() -> Iterator[Path]:
    directory = tempfile.TemporaryDirectory(prefix="phantom-ech-output-")
    primary = None
    try:
        yield Path(directory.name)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            directory.cleanup()
        except BaseException as cleanup:
            failure = ProcessCleanupError(
                (("remove ECH output directory", cleanup),), primary=primary
            )
            # Failed process cleanup may retain inherited Windows file handles.
            # Keep the directory owner and previous cause for explicit retry.
            failure.output_directory = directory
            if primary is not None:
                raise primary from failure
            raise failure from cleanup


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
        self.pending = ""
        self.decoder = io.IncrementalNewlineDecoder(
            codecs.getincrementaldecoder("ascii")(), translate=True
        )
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
            self.pending += self.decoder.decode(chunk)
            while "\n" in self.pending:
                line, _, self.pending = self.pending.partition("\n")
                self._line(line)
            if len(self.pending) > MAX_DIAGNOSTIC_LINE:
                raise ValueError("ECH diagnostic line exceeds the capture limit")
        if final:
            self.pending += self.decoder.decode(b"", final=True)
            while "\n" in self.pending:
                line, _, self.pending = self.pending.partition("\n")
                self._line(line)
            if self.pending:
                self._line(self.pending)
                self.pending = ""

    def _line(self, line: str) -> None:
        if len(line) > MAX_DIAGNOSTIC_LINE:
            raise ValueError("ECH diagnostic line exceeds the capture limit")
        text = line.rstrip()
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
    parser.add_argument(
        "--browser", choices=(*DESKTOP_CHROMIUM_BROWSERS, "firefox"), required=True
    )
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
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--certificate-sha256")
    parser.add_argument("--cert9-db", type=Path)
    parser.add_argument("--cert9-sha256")
    parser.add_argument("--resumption", choices=RESUMPTION_SEQUENCES)
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
            certificate=arguments.certificate,
            private_key=arguments.private_key,
            certificate_sha256=arguments.certificate_sha256,
            cert9_db=arguments.cert9_db,
            cert9_sha256=arguments.cert9_sha256,
            resumption=arguments.resumption,
        )
    )
    write_text_fixture(arguments.output, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
