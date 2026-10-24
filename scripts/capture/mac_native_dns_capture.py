"""Capture a configured-native Firefox lookup using one scoped Mac resolver.

Run as your ordinary user after approving the reviewed guard's sudo invocation.
No global DNS settings or browser trust stores are changed. A successful result
requires resolver restoration and complete browser, origin and DNS cleanup.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
import secrets
import sys
from pathlib import Path

from .browser_failures import raise_browser_failures
from .browser_launch import FIREFOX_PREFERENCES, BrowserDriver, LaunchPlan
from .capture_report import file_digest as digest
from .mac_native_dns_guard import OWNER_SECONDS, resolver_name
from .native_dns import NativeDnsServer

ROOT = Path(__file__).resolve().parents[2]
GUARD = Path(__file__).with_name("mac_native_dns_guard.py")
SCUTIL = "/usr/sbin/scutil"
PYTHON = str(Path(sys.executable).resolve())
RUN_SECONDS = 45.0
REGISTRATION_SECONDS = 10.0
SOURCE_PATHS = (
    "scripts/capture/mac_native_dns_capture.py",
    "scripts/capture/mac_native_dns_guard.py",
    "scripts/capture/native_dns.py",
    "scripts/capture/browser_launch.py",
    "scripts/capture/browser_failures.py",
    "scripts/capture/process_container.py",
    "scripts/requirements.txt",
)


def resolver_blocks(text: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Keep resolver fields and sections; ignore display indices and block order."""
    section = ""
    fields: list[str] | None = None
    blocks = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("DNS configuration"):
            if fields is not None:
                blocks.append((section, tuple(fields)))
                fields = None
            section = line
        elif re.fullmatch(r"resolver #\d+", line):
            if fields is not None:
                blocks.append((section, tuple(fields)))
            fields = []
        elif line and fields is not None:
            fields.append(": ".join(part.strip() for part in line.split(":", 1)))
        elif line and not section:
            raise ValueError("scutil output has no DNS configuration section")
    if fields is not None:
        blocks.append((section, tuple(fields)))
    if not blocks:
        raise ValueError("scutil output has no resolver blocks")
    return tuple(sorted(blocks))


def owned_resolvers(text: str, domain: str) -> tuple:
    return tuple(
        block for block in resolver_blocks(text) if f"domain: {domain}" in block[1]
    )


def verify_dns(
    text: str, baseline: tuple, domain: str, port: int, *, installed: bool
) -> None:
    owned = owned_resolvers(text, domain)
    if installed:
        if len(owned) != 1:
            raise RuntimeError("scoped resolver is not registered exactly once")
        fields = owned[0][1]
        nameservers = [field for field in fields if field.startswith("nameserver[")]
        if nameservers != ["nameserver[0]: 127.0.0.1"] or f"port: {port}" not in fields:
            raise RuntimeError("scoped resolver address or port differs from the peer")
    elif owned:
        raise RuntimeError("scoped resolver remains registered after restoration")
    others = tuple(block for block in resolver_blocks(text) if block not in owned)
    if others != baseline:
        raise RuntimeError("pre-existing DNS configuration changed during capture")


async def dns_configuration() -> str:
    pending = asyncio.create_task(
        asyncio.create_subprocess_exec(
            SCUTIL,
            "--dns",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    )
    interrupted = None
    while not pending.done():
        try:
            await asyncio.shield(pending)
        except asyncio.CancelledError as error:
            interrupted = error
    process = pending.result()
    try:
        if interrupted is not None:
            raise interrupted

        async def read_bounded(stream: asyncio.StreamReader) -> bytes:
            output = bytearray()
            while chunk := await stream.read(65536):
                output.extend(chunk)
                if len(output) > 524288:
                    raise RuntimeError("scutil DNS output exceeds 512 KiB per stream")
            return bytes(output)

        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(read_bounded(process.stdout), read_bounded(process.stderr)),
            3.0,
        )
        await asyncio.wait_for(process.wait(), 1.0)
    except BaseException as primary:
        try:
            if process.returncode is None:
                process.kill()
            await asyncio.wait_for(process.wait(), 2.0)
        except BaseException as error:
            raise_browser_failures(primary, (error,))
        raise
    if process.returncode:
        raise RuntimeError(
            f"scutil DNS query failed: {stderr.decode('utf-8', 'replace')}"
        )
    return stdout.decode("utf-8", "strict")


async def wait_dns(baseline: tuple, domain: str, port: int, *, installed: bool) -> str:
    deadline = asyncio.get_running_loop().time() + REGISTRATION_SECONDS
    while True:
        text = await dns_configuration()
        try:
            verify_dns(text, baseline, domain, port, installed=installed)
        except RuntimeError:
            if asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(0.1)
        else:
            return text


class ResolverGuard:
    """One finite privileged owner; its stdin writer stays in this process only."""

    def __init__(self, nonce: str, port: int, record: dict) -> None:
        self.nonce = nonce
        self.port = port
        self.record = record
        self.process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        command = (
            "/usr/bin/sudo",
            "-n",
            "--",
            PYTHON,
            "-I",
            str(GUARD),
            "--nonce",
            self.nonce,
            "--port",
            str(self.port),
        )
        self.record["guard_command"] = list(command)
        pending = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                close_fds=True,
                limit=8192,
            )
        )
        interrupted = None
        while not pending.done():
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError as error:
                interrupted = error
        self.process = pending.result()
        if interrupted is not None:
            raise interrupted
        line = await asyncio.wait_for(self.process.stdout.readline(), 5.0)
        self.record["guard_installed_raw"] = line.decode("utf-8", "replace")
        installed = json.loads(line)
        self.record["guard_installed"] = installed
        if (
            installed.get("event") != "installed"
            or installed.get("domain") != resolver_name(self.nonce, self.port)
            or installed.get("port") != self.port
        ):
            raise RuntimeError(
                "resolver guard did not acknowledge the owned configuration"
            )

    async def close(self) -> None:
        if self.process is None:
            return
        try:
            self.process.stdin.write(b"STOP\n")
            await self.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # The finite owner may already have restored after EOF or a signal.
        finally:
            self.process.stdin.close()
        # Do not kill a privileged owner while it may still owe restoration.
        stdout, stderr = await asyncio.wait_for(
            self.process.communicate(), OWNER_SECONDS + 10.0
        )
        self.record["guard_final_raw"] = stdout.decode("utf-8", "replace")
        self.record["guard_stderr"] = stderr.decode("utf-8", "replace")
        self.record["guard_exit"] = self.process.returncode
        records = [json.loads(line) for line in stdout.splitlines()]
        final = records[-1] if records else {}
        self.record["guard_final"] = final
        if (
            self.process.returncode != 0
            or final.get("event") != "restored"
            or final.get("domain") != resolver_name(self.nonce, self.port)
            or final.get("cleanup") is not None
            or final.get("primary") is not None
        ):
            raise RuntimeError("resolver guard did not confirm successful restoration")


class Origin:
    """A small HTTP scene: navigation, fully consumed body, then token-bound done."""

    def __init__(self, domain: str, token: str) -> None:
        self.domain, self.token = domain, token
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.errors: list[BaseException] = []
        self.requests: list[str] = []
        self.done = asyncio.Event()
        self.body_drained = False
        self.accepted = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.accept, "127.0.0.1", 0, limit=65536, backlog=8
        )
        self.port = self.server.sockets[0].getsockname()[1]

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.accepted += 1
        self.writers.add(writer)
        if self.accepted > 64 or len(self.tasks) >= 8:
            self.errors.append(
                RuntimeError("native DNS origin connection limit exceeded")
            )
            writer.close()
            self.server.close()
            return
        task = asyncio.create_task(self.serve(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5.0)
            lines = head.decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ")
            host = f"host: {self.domain}:{self.port}"
            if (
                method != "GET"
                or version != "HTTP/1.1"
                or host not in [line.lower() for line in lines[1:]]
            ):
                raise ValueError("native DNS origin received an unexpected request")
            self.requests.append(target)
            status, content_type = "200 OK", "text/plain"
            if target == f"/start?token={self.token}":
                content_type = "text/html"
                body = (
                    "<!doctype html><script>"
                    f"fetch('/body?token={self.token}').then(r=>r.text()).then(text=>{{"
                    "if(text!=='ok\\n')throw new Error('body mismatch');"
                    f"return fetch('/done?token={self.token}');}});</script>"
                ).encode("ascii")
            elif target == f"/body?token={self.token}":
                body = b"ok\n"
            elif target == f"/done?token={self.token}":
                if not self.body_drained:
                    raise ValueError("native DNS completion preceded the measured body")
                body = b"done\n"
            else:
                status, body = "404 Not Found", b"not found\n"
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
                f"Content-Type: {content_type}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
                + body
            )
            await asyncio.wait_for(writer.drain(), 5.0)
            if target == f"/body?token={self.token}":
                self.body_drained = True
            if target == f"/done?token={self.token}":
                self.done.set()
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            self.errors.append(error)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 5.0)
            except BaseException as error:
                self.errors.append(error)
            else:
                self.writers.discard(writer)

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
        for writer in self.writers:
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 6.0)
        writers = tuple(self.writers)
        if writers:
            outcomes = await asyncio.wait_for(
                asyncio.gather(
                    *(writer.wait_closed() for writer in writers),
                    return_exceptions=True,
                ),
                5.0,
            )
            for writer, error in zip(writers, outcomes, strict=True):
                if isinstance(error, BaseException):
                    self.errors.append(error)
                else:
                    self.writers.discard(writer)
        if self.server is not None:
            await asyncio.wait_for(self.server.wait_closed(), 5.0)
        if self.errors:
            raise_browser_failures(None, tuple(self.errors))


def verify_retry(records: list[dict], domain: str) -> None:
    """Require one intentionally unanswered UDP A before a real sent A reply."""
    dropped = [
        index
        for index, item in enumerate(records)
        if item.get("disposition") == "dropped-first-udp-a"
    ]
    if len(dropped) == 1:
        index = dropped[0]
        first = records[index]
        if (
            first.get("name") == domain
            and first.get("kind") == 1
            and first.get("transport") == "udp"
            and first.get("error") is None
            and first.get("response_hex") is None
            and "response_queued_ns" not in first
            and "response_drained_ns" not in first
            and not any(
                item.get("name") == domain
                and item.get("kind") == 1
                and item.get("transport") == "udp"
                for item in records[:index]
            )
            and any(
                item.get("name") == domain
                and item.get("kind") == 1
                and item.get("error") is None
                and item.get("response_hex")
                and (
                    item.get("transport") == "udp"
                    and "response_queued_ns" in item
                    or item.get("transport") == "tcp"
                    and "response_drained_ns" in item
                )
                for item in records[index + 1 :]
            )
        ):
            return
    raise RuntimeError("dropped UDP A was not followed by a sent owned A answer")


async def capture(
    executable: Path, record: dict, *, drop_first_udp_a: bool = False
) -> None:
    nonce = secrets.token_hex(16)
    domain = resolver_name(nonce, 1024)
    dns = NativeDnsServer(domain, "127.0.0.1", 0, drop_first_udp_a=drop_first_udp_a)
    if drop_first_udp_a:
        record["drop_first_udp_a"] = True
    origin = Origin(domain, nonce)
    guard = None
    driver = None
    primary = None
    cleanup: list[BaseException] = []
    baseline = None
    waiters = []
    try:
        await dns.start()
        await origin.start()
        port = dns.address[1]
        record.update(domain=domain, dns_address=dns.address, origin_port=origin.port)
        record["dns_before"] = await dns_configuration()
        baseline = resolver_blocks(record["dns_before"])
        if owned_resolvers(record["dns_before"], domain):
            raise RuntimeError("generated resolver domain already exists")
        guard = ResolverGuard(nonce, port, record)
        await guard.start()
        record["dns_installed"] = await wait_dns(baseline, domain, port, installed=True)
        url = f"http://{domain}:{origin.port}/start?token={nonce}"
        plan = LaunchPlan("firefox", executable, headless=False)
        record["launch_arguments"] = plan.recorded_arguments(url)
        record["firefox_preferences"] = FIREFOX_PREFERENCES
        driver = BrowserDriver(plan, url)
        await driver.__aenter__()
        waiters = [
            asyncio.create_task(origin.done.wait()),
            asyncio.create_task(dns.failed.wait()),
        ]
        finished, _ = await asyncio.wait(
            waiters, timeout=RUN_SECONDS, return_when=asyncio.FIRST_COMPLETED
        )
        if waiters[1] in finished:
            raise RuntimeError("native DNS peer failed") from dns.failures[0]
        if waiters[0] not in finished:
            raise TimeoutError("native DNS browser scene did not complete")
        if not any(
            item.get("name") == domain
            and item.get("kind") == 1
            and item.get("error") is None
            and item.get("response_hex")
            and ("response_queued_ns" in item or "response_drained_ns" in item)
            for item in dns.records()
        ):
            raise RuntimeError("no owned A question received a sent response")
        if drop_first_udp_a:
            verify_retry(dns.records(), domain)
    except BaseException as error:
        primary = error
    finally:

        async def restore() -> None:
            for waiter in waiters:
                waiter.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)
            operations = []
            if driver is not None:
                operations.append(driver.__aexit__(None, None, None))
            if guard is not None:
                operations.append(guard.close())
            for operation in operations:
                try:
                    await operation
                except BaseException as error:
                    cleanup.append(error)
            if guard is not None and baseline is not None:
                try:
                    record["dns_after"] = await wait_dns(
                        baseline, domain, dns.address[1], installed=False
                    )
                except BaseException as error:
                    cleanup.append(error)
            for operation in (origin.close(), dns.close()):
                try:
                    await operation
                except BaseException as error:
                    cleanup.append(error)

        restoring = asyncio.create_task(restore())
        while not restoring.done():
            try:
                await asyncio.shield(restoring)
            except asyncio.CancelledError as error:
                if primary is None:
                    primary = error
        restoring.result()
        record["dns_records"] = dns.records()
        record["origin_requests"] = origin.requests
        record["cleanup_errors"] = [
            f"{type(error).__name__}: {error}" for error in cleanup
        ]
    raise_browser_failures(primary, tuple(cleanup))


def browser_identity(executable: Path) -> dict:
    # The caller selects an existing Firefox.app executable; nothing is staged.
    import configparser

    application = executable.parent.parent / "Resources/application.ini"
    config = configparser.ConfigParser()
    with application.open(encoding="utf-8") as source:
        config.read_file(source)
    return {
        "executable": str(executable),
        "executable_sha256": digest(executable),
        "application_ini_sha256": digest(application),
        "version": config["App"]["Version"],
        "build_id": config["App"]["BuildID"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firefox", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--drop-first-udp-a",
        action="store_true",
        help="leave the first owned UDP A question unanswered and require a later answer",
    )
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() == 0:
        parser.error("capture requires a non-root macOS user")
    executable = args.firefox.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    record = {
        "platform": platform.platform(),
        "python": sys.version,
        "scope": "configured-native A lookup and complete HTTP body",
        "interventions": {
            "network.trr.mode": 5,
            "network.proxy.type": 0,
            "scoped_resolver": True,
        },
        "source_before": {path: digest(ROOT / path) for path in SOURCE_PATHS},
    }
    try:
        record["browser_before"] = browser_identity(executable)
        asyncio.run(capture(executable, record, drop_first_udp_a=args.drop_first_udp_a))
        record["browser_after"] = browser_identity(executable)
        record["source_after"] = {path: digest(ROOT / path) for path in SOURCE_PATHS}
        if (
            record["browser_before"] != record["browser_after"]
            or record["source_before"] != record["source_after"]
        ):
            raise RuntimeError("browser or capture source changed during capture")
        record["status"] = "complete"
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        (args.output / "result.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
