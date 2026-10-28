"""The trusted TLS peer and observations for the hosted native HTTPS scene."""

from __future__ import annotations

import asyncio
import re
import struct
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

from scripts.capture import chrome_ech, firefox_socket_hooks
from scripts.capture.browser_launch import LaunchedBrowser, LaunchPlan
from scripts.capture.capture_report import file_digest
from scripts.capture.native_dns import HttpsAnswer, https_parameters_offset, question
from scripts.capture.process_container import ProcessContainer

HOSTNAME = "server.phantom.test"
ROOT = Path(__file__).resolve().parents[2]
IDENTITY = ROOT / "scripts/capture/fixtures/native-https"
PEER = ROOT / "target/debug/examples/capture_ech_client_hello.exe"
METADATA_PREFIX = "native_dns_https_rdata_hex="
READY_SECONDS = 30.0
FINISH_SECONDS = 15.0


def ech_config(rdata: bytes) -> bytes:
    """Return the validated scene record's ECHConfigList."""
    offset = https_parameters_offset(rdata)
    while offset < len(rdata):
        key, size = struct.unpack_from("!HH", rdata, offset)
        offset += 4
        value = rdata[offset : offset + size]
        if key == 5:
            return value
        offset += size
    raise ValueError("native HTTPS record has no ECHConfigList")


class NativeHttpsPeer:
    def __init__(self, output: Path, record: dict) -> None:
        self.output = output
        self.record = record
        self.files = ExitStack()
        self.process: ProcessContainer | None = None
        self.rdata: bytes | None = None
        self.answer: HttpsAnswer | None = None
        self.observer: chrome_ech._CaptureOutput | None = None
        self.stdout = None
        self.origin = ""

    def diagnostic(self, line: str) -> None:
        if not line.startswith(METADATA_PREFIX):
            return  # The complete peer diagnostic stream is retained on disk.
        text = line[len(METADATA_PREFIX) :]
        if self.rdata is not None or re.fullmatch(r"[0-9a-f]{6,1024}", text) is None:
            raise ValueError("native HTTPS peer metadata is malformed or repeated")
        self.rdata = bytes.fromhex(text)

    async def start(self) -> None:
        certificate = IDENTITY / "certificate.pem"
        key = IDENTITY / "key.pem"
        self.database = chrome_ech.checked_input(
            IDENTITY / "cert9.db", chrome_ech.MAX_CERT9_BYTES
        )
        if not self.database.startswith(b"SQLite format 3\0"):
            raise ValueError("native HTTPS trust database is not NSS SQL")
        chrome_ech.checked_input(certificate, chrome_ech.MAX_IDENTITY_BYTES)
        chrome_ech.checked_input(key, chrome_ech.MAX_IDENTITY_BYTES)
        command = [
            str(PEER),
            "--identity",
            str(certificate),
            str(key),
            "accept",
            "127.0.0.1:0",
            "Mozilla Firefox",
            "157.0",
            "Windows Server 2025",
            "native DNS; TRR5; direct; HTTP/3 disabled",
            "headful",
            "recorded separately in result.json",
        ]
        self.record["ech_peer"] = {
            "argv": command,
            "binary_sha256": file_digest(PEER),
            "identity_sha256": {
                name: file_digest(IDENTITY / name)
                for name in ("ca.pem", "certificate.pem", "key.pem", "cert9.db")
            },
        }
        output = self.files.enter_context((self.output / "ech-peer.txt").open("wb"))
        diagnostics = self.files.enter_context(
            (self.output / "ech-peer.stderr").open("wb")
        )
        self.stdout = self.files.enter_context(
            (self.output / "ech-peer.txt").open("rb")
        )
        errors = self.files.enter_context((self.output / "ech-peer.stderr").open("rb"))
        self.observer = chrome_ech._CaptureOutput(self.stdout, errors, self.diagnostic)
        self.process = ProcessContainer(command, stdout=output, stderr=diagnostics)
        if not self.process.start():
            raise RuntimeError("native HTTPS peer stopped before launch")
        deadline = asyncio.get_running_loop().time() + READY_SECONDS
        while True:
            code = self.process.poll()
            self.observer.poll(final=code is not None)
            if code is not None:
                raise RuntimeError(f"native HTTPS peer exited before readiness: {code}")
            if self.observer.ready is not None:
                break
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("native HTTPS peer readiness timed out")
            await asyncio.sleep(chrome_ech.POLL_SECONDS)
        _template, address, spki = self.observer.ready
        host, _, port = address.rpartition(":")
        if host != "127.0.0.1" or spki is not None or self.rdata is None:
            raise ValueError("native HTTPS peer readiness does not match TCP scene")
        self.answer = HttpsAnswer(int(port), self.rdata)
        ech_config(self.rdata)
        self.origin = f"https://{HOSTNAME}:{self.answer.port}"
        self.record["ech_peer"]["origin"] = self.origin
        self.record["ech_peer"]["https_rdata_hex"] = self.rdata.hex()

    def browser(self, plan: LaunchPlan, url: str) -> LaunchedBrowser:
        if plan.profile_files or plan.firefox_preferences:
            raise ValueError("native HTTPS launcher requires an unmodified direct plan")
        configured = replace(
            plan,
            firefox_preferences=(
                ("network.trr.mode", 5),
                ("network.proxy.type", 0),
                ("network.http.http3.enable", False),
            ),
        )
        self.record["ech_peer"]["firefox_preferences"] = list(
            configured.firefox_preferences
        )
        return chrome_ech._TrustedFirefox(configured, url, self.database)

    async def completed(self) -> str:
        deadline = asyncio.get_running_loop().time() + FINISH_SECONDS
        while True:
            code = self.process.poll()
            self.observer.poll(final=code is not None)
            if code is not None:
                self.record["ech_peer"]["exit"] = code
                if code != 0:
                    raise RuntimeError(f"native HTTPS peer failed: {code}")
                self.stdout.seek(0)
                return self.stdout.read(chrome_ech.MAX_CAPTURE_OUTPUT + 1).decode(
                    "ascii"
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(
                    "native HTTPS peer did not finish after browser DONE"
                )
            await asyncio.sleep(chrome_ech.POLL_SECONDS)

    async def close(self) -> None:
        # ProcessContainer owns descendants and enforces its existing close bound.
        # Retain its open files if closure fails, so the owner remains retryable.
        if self.process is not None:
            self.process.close()
        self.files.close()


def validate(
    result: firefox_socket_hooks.RunResult,
    records: list[dict],
    answer: HttpsAnswer,
    fixture: str,
) -> dict:
    ready = [
        entry["time_ms"] * 1_000_000
        for entry in result.reports
        if entry.get("kind") == "firefox-config" and type(entry.get("time_ms")) is int
    ]
    if (
        result.timed_out
        or result.errors
        or not ready
        or not result.origins.done.is_set()
        or result.frida_version != "17.24.3"
    ):
        raise RuntimeError("native HTTPS browser did not complete with ready hooks")
    service = f"_{answer.port}._https.{HOSTNAME}"
    owned = [entry for entry in records if entry.get("name") in (HOSTNAME, service)]
    if any(entry["unix_ns"] < min(ready) for entry in owned):
        raise RuntimeError("native HTTPS query preceded hook attachment")
    positive = []
    for entry in owned:
        if entry.get("name") != service or entry.get("kind") != 65:
            continue
        wire = bytes.fromhex(entry["query_hex"])
        parsed = question(wire)
        if parsed.name != service or parsed.kind != 65:
            raise RuntimeError("native HTTPS query bytes differ from journal metadata")
        reply = bytes.fromhex(entry.get("response_hex") or "")
        end = parsed.end
        tail = (
            b"\0" + struct.pack("!HHIH", 41, parsed.edns_size, 0, 0)
            if parsed.edns_size is not None
            else b""
        )
        if (
            entry.get("error") is not None
            or not ("response_queued_ns" in entry or "response_drained_ns" in entry)
            or len(reply) < end + 12
            or reply[:2] != wire[:2]
            or struct.unpack_from("!5H", reply, 2)
            != (
                0x8400 | (int.from_bytes(wire[2:4], "big") & 0x0100),
                1,
                1,
                0,
                int(parsed.edns_size is not None),
            )
            or reply[12:end] != wire[12:end]
            or reply[end : end + 2] != b"\xc0\x0c"
            or struct.unpack_from("!HHIH", reply, end + 2)
            != (65, 1, 5, len(answer.rdata))
            or reply[end + 12 : end + 12 + len(answer.rdata)] != answer.rdata
            or reply[end + 12 + len(answer.rdata) :] != tail
        ):
            raise RuntimeError(
                "native HTTPS response differs from published peer record"
            )
        positive.append(entry)
    if not positive:
        raise RuntimeError("no post-attachment positive native HTTPS response")
    native = [
        entry
        for entry in result.reports
        if entry.get("kind") == "dnsquery-return"
        and entry.get("host") == service
        and entry.get("query_type") == 65
        and entry.get("status") == 0
        and entry.get("time_ms", 0) * 1_000_000 >= min(ready)
        and [65, 1, 5] in entry.get("records", [])
    ]
    if not native:
        raise RuntimeError("no successful native HTTPS API result with TTL5 answer")
    fields = {}
    for line in fixture.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ValueError("ECH peer fixture contains malformed or repeated fields")
        fields[key] = value
    if (
        fields.get("format") != "phantom-ech-client-hello-v2"
        or fields.get("scenario") != "accept"
        or fields.get("listen_address") != f"127.0.0.1:{answer.port}"
        or fields.get("dns_ech_config_list_hex") != ech_config(answer.rdata).hex()
    ):
        raise RuntimeError("ECH peer fixture differs from native DNS publication")
    count = int(fields.get("connection_count", "0"))
    if not 1 <= count <= 64:
        raise ValueError("ECH peer connection count is outside 1..64")
    accepted = [
        index
        for index in range(count)
        if fields.get(f"connection_{index}_ech_accepted") == "true"
        and fields.get(f"connection_{index}_inner_server_name") == HOSTNAME
        and fields.get(f"connection_{index}_handshake") == "ok"
        and fields.get(f"connection_{index}_request_served") == "true"
    ]
    if not accepted:
        raise RuntimeError("no accepted ECH connection served the browser probe")
    return {
        "positive_https_wire_responses": len(positive),
        "successful_native_https_returns": len(native),
        "ech_accepted_connections": accepted,
        "browser_body_completed": True,
    }
