"""Record browser WebSocket openings and send policy over H2 and HTTP/1.1."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import platform
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from urllib.parse import urlencode

from .browser_launch import (
    BROWSERS,
    CHROMIUM_BROWSERS,
    BrowserDriver,
    LaunchPlan,
    add_android_entry_option,
    add_browser_switch_option,
    check_android_entry,
    check_browser_switches,
    render_preferences,
    with_android_entry,
)
from .fixture_file import write_text_fixture
from .http2_session import (
    HOSTNAME,
    CaptureRun,
    CaptureServer,
    Certificate,
    ConnectionRecord,
    ServerPolicy,
    WebSocketRecord,
    analyze_http2,
    frame_details,
    generate_certificate,
    priority_text,
)
from .websocket_frames import BINARY, TEXT, summarize_send_policy

FORMAT = "phantom-http2-websocket-v1"
SUPPORTED_H2 = "4.4.1"
SUPPORTED_HPACK = "4.2.0"
SENSITIVE_FIELDS = {b"authorization", b"proxy-authorization", b"cookie"}
CORPUS_SEED = 0x5048414E
TEXT_UNIT = "phantom websocket corpus "


# -- Corpus ----------------------------------------------------------------


@dataclass(frozen=True)
class CorpusMessage:
    label: str
    opcode: int
    payload: bytes


def xorshift32(seed: int, length: int) -> bytes:
    """Match the page's generator: xorshift32, low byte of each state."""
    state = seed
    output = bytearray(length)
    for index in range(length):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        output[index] = state & 0xFF
    return bytes(output)


def pattern(length: int) -> bytes:
    return (bytes(range(251)) * (length // 251 + 1))[:length]


CORPUS = (
    CorpusMessage("empty-text", TEXT, b""),
    CorpusMessage("one-byte-text", TEXT, b"x"),
    CorpusMessage("compressible-text-100", TEXT, (TEXT_UNIT * 4)[:100].encode()),
    CorpusMessage("random-binary-64k", BINARY, xorshift32(CORPUS_SEED, 64 * 1024)),
    CorpusMessage("pattern-binary-1m", BINARY, pattern(1024 * 1024)),
)

# The page rebuilds CORPUS byte-for-byte; keep the two definitions in step.
PAGE_SCRIPT = """
const socketUrl = %(socket)s;
const doneUrl = %(done)s;
function xorshift32(seed, length) {
  const output = new Uint8Array(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index++) {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    output[index] = state & 0xff;
  }
  return output;
}
const big = new Uint8Array(%(big)d);
for (let index = 0; index < big.length; index++) big[index] = index %% 251;
const corpus = ["", "x", %(text)s, xorshift32(%(seed)d, %(random)d), big];
let opened = false;
let echoed = 0;
const socket = new WebSocket(socketUrl);
socket.binaryType = "arraybuffer";
socket.onopen = () => {
  opened = true;
  for (const message of corpus) socket.send(message);
};
socket.onmessage = () => {
  echoed += 1;
  if (echoed === corpus.length) socket.close(1000);
};
socket.onclose = (event) => {
  const result = new URLSearchParams({
    opened: String(opened),
    code: String(event.code),
    clean: String(event.wasClean),
    extensions: socket.extensions,
    protocol: socket.protocol,
    echoed: String(echoed),
  });
  fetch(doneUrl + "&" + result, {cache: "no-store"});
};
"""


def page(socket_url: str, token: str) -> bytes:
    script = PAGE_SCRIPT % {
        "socket": json.dumps(socket_url),
        "done": json.dumps(f"/done?run={token}"),
        "big": len(CORPUS[4].payload),
        "text": json.dumps(CORPUS[2].payload.decode()),
        "seed": CORPUS_SEED,
        "random": len(CORPUS[3].payload),
    }
    return (
        "<!doctype html><meta charset=utf-8>"
        '<link rel=icon href="data:,">'
        f"<script>{script}</script>\n"
    ).encode()


# -- Scenarios -------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    name: str
    purpose: str
    # Listener serving the page: `tls` (https, H2 when negotiated) or `plain`.
    page: str
    socket: str
    policy: ServerPolicy

    def __post_init__(self) -> None:
        if self.page not in {"tls", "plain"} or self.socket not in {"wss", "ws"}:
            raise ValueError(f"unsupported scenario origin: {self.name}")


CATALOG = (
    Scenario(
        "accept",
        "extended CONNECT fields, priority, and send policy on the page's H2 session",
        "tls",
        "wss",
        ServerPolicy(),
    ),
    Scenario(
        "accept-deflate",
        "per-message RSV1 and fragmentation after permessage-deflate is accepted",
        "tls",
        "wss",
        ServerPolicy(deflate=True),
    ),
    Scenario(
        "no-connect-protocol",
        "fallback connection ALPN offer and Upgrade fields without the setting",
        "tls",
        "wss",
        ServerPolicy(connect_protocol=False),
    ),
    Scenario(
        "reject-403",
        "stream termination and any retry after a 403 with a body",
        "tls",
        "wss",
        ServerPolicy(response="reject-403"),
    ),
    Scenario(
        "refused-stream",
        "reaction to RST_STREAM(REFUSED_STREAM); later openings are accepted",
        "tls",
        "wss",
        ServerPolicy(response="refuse-first"),
    ),
    Scenario(
        "extension-mismatch",
        "reaction to a 200 selecting an extension that was not offered",
        "tls",
        "wss",
        ServerPolicy(response="extension-mismatch"),
    ),
    Scenario(
        "fresh-origin",
        "ALPN offer when the WebSocket is the first connection to its origin",
        "plain",
        "wss",
        ServerPolicy(),
    ),
    Scenario(
        "h1-accept",
        "plaintext ws:// opening request lines in order and send policy",
        "plain",
        "ws",
        ServerPolicy(),
    ),
    Scenario(
        "h1-accept-deflate",
        "plaintext ws:// opening with permessage-deflate accepted",
        "plain",
        "ws",
        ServerPolicy(deflate=True),
    ),
)
SCENARIOS = {scenario.name: scenario for scenario in CATALOG}


def urls(server: CaptureServer, scenario: Scenario, token: str) -> tuple[str, str]:
    """Return the page URL and the WebSocket URL for one run."""
    if server.tls_address is None or server.plain_address is None:
        raise RuntimeError("server has not started")
    tls_port = server.tls_address[1]
    plain_host, plain_port = server.plain_address
    if scenario.page == "tls":
        page_url = f"https://{HOSTNAME}:{tls_port}/ws.html?run={token}"
    else:
        page_url = f"http://{plain_host}:{plain_port}/ws.html?run={token}"
    if scenario.socket == "wss":
        socket_url = f"wss://{HOSTNAME}:{tls_port}/echo?run={token}"
    else:
        socket_url = f"ws://{plain_host}:{plain_port}/echo?run={token}"
    return page_url, socket_url


async def capture_scenario(
    server: CaptureServer,
    scenario: Scenario,
    *,
    repeat: int,
    run_timeout: float,
    observation_seconds: float,
    drive: Callable[[str], object],
) -> list[CaptureRun]:
    """Run `scenario` `repeat` times; `drive(url)` owns one client per run."""
    runs = []
    for _ in range(repeat):
        token = secrets.token_hex(8)
        page_url, socket_url = urls(server, scenario, token)
        body = page(socket_url, token)
        run = CaptureRun(
            token,
            scenario.policy,
            {scenario.page: body},
            observation_seconds=observation_seconds,
        )
        server.run = run
        try:
            async with drive(page_url):
                try:
                    await asyncio.wait_for(
                        run.done.wait(), timeout=run_timeout + observation_seconds
                    )
                except asyncio.TimeoutError:
                    run.timed_out = True
        finally:
            server.run = None
            server.drop_connections()
        runs.append(run)
    return runs


# -- Fixture ---------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMetadata:
    client: str
    client_version: str
    operating_system: str
    tls_listen_address: str
    plain_listen_address: str
    launch_mode: str
    launch_arguments: str
    firefox_preferences: str = "none"
    profile_files: str = "none"


def milliseconds(value: float | None) -> str:
    return "none" if value is None else f"{value * 1000:.3f}"


def flag(value: bool) -> str:
    return str(value).lower()


def optional_hex(value: bytes | None) -> str:
    return "none" if value is None else value.hex()


def validate_retained_fields(run: CaptureRun) -> None:
    names = [
        line.partition(b":")[0].strip().lower()
        for request in run.requests
        for line in request.header_lines
    ]
    for connection in run.connections:
        if connection.protocol == "h2" and connection.client_chunks:
            names.extend(
                item.name
                for block in analyze_http2(connection).client_headers
                for item in block.fields
            )
    if SENSITIVE_FIELDS.intersection(names):
        raise ValueError(
            "refusing to retain a fixture with credential or cookie fields"
        )


def corpus_index(payload: bytes | None) -> str:
    for index, message in enumerate(CORPUS):
        if payload == message.payload:
            return str(index)
    return "none"


def connection_lines(prefix: str, record: ConnectionRecord) -> list[str]:
    hello = record.client_hello
    offer = "none"
    server_name = "none"
    if hello is not None:
        if hello.alpn_offer is not None:
            offer = ";".join(hello.alpn_offer) or "empty"
        server_name = hello.server_name or "none"
    lines = [
        f"{prefix}=listener:{record.listener},"
        f"accepted_ms:{milliseconds(record.accepted)},"
        f"alpn_offer:{offer},sni:{server_name},"
        f"alpn:{record.alpn or 'none'},protocol:{record.protocol or 'none'},"
        f"client_bytes:{record.received},"
        f"client_eof_ms:{milliseconds(record.client_eof)},"
        f"failure:{record.failure or 'none'}"
    ]
    if record.protocol != "h2" or not record.client_chunks:
        return lines
    analysis = analyze_http2(record)
    lines.append(f"{prefix}_frame_count={len(analysis.frames)}")
    for index, frame in enumerate(analysis.frames):
        details = ",".join(frame_details(frame))
        lines.append(
            f"{prefix}_frame_{index}=dir:{frame.direction},"
            f"ms:{milliseconds(frame.received)},type:{frame.type_name},"
            f"flags:0x{frame.flags:02x},stream:{frame.stream_id},"
            f"length:{len(frame.payload)}" + (f",{details}" if details else "")
        )
    lines.append(f"{prefix}_client_trailing_bytes={analysis.client_trailing}")
    lines.append(f"{prefix}_headers_count={len(analysis.client_headers)}")
    for index, block in enumerate(analysis.client_headers):
        key = f"{prefix}_headers_{index}"
        priority = "none" if block.priority is None else priority_text(block.priority)
        lines.append(
            f"{key}=stream:{block.stream_id},flags:0x{block.flags:02x},"
            f"end_stream:{flag(bool(block.flags & 0x1))},"
            f"continuations:{block.continuation_count},priority:{priority}"
        )
        lines.append(f"{key}_block_hex={block.block.hex()}")
        lines.append(
            f"{key}_field_order="
            + ",".join(
                (item.name or b"").decode("latin-1")
                for item in block.fields
                if item.representation != "size-update"
            )
        )
        lines.append(f"{key}_field_count={len(block.fields)}")
        for position, item in enumerate(block.fields):
            lines.append(
                f"{key}_field_{position}=repr:{item.representation},"
                f"index:{item.index},"
                f"name_huffman:{huffman_text(item.name_huffman)},"
                f"value_huffman:{huffman_text(item.value_huffman)},"
                f"name_hex:{optional_hex(item.name)},"
                f"value_hex:{optional_hex(item.value)}"
            )
    return lines


def huffman_text(value: bool | None) -> str:
    return "none" if value is None else flag(value)


def websocket_stream(run: CaptureRun, record: WebSocketRecord) -> bytes:
    connection = run.connections[record.connection]
    if record.protocol == "h2":
        if record.stream_id is None:
            return b""
        return analyze_http2(connection).stream_data.get(record.stream_id, b"")
    if record.stream_offset is None:
        return b""
    return connection.client_stream()[record.stream_offset :]


def websocket_lines(prefix: str, run: CaptureRun, record: WebSocketRecord) -> list[str]:
    lines = [
        f"{prefix}=connection:{record.connection},protocol:{record.protocol},"
        f"stream:{record.stream_id if record.stream_id is not None else 'none'},"
        f"request:{record.request if record.request is not None else 'none'},"
        f"outcome:{record.outcome},status:{record.status or 'none'},"
        f"received_ms:{milliseconds(record.received)},"
        f"client_closed:{flag(record.client_closed)}",
        f"{prefix}_target_hex={record.target.hex()}",
        f"{prefix}_extensions_offer_hex={optional_hex(record.extensions_offer)}",
        f"{prefix}_extensions_selected_hex={optional_hex(record.selected_extensions)}",
    ]
    if record.outcome not in {"accepted", "extension-mismatch"}:
        return lines
    policy = summarize_send_policy(
        websocket_stream(run, record), inflate=record.inflate
    )
    lines.append(f"{prefix}_message_count={len(policy.messages)}")
    for index, message in enumerate(policy.messages):
        decoded = "none" if message.payload is None else str(len(message.payload))
        lines.append(
            f"{prefix}_message_{index}=opcode:{message.opcode},"
            f"rsv1:{flag(message.rsv1)},frames:{len(message.frame_lengths)},"
            "frame_lengths:" + ";".join(map(str, message.frame_lengths)) + ","
            f"wire_length:{message.wire_length},decoded_length:{decoded},"
            f"corpus:{corpus_index(message.payload)}"
        )
    lines.append(f"{prefix}_control_count={len(policy.controls)}")
    lines.extend(
        f"{prefix}_control_{index}=opcode:{control.opcode},length:{control.length},"
        f"close_code:{control.close_code if control.close_code is not None else 'none'},"
        f"after_message:{control.after_message}"
        for index, control in enumerate(policy.controls)
    )
    lines.append(f"{prefix}_incomplete={flag(policy.incomplete)}")
    lines.append(f"{prefix}_anomalies={';'.join(policy.anomalies) or 'none'}")
    return lines


def run_lines(prefix: str, run: CaptureRun) -> list[str]:
    lines = [
        f"{prefix}_timed_out={flag(run.timed_out)}",
        f"{prefix}_finished_ms={milliseconds(run.finished)}",
        f"{prefix}_result_count={len(run.results)}",
    ]
    lines.extend(
        f"{prefix}_result_{index}={urlencode(result)}"
        for index, result in enumerate(run.results)
    )
    lines.append(f"{prefix}_connection_count={len(run.connections)}")
    for index, connection in enumerate(run.connections):
        lines.extend(connection_lines(f"{prefix}_connection_{index}", connection))
    lines.append(f"{prefix}_request_count={len(run.requests)}")
    for index, request in enumerate(run.requests):
        key = f"{prefix}_request_{index}"
        lines.append(
            f"{key}=connection:{request.connection},kind:{request.kind},"
            f"status:{request.status or 'none'},"
            f"received_ms:{milliseconds(request.received)}"
        )
        lines.append(f"{key}_line_hex={request.request_line.hex()}")
        lines.append(f"{key}_header_count={len(request.header_lines)}")
        lines.extend(
            f"{key}_header_{position}={line.hex()}"
            for position, line in enumerate(request.header_lines)
        )
    lines.append(f"{prefix}_websocket_count={len(run.websockets)}")
    for index, record in enumerate(run.websockets):
        lines.extend(websocket_lines(f"{prefix}_websocket_{index}", run, record))
    return lines


def capture_tool() -> str:
    return (
        f"python {platform.python_version()} "
        f"h2 {metadata.version('h2')} hpack {metadata.version('hpack')}"
    )


def fixture(
    scenario: Scenario, runs: Sequence[CaptureRun], capture: CaptureMetadata
) -> str:
    for run in runs:
        validate_retained_fields(run)
    policy = scenario.policy
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={capture.client}",
        f"client_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"hostname={HOSTNAME}",
        f"tls_listen_address={capture.tls_listen_address}",
        f"plain_listen_address={capture.plain_listen_address}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"firefox_preferences={capture.firefox_preferences}",
        f"profile_files={capture.profile_files}",
        f"capture_tool={capture_tool()}",
        f"scenario={scenario.name}",
        f"scenario_purpose={scenario.purpose}",
        f"page_listener={scenario.page}",
        f"socket_scheme={scenario.socket}",
        f"server_connect_protocol={flag(policy.connect_protocol)}",
        f"server_response={policy.response}",
        f"server_deflate={flag(policy.deflate)}",
        f"corpus_count={len(CORPUS)}",
    ]
    lines.extend(
        f"corpus_{index}=label:{message.label},opcode:{message.opcode},"
        f"length:{len(message.payload)},"
        f"sha256:{hashlib.sha256(message.payload).hexdigest()}"
        for index, message in enumerate(CORPUS)
    )
    lines.append(f"repeat_count={len(runs)}")
    for index, run in enumerate(runs):
        lines.extend(run_lines(f"run_{index}", run))
    return "\n".join(lines) + "\n"


# -- Browser launch --------------------------------------------------------


def firefox_cert_override(host: str, port: int, certificate: Certificate) -> str:
    """Trust the throwaway leaf inside one disposable Firefox profile only."""
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file!  Do not edit.\n"
        f"{host}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t"
        f"{certificate.sha256_fingerprint}\t\n"
    )


def launch_plan(
    args: argparse.Namespace, certificate: Certificate, listen_host: str, tls_port: int
) -> LaunchPlan:
    if args.browser in CHROMIUM_BROWSERS:
        return LaunchPlan(
            browser=args.browser,
            executable=args.browser_path,
            headless=not args.headful,
            extra_arguments=(
                f"--host-resolver-rules=MAP {HOSTNAME} {listen_host}, EXCLUDE localhost",
                "--ignore-certificate-errors-spki-list="
                + certificate.spki_sha256_base64,
                "--disable-quic",
                *args.browser_switch,
            ),
        )
    if args.browser == "firefox":
        files: tuple[tuple[str, str], ...] = ()
        if not args.firefox_skip_tls_trust:
            files = (
                (
                    "cert_override.txt",
                    firefox_cert_override(HOSTNAME, tls_port, certificate),
                ),
            )
        return LaunchPlan(
            browser="firefox",
            executable=args.browser_path,
            headless=not args.headful,
            firefox_preferences=(
                ("network.dns.localDomains", HOSTNAME),
                ("network.dns.disableIPv6", True),
                ("network.http.http3.enable", False),
            ),
            profile_files=files,
        )
    return LaunchPlan(browser="manual", executable=None, headless=False)


async def run(args: argparse.Namespace) -> None:
    certificate = generate_certificate()
    server = CaptureServer(certificate)
    await server.start(args.listen, args.tls_port, args.plain_port)
    try:
        tls = "{}:{}".format(*server.tls_address)
        plain = "{}:{}".format(*server.plain_address)
        plan = with_android_entry(
            launch_plan(args, certificate, args.listen, server.tls_address[1]),
            args.android_entry,
        )
        names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            scenario = SCENARIOS[name]
            runs = await capture_scenario(
                server,
                scenario,
                repeat=args.repeat,
                run_timeout=args.run_timeout,
                observation_seconds=args.observation,
                drive=lambda url: BrowserDriver(plan, url),
            )
            page_url, _ = urls(server, scenario, "<token>")
            capture = CaptureMetadata(
                client=args.client or plan.client_name,
                client_version=args.client_version,
                operating_system=args.operating_system,
                tls_listen_address=tls,
                plain_listen_address=plain,
                launch_mode=plan.launch_mode,
                launch_arguments=plan.recorded_arguments(page_url),
                firefox_preferences=render_preferences(plan.firefox_preferences)
                or "none",
                profile_files=",".join(name for name, _ in plan.profile_files)
                or "none",
            )
            write_text_fixture(
                args.output_dir / f"{name}.txt", fixture(scenario, runs, capture)
            )
            timed_out = sum(run.timed_out for run in runs)
            print(f"captured {name} ({timed_out} timed out)", file=sys.stderr)
    finally:
        await server.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=(*BROWSERS, "manual"), required=True)
    parser.add_argument("--browser-path", type=Path)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--tls-port", type=int, default=0)
    parser.add_argument("--plain-port", type=int, default=0)
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=30.0)
    parser.add_argument("--observation", type=float, default=1.5)
    parser.add_argument(
        "--firefox-skip-tls-trust",
        action="store_true",
        help="do not write a certificate override into the Firefox profile",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    add_browser_switch_option(parser)
    add_android_entry_option(parser)
    args = parser.parse_args(argv)
    check_browser_switches(parser, args)
    check_android_entry(parser, args)
    if args.browser != "manual" and args.browser_path is None:
        parser.error("--browser-path is required unless --browser manual")
    unknown = sorted(set(args.scenario) - set(SCENARIOS) - {"all"})
    if unknown or ("all" in args.scenario and len(args.scenario) > 1):
        parser.error(f"unknown or mixed scenarios: {', '.join(unknown) or 'all'}")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    try:
        loopback = ipaddress.ip_address(args.listen).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        parser.error("the capture listener must be a loopback address")
    for package, version in (("h2", SUPPORTED_H2), ("hpack", SUPPORTED_HPACK)):
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
