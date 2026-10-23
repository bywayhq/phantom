"""Capture decrypted wss openings through an explicit loopback proxy route.

Proxy and origin ALPN are selected independently. Only actual decoded origin
events establish an H1 or H2 WebSocket opening.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import platform
import sys
import time
from collections.abc import Sequence
from contextlib import asynccontextmanager
from importlib import metadata
from pathlib import Path

from .browser_launch import DESKTOP_CHROMIUM_BROWSERS, LaunchPlan, render_preferences
from .fixture_file import write_text_fixture
from .http2_analysis import analyze_http2
from .http2_session import (
    HOSTNAME,
    MAX_RUNS,
    authority,
    generate_certificate,
    raise_capture_failures,
)
from .http2_websocket import (
    CORPUS,
    SUPPORTED_H2,
    SUPPORTED_HPACK,
    CaptureMetadata,
    capture_scenario,
    capture_tool,
    connection_lines,
    firefox_cert_override,
    run_lines,
    urls,
    validate_browser_listener,
    validate_capture_arguments,
    validate_retained_fields,
)
from .http2_websocket import (
    SCENARIOS as ORIGIN_SCENARIOS,
)
from .proxy_route import ProxyBrowserDriver, recorded_arguments
from .websocket_tunnel import (
    MODES,
    PROXY_HOST,
    SENSITIVE,
    TunnelOrigin,
    TunnelRun,
    TunnelServer,
    correlate,
)

FORMAT = "phantom-tunnelled-websocket-v1"
SCENARIOS = {
    name: value
    for name, value in ORIGIN_SCENARIOS.items()
    if value.page == "tls" and value.socket == "wss"
}
BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, "firefox")


def launch_plan(
    args, origin, proxy, origin_certificate, proxy_certificate
) -> LaunchPlan:
    host, origin_port = origin.tls_address
    _, proxy_port = proxy.address
    if args.browser in DESKTOP_CHROMIUM_BROWSERS:
        extra = (
            f"--host-resolver-rules=MAP {HOSTNAME} {authority(host, 0).rsplit(':', 1)[0]}, MAP {PROXY_HOST} {authority(host, 0).rsplit(':', 1)[0]}, EXCLUDE localhost",
            "--ignore-certificate-errors-spki-list="
            + ",".join(
                (
                    origin_certificate.spki_sha256_base64,
                    proxy_certificate.spki_sha256_base64,
                )
            ),
            "--disable-quic",
            "--disable-field-trial-config",
            f"--proxy-server={args.proxy}://"
            + (
                f"{PROXY_HOST}:{proxy_port}"
                if args.proxy == "https"
                else authority(host, proxy_port)
            ),
            "--proxy-bypass-list=<-loopback>",
        )
        return LaunchPlan(
            args.browser, args.browser_path, not args.headful, extra_arguments=extra
        )
    preferences = [
        ("network.dns.localDomains", f"{HOSTNAME},{PROXY_HOST}"),
        ("network.dns.disableIPv6", ipaddress.ip_address(host).version == 4),
        ("network.http.http3.enable", False),
        ("network.proxy.allow_hijacking_localhost", True),
        ("network.proxy.no_proxies_on", ""),
    ]
    overrides = firefox_cert_override(HOSTNAME, origin_port, origin_certificate)
    if args.proxy == "https":
        preferences.extend(
            (
                ("network.proxy.type", 2),
                (
                    "network.proxy.autoconfig_url",
                    "data:text/plain,function FindProxyForURL(url, host) "
                    + f"{{ return 'HTTPS {PROXY_HOST}:{proxy_port}'; }}",
                ),
            )
        )
        # Each override file has one header and one line per actual TLS endpoint.
        overrides += (
            firefox_cert_override(
                PROXY_HOST, proxy_port, proxy_certificate
            ).splitlines()[-1]
            + "\n"
        )
    elif args.proxy == "http":
        preferences.extend(
            (
                ("network.proxy.type", 1),
                ("network.proxy.http", host),
                ("network.proxy.http_port", proxy_port),
                ("network.proxy.ssl", host),
                ("network.proxy.ssl_port", proxy_port),
            )
        )
    else:
        preferences.extend(
            (
                ("network.proxy.type", 1),
                ("network.proxy.socks", host),
                ("network.proxy.socks_port", proxy_port),
                ("network.proxy.socks_version", 5),
                ("network.proxy.socks_remote_dns", True),
            )
        )
    return LaunchPlan(
        "firefox",
        args.browser_path,
        not args.headful,
        firefox_preferences=tuple(preferences),
        profile_files=(("cert_override.txt", overrides),),
    )


def fixture(
    scenario,
    runs: Sequence[TunnelRun],
    capture: CaptureMetadata,
    *,
    mode: str,
    origin_alpn: str,
    proxy_address: str,
    proxy_alpn: str = "h1",
) -> str:
    for run in runs:
        validate_retained_fields(run.origin)
        if proxy_alpn == "h2":
            if not run.proxy_connections or any(
                opening.connection.alpn != "h2" or opening.connection.protocol != "h2"
                for opening in run.proxy_connections
            ):
                raise ValueError("the proxy capture did not negotiate HTTP/2")
            for opening in run.proxy_connections:
                analysis = analyze_http2(opening.connection)
                if any(
                    item.name in SENSITIVE
                    for block in analysis.client_headers
                    for item in block.fields
                ):
                    raise ValueError("credential or cookie field in H2 proxy capture")
    lines = [
        f"format={FORMAT}",
        f"captured_at_unix={int(time.time())}",
        f"client={capture.client}",
        f"client_version={capture.client_version}",
        f"operating_system={capture.operating_system}",
        f"launch_mode={capture.launch_mode}",
        f"launch_arguments={capture.launch_arguments}",
        f"firefox_preferences={capture.firefox_preferences}",
        f"profile_files={capture.profile_files}",
        f"capture_tool={capture_tool()}",
        f"proxy_mode={mode}",
        f"proxy_listen_address={proxy_address}",
        f"proxy_alpn_offer={'h2' if proxy_alpn == 'h2' else 'http/1.1'}"
        if mode == "https"
        else "proxy_alpn_offer=none",
        f"origin_hostname={HOSTNAME}",
        f"origin_tls_listen_address={capture.tls_listen_address}",
        f"origin_alpn_offer={'http/1.1' if origin_alpn == 'h1' else 'h2;http/1.1'}",
        "socket_scheme=wss",
        f"scenario={scenario.name}",
        f"scenario_purpose={scenario.purpose}",
        f"server_connect_protocol={str(scenario.policy.connect_protocol).lower()}",
        f"server_response={scenario.policy.response}",
        f"server_deflate={str(scenario.policy.deflate).lower()}",
        f"corpus_count={len(CORPUS)}",
    ]
    lines.extend(
        f"corpus_{index}=label:{message.label},opcode:{message.opcode},length:{len(message.payload)},sha256:{hashlib.sha256(message.payload).hexdigest()}"
        for index, message in enumerate(CORPUS)
    )
    lines.append(f"repeat_count={len(runs)}")
    for index, run in enumerate(runs):
        prefix = f"run_{index}"
        if proxy_alpn == "h2":
            lines.extend(h2_proxy_lines(prefix, run))
            lines.extend(run_lines(prefix + "_origin", run.origin))
            continue
        lines.append(f"{prefix}_proxy_connection_count={len(run.openings)}")
        for number, opening in enumerate(run.openings):
            key = f"{prefix}_proxy_{number}"
            lines.extend(connection_lines(key, opening.connection))
            hello = opening.connection.client_hello
            if hello is not None:
                length = 4 + int.from_bytes(hello.handshake[1:4], "big")
                lines.append(
                    f"{key}_client_hello_handshake_hex={bytes(hello.handshake[:length]).hex()}"
                )
            lines.extend(
                (
                    f"{key}_tls_version={opening.tls_version or 'none'}",
                    f"{key}_peer={authority(*opening.peer[:2])}",
                    f"{key}_upstream={authority(*opening.upstream[:2]) if opening.upstream else 'none'}",
                    f"{key}_origin_connection={opening.origin_connection if opening.origin_connection is not None else 'none'}",
                    f"{key}_opening_hex={opening.head.hex()}",
                    f"{key}_reply_hex={opening.reply.hex()}",
                    f"{key}_outcome={opening.outcome}",
                    f"{key}_finished_ms={opening.finished * 1000:.3f}"
                    if opening.finished is not None
                    else f"{key}_finished_ms=none",
                )
            )
        lines.extend(run_lines(prefix + "_origin", run.origin))
    return "\n".join(lines) + "\n"


def h2_proxy_lines(prefix: str, run: TunnelRun) -> list[str]:
    lines = [
        f"{prefix}_proxy_connection_count={len(run.proxy_connections)}",
        f"{prefix}_proxy_stream_count={len(run.openings)}",
    ]
    for number, opening in enumerate(run.proxy_connections):
        key = f"{prefix}_proxy_{number}"
        lines.extend(connection_lines(key, opening.connection))
        hello = opening.connection.client_hello
        if hello is not None:
            length = 4 + int.from_bytes(hello.handshake[1:4], "big")
            lines.append(
                f"{key}_client_hello_handshake_hex={bytes(hello.handshake[:length]).hex()}"
            )
        lines.extend(
            (
                f"{key}_tls_version={opening.tls_version or 'none'}",
                f"{key}_peer={authority(*opening.peer[:2])}",
                f"{key}_client_stream_hex={opening.connection.client_stream().hex()}",
                f"{key}_server_stream_hex={b''.join(data for _, data in opening.connection.server_chunks).hex()}",
                f"{key}_outcome={opening.outcome}",
                f"{key}_finished_ms={opening.finished * 1000:.3f}"
                if opening.finished is not None
                else f"{key}_finished_ms=none",
            )
        )
    for number, opening in enumerate(run.openings):
        key = f"{prefix}_proxy_stream_{number}"
        lines.extend(
            (
                f"{key}=connection:{opening.proxy_connection},stream:{opening.stream_id},status:{opening.status},outcome:{opening.outcome}",
                f"{key}_header_count={len(opening.headers)}",
                f"{key}_upstream={authority(*opening.upstream[:2]) if opening.upstream else 'none'}",
                f"{key}_origin_connection={opening.origin_connection if opening.origin_connection is not None else 'none'}",
                f"{key}_finished_ms={opening.finished * 1000:.3f}"
                if opening.finished is not None
                else f"{key}_finished_ms=none",
            )
        )
        lines.extend(
            f"{key}_header_{index}={name.hex()}:{value.hex()}"
            for index, (name, value) in enumerate(opening.headers)
        )
    return lines


async def capture_through_proxy(
    origin, proxy, scenario, plan, *, repeat, run_timeout, observation
):
    tunnel_runs = []

    @asynccontextmanager
    async def drive(url):
        tunnel_runs.append(proxy.begin_run(origin.run))
        primary = None
        try:
            async with ProxyBrowserDriver(plan, url):
                yield
        except BaseException as error:
            primary = error
        cleanup = []
        try:
            await proxy.stop_connections()
        except BaseException as error:
            cleanup.append(error)
        raise_capture_failures(primary, tuple(cleanup))

    await capture_scenario(
        origin,
        scenario,
        repeat=repeat,
        run_timeout=run_timeout,
        observation_seconds=observation,
        drive=drive,
    )
    for run in tunnel_runs:
        correlate(run, origin)
    return tunnel_runs


async def run(args) -> None:
    validate_capture_arguments(args.repeat, args.run_timeout, args.observation)
    names = list(SCENARIOS) if args.scenario == ["all"] else args.scenario
    if len(names) * args.repeat > MAX_RUNS:
        raise ValueError(f"capture must contain at most {MAX_RUNS} runs")
    origin_certificate = generate_certificate()
    proxy_certificate = generate_certificate(PROXY_HOST)
    origin = TunnelOrigin(origin_certificate)
    proxy = None
    primary = None
    captures = []
    try:
        if args.origin_alpn == "h1":
            origin.context.set_alpn_protocols(["http/1.1"])
        await origin.start(args.listen)
        proxy = TunnelServer(
            args.proxy, proxy_certificate, origin.tls_address, alpn=args.proxy_alpn
        )
        await proxy.start()
        plan = launch_plan(args, origin, proxy, origin_certificate, proxy_certificate)
        for name in names:
            scenario = SCENARIOS[name]
            runs = await capture_through_proxy(
                origin,
                proxy,
                scenario,
                plan,
                repeat=args.repeat,
                run_timeout=args.run_timeout,
                observation=args.observation,
            )
            page_url, _ = urls(origin, scenario, "<token>")
            capture = CaptureMetadata(
                args.client or plan.client_name,
                args.client_version,
                args.operating_system,
                authority(*origin.tls_address),
                authority(*origin.plain_address),
                plan.launch_mode,
                recorded_arguments(plan, page_url),
                render_preferences(plan.firefox_preferences) or "none",
                ",".join(name for name, _ in plan.profile_files) or "none",
            )
            captures.append(
                (
                    args.output_dir
                    / f"{args.proxy}{'-h2' if args.proxy_alpn == 'h2' else ''}-{args.origin_alpn}-{name}.txt",
                    fixture(
                        scenario,
                        runs,
                        capture,
                        mode=args.proxy,
                        origin_alpn=args.origin_alpn,
                        proxy_address=authority(*proxy.address),
                        proxy_alpn=args.proxy_alpn,
                    ),
                )
            )
    except BaseException as error:
        primary = error
    cleanup = []
    for server in (proxy, origin):
        if server is None:
            continue
        try:
            await server.close()
        except BaseException as error:
            cleanup.append(error)
    raise_capture_failures(primary, tuple(cleanup))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for path, text in captures:
        write_text_fixture(path, text)
        print(f"captured {path.name}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=BROWSERS, required=True)
    parser.add_argument("--browser-path", type=Path, required=True)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--proxy", choices=MODES, required=True)
    parser.add_argument("--proxy-alpn", choices=("h1", "h2"), default="h1")
    parser.add_argument(
        "--origin-alpn", choices=("h1", "negotiate"), default="negotiate"
    )
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--scenario", nargs="+", default=["all"])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=30.0)
    parser.add_argument("--observation", type=float, default=1.5)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    unknown = set(args.scenario) - set(SCENARIOS) - {"all"}
    if unknown or ("all" in args.scenario and len(args.scenario) > 1):
        parser.error("unknown or mixed scenarios")
    try:
        if args.proxy_alpn == "h2" and args.proxy != "https":
            raise ValueError("HTTP/2 proxy ALPN requires an HTTPS proxy")
        if not ipaddress.ip_address(args.listen).is_loopback:
            raise ValueError("the capture listener must be loopback")
        validate_capture_arguments(args.repeat, args.run_timeout, args.observation)
        validate_browser_listener(args.browser, args.listen)
        for value in (args.client, args.client_version, args.operating_system):
            if value is not None and any(character in value for character in "\r\n"):
                raise ValueError("capture metadata must be single-line")
    except ValueError as error:
        parser.error(str(error))
    for package, version in (("h2", SUPPORTED_H2), ("hpack", SUPPORTED_HPACK)):
        if metadata.version(package) != version:
            parser.error(f"{package} {version} is required")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
