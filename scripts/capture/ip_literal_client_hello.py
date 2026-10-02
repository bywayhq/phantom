"""Record the ClientHellos Firefox sends to an IP-literal URL.

Firefox sends no `server_name` to an IP literal, yet pads its ECH GREASE
payload by the address text. This tool points a fresh headless Firefox at
`https://127.0.0.1:<port>/` or `https://[::1]:<port>/` and keeps the raw
ClientHellos, optionally with `security.tls.ech.grease_size` set, so a sweep
of that preference shows which host length Firefox pads by.

Over TCP a listener reads each ClientHello and closes the connection, so
Firefox retries and one run keeps several. Over QUIC the alt-svc test mapping
points Firefox at `h3` on the same port; a UDP socket records the client's
datagrams and the first connection's ClientHello is read from its Initial
packets with the Initial keys. A TCP listener on that port accepts and closes
the page's connections. Neither listener answers a handshake.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import socket
import subprocess
import threading
import time
from collections.abc import Sequence
from pathlib import Path

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from scripts.capture.browser_launch import LaunchedBrowser, LaunchPlan
from scripts.capture.fixture_file import write_text_fixture
from scripts.capture.reserved_ports import open_past_reserved_ports

HANDSHAKE = 0x16
CRYPTO = 0x06
HOSTS = {"ipv4": "127.0.0.1", "ipv6": "::1"}
SHARED_PORTS_FIRST = 20_000
SHARED_PORTS_END = 32_768


def client_hello_from_records(data: bytes) -> bytes | None:
    """Return the first handshake message of TLS records `data`, once whole."""
    handshake = b""
    offset = 0
    while offset + 5 <= len(data):
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if offset + 5 + length > len(data):
            break
        if data[offset] == HANDSHAKE:
            handshake += data[offset + 5 : offset + 5 + length]
        offset += 5 + length
    if len(handshake) < 4:
        return None
    end = 4 + int.from_bytes(handshake[1:4], "big")
    return handshake[:end] if len(handshake) >= end else None


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Return a QUIC variable-length integer and the offset after it."""
    first = data[offset]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for index in range(1, length):
        value = (value << 8) | data[offset + index]
    return value, offset + length


def crypto_frames(payload: bytes) -> dict[int, bytes]:
    """Return the CRYPTO frame data of an Initial payload by offset."""
    chunks: dict[int, bytes] = {}
    offset = 0
    while offset < len(payload):
        frame, offset = read_varint(payload, offset)
        if frame in (0x00, 0x01):  # PADDING, PING
            continue
        if frame == CRYPTO:
            start, offset = read_varint(payload, offset)
            length, offset = read_varint(payload, offset)
            chunks[start] = payload[offset : offset + length]
            offset += length
        elif frame in (0x02, 0x03):  # ACK, ACK with ECN counts
            for _ in range(2):
                _, offset = read_varint(payload, offset)
            ranges, offset = read_varint(payload, offset)
            _, offset = read_varint(payload, offset)
            for _ in range(2 * ranges + (3 if frame == 0x03 else 0)):
                _, offset = read_varint(payload, offset)
        else:
            break
    return chunks


def client_hello_from_initials(datagrams: Sequence[bytes]) -> bytes | None:
    """Return the ClientHello of the first connection's Initial packets."""
    crypto: CryptoPair | None = None
    destination: bytes | None = None
    chunks: dict[int, bytes] = {}
    for datagram in datagrams:
        buffer = Buffer(data=datagram)
        while not buffer.eof():
            start = buffer.tell()
            try:
                header = pull_quic_header(buffer, host_cid_length=8)
            except ValueError:
                break
            if header.packet_type != QuicPacketType.INITIAL:
                break
            header_length = buffer.tell() - start
            end = start + header.packet_length
            packet = datagram[start:end]
            buffer.seek(end)
            if crypto is None:
                destination = header.destination_cid
                crypto = CryptoPair()
                crypto.setup_initial(
                    cid=destination, is_client=False, version=header.version
                )
            if header.destination_cid != destination:
                continue
            try:
                _, payload, _, _ = crypto.recv.decrypt_packet(packet, header_length, 0)
            except Exception:  # noqa: BLE001 - a packet of another connection
                continue
            chunks.update(crypto_frames(payload))
    data = b""
    while len(data) in chunks and chunks[len(data)]:
        data += chunks[len(data)]
    if len(data) < 4:
        return None
    end = 4 + int.from_bytes(data[1:4], "big")
    return data[:end] if len(data) >= end else None


def bind(
    family: socket.AddressFamily, kind: int, host: str, port: int
) -> socket.socket:
    """Bind a socket, retrying a port-0 bind refused by a reserved port block."""

    async def open_at(host: str, port: int) -> socket.socket:
        bound = socket.socket(family, kind)
        try:
            bound.bind((host, port))
        except OSError:
            bound.close()
            raise
        return bound

    return asyncio.run(open_past_reserved_ports(open_at, host, port))


def bind_shared_port(
    family: socket.AddressFamily, host: str
) -> tuple[socket.socket, socket.socket]:
    """Bind UDP and TCP sockets to one port below the ephemeral ranges.

    Binding UDP to port 0 and TCP to the port it got fails on Windows while
    the host's sequential UDP counter walks through a block reserved for TCP,
    so candidates come from 20000 to 32767, as in Phantom's Rust tests.
    """
    for port in random.sample(range(SHARED_PORTS_FIRST, SHARED_PORTS_END), 256):
        udp = socket.socket(family, socket.SOCK_DGRAM)
        tcp = socket.socket(family, socket.SOCK_STREAM)
        try:
            udp.bind((host, port))
            tcp.bind((host, port))
        except OSError:
            udp.close()
            tcp.close()
            continue
        return udp, tcp
    raise OSError("no port was free for both UDP and TCP")


def read_client_hello(connection: socket.socket) -> bytes | None:
    """Read one ClientHello from a TCP connection."""
    connection.settimeout(5)
    data = b""
    try:
        while (hello := client_hello_from_records(data)) is None:
            chunk = connection.recv(65536)
            if not chunk:
                return None
            data += chunk
    except OSError:
        return None
    return hello


def capture_tcp(
    plan: LaunchPlan, host: str, family: socket.AddressFamily, timeout: float
) -> tuple[str, list[bytes]]:
    """Return the URL and every ClientHello Firefox sent to it over TCP."""
    listener = bind(family, socket.SOCK_STREAM, host, 0)
    listener.listen(16)
    port = listener.getsockname()[1]
    url = f"https://{url_host(host)}:{port}/"
    hellos: list[bytes] = []
    stop = threading.Event()

    def accept_loop() -> None:
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                continue
            with connection:
                if hello := read_client_hello(connection):
                    hellos.append(hello)

    thread = threading.Thread(target=accept_loop)
    thread.start()
    try:
        with LaunchedBrowser(plan, url):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and not hellos:
                time.sleep(0.2)
    finally:
        stop.set()
        thread.join()
        listener.close()
    return url, hellos


def capture_quic(
    plan: LaunchPlan, host: str, family: socket.AddressFamily, timeout: float
) -> tuple[str, list[bytes], LaunchPlan, int]:
    """Return the URL, the first QUIC ClientHello, the plan, and the datagram count."""
    udp, tcp = bind_shared_port(family, host)
    port = udp.getsockname()[1]
    tcp.listen(16)
    url = f"https://{url_host(host)}:{port}/"
    plan = LaunchPlan(
        plan.browser,
        plan.executable,
        plan.headless,
        firefox_preferences=(
            ("network.http.http3.enable", True),
            ("network.http.http3.alt-svc-mapping-for-testing", f"{host};h3=:{port}"),
            ("network.http.http3.disable_when_third_party_roots_found", False),
            *plan.firefox_preferences,
        ),
    )
    datagrams: list[bytes] = []
    stop = threading.Event()

    def udp_loop() -> None:
        udp.settimeout(0.5)
        while not stop.is_set():
            try:
                datagram, _ = udp.recvfrom(65536)
            except OSError:
                continue
            datagrams.append(datagram)

    def tcp_loop() -> None:
        tcp.settimeout(0.5)
        while not stop.is_set():
            try:
                connection, _ = tcp.accept()
            except OSError:
                continue
            connection.close()

    threads = [threading.Thread(target=udp_loop), threading.Thread(target=tcp_loop)]
    for thread in threads:
        thread.start()
    hello = None
    try:
        with LaunchedBrowser(plan, url):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and hello is None:
                time.sleep(0.5)
                hello = client_hello_from_initials(list(datagrams))
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        udp.close()
        tcp.close()
    return url, [hello] if hello else [], plan, len(datagrams)


def url_host(host: str) -> str:
    """Return an IP literal as a URL writes it, an IPv6 address in brackets."""
    return f"[{host}]" if ":" in host else host


def render_fixture(
    client_version: str,
    url: str,
    preferences: Sequence[tuple[str, bool | int | str]],
    hellos: Sequence[bytes],
    datagrams: int | None,
) -> str:
    """Render one capture: the build, URL, preferences set, and ClientHellos."""
    lines = [f"client_version={client_version}", f"url={url}"]
    lines.append("prefs=" + ";".join(f"{name}={value}" for name, value in preferences))
    if datagrams is not None:
        lines.append(f"datagrams={datagrams}")
    lines.extend(
        f"client_hello_{index}_hex={hello.hex()}" for index, hello in enumerate(hellos)
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firefox-path", type=Path, required=True)
    parser.add_argument("--transport", choices=("tcp", "quic"), required=True)
    parser.add_argument("--family", choices=tuple(HOSTS), required=True)
    parser.add_argument("--grease-size", type=int, help="security.tls.ech.grease_size")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    host = HOSTS[args.family]
    family = socket.AF_INET6 if args.family == "ipv6" else socket.AF_INET
    preferences: tuple[tuple[str, bool | int | str], ...] = ()
    if args.grease_size is not None:
        preferences = (("security.tls.ech.grease_size", args.grease_size),)
    plan = LaunchPlan(
        "firefox", args.firefox_path, headless=True, firefox_preferences=preferences
    )
    version = subprocess.run(
        [str(args.firefox_path), "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    datagrams: int | None = None
    if args.transport == "tcp":
        url, hellos = capture_tcp(plan, host, family, args.timeout)
    else:
        url, hellos, plan, datagrams = capture_quic(plan, host, family, args.timeout)
    fixture = render_fixture(version, url, plan.firefox_preferences, hellos, datagrams)
    write_text_fixture(args.output, fixture)
    print(f"{version} {url}: {len(hellos)} ClientHello(s)")


if __name__ == "__main__":
    main()
