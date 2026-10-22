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
import errno
import math
import random
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoError, CryptoPair
from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, pull_quic_header

from scripts.capture.browser_launch import LaunchedBrowser, LaunchPlan
from scripts.capture.fixture_file import write_text_fixture
from scripts.capture.quic_crypto import validate_protected_packet
from scripts.capture.reserved_ports import open_past_reserved_ports

HANDSHAKE = 0x16
CRYPTO = 0x06
HOSTS = {"ipv4": "127.0.0.1", "ipv6": "::1"}
SHARED_PORTS_FIRST = 20_000
SHARED_PORTS_END = 32_768
MAX_CLIENT_HELLO_BYTES = 64 * 1024
MAX_TLS_BYTES = 128 * 1024
MAX_TLS_RECORDS = 128
MAX_CLIENT_HELLOS = 64
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_DATAGRAMS = 256
MAX_PACKETS = 1024
MAX_FRAMES = 4096
MAX_ACK_RANGES = 128
MAX_CONNECTIONS = 128
POLL_INTERVAL = 0.2
CLEANUP_TIMEOUT = 5.0
VERSION_TIMEOUT = 5.0


def positive_timeout(value: str | float) -> float:
    """Require a finite positive capture deadline before acquiring resources."""
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("capture timeout must be finite and positive")
    return timeout


def _client_hello(data: bytes | bytearray) -> bytes | None:
    if len(data) < 4:
        return None
    if data[0] != 1:
        raise ValueError("handshake does not begin with a ClientHello")
    end = 4 + int.from_bytes(data[1:4], "big")
    if end > MAX_CLIENT_HELLO_BYTES:
        raise ValueError("ClientHello exceeds the capture byte limit")
    return bytes(data[:end]) if len(data) >= end else None


def client_hello_from_records(data: bytes) -> bytes | None:
    """Return the first handshake message of TLS records `data`, once whole."""
    if len(data) > MAX_TLS_BYTES:
        raise ValueError("TLS records exceed the capture byte limit")
    handshake = bytearray()
    offset = 0
    records = 0
    while offset + 5 <= len(data):
        records += 1
        if records > MAX_TLS_RECORDS:
            raise ValueError("TLS record count exceeds the capture limit")
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if offset + 5 + length > len(data):
            break
        if data[offset] == HANDSHAKE:
            if len(handshake) + length > MAX_CLIENT_HELLO_BYTES:
                raise ValueError("TLS handshake exceeds the capture byte limit")
            handshake.extend(data[offset + 5 : offset + 5 + length])
            if (hello := _client_hello(handshake)) is not None:
                return hello
        offset += 5 + length
    return None


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Return a QUIC variable-length integer and the offset after it."""
    if not 0 <= offset < len(data):
        raise ValueError("QUIC variable-length integer is missing")
    first = data[offset]
    length = 1 << (first >> 6)
    if offset + length > len(data):
        raise ValueError("QUIC variable-length integer is truncated")
    value = first & 0x3F
    for index in range(1, length):
        value = (value << 8) | data[offset + index]
    return value, offset + length


def crypto_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """Keep CRYPTO fragments until an unsupported frame, preserving repeated offsets."""
    if len(payload) > MAX_TLS_BYTES:
        raise ValueError("Initial payload exceeds the capture byte limit")
    chunks = []
    offset = 0
    frames = 0
    while offset < len(payload):
        frames += 1
        if frames > MAX_FRAMES:
            raise ValueError("Initial frame count exceeds the capture limit")
        frame, offset = read_varint(payload, offset)
        if frame in (0x00, 0x01):  # PADDING, PING
            continue
        if frame == CRYPTO:
            start, offset = read_varint(payload, offset)
            length, offset = read_varint(payload, offset)
            if start + length > MAX_CLIENT_HELLO_BYTES:
                raise ValueError("Initial CRYPTO exceeds the capture byte limit")
            if length > len(payload) - offset:
                raise ValueError("Initial CRYPTO data is truncated")
            chunks.append((start, payload[offset : offset + length]))
            offset += length
        elif frame in (0x02, 0x03):  # ACK, ACK with ECN counts
            largest, offset = read_varint(payload, offset)
            _, offset = read_varint(payload, offset)
            ranges, offset = read_varint(payload, offset)
            if ranges > MAX_ACK_RANGES:
                raise ValueError("ACK range count exceeds the capture limit")
            first_range, offset = read_varint(payload, offset)
            if first_range > largest:
                raise ValueError("ACK first range exceeds its largest packet")
            smallest = largest - first_range
            for _ in range(ranges):
                gap, offset = read_varint(payload, offset)
                length, offset = read_varint(payload, offset)
                if gap + 2 > smallest or length > smallest - gap - 2:
                    raise ValueError("ACK range precedes packet zero")
                smallest -= gap + 2 + length
            if frame == 0x03:
                for _ in range(3):
                    _, offset = read_varint(payload, offset)
        else:
            break
    return chunks


class _CryptoStream:
    def __init__(self) -> None:
        self.data = bytearray()
        self.received = bytearray()

    def add(self, offset: int, fragment: bytes) -> None:
        end = offset + len(fragment)
        if offset < 0 or end > MAX_CLIENT_HELLO_BYTES:
            raise ValueError("Initial CRYPTO exceeds the capture byte limit")
        if not fragment:
            return
        if end > len(self.data):
            growth = end - len(self.data)
            self.data.extend(bytes(growth))
            self.received.extend(bytes(growth))
        for index, value in enumerate(fragment, start=offset):
            if self.received[index] and self.data[index] != value:
                raise ValueError("Initial CRYPTO contains conflicting overlap")
            self.data[index] = value
            self.received[index] = 1

    def client_hello(self) -> bytes | None:
        if len(self.data) < 4 or not all(self.received[:4]):
            return None
        # Validate the declared size even while the body is incomplete.
        hello = _client_hello(self.data)
        if hello is None or not all(self.received[: len(hello)]):
            return None
        return hello


def client_hello_from_initials(datagrams: Sequence[bytes]) -> bytes | None:
    """Read the first authenticated Initial connection.

    Initial keys are public.
    """
    if len(datagrams) > MAX_DATAGRAMS or sum(map(len, datagrams)) > MAX_CAPTURE_BYTES:
        raise ValueError("Initial datagrams exceed the capture limit")
    crypto: CryptoPair | None = None
    connection: tuple[bytes, int] | None = None
    stream = _CryptoStream()
    expected_packet_number = 0
    packets = 0
    try:
        for datagram in datagrams:
            buffer = Buffer(data=datagram)
            while not buffer.eof():
                start = buffer.tell()
                if not datagram[start] & 0x80:
                    break  # The remaining short-header packet has no length field.
                header = pull_quic_header(buffer, host_cid_length=8)
                header_length = buffer.tell() - start
                end = start + header.packet_length
                if not start < end <= len(datagram):
                    raise ValueError("QUIC packet has an invalid extent")
                buffer.seek(end)
                packets += 1
                if packets > MAX_PACKETS:
                    raise ValueError("QUIC packet count exceeds the capture limit")
                if header.packet_type != QuicPacketType.INITIAL:
                    continue
                if header.version not in (
                    QuicProtocolVersion.VERSION_1,
                    QuicProtocolVersion.VERSION_2,
                ):
                    continue
                identity = (header.destination_cid, header.version)
                if connection is not None and identity != connection:
                    continue
                packet = datagram[start:end]
                validate_protected_packet(packet, header_length)
                candidate = crypto
                if candidate is None:
                    candidate = CryptoPair()
                    candidate.setup_initial(
                        cid=header.destination_cid,
                        is_client=False,
                        version=header.version,
                    )
                try:
                    _, payload, number, _ = candidate.recv.decrypt_packet(
                        packet, header_length, expected_packet_number
                    )
                except CryptoError as error:
                    if candidate is not crypto:
                        candidate.teardown()
                    if str(error) != "Payload decryption failed":
                        raise
                    continue  # Only an authentication mismatch is unrelated traffic.
                if crypto is None:
                    crypto = candidate
                    connection = identity
                expected_packet_number = max(expected_packet_number, number + 1)
                for offset, fragment in crypto_frames(payload):
                    stream.add(offset, fragment)
        return stream.client_hello()
    finally:
        if crypto is not None:
            crypto.teardown()


class _CaptureFailures(Exception):
    def __init__(
        self, primary: BaseException | None, cleanup: tuple[BaseException, ...]
    ) -> None:
        self.primary = primary
        self.cleanup = cleanup
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        self.interruption_cause: BaseException | None = None
        self.interruption_context: BaseException | None = None
        super().__init__("IP-literal capture cleanup failed")


def _raise_capture_failures(
    primary: BaseException | None, cleanup: Sequence[BaseException], owner: _Capture
) -> None:
    if primary is None and not cleanup:
        return
    if not cleanup:
        failure = primary
    elif primary is None and len(cleanup) == 1:
        failure = cleanup[0]
    else:
        failure = _CaptureFailures(primary, tuple(cleanup))
    # Failed resources stay reachable without retrying an unobserved identity.
    failure.capture = owner
    interruption = next(
        (
            error
            for error in (primary, *cleanup)
            if error is not None and not isinstance(error, Exception)
        ),
        None,
    )
    if isinstance(failure, _CaptureFailures) and interruption is not None:
        failure.interruption_cause = interruption.__cause__
        failure.interruption_context = interruption.__context__
        raise interruption from failure
    if failure is primary or primary is None:
        raise failure
    raise failure from primary


class _Capture:
    """Own this run's sockets, started workers and bounded captured records."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.closing = threading.Lock()
        self.sockets: list[socket.socket] = []
        self.threads: list[
            tuple[threading.Thread, threading.Event, threading.Event]
        ] = []
        self.failures: list[BaseException] = []
        self.records: list[bytes] = []
        self.record_bytes = 0
        self.connections = 0

    def open_socket(self, family: socket.AddressFamily, kind: int) -> socket.socket:
        with self.lock:
            if self.stop.is_set():
                raise RuntimeError("IP-literal capture has stopped")
            bound = socket.socket(family, kind)
            self.sockets.append(bound)
            return bound

    def release(self, bound: socket.socket) -> list[BaseException]:
        with self.lock:
            if bound not in self.sockets:
                return []
            try:
                bound.close()
            except BaseException as error:
                return [error]
            self.sockets.remove(bound)
        return []

    def bind(
        self, family: socket.AddressFamily, kind: int, host: str, port: int
    ) -> socket.socket:
        async def open_at(host: str, port: int) -> socket.socket:
            bound = self.open_socket(family, kind)
            try:
                bound.bind((host, port))
            except BaseException as primary:
                _raise_capture_failures(primary, self.release(bound), self)
            return bound

        return asyncio.run(open_past_reserved_ports(open_at, host, port))

    def bind_shared_port(
        self, family: socket.AddressFamily, host: str
    ) -> tuple[socket.socket, socket.socket]:
        # Fixed candidates avoid Windows' independent reserved TCP/UDP ranges.
        last_busy: OSError | None = None
        for port in random.sample(range(SHARED_PORTS_FIRST, SHARED_PORTS_END), 256):
            udp = self.open_socket(family, socket.SOCK_DGRAM)
            tcp = self.open_socket(family, socket.SOCK_STREAM)
            try:
                udp.bind((host, port))
                tcp.bind((host, port))
            except OSError as primary:
                cleanup = [*self.release(udp), *self.release(tcp)]
                busy = primary.errno == errno.EADDRINUSE or getattr(
                    primary, "winerror", None
                ) in (10013, 10055)
                if cleanup or not busy:
                    _raise_capture_failures(primary, cleanup, self)
                last_busy = primary
                continue
            return udp, tcp
        raise OSError("no port was free for both UDP and TCP") from last_busy

    def start(self, operation: Callable[[], None]) -> None:
        entered = threading.Event()
        finished = threading.Event()

        def worker() -> None:
            entered.set()
            try:
                with self.lock:
                    if self.stop.is_set():
                        return
                operation()
            except BaseException as error:
                with self.lock:
                    self.failures.append(error)
                    self.stop.set()
            finally:
                finished.set()

        thread = threading.Thread(target=worker)
        with self.lock:
            if self.stop.is_set():
                if self.failures:
                    raise self.failures.pop(0)
                raise RuntimeError("IP-literal capture has stopped")
            self.threads.append((thread, entered, finished))
        thread.start()

    def check_failure(self) -> None:
        with self.lock:
            if self.failures:
                raise self.failures.pop(0)

    def record(self, data: bytes, maximum: int) -> None:
        with self.lock:
            if (
                len(self.records) >= maximum
                or self.record_bytes + len(data) > MAX_CAPTURE_BYTES
            ):
                raise ValueError("IP-literal capture record limit exceeded")
            self.records.append(data)
            self.record_bytes += len(data)

    def tcp_loop(self, listener: socket.socket, capture_hello: bool) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            with self.lock:
                self.sockets.append(connection)
                self.connections += 1
                if self.connections > MAX_CONNECTIONS:
                    raise ValueError(
                        "IP-literal connection count exceeds the capture limit"
                    )
            primary = None
            try:
                if capture_hello:
                    hello = read_client_hello(connection, self.stop)
                    if hello is not None:
                        self.record(hello, MAX_CLIENT_HELLOS)
            except BaseException as error:
                primary = error
            _raise_capture_failures(primary, self.release(connection), self)

    def udp_loop(self, udp: socket.socket) -> None:
        while not self.stop.is_set():
            try:
                datagram, _ = udp.recvfrom(65536)
            except TimeoutError:
                continue
            self.record(datagram, MAX_DATAGRAMS)

    def close(self) -> list[BaseException]:
        with self.lock:
            self.stop.set()
        try:
            acquired = self.closing.acquire(timeout=CLEANUP_TIMEOUT)
        except BaseException as error:
            return [error]
        if not acquired:
            return [TimeoutError("IP-literal capture cleanup is still active")]
        failures = []
        try:
            deadline = time.monotonic() + CLEANUP_TIMEOUT
            with self.lock:
                threads = tuple(self.threads)
            for thread, entered, finished in threads:
                try:
                    if not entered.wait(max(0, deadline - time.monotonic())):
                        raise TimeoutError("IP-literal worker start remains unobserved")
                    if not finished.wait(max(0, deadline - time.monotonic())):
                        raise TimeoutError(
                            "IP-literal worker did not finish its operation"
                        )
                    thread.join(max(0, deadline - time.monotonic()))
                    if thread.is_alive():
                        raise TimeoutError("IP-literal worker did not stop")
                except BaseException as error:
                    failures.append(error)
                else:
                    self.threads.remove((thread, entered, finished))
            with self.lock:
                sockets = tuple(self.sockets)
            for bound in sockets:
                failures.extend(self.release(bound))
            with self.lock:
                failures[:0] = self.failures
                self.failures.clear()
            return failures
        finally:
            self.closing.release()


def _finish_capture(primary: BaseException | None, owner: _Capture) -> None:
    try:
        cleanup = owner.close()
    except BaseException as error:
        cleanup = [error]
    _raise_capture_failures(primary, cleanup, owner)


def read_client_hello(
    connection: socket.socket, stop: threading.Event | None = None
) -> bytes | None:
    """Read one ClientHello from a TCP connection."""
    stop = stop if stop is not None else threading.Event()
    deadline = time.monotonic() + 5
    data = bytearray()
    last_timeout = None
    while not stop.is_set():
        if (hello := client_hello_from_records(data)) is not None:
            return hello
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                "TCP ClientHello read exceeded its deadline"
            ) from last_timeout
        connection.settimeout(min(POLL_INTERVAL, remaining))
        try:
            chunk = connection.recv(min(65536, MAX_TLS_BYTES + 1 - len(data)))
        except TimeoutError as error:
            last_timeout = error
            continue  # A finite polling timeout permits cooperative shutdown.
        if not chunk:
            if data:
                raise EOFError("TCP peer closed during its ClientHello")
            return None
        data.extend(chunk)
    return None  # Explicit owner shutdown, rather than a failed socket read.


def capture_tcp(
    plan: LaunchPlan, host: str, family: socket.AddressFamily, timeout: float
) -> tuple[str, list[bytes]]:
    """Return the URL and every ClientHello Firefox sent to it over TCP."""
    timeout = positive_timeout(timeout)
    owner = _Capture()
    primary = None
    try:
        listener = owner.bind(family, socket.SOCK_STREAM, host, 0)
        listener.listen(16)
        listener.settimeout(POLL_INTERVAL)
        port = listener.getsockname()[1]
        url = f"https://{url_host(host)}:{port}/"
        owner.start(lambda: owner.tcp_loop(listener, True))
        owner.check_failure()
        with LaunchedBrowser(plan, url):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                with owner.lock:
                    if owner.records or owner.failures:
                        break
                owner.stop.wait(min(0.2, max(0, deadline - time.monotonic())))
    except BaseException as error:
        primary = error
    _finish_capture(primary, owner)
    return url, owner.records


def capture_quic(
    plan: LaunchPlan, host: str, family: socket.AddressFamily, timeout: float
) -> tuple[str, list[bytes], LaunchPlan, int]:
    """Return the URL, the first QUIC ClientHello, the plan, and the datagram count."""
    timeout = positive_timeout(timeout)
    owner = _Capture()
    primary = None
    hello = None
    try:
        udp, tcp = owner.bind_shared_port(family, host)
        port = udp.getsockname()[1]
        tcp.listen(16)
        udp.settimeout(POLL_INTERVAL)
        tcp.settimeout(POLL_INTERVAL)
        url = f"https://{url_host(host)}:{port}/"
        plan = LaunchPlan(
            plan.browser,
            plan.executable,
            plan.headless,
            firefox_preferences=(
                ("network.http.http3.enable", True),
                (
                    "network.http.http3.alt-svc-mapping-for-testing",
                    f"{host};h3=:{port}",
                ),
                ("network.http.http3.disable_when_third_party_roots_found", False),
                *plan.firefox_preferences,
            ),
        )
        owner.start(lambda: owner.udp_loop(udp))
        owner.start(lambda: owner.tcp_loop(tcp, False))
        owner.check_failure()
        with LaunchedBrowser(plan, url):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and hello is None:
                owner.stop.wait(min(0.5, max(0, deadline - time.monotonic())))
                with owner.lock:
                    if owner.failures:
                        break
                    datagrams = tuple(owner.records)
                hello = client_hello_from_initials(datagrams)
    except BaseException as error:
        primary = error
    _finish_capture(primary, owner)
    return url, [hello] if hello else [], plan, len(owner.records)


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
    parser.add_argument("--timeout", type=positive_timeout, default=15.0)
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
        timeout=VERSION_TIMEOUT,
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
