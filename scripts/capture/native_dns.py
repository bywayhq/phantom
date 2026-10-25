"""A bounded loopback DNS peer for one explicitly owned capture hostname.

A answers contain 127.0.0.1; AAAA and HTTPS answers contain no records. This
authoritative peer performs no recursion or DNSSEC validation. It accepts one
uncompressed IN question and optionally one empty EDNS0 OPT without flags.
Malformed/unsupported packets stop the capture rather than inventing a reply.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import time
from dataclasses import dataclass

MAX_MESSAGE = 4096
MAX_QUERIES = 512
MAX_TCP_CONNECTIONS = 64
MAX_ACTIVE_TCP = 16
IO_SECONDS = 5.0


@dataclass(frozen=True)
class Question:
    name: str
    kind: int
    end: int
    edns_size: int | None


def question(wire: bytes) -> Question:
    """Parse the supported query shape; reject compression and extra sections."""
    if not 12 <= len(wire) <= MAX_MESSAGE:
        raise ValueError("DNS message length is outside 12..4096 bytes")
    _, flags, questions, answers, authority, additional = struct.unpack(
        "!6H", wire[:12]
    )
    if flags & ~0x0100:
        raise ValueError("DNS query supports only the recursion-desired flag")
    if (questions, answers, authority) != (1, 0, 0) or additional > 1:
        raise ValueError("DNS query requires one question and at most one empty OPT")
    labels = []
    offset = 12
    while True:
        if offset >= len(wire):
            raise ValueError("DNS question name is truncated")
        size = wire[offset]
        offset += 1
        if size == 0:
            break
        if size > 63:
            raise ValueError("DNS compressed or extended question label is unsupported")
        end = offset + size
        if end > len(wire) or end - 12 >= 255:
            raise ValueError(
                "DNS question label is truncated or name exceeds 255 bytes"
            )
        try:
            label = wire[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("DNS question labels must be ASCII") from error
        if any(ord(char) <= 32 or ord(char) >= 127 or char == "." for char in label):
            raise ValueError(
                "DNS question label is outside the supported hostname form"
            )
        labels.append(label.lower())
        offset = end
    if offset + 4 > len(wire):
        raise ValueError("DNS question type or class is truncated")
    kind, klass = struct.unpack("!HH", wire[offset : offset + 4])
    if klass != 1:
        raise ValueError("DNS question requires class IN")
    offset += 4
    edns_size = None
    if additional:
        opt = wire[offset:]
        if len(opt) != 11 or opt[0] != 0:
            raise ValueError("DNS additional record must be one empty root OPT")
        opt_kind, size, extensions, length = struct.unpack("!HHIH", opt[1:])
        if opt_kind != 41 or extensions != 0 or length != 0:
            raise ValueError("DNS OPT requires EDNS0 without flags or options")
        edns_size = min(MAX_MESSAGE, max(512, size))
    elif offset != len(wire):
        raise ValueError("DNS query has trailing bytes")
    return Question(".".join(labels), kind, offset, edns_size)


def response(
    wire: bytes,
    parsed: Question,
    hostname: str,
    ttl: int,
    ipv4_answers: tuple[str, ...] = ("127.0.0.1",),
) -> bytes:
    """Echo the question; advertise authority only for the supported owned name."""
    owned = parsed.name == hostname
    supported = parsed.kind in (1, 28, 65)
    answer = owned and parsed.kind == 1
    code = 0 if owned and supported else 5  # REFUSED outside this narrow contract.
    flags = 0x8000 | (struct.unpack("!H", wire[2:4])[0] & 0x0100) | code
    if owned and supported:
        flags |= 0x0400
    output = (
        struct.pack(
            "!6H",
            int.from_bytes(wire[:2], "big"),
            flags,
            1,
            len(ipv4_answers) if answer else 0,
            0,
            int(parsed.edns_size is not None),
        )
        + wire[12 : parsed.end]
    )
    if answer:
        for address in ipv4_answers:
            output += (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, ttl, 4)
                + ipaddress.IPv4Address(address).packed
            )
    if parsed.edns_size is not None:
        output += b"\x00" + struct.pack("!HHIH", 41, parsed.edns_size, 0, 0)
    return output


class NativeDnsFailure(RuntimeError):
    """The peer's original failures remain available after cleanup."""

    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        super().__init__("native DNS peer failed")


class _ReadTimeout(TimeoutError):
    def __init__(self, partial: bytes) -> None:
        self.partial = partial
        super().__init__("native DNS TCP frame read timed out")


async def _read_part(reader: asyncio.StreamReader, size: int) -> bytes:
    partial = bytearray()
    deadline = asyncio.get_running_loop().time() + IO_SECONDS
    while len(partial) < size:
        remaining = max(0, deadline - asyncio.get_running_loop().time())
        try:
            data = await asyncio.wait_for(reader.read(size - len(partial)), remaining)
        except asyncio.TimeoutError as error:
            raise _ReadTimeout(bytes(partial)) from error
        if not data:
            raise asyncio.IncompleteReadError(bytes(partial), size)
        partial.extend(data)
    return bytes(partial)


class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, owner: NativeDnsServer) -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, peer: tuple) -> None:
        if self.owner.stopping:
            return
        previous = len(self.owner.journal)
        try:
            answer = self.owner.exchange(data, peer, "udp")
            if answer is not None:
                self.owner.udp.sendto(answer, peer)
                self.owner.journal[-1]["response_queued_ns"] = time.time_ns()
        except BaseException as error:
            if len(self.owner.journal) > previous:
                self.owner.journal[-1]["error"] = str(error)
            self.owner.fail(error)

    def error_received(self, error: Exception) -> None:
        self.owner.fail(error)

    def connection_lost(self, error: Exception | None) -> None:
        if error is not None:
            self.owner.fail(error)
        elif not self.owner.stopping:
            self.owner.fail(
                RuntimeError("native DNS UDP listener stopped unexpectedly")
            )
        self.owner.udp_closed.set()


class NativeDnsServer:
    """Own UDP/TCP listeners and a bounded raw journal for one capture hostname.

    `start()` binds both protocols to the same loopback port, refusing an existing
    listener. Port 0 is for tests. `close()` is idempotent, observes all handlers,
    and raises `NativeDnsFailure` for any retained error. A cancelled/timed-out
    close retains its cleanup task; call close again to collect that owner.
    `drop_first_udp_a` leaves exactly the first owned UDP A question unanswered.
    `drop_owned_udp` leaves every owned UDP question unanswered and rejects TCP
    connections as capture failures, so another transport cannot defeat silence.
    `ipv4_answers` retains one or two distinct loopback addresses in wire order,
    with the same TTL on each A record.
    """

    def __init__(
        self,
        hostname: str,
        address: str = "127.0.0.53",
        port: int = 53,
        *,
        ttl: int = 5,
        ipv4_answers: tuple[str, ...] = ("127.0.0.1",),
        drop_first_udp_a: bool = False,
        drop_owned_udp: bool = False,
    ) -> None:
        labels = hostname.removesuffix(".").split(".")
        if (
            not labels
            or any(not 1 <= len(label) <= 63 for label in labels)
            or any(label.startswith("-") or label.endswith("-") for label in labels)
            or any(
                not label.isascii() or not all(c.isalnum() or c == "-" for c in label)
                for label in labels
            )
            or len(".".join(labels)) > 253
        ):
            raise ValueError("native DNS hostname must be a bounded ASCII hostname")
        if not ipaddress.ip_address(address).is_loopback:
            raise ValueError("native DNS listener must be loopback")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("native DNS port must be in 0..65535")
        if type(ttl) is not int or not 0 <= ttl <= 86400:
            raise ValueError("native DNS TTL must be in 0..86400 seconds")
        if drop_first_udp_a and drop_owned_udp:
            raise ValueError("native DNS drop policies are mutually exclusive")
        if (
            not isinstance(ipv4_answers, tuple)
            or not 1 <= len(ipv4_answers) <= 2
            or any(not isinstance(item, str) for item in ipv4_answers)
            or len(set(ipv4_answers)) != len(ipv4_answers)
            or any(not ipaddress.IPv4Address(item).is_loopback for item in ipv4_answers)
        ):
            raise ValueError(
                "native DNS requires one or two distinct loopback A answers"
            )
        self.hostname = ".".join(labels).lower()
        self.address = (address, port)
        self.ttl = ttl
        self.ipv4_answers = ipv4_answers
        self._drop_first_udp_a = drop_first_udp_a
        self._drop_owned_udp = drop_owned_udp
        self.udp: asyncio.DatagramTransport | None = None
        self.tcp: asyncio.Server | None = None
        self.udp_closed = asyncio.Event()
        self.failed = asyncio.Event()
        self.failures: list[BaseException] = []
        self.handlers: set[asyncio.Task] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.journal: list[dict] = []
        self.accepted = 0
        self.stopping = False
        self.started = False
        self.cleanup: asyncio.Task | None = None
        self.cleanup_complete = False

    async def start(self) -> None:
        if self.started or self.stopping:
            raise RuntimeError("native DNS peer cannot be started twice")
        self.started = True
        udp_socket = None
        tcp_socket = None
        try:
            if self.address[1] == 0:
                # Shared ephemeral ports need dispersed candidates on Windows;
                # the existing capture allocator handles both exclusions.
                from .alt_svc_race import reserve_ports

                udp_socket, tcp_socket = reserve_ports(self.address[0])
            else:
                udp_socket = self.bound_socket(socket.SOCK_DGRAM, *self.address)
                tcp_socket = self.bound_socket(socket.SOCK_STREAM, *self.address)
            self.address = udp_socket.getsockname()[:2]
            tcp_socket.listen(MAX_ACTIVE_TCP)
            self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _Datagrams(self), sock=udp_socket
            )
            udp_socket = None  # Ownership moved into the datagram transport.
            self.tcp = await asyncio.start_server(
                self.accept, sock=tcp_socket, limit=MAX_MESSAGE + 2
            )
            tcp_socket = None
        except BaseException as error:
            for channel in (udp_socket, tcp_socket):
                if channel is not None:
                    channel.close()
            self.fail(error)
            try:
                await self.close()
            except NativeDnsFailure as cleanup:
                if isinstance(error, asyncio.CancelledError):
                    raise error from cleanup
                raise

    @staticmethod
    def bound_socket(kind: int, host: str, port: int) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        channel = socket.socket(family, kind)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            channel.bind((host, port))
            channel.setblocking(False)
            return channel
        except BaseException:
            channel.close()
            raise

    def fail(self, error: BaseException) -> None:
        if not any(error is previous for previous in self.failures):
            self.failures.append(error)
        self.failed.set()
        self.stopping = True
        if self.udp is not None:
            self.udp.close()
        if self.tcp is not None:
            self.tcp.close()

    def record(self, wire: bytes, peer: tuple, transport: str) -> dict:
        if len(self.journal) >= MAX_QUERIES:
            raise ValueError("native DNS query count exceeds 512")
        record = {
            "unix_ns": time.time_ns(),
            "transport": transport,
            "peer": peer,
            "query_hex": wire[:MAX_MESSAGE].hex(),
            "query_size": len(wire),
            "response_hex": None,
            "error": None,
        }
        self.journal.append(record)
        return record

    def exchange(self, wire: bytes, peer: tuple, transport: str) -> bytes | None:
        record = self.record(wire, peer, transport)
        try:
            parsed = question(wire)
            record.update(name=parsed.name, kind=parsed.kind)
            if self._drop_owned_udp and parsed.name == self.hostname:
                if transport != "udp":
                    raise ValueError("silent native DNS peer does not support TCP")
                record["disposition"] = "dropped-owned-udp"
                return None
            if (
                self._drop_first_udp_a
                and transport == "udp"
                and parsed.name == self.hostname
                and parsed.kind == 1
            ):
                self._drop_first_udp_a = False
                record["disposition"] = "dropped-first-udp-a"
                return None
            answer = response(wire, parsed, self.hostname, self.ttl, self.ipv4_answers)
        except BaseException as error:
            record["error"] = str(error)
            raise
        record["response_hex"] = answer.hex()
        return answer

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.accepted += 1
        if self._drop_owned_udp:
            writer.transport.abort()
            self.fail(ValueError("silent native DNS peer does not support TCP"))
            return
        if (
            self.stopping
            or len(self.handlers) >= MAX_ACTIVE_TCP
            or self.accepted > MAX_TCP_CONNECTIONS
        ):
            # No handler/task is admitted for excess connections. Abort also
            # retires the stream protocol without waiting on remote input.
            writer.transport.abort()
            self.fail(ValueError("native DNS TCP connection limit exceeded"))
            return
        self.writers.add(writer)
        task = asyncio.create_task(self.serve(reader, writer))
        self.handlers.add(task)
        task.add_done_callback(self.completed)

    def completed(self, task: asyncio.Task) -> None:
        self.handlers.discard(task)
        try:
            task.result()
        except asyncio.CancelledError as error:
            if not self.stopping:
                self.fail(error)
        except BaseException as error:
            self.fail(error)

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        record = None
        try:
            while not self.stopping:
                record = None
                try:
                    prefix = await _read_part(reader, 2)
                except (asyncio.IncompleteReadError, _ReadTimeout) as error:
                    if (
                        isinstance(error, asyncio.IncompleteReadError)
                        and not error.partial
                    ):
                        return  # Clean EOF between framed requests.
                    record = self.record(b"", peer, "tcp")
                    record["length_hex"] = error.partial.hex()
                    if isinstance(error, _ReadTimeout):
                        raise
                    raise ValueError("native DNS TCP length is truncated") from error
                size = int.from_bytes(prefix, "big")
                if not 12 <= size <= MAX_MESSAGE:
                    record = self.record(b"", peer, "tcp")
                    record.update(length_hex=prefix.hex(), declared_size=size)
                    raise ValueError("native DNS TCP frame length is outside 12..4096")
                try:
                    wire = await _read_part(reader, size)
                except (asyncio.IncompleteReadError, _ReadTimeout) as error:
                    record = self.record(error.partial, peer, "tcp")
                    record.update(length_hex=prefix.hex(), declared_size=size)
                    if isinstance(error, _ReadTimeout):
                        raise
                    raise ValueError("native DNS TCP payload is truncated") from error
                answer = self.exchange(wire, peer, "tcp")
                record = self.journal[-1]
                if answer is None:
                    raise RuntimeError("native DNS TCP reply was unexpectedly dropped")
                writer.write(struct.pack("!H", len(answer)) + answer)
                await asyncio.wait_for(writer.drain(), IO_SECONDS)
                record["response_drained_ns"] = time.time_ns()
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError) or not self.stopping:
                if isinstance(error, asyncio.TimeoutError):
                    timeout = TimeoutError("native DNS TCP exchange timed out")
                    timeout.__cause__ = error
                    error = timeout
                if record is not None:
                    record["error"] = str(error)
                self.fail(error)
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), IO_SECONDS)
            except BaseException as error:
                if isinstance(error, asyncio.TimeoutError):
                    timeout = TimeoutError("native DNS TCP close timed out")
                    timeout.__cause__ = error
                    error = timeout
                self.fail(error)
            else:
                self.writers.discard(writer)

    async def shutdown(self) -> None:
        self.stopping = True
        if self.udp is not None:
            self.udp.close()
        if self.tcp is not None:
            self.tcp.close()
        for task in tuple(self.handlers):
            task.cancel()
        if self.handlers:
            outcomes = await asyncio.gather(
                *tuple(self.handlers), return_exceptions=True
            )
            for error in outcomes:
                if isinstance(error, BaseException) and not isinstance(
                    error, asyncio.CancelledError
                ):
                    self.fail(error)
        for writer in tuple(self.writers):
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), IO_SECONDS)
            except BaseException as error:
                self.fail(error)
            else:
                self.writers.discard(writer)
        if self.tcp is not None:
            await self.tcp.wait_closed()
        if self.udp is not None:
            await self.udp_closed.wait()
        self.cleanup_complete = not self.writers and not self.handlers

    async def close(self) -> None:
        if self.cleanup is None or (self.cleanup.done() and not self.cleanup_complete):
            self.cleanup = asyncio.create_task(self.shutdown())
            self.cleanup.add_done_callback(self.observe_cleanup)
        _, pending = await asyncio.wait((self.cleanup,), timeout=IO_SECONDS)
        if pending:
            error = TimeoutError(
                "native DNS cleanup timed out; owner remains collectable"
            )
            self.fail(error)
            raise error
        self.observe_cleanup(self.cleanup)
        if self.failures:
            raise NativeDnsFailure(tuple(self.failures)) from self.failures[0]

    def observe_cleanup(self, task: asyncio.Task) -> None:
        try:
            task.result()
        except BaseException as error:
            self.fail(error)

    def records(self) -> list[dict]:
        """Snapshot raw input and prepared replies; queue/drain events are explicit.

        Oversized UDP input is retained up to MAX_MESSAGE with its actual size.
        Partial TCP frames retain their received bytes and declared length.
        """
        return [dict(record) for record in self.journal]
