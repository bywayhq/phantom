"""Pinned aioquic/python-h2 CONNECT-UDP relay for explicit interoperability runs."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.metadata
import ipaddress
import json
import ssl
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection, Setting, stream_is_request_response
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.h3.exceptions import InvalidStreamTypeError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    StopSendingReceived,
)
from aioquic.quic.events import StreamReset as QuicStreamReset
from aioquic.quic.packet import pull_quic_transport_parameters
from aioquic.tls import Epoch
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts.capture.reserved_ports import open_past_reserved_ports

MAX_UDP = 65_527
# Loopback peer path ceiling; negotiated receive limits can lower it.
MAX_OUTER_PACKET = 1472
MAX_STREAMS = 128
MAX_BUFFER = 2 * (MAX_UDP + 16)
AUTHORIZATION = b"Basic dXNlcjpwYXNz"


def varint(value: int) -> bytes:
    """Encode one RFC 9000 integer without masking overflow."""
    if not 0 <= value < 1 << 62:
        raise ValueError("varint outside wire range")
    for width, bound, prefix in (
        (1, 64, 0),
        (2, 16384, 0x4000),
        (4, 1 << 30, 0x80000000),
        (8, 1 << 62, 0xC000000000000000),
    ):
        if value < bound:
            return (value | prefix).to_bytes(width, "big")
    raise AssertionError("integer range already validated")


def decode(data: bytes | bytearray, offset: int = 0) -> tuple[int, int] | None:
    if len(data) <= offset:
        return None
    width = 1 << (data[offset] >> 6)
    if len(data) < offset + width:
        return None
    return int.from_bytes(data[offset : offset + width], "big") & (
        (1 << (8 * width - 2)) - 1
    ), offset + width


def target(headers: list[tuple[bytes, bytes]]) -> tuple[str, int]:
    fields = dict(headers)
    if (
        fields.get(b":method") != b"CONNECT"
        or fields.get(b":protocol") != b"connect-udp"
    ):
        raise ValueError("peer requires extended CONNECT-UDP")
    if fields.get(b"capsule-protocol") != b"?1":
        raise ValueError("peer requires capsule-protocol")
    path = fields[b":path"].decode("ascii")
    prefix = "/.well-known/masque/udp/"
    if not path.startswith(prefix):
        raise ValueError("unsupported peer URI template")
    host, port, end = path[len(prefix) :].split("/")
    host = host.replace("%3A", ":")
    if end or not ipaddress.ip_address(host).is_loopback:
        raise ValueError("peer target must be loopback")
    port = int(port)
    if not 0 < port <= 65535:
        raise ValueError("invalid target port")
    return host, port


class Capsules:
    """Incremental bounded parser; unknown types/contexts are skipped."""

    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        if len(self.buffer) + len(data) > MAX_BUFFER:
            raise ValueError("capsule buffer bound exceeded")
        self.buffer.extend(data)
        result = []
        while self.buffer:
            capsule_type = decode(self.buffer)
            if capsule_type is None:
                break
            length = decode(self.buffer, capsule_type[1])
            if length is None:
                break
            if length[0] > MAX_UDP + 8:
                raise ValueError("capsule length bound exceeded")
            end = length[1] + length[0]
            if len(self.buffer) < end:
                break
            payload = bytes(self.buffer[length[1] : end])
            del self.buffer[:end]
            if capsule_type[0] == 0:
                context = decode(payload)
                if context is None:
                    raise ValueError("missing datagram context")
                if context[0] == 0:
                    value = payload[context[1] :]
                    if len(value) > MAX_UDP:
                        raise ValueError("UDP payload bound exceeded")
                    result.append(value)
        return result

    def finish(self):
        if self.buffer:
            raise ValueError("truncated capsule")


class Statistics:
    def __init__(self, path: Path):
        self.path = path
        self.connections = 0
        self.requests = []
        self.failures = []
        self.write()

    def write(self):
        # The reader observes a complete JSON snapshot after atomic replacement.
        temporary = self.path.with_suffix(".next")
        temporary.write_text(
            json.dumps(
                {
                    "connections": self.connections,
                    "requests": self.requests,
                    "failures": self.failures,
                }
            ),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def request(self, connection, stream, headers):
        if len(self.requests) == MAX_STREAMS:
            raise ValueError("peer request record bound exceeded")
        self.requests.append(
            {
                "connection": connection,
                "stream": stream,
                "authorized": (b"proxy-authorization", AUTHORIZATION) in headers,
            }
        )
        self.write()

    def failure(self, error):
        self.failures.append(type(error).__name__ + ": " + str(error))
        self.write()


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, received):
        self.received = received
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, _address):
        self.received(data)

    def error_received(self, error):
        # An origin shut down independently; ICMP does not close sibling flows.
        if (
            isinstance(error, ConnectionRefusedError)
            or getattr(error, "winerror", None) == 10054
        ):
            return
        asyncio.get_running_loop().call_exception_handler(
            {"message": "UDP relay error", "exception": error}
        )


async def udp_relay(destination, received):
    async def bind(host, port):
        return await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UdpRelay(received), local_addr=(host, port), remote_addr=destination
        )

    transport, _ = await open_past_reserved_ports(bind, destination[0], 0)
    return transport


def datagram_fits(quic, stream_id, data):
    # Pinned aioquic 1.3.0 packet_builder.py: 1-RTT header is 3 + peer CID,
    # followed by the AEAD tag. connection.py adds type and varint length.
    payload_size = len(varint(stream_id // 4)) + len(data)
    frame_size = 1 + len(varint(payload_size)) + payload_size
    remote_limit = quic._remote_max_datagram_frame_size
    crypto = quic._cryptos[Epoch.ONE_RTT]
    packet_space = quic._max_datagram_size - 3 - len(quic._peer_cid.cid)
    packet_space -= crypto.aead_tag_size
    return remote_limit is not None and frame_size <= min(remote_limit, packet_space)


class DatagramH3(H3Connection):
    def send_datagram(self, stream_id, data):
        if not stream_is_request_response(stream_id):
            raise InvalidStreamTypeError("Datagrams require a client request stream")
        if not datagram_fits(self._quic, stream_id, data):
            return False
        super().send_datagram(stream_id, data)
        return True

    def _get_local_settings(self):
        # Pinned aioquic 1.3.0 seam: enable RFC 9297 without WebTransport.
        settings = super()._get_local_settings()
        settings[Setting.H3_DATAGRAM] = 1
        return settings


class H3Relay(QuicConnectionProtocol):
    def __init__(self, *args, stats, challenge, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats = stats
        self.challenge = challenge
        self.http = None
        self.flows = {}
        self.tasks = set()
        self.connection_id = None
        # aioquic validates max_udp_payload_size but does not retain/apply it.
        # Install before the server receives its first handshake datagram.
        parse_parameters = self._quic._parse_transport_parameters

        def apply_parameters(data, from_session_ticket=False):
            parse_parameters(data, from_session_ticket=from_session_ticket)
            parameters = pull_quic_transport_parameters(Buffer(data=data))
            if parameters.max_udp_payload_size is not None:
                self._quic._max_datagram_size = min(
                    self._quic._max_datagram_size, parameters.max_udp_payload_size
                )

        self._quic._parse_transport_parameters = apply_parameters

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = DatagramH3(self._quic)
            self.stats.connections += 1
            self.connection_id = self.stats.connections
            self.stats.write()
        if isinstance(event, ConnectionTerminated):
            for transport, _ in self.flows.values():
                if transport is not None:
                    transport.close()
            for task in self.tasks:
                task.cancel()
            self.flows.clear()
        if isinstance(event, (QuicStreamReset, StopSendingReceived)):
            flow = self.flows.pop(event.stream_id, None)
            if flow is not None and flow[0] is not None:
                flow[0].close()
        if self.http is None:
            return
        for received in self.http.handle_event(event):
            if isinstance(received, HeadersReceived):
                headers = received.headers
                self.stats.request(self.connection_id, received.stream_id, headers)
                if (
                    self.challenge
                    and (b"proxy-authorization", AUTHORIZATION) not in headers
                ):
                    self.http.send_headers(
                        received.stream_id,
                        [
                            (b":status", b"407"),
                            (b"proxy-authenticate", b'Basic realm="masque"'),
                        ],
                        end_stream=True,
                    )
                    self.transmit()
                    continue
                destination = target(headers)
                if len(self.flows) == MAX_STREAMS:
                    raise ValueError("peer active stream bound exceeded")
                self.flows[received.stream_id] = (None, [])
                task = asyncio.create_task(
                    self.open_flow(received.stream_id, destination)
                )
                self.tasks.add(task)
                task.add_done_callback(self.flow_finished)
            elif isinstance(received, DatagramReceived):
                context = decode(received.data)
                if (
                    context is None
                    or context[0] != 0
                    or len(received.data) - context[1] > MAX_UDP
                ):
                    continue
                flow = self.flows.get(received.stream_id)
                if flow is not None:
                    payload = received.data[context[1] :]
                    if flow[0] is not None:
                        flow[0].sendto(payload)
                    elif len(flow[1]) < 64:
                        flow[1].append(payload)
            elif isinstance(received, DataReceived) and received.stream_ended:
                flow = self.flows.pop(received.stream_id, None)
                if flow is not None and flow[0] is not None:
                    flow[0].close()

    def flow_finished(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.stats.failure(task.exception())
            self.close(error_code=0x102, reason_phrase="relay setup failed")

    async def open_flow(self, stream_id, destination):
        def received(data):
            self.http.send_datagram(stream_id, b"\x00" + data)
            self.transmit()

        transport = await udp_relay(destination, received)
        flow = self.flows.get(stream_id)
        if flow is None:
            transport.close()
            return
        self.flows[stream_id] = (transport, [])
        self.http.send_headers(
            stream_id, [(b":status", b"200"), (b"capsule-protocol", b"?1")]
        )
        self.transmit()
        for payload in flow[1]:
            transport.sendto(payload)


async def h2_connection(reader, writer, stats, challenge):
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import (
        ConnectionTerminated as H2Terminated,
    )
    from h2.events import (
        DataReceived as H2Data,
    )
    from h2.events import (
        RequestReceived,
        StreamEnded,
        StreamReset,
        WindowUpdated,
    )
    from h2.settings import SettingCodes

    stats.connections += 1
    connection_id = stats.connections
    stats.write()
    connection = H2Connection(
        config=H2Configuration(client_side=False, header_encoding=None)
    )
    connection.initiate_connection()
    connection.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
    writer.write(connection.data_to_send())
    await writer.drain()
    flows = {}
    tasks = set()
    capacity = asyncio.Event()
    stream_writes = {}

    async def send(stream, data):
        async with stream_writes.setdefault(stream, asyncio.Lock()):
            await send_ordered(stream, data)

    async def send_ordered(stream, data):
        try:
            while data:
                count = min(
                    connection.local_flow_control_window(stream),
                    connection.max_outbound_frame_size,
                    len(data),
                )
                if count == 0:
                    capacity.clear()
                    await capacity.wait()
                    continue
                connection.send_data(stream, data[:count])
                data = data[count:]
                writer.write(connection.data_to_send())
                await writer.drain()
        except Exception as error:
            stats.failure(error)
            writer.close()

    def task_finished(task):
        tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            stats.failure(task.exception())
            writer.close()

    async def open_flow(stream, destination):
        def received(data):
            payload = b"\x00" + data
            if len(tasks) >= 256:
                return
            task = asyncio.create_task(
                send(stream, b"\x00" + varint(len(payload)) + payload)
            )
            tasks.add(task)
            task.add_done_callback(task_finished)

        transport = await udp_relay(destination, received)
        flow = flows.get(stream)
        if flow is None:
            transport.close()
            return
        flows[stream] = (transport, flow[1], [])
        connection.send_headers(
            stream, [(b":status", b"200"), (b"capsule-protocol", b"?1")]
        )
        writer.write(connection.data_to_send())
        await writer.drain()
        for payload in flow[2]:
            transport.sendto(payload)

    try:
        while data := await reader.read(16 * 1024):
            for event in connection.receive_data(data):
                if isinstance(event, RequestReceived):
                    stats.request(connection_id, event.stream_id, event.headers)
                    if (
                        challenge
                        and (b"proxy-authorization", AUTHORIZATION) not in event.headers
                    ):
                        connection.send_headers(
                            event.stream_id,
                            [
                                (b":status", b"407"),
                                (b"proxy-authenticate", b'Basic realm="masque"'),
                            ],
                            end_stream=True,
                        )
                        continue
                    destination = target(event.headers)
                    if len(flows) == MAX_STREAMS:
                        raise ValueError("peer active stream bound exceeded")
                    flows[event.stream_id] = (None, Capsules(), [])
                    task = asyncio.create_task(open_flow(event.stream_id, destination))
                    tasks.add(task)
                    task.add_done_callback(task_finished)
                elif isinstance(event, H2Data):
                    connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    flow = flows.get(event.stream_id)
                    if flow is not None:
                        for payload in flow[1].feed(event.data):
                            if flow[0] is not None:
                                flow[0].sendto(payload)
                            elif len(flow[2]) < 64:
                                flow[2].append(payload)
                elif isinstance(event, (StreamEnded, StreamReset)):
                    flow = flows.pop(event.stream_id, None)
                    if flow is not None:
                        if isinstance(event, StreamEnded):
                            flow[1].finish()
                        if flow[0] is not None:
                            flow[0].close()
                elif isinstance(event, WindowUpdated):
                    capacity.set()
                elif isinstance(event, H2Terminated):
                    return
            writer.write(connection.data_to_send())
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        pass
    except Exception as error:
        stats.failure(error)
    finally:
        for transport, _, _ in flows.values():
            if transport is not None:
                transport.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        with contextlib.suppress(
            ConnectionResetError, BrokenPipeError, ConnectionAbortedError
        ):
            await writer.wait_closed()


async def run(args):
    for package, version in (("aioquic", "1.3.0"), ("h2", "4.4.1"), ("hpack", "4.2.0")):
        if importlib.metadata.version(package) != version:
            raise ValueError(f"peer requires {package}=={version}")
    certificate = x509.load_der_x509_certificate(
        (args.directory / "certificate.der").read_bytes()
    )
    key = serialization.load_der_private_key(
        (args.directory / "key.der").read_bytes(), password=None
    )
    cert_path = args.directory / "certificate.pem"
    key_path = args.directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    stats = Statistics(args.directory / "stats.json")
    asyncio.get_running_loop().set_exception_handler(
        lambda _loop, context: stats.failure(
            context.get("exception", RuntimeError(context["message"]))
        )
    )
    if args.leg == "h3":
        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=["h3"],
            max_datagram_frame_size=65536,
            max_datagram_size=MAX_OUTER_PACKET,
        )
        configuration.load_cert_chain(cert_path, key_path)

        async def bind(host, port):
            return await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: QuicServer(
                    configuration=configuration,
                    create_protocol=lambda *a, **kw: H3Relay(
                        *a, stats=stats, challenge=args.challenge, **kw
                    ),
                ),
                local_addr=(host, port),
            )

        server, _ = await open_past_reserved_ports(bind, "127.0.0.1", 0)
        address = server.get_extra_info("sockname")
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.set_alpn_protocols(["h2"])
        server = await asyncio.start_server(
            lambda r, w: h2_connection(r, w, stats, args.challenge),
            "127.0.0.1",
            0,
            ssl=context,
        )
        address = server.sockets[0].getsockname()
    ready_path = args.directory / "ready.next"
    ready_path.write_text(
        json.dumps(
            {
                "port": address[1],
                "leg": args.leg,
                "aioquic": "1.3.0",
                "h2": "4.4.1",
                "hpack": "4.2.0",
            }
        ),
        encoding="utf-8",
    )
    ready_path.replace(args.directory / "ready.json")
    try:
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()

        def check_stop():
            if (args.directory / "stop").exists():
                stopped.set()
            else:
                loop.call_later(0.02, check_stop)

        check_stop()
        await stopped.wait()
    finally:
        server.close()
        if args.leg == "h2":
            await server.wait_closed()
        stats.write()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--leg", choices=("h2", "h3"), required=True)
    parser.add_argument("--challenge", action="store_true")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
