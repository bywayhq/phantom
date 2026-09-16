"""Bounded, payload-free analysis of captured client QUIC datagrams.

The analyzer accepts UDP payloads and NSS key-log lines in memory, authenticates
and decrypts QUIC v1 packets with aioquic, and returns only packet-space and
frame-layout metadata. Captured datagrams and traffic secrets are cleared after
one analysis attempt and are never included in the returned summary.
"""

from __future__ import annotations

from aioquic.buffer import Buffer, BufferReadError
from aioquic.quic.crypto import CryptoContext, CryptoError, CryptoPair
from aioquic.quic.packet import (
    CONNECTION_ID_MAX_SIZE,
    QuicFrameType,
    QuicPacketType,
    QuicProtocolVersion,
    pull_quic_header,
)
from aioquic.tls import CipherSuite

from .quic_flight import PacketSummary
from .quic_summary import (
    FrameKind,
    NormalizedPacket,
    StreamFrame,
    SymbolicSpan,
)

DEFAULT_MAX_DATAGRAMS = 64
DEFAULT_MAX_DATAGRAM_BYTES = 256 * 1024
DEFAULT_MAX_KEY_LOG_LINES = 8
DEFAULT_MAX_KEY_LOG_CHARS = 4096

_CLIENT_HANDSHAKE_SECRET = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
_CLIENT_APPLICATION_SECRET = "CLIENT_TRAFFIC_SECRET_0"
_IGNORED_SERVER_SECRETS = {
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
}


class QuicPacketCapture:
    """Collects bounded datagrams and key-log lines for one analysis attempt."""

    def __init__(
        self,
        *,
        max_datagrams: int = DEFAULT_MAX_DATAGRAMS,
        max_datagram_bytes: int = DEFAULT_MAX_DATAGRAM_BYTES,
        max_key_log_lines: int = DEFAULT_MAX_KEY_LOG_LINES,
        max_key_log_chars: int = DEFAULT_MAX_KEY_LOG_CHARS,
    ) -> None:
        if (
            min(
                max_datagrams,
                max_datagram_bytes,
                max_key_log_lines,
                max_key_log_chars,
            )
            <= 0
        ):
            raise ValueError("capture limits must be positive")
        self._max_datagrams = max_datagrams
        self._max_datagram_bytes = max_datagram_bytes
        self._max_key_log_lines = max_key_log_lines
        self._max_key_log_chars = max_key_log_chars
        self._datagrams: list[bytearray] = []
        self._datagram_bytes = 0
        self._key_log_lines = 0
        self._key_log_chars = 0
        self._key_log_pending = ""
        self._client_random: bytearray | None = None
        self._secrets: dict[str, bytearray] = {}
        self._accept_datagrams = True
        self._closed = False

    @property
    def buffered_datagram_count(self) -> int:
        """Returns the number of datagrams still retained in memory."""

        return len(self._datagrams)

    @property
    def buffered_secret_count(self) -> int:
        """Returns the number of traffic secrets still retained in memory."""

        return len(self._secrets)

    def add_datagram(self, data: bytes) -> None:
        """Copies one UDP payload into the bounded in-memory capture."""

        self._require_open()
        if not self._accept_datagrams:
            return
        if len(self._datagrams) >= self._max_datagrams:
            self._abort("datagram count exceeds the capture limit")
        if self._datagram_bytes + len(data) > self._max_datagram_bytes:
            self._abort("datagram bytes exceed the capture limit")
        self._datagrams.append(bytearray(data))
        self._datagram_bytes += len(data)

    def finish_datagrams(self) -> None:
        """Freezes the packet boundary while still accepting pending key-log lines."""

        self._require_open()
        self._accept_datagrams = False

    def write(self, data: str) -> int:
        """Consumes NSS key-log text, matching the TextIO interface aioquic uses."""

        self._require_open()
        if not isinstance(data, str):
            raise TypeError("key-log input must be text")
        if self._key_log_chars + len(data) > self._max_key_log_chars:
            self._abort("key-log text exceeds the capture limit")
        self._key_log_chars += len(data)
        self._key_log_pending += data
        while "\n" in self._key_log_pending:
            line, self._key_log_pending = self._key_log_pending.split("\n", 1)
            if line:
                self._consume_key_log_line(line)
        return len(data)

    def flush(self) -> None:
        """Provides the no-op flush method required by aioquic."""

        self._require_open()

    def summarize(
        self,
        *,
        cipher_suite: CipherSuite,
        short_header_cid_length: int,
        spans: tuple[SymbolicSpan, ...] = (),
    ) -> PacketSummary:
        """Authenticates captured packets and returns payload-free metadata once."""

        self._require_open()
        try:
            if self._key_log_pending:
                self._consume_key_log_line(self._key_log_pending)
                self._key_log_pending = ""
            return self._summarize(
                cipher_suite=cipher_suite,
                short_header_cid_length=short_header_cid_length,
                spans=spans,
            )
        finally:
            self.clear()

    def clear(self) -> None:
        """Overwrites mutable captured material and makes the capture unusable."""

        if self._closed:
            return
        for datagram in self._datagrams:
            datagram[:] = bytes(len(datagram))
        self._datagrams.clear()
        self._datagram_bytes = 0
        if self._client_random is not None:
            self._client_random[:] = bytes(len(self._client_random))
            self._client_random = None
        for secret in self._secrets.values():
            secret[:] = bytes(len(secret))
        self._secrets.clear()
        self._key_log_pending = ""
        self._accept_datagrams = False
        self._closed = True

    def _summarize(
        self,
        *,
        cipher_suite: CipherSuite,
        short_header_cid_length: int,
        spans: tuple[SymbolicSpan, ...],
    ) -> PacketSummary:
        if not 0 <= short_header_cid_length <= CONNECTION_ID_MAX_SIZE:
            raise ValueError("invalid short-header connection ID length")
        if not self._datagrams:
            raise ValueError("capture contains no datagrams")

        expected_packet_number = {"initial": 0, "handshake": 0, "1rtt": 0}
        initial_crypto: CryptoPair | None = None
        traffic_cryptos: dict[str, CryptoContext] = {}
        version: int | None = None
        packets = []
        try:
            for datagram in self._datagrams:
                buf = Buffer(data=bytes(datagram))
                while not buf.eof():
                    packet_start = buf.tell()
                    header = pull_quic_header(
                        buf, host_cid_length=short_header_cid_length
                    )
                    encrypted_offset = buf.tell() - packet_start
                    packet_end = packet_start + header.packet_length
                    packet = bytes(datagram[packet_start:packet_end])
                    buf.seek(packet_end)

                    space = _packet_space(header.packet_type)
                    if header.version is not None:
                        if header.version != QuicProtocolVersion.VERSION_1:
                            raise ValueError("only QUIC v1 packets are supported")
                        if version is not None and version != header.version:
                            raise ValueError("capture changes QUIC version")
                        version = header.version
                    if version is None:
                        raise ValueError(
                            "short-header packet precedes a QUIC v1 packet"
                        )

                    if space == "initial":
                        if initial_crypto is None:
                            initial_crypto = CryptoPair()
                            initial_crypto.setup_initial(
                                cid=header.destination_cid,
                                is_client=False,
                                version=version,
                            )
                        crypto = initial_crypto.recv
                    else:
                        crypto = traffic_cryptos.get(space)
                        if crypto is None:
                            label = {
                                "handshake": _CLIENT_HANDSHAKE_SECRET,
                                "1rtt": _CLIENT_APPLICATION_SECRET,
                            }[space]
                            secret = self._secrets.get(label)
                            if secret is None:
                                raise ValueError(f"capture is missing {label}")
                            crypto = CryptoContext()
                            crypto.setup(
                                cipher_suite=cipher_suite,
                                secret=bytes(secret),
                                version=version,
                            )
                            traffic_cryptos[space] = crypto

                    _, payload, packet_number, updated = crypto.decrypt_packet(
                        packet,
                        encrypted_offset,
                        expected_packet_number[space],
                    )
                    if updated:
                        raise ValueError("QUIC key updates are outside this analyzer")
                    expected_packet_number[space] = max(
                        expected_packet_number[space], packet_number + 1
                    )
                    packets.append(
                        NormalizedPacket(
                            space=space,
                            frames=_parse_frames(payload, spans),
                        )
                    )
                    payload = b""
                    packet = b""
            return PacketSummary.build(tuple(packets), spans)
        except (BufferReadError, CryptoError) as error:
            raise ValueError(
                "failed to authenticate or decode captured QUIC packet"
            ) from error
        finally:
            if initial_crypto is not None:
                initial_crypto.teardown()
            for crypto in traffic_cryptos.values():
                crypto.teardown()

    def _consume_key_log_line(self, line: str) -> None:
        self._key_log_lines += 1
        if self._key_log_lines > self._max_key_log_lines:
            self._abort("key-log line count exceeds the capture limit")
        fields = line.split()
        if len(fields) != 3:
            self._abort("invalid NSS key-log line")
        label, client_random_hex, secret_hex = fields
        if label == "CLIENT_EARLY_TRAFFIC_SECRET":
            self._abort("0-RTT traffic secrets are outside this analyzer")
        if label not in {
            _CLIENT_HANDSHAKE_SECRET,
            _CLIENT_APPLICATION_SECRET,
            *_IGNORED_SERVER_SECRETS,
        }:
            self._abort("unsupported NSS key-log label")
        try:
            client_random = bytearray.fromhex(client_random_hex)
            secret = bytearray.fromhex(secret_hex)
        except ValueError:
            self._abort("invalid hexadecimal NSS key-log field")
        if len(client_random) != 32 or len(secret) not in (32, 48):
            client_random[:] = bytes(len(client_random))
            secret[:] = bytes(len(secret))
            self._abort("invalid NSS key-log field length")
        if self._client_random is None:
            self._client_random = client_random
        elif self._client_random != client_random:
            client_random[:] = bytes(len(client_random))
            secret[:] = bytes(len(secret))
            self._abort("key-log lines describe multiple TLS connections")
        else:
            client_random[:] = bytes(len(client_random))
        if label in _IGNORED_SERVER_SECRETS:
            secret[:] = bytes(len(secret))
            return
        if label in self._secrets:
            secret[:] = bytes(len(secret))
            self._abort("duplicate client traffic secret")
        self._secrets[label] = secret

    def _abort(self, message: str) -> None:
        self.clear()
        raise ValueError(message)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("capture has already been cleared")


def _packet_space(packet_type: QuicPacketType) -> str:
    if packet_type == QuicPacketType.INITIAL:
        return "initial"
    if packet_type == QuicPacketType.HANDSHAKE:
        return "handshake"
    if packet_type == QuicPacketType.ONE_RTT:
        return "1rtt"
    raise ValueError(f"unsupported QUIC packet type: {packet_type.name.lower()}")


def _parse_frames(
    payload: bytes, spans: tuple[SymbolicSpan, ...]
) -> tuple[FrameKind | StreamFrame, ...]:
    buf = Buffer(data=payload)
    frames: list[FrameKind | StreamFrame] = []
    while not buf.eof():
        frame_type = buf.pull_uint_var()
        if frame_type == QuicFrameType.PADDING:
            while not buf.eof() and payload[buf.tell()] == 0:
                buf.pull_uint8()
            frames.append(FrameKind("padding"))
        elif frame_type == QuicFrameType.PING:
            frames.append(FrameKind("ping"))
        elif frame_type in (QuicFrameType.ACK, QuicFrameType.ACK_ECN):
            _pull_ack(buf, ecn=frame_type == QuicFrameType.ACK_ECN)
            frames.append(FrameKind("ack_ecn" if frame_type == 3 else "ack"))
        elif frame_type == QuicFrameType.RESET_STREAM:
            _pull_varints(buf, 3)
            frames.append(FrameKind("reset_stream"))
        elif frame_type == QuicFrameType.STOP_SENDING:
            _pull_varints(buf, 2)
            frames.append(FrameKind("stop_sending"))
        elif frame_type == QuicFrameType.CRYPTO:
            _pull_length_prefixed(buf, prefix_fields=1)
            frames.append(FrameKind("crypto"))
        elif frame_type == QuicFrameType.NEW_TOKEN:
            _pull_length_prefixed(buf)
            frames.append(FrameKind("new_token"))
        elif 0x08 <= frame_type <= 0x0F:
            frames.append(_pull_stream(buf, frame_type, spans))
        elif frame_type == QuicFrameType.MAX_DATA:
            _pull_varints(buf, 1)
            frames.append(FrameKind("max_data"))
        elif frame_type == QuicFrameType.MAX_STREAM_DATA:
            _pull_varints(buf, 2)
            frames.append(FrameKind("max_stream_data"))
        elif frame_type in (
            QuicFrameType.MAX_STREAMS_BIDI,
            QuicFrameType.MAX_STREAMS_UNI,
        ):
            _pull_varints(buf, 1)
            frames.append(
                FrameKind(
                    "max_streams_bidi" if frame_type == 0x12 else "max_streams_uni"
                )
            )
        elif frame_type == QuicFrameType.DATA_BLOCKED:
            _pull_varints(buf, 1)
            frames.append(FrameKind("data_blocked"))
        elif frame_type == QuicFrameType.STREAM_DATA_BLOCKED:
            _pull_varints(buf, 2)
            frames.append(FrameKind("stream_data_blocked"))
        elif frame_type in (
            QuicFrameType.STREAMS_BLOCKED_BIDI,
            QuicFrameType.STREAMS_BLOCKED_UNI,
        ):
            _pull_varints(buf, 1)
            frames.append(
                FrameKind(
                    "streams_blocked_bidi"
                    if frame_type == 0x16
                    else "streams_blocked_uni"
                )
            )
        elif frame_type == QuicFrameType.NEW_CONNECTION_ID:
            _pull_varints(buf, 2)
            connection_id_length = buf.pull_uint8()
            if connection_id_length > CONNECTION_ID_MAX_SIZE:
                raise ValueError("NEW_CONNECTION_ID carries an oversized connection ID")
            buf.pull_bytes(connection_id_length + 16)
            frames.append(FrameKind("new_connection_id"))
        elif frame_type == QuicFrameType.RETIRE_CONNECTION_ID:
            _pull_varints(buf, 1)
            frames.append(FrameKind("retire_connection_id"))
        elif frame_type in (QuicFrameType.PATH_CHALLENGE, QuicFrameType.PATH_RESPONSE):
            buf.pull_bytes(8)
            frames.append(
                FrameKind("path_challenge" if frame_type == 0x1A else "path_response")
            )
        elif frame_type == QuicFrameType.TRANSPORT_CLOSE:
            _pull_varints(buf, 2)
            _pull_length_prefixed(buf)
            frames.append(FrameKind("transport_close"))
        elif frame_type == QuicFrameType.APPLICATION_CLOSE:
            _pull_varints(buf, 1)
            _pull_length_prefixed(buf)
            frames.append(FrameKind("application_close"))
        elif frame_type == QuicFrameType.HANDSHAKE_DONE:
            frames.append(FrameKind("handshake_done"))
        elif frame_type == QuicFrameType.DATAGRAM:
            buf.pull_bytes(buf.capacity - buf.tell())
            frames.append(FrameKind("datagram"))
        elif frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            _pull_length_prefixed(buf)
            frames.append(FrameKind("datagram"))
        else:
            raise ValueError(f"unsupported QUIC frame type: {frame_type}")
    return tuple(frames)


def _pull_varints(buf: Buffer, count: int) -> None:
    for _ in range(count):
        buf.pull_uint_var()


def _pull_length_prefixed(buf: Buffer, *, prefix_fields: int = 0) -> None:
    _pull_varints(buf, prefix_fields)
    length = buf.pull_uint_var()
    buf.pull_bytes(length)


def _pull_ack(buf: Buffer, *, ecn: bool) -> None:
    _pull_varints(buf, 2)
    range_count = buf.pull_uint_var()
    buf.pull_uint_var()
    for _ in range(range_count):
        _pull_varints(buf, 2)
    if ecn:
        _pull_varints(buf, 3)


def _pull_stream(
    buf: Buffer, frame_type: int, spans: tuple[SymbolicSpan, ...]
) -> StreamFrame:
    stream_id = buf.pull_uint_var()
    offset = buf.pull_uint_var() if frame_type & 0x04 else 0
    length = buf.pull_uint_var() if frame_type & 0x02 else buf.capacity - buf.tell()
    buf.pull_bytes(length)
    end = offset + length
    overlaps = tuple(
        span.label
        for span in spans
        if span.stream_id == stream_id and offset < span.end and span.start < end
    )
    return StreamFrame(
        kind="stream",
        stream_id=stream_id,
        offset=offset,
        length=length,
        fin=bool(frame_type & 0x01),
        overlaps=overlaps,
    )
