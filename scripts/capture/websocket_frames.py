"""RFC 6455 framing for capture servers: parse client frames and echo messages."""

from __future__ import annotations

import os
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field

CONTINUATION = 0x0
TEXT = 0x1
BINARY = 0x2
CLOSE = 0x8
PING = 0x9
PONG = 0xA
DATA_OPCODES = (TEXT, BINARY)
MAX_FRAME_PAYLOAD = 16 * 1024 * 1024
# RFC 7692 section 7.2.2: the sender removes this empty stored block's tail.
DEFLATE_TAIL = b"\x00\x00\xff\xff"


@dataclass(frozen=True)
class WebSocketFrame:
    fin: bool
    rsv1: bool
    rsv2: bool
    rsv3: bool
    opcode: int
    masked: bool
    payload: bytes


class FrameReader:
    """Incrementally split a byte stream into frames and unmask their payloads."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[WebSocketFrame]:
        self.buffer.extend(data)
        frames = []
        while True:
            frame = self._next()
            if frame is None:
                return frames
            frames.append(frame)

    def _next(self) -> WebSocketFrame | None:
        buffer = self.buffer
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        length = second & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < 4:
                return None
            length = int.from_bytes(buffer[2:4], "big")
            offset = 4
        elif length == 127:
            if len(buffer) < 10:
                return None
            length = int.from_bytes(buffer[2:10], "big")
            offset = 10
        if length > MAX_FRAME_PAYLOAD:
            raise ValueError("WebSocket frame exceeds the capture limit")
        masked = bool(second & 0x80)
        mask = b""
        if masked:
            if len(buffer) < offset + 4:
                return None
            mask = bytes(buffer[offset : offset + 4])
            offset += 4
        if len(buffer) < offset + length:
            return None
        payload = bytes(buffer[offset : offset + length])
        del buffer[: offset + length]
        if masked:
            payload = unmask(payload, mask)
        return WebSocketFrame(
            fin=bool(first & 0x80),
            rsv1=bool(first & 0x40),
            rsv2=bool(first & 0x20),
            rsv3=bool(first & 0x10),
            opcode=first & 0x0F,
            masked=masked,
            payload=payload,
        )


def unmask(payload: bytes, mask: bytes) -> bytes:
    repeated = (mask * (len(payload) // 4 + 1))[: len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(
        len(payload), "big"
    )


def encode_frame(
    opcode: int,
    payload: bytes,
    *,
    fin: bool = True,
    rsv1: bool = False,
    mask: bytes | None = None,
) -> bytes:
    """Serialize one frame; clients pass a four-byte `mask`, servers pass none."""
    first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    mask_bit = 0x80 if mask is not None else 0
    length = len(payload)
    if length < 126:
        head = bytes([first, mask_bit | length])
    elif length < 1 << 16:
        head = bytes([first, mask_bit | 126]) + length.to_bytes(2, "big")
    else:
        head = bytes([first, mask_bit | 127]) + length.to_bytes(8, "big")
    if mask is None:
        return head + payload
    return head + mask + unmask(payload, mask)


def client_frame(opcode: int, payload: bytes, **options) -> bytes:
    return encode_frame(opcode, payload, mask=os.urandom(4), **options)


@dataclass(frozen=True)
class MessageSummary:
    """One client data message, reassembled from its frames."""

    opcode: int
    rsv1: bool
    frame_lengths: tuple[int, ...]
    wire_payload: bytes
    payload: bytes | None

    @property
    def wire_length(self) -> int:
        return len(self.wire_payload)


@dataclass(frozen=True)
class ControlSummary:
    opcode: int
    length: int
    close_code: int | None
    # Index of the data message this control frame followed.
    after_message: int


@dataclass(frozen=True)
class SendPolicy:
    messages: tuple[MessageSummary, ...]
    controls: tuple[ControlSummary, ...]
    incomplete: bool
    # Frames that violate RFC 6455 ordering, recorded instead of repaired.
    anomalies: tuple[str, ...]


def summarize_send_policy(stream: bytes, *, inflate: bool) -> SendPolicy:
    """Summarize the client frames in `stream` without keeping masks.

    With `inflate`, RSV1 messages are decompressed with shared context
    takeover, which is the RFC 7692 default the capture server negotiates.
    """
    reader = FrameReader()
    frames = reader.feed(stream)
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    messages: list[MessageSummary] = []
    controls: list[ControlSummary] = []
    anomalies: list[str] = []
    current: list[WebSocketFrame] = []
    for frame in frames:
        if frame.opcode >= CLOSE:
            code = (
                int.from_bytes(frame.payload[:2], "big")
                if frame.opcode == CLOSE and len(frame.payload) >= 2
                else None
            )
            controls.append(
                ControlSummary(frame.opcode, len(frame.payload), code, len(messages))
            )
            continue
        if frame.opcode == CONTINUATION and not current:
            anomalies.append(f"continuation-without-start:{len(messages)}")
            continue
        if frame.opcode != CONTINUATION and current:
            anomalies.append(f"interrupted-message:{len(messages)}")
            current = []
        current.append(frame)
        if frame.fin:
            messages.append(message_summary(current, inflate, decompressor))
            current = []
    return SendPolicy(
        messages=tuple(messages),
        controls=tuple(controls),
        incomplete=bool(current or reader.buffer),
        anomalies=tuple(anomalies),
    )


def message_summary(
    frames: Sequence[WebSocketFrame], inflate: bool, decompressor
) -> MessageSummary:
    first = frames[0]
    wire = b"".join(frame.payload for frame in frames)
    payload: bytes | None = wire
    if first.rsv1:
        payload = None
        if inflate:
            try:
                payload = decompressor.decompress(wire + DEFLATE_TAIL)
            except zlib.error:
                payload = None
    return MessageSummary(
        opcode=first.opcode,
        rsv1=first.rsv1,
        frame_lengths=tuple(len(frame.payload) for frame in frames),
        wire_payload=wire,
        payload=payload,
    )


@dataclass
class EchoPeer:
    """Server endpoint that echoes each data message uncompressed.

    Uncompressed replies are valid after permessage-deflate is negotiated, so
    the server never needs a compressor whose output could vary.
    """

    inflate: bool
    reader: FrameReader = field(default_factory=FrameReader)
    fragments: list[WebSocketFrame] = field(default_factory=list)
    closed: bool = False
    decompressor: object = field(
        default_factory=lambda: zlib.decompressobj(-zlib.MAX_WBITS)
    )

    def feed(self, data: bytes) -> bytes:
        """Consume client bytes and return the server frames to send."""
        output = bytearray()
        for frame in self.reader.feed(data):
            if self.closed:
                break
            if frame.opcode == CLOSE:
                self.closed = True
                output.extend(encode_frame(CLOSE, frame.payload[:2]))
            elif frame.opcode == PING:
                output.extend(encode_frame(PONG, frame.payload))
            elif frame.opcode in (*DATA_OPCODES, CONTINUATION):
                self.fragments.append(frame)
                if frame.fin:
                    output.extend(self._echo())
        return bytes(output)

    def _echo(self) -> bytes:
        frames, self.fragments = self.fragments, []
        payload = b"".join(frame.payload for frame in frames)
        if frames[0].rsv1:
            if not self.inflate:
                raise ValueError("compressed message without a negotiated extension")
            payload = self.decompressor.decompress(payload + DEFLATE_TAIL)
        return encode_frame(frames[0].opcode, payload)
