"""Read tapped HTTP/2 frames and HPACK fields in wire order."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from h2.errors import ErrorCodes
from hpack import Decoder

from .http2_session import (
    CONNECTION_PREFACE,
    MAX_CONNECTION_CAPTURE,
    MAX_H2_FRAMES,
    MAX_HEADER_FIELDS,
    MAX_REQUEST_HEAD,
    CaptureLimitError,
    ConnectionRecord,
    MalformedCaptureError,
)


FRAME_TYPES = {
    0x0: "DATA",
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x5: "PUSH_PROMISE",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}
ERROR_CODES = {code.value: code.name for code in ErrorCodes}
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20


@dataclass(frozen=True)
class Http2Frame:
    direction: str
    received: float
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes

    @property
    def type_name(self) -> str:
        return FRAME_TYPES.get(self.frame_type, f"0x{self.frame_type:02x}")


@dataclass(frozen=True)
class Priority:
    exclusive: bool
    depends_on: int
    weight: int


@dataclass(frozen=True)
class HeaderField:
    """One HPACK representation and, unless it is a size update, its field."""

    representation: str
    # Table index, literal name index (0 for a new name), or new table size.
    index: int
    name_huffman: bool | None
    value_huffman: bool | None
    name: bytes | None = None
    value: bytes | None = None


@dataclass(frozen=True)
class HeaderBlock:
    stream_id: int
    flags: int
    priority: Priority | None
    continuation_count: int
    block: bytes
    fields: tuple[HeaderField, ...]

    def field(self, name: bytes) -> bytes | None:
        for item in self.fields:
            if item.name == name:
                return item.value
        return None


@dataclass(frozen=True)
class Http2Analysis:
    frames: tuple[Http2Frame, ...]
    client_headers: tuple[HeaderBlock, ...]
    stream_data: dict[int, bytes]
    client_trailing: int


def split_frames(
    chunks: Sequence[tuple[float, bytes]], direction: str, *, preface: bool
) -> tuple[list[Http2Frame], int]:
    """Split a tapped byte stream; each frame takes its last byte's time."""
    data = bytearray()
    frames = []
    waiting_for_preface = preface
    received_bytes = 0
    continuation_stream: int | None = None
    for received, chunk in chunks:
        received_bytes += len(chunk)
        if received_bytes > MAX_CONNECTION_CAPTURE:
            raise CaptureLimitError("H2 bytes exceed the capture limit")
        data.extend(chunk)
        if waiting_for_preface:
            if len(data) < len(CONNECTION_PREFACE):
                continue
            if bytes(data[: len(CONNECTION_PREFACE)]) != CONNECTION_PREFACE:
                raise ValueError("client stream does not start with the H2 preface")
            del data[: len(CONNECTION_PREFACE)]
            waiting_for_preface = False
        while len(data) >= 9:
            length = int.from_bytes(data[:3], "big")
            if len(data) < 9 + length:
                break
            if len(frames) >= MAX_H2_FRAMES:
                raise CaptureLimitError("H2 frame count exceeds the capture limit")
            frame = Http2Frame(
                direction=direction,
                received=received,
                frame_type=data[3],
                flags=data[4],
                stream_id=int.from_bytes(data[5:9], "big") & 0x7FFFFFFF,
                payload=bytes(data[9 : 9 + length]),
            )
            validate_frame_extent(frame)
            if frame.frame_type == 0x9:
                if continuation_stream is None or frame.stream_id != continuation_stream:
                    raise MalformedCaptureError("H2 continuation has no matching header block")
                if frame.flags & FLAG_END_HEADERS:
                    continuation_stream = None
            elif continuation_stream is not None:
                raise MalformedCaptureError("H2 header block has an interleaved frame")
            elif frame.frame_type in (0x1, 0x5) and not frame.flags & FLAG_END_HEADERS:
                continuation_stream = frame.stream_id
            frames.append(frame)
            del data[: 9 + length]
    return frames, len(data)


def validate_frame_extent(frame: Http2Frame) -> None:
    kind = frame.frame_type
    size = len(frame.payload)
    fixed = {0x2: 5, 0x3: 4, 0x6: 8, 0x8: 4}
    if kind in fixed and size != fixed[kind]:
        raise MalformedCaptureError("invalid H2 fixed frame length")
    if kind == 0x4 and (size % 6 or (frame.flags & FLAG_ACK and size)):
        raise MalformedCaptureError("invalid H2 SETTINGS length")
    if kind == 0x7 and size < 8:
        raise MalformedCaptureError("truncated H2 GOAWAY")
    if kind in (0x0, 0x1, 0x5):
        _, payload = strip_padding(frame)
        if kind == 0x1 and frame.flags & FLAG_PRIORITY and len(payload) < 5:
            raise MalformedCaptureError("truncated H2 HEADERS priority")
        if kind == 0x5 and len(payload) < 4:
            raise MalformedCaptureError("truncated H2 PUSH_PROMISE")
    if kind in (0x0, 0x1, 0x2, 0x3, 0x5, 0x9) and frame.stream_id == 0:
        raise MalformedCaptureError("H2 stream frame has stream zero")


def strip_padding(frame: Http2Frame) -> tuple[int, bytes]:
    if not frame.flags & FLAG_PADDED:
        return 0, frame.payload
    if not frame.payload:
        raise MalformedCaptureError("H2 padded frame omits its padding length")
    pad = frame.payload[0]
    if pad > len(frame.payload) - 1:
        raise MalformedCaptureError("H2 padding exceeds its frame")
    return 1, frame.payload[1 : len(frame.payload) - pad]


def headers_priority(frame: Http2Frame) -> tuple[Priority | None, bytes]:
    _, payload = strip_padding(frame)
    if not frame.flags & FLAG_PRIORITY:
        return None, payload
    return parse_priority(payload[:5]), payload[5:]


def parse_priority(payload: bytes) -> Priority:
    if len(payload) != 5:
        raise MalformedCaptureError("invalid H2 priority length")
    raw = int.from_bytes(payload[:4], "big")
    return Priority(bool(raw >> 31), raw & 0x7FFFFFFF, payload[4] + 1)


def hpack_integer(block: bytes, offset: int, prefix: int) -> tuple[int, int]:
    if offset < 0 or offset >= len(block) or not 1 <= prefix <= 8:
        raise MalformedCaptureError("truncated HPACK integer")
    limit = (1 << prefix) - 1
    value = block[offset] & limit
    offset += 1
    if value < limit:
        return value, offset
    shift = 0
    while True:
        if offset >= len(block) or shift > 28:
            raise ValueError("malformed HPACK integer")
        byte = block[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset


def hpack_string(block: bytes, offset: int) -> tuple[bool, int]:
    if offset < 0 or offset >= len(block):
        raise ValueError("truncated HPACK string")
    huffman = bool(block[offset] & 0x80)
    length, offset = hpack_integer(block, offset, 7)
    if offset + length > len(block):
        raise ValueError("truncated HPACK string")
    return huffman, offset + length


def hpack_representations(block: bytes) -> list[HeaderField]:
    """Classify each representation (RFC 7541 section 6) in block order."""
    representations = []
    if len(block) > MAX_REQUEST_HEAD:
        raise CaptureLimitError("H2 header block exceeds the capture limit")
    offset = 0
    while offset < len(block):
        if len(representations) >= MAX_HEADER_FIELDS:
            raise CaptureLimitError("H2 header field count exceeds the capture limit")
        first = block[offset]
        if first & 0x80:
            index, offset = hpack_integer(block, offset, 7)
            representations.append(HeaderField("indexed", index, None, None))
            continue
        if first & 0x40:
            kind, prefix = "incremental", 6
        elif first & 0x20:
            size, offset = hpack_integer(block, offset, 5)
            representations.append(HeaderField("size-update", size, None, None))
            continue
        elif first & 0x10:
            kind, prefix = "never-indexed", 4
        else:
            kind, prefix = "without-indexing", 4
        index, offset = hpack_integer(block, offset, prefix)
        name_huffman = None
        if index == 0:
            name_huffman, offset = hpack_string(block, offset)
        value_huffman, offset = hpack_string(block, offset)
        representations.append(HeaderField(kind, index, name_huffman, value_huffman))
    return representations


def decode_header_block(decoder: Decoder, block: bytes) -> tuple[HeaderField, ...]:
    representations = hpack_representations(block)
    decoded = list(decoder.decode(block, raw=True))
    if sum(len(name) + len(value) for name, value in decoded) > MAX_REQUEST_HEAD:
        raise CaptureLimitError("decoded H2 fields exceed the capture limit")
    fields = []
    for representation in representations:
        if representation.representation == "size-update":
            fields.append(representation)
            continue
        if not decoded:
            raise ValueError("HPACK decoder returned fewer fields than the block")
        name, value = decoded.pop(0)
        fields.append(
            HeaderField(
                representation.representation,
                representation.index,
                representation.name_huffman,
                representation.value_huffman,
                bytes(name),
                bytes(value),
            )
        )
    if decoded:
        raise ValueError("HPACK decoder returned more fields than the block")
    return tuple(fields)


def analyze_http2(record: ConnectionRecord) -> Http2Analysis:
    client, trailing = split_frames(record.client_chunks, "client", preface=True)
    server, _ = split_frames(record.server_chunks, "server", preface=False)
    decoder = Decoder()
    blocks = []
    stream_data: dict[int, bytearray] = {}
    pending: tuple[Http2Frame, Priority | None, bytearray, int] | None = None
    for frame in client:
        if frame.frame_type == 0x0:
            _, payload = strip_padding(frame)
            stream_data.setdefault(frame.stream_id, bytearray()).extend(payload)
        elif frame.frame_type == 0x1:
            priority, fragment = headers_priority(frame)
            pending = (frame, priority, bytearray(fragment), 0)
        elif frame.frame_type == 0x9 and pending is not None:
            first, priority, fragment, continuations = pending
            fragment.extend(frame.payload)
            if len(fragment) > MAX_REQUEST_HEAD:
                raise CaptureLimitError("H2 header block exceeds the capture limit")
            pending = (first, priority, fragment, continuations + 1)
        else:
            continue
        if pending is not None and frame.flags & FLAG_END_HEADERS:
            first, priority, fragment, continuations = pending
            block = bytes(fragment)
            blocks.append(
                HeaderBlock(
                    stream_id=first.stream_id,
                    flags=first.flags,
                    priority=priority,
                    continuation_count=continuations,
                    block=block,
                    fields=decode_header_block(decoder, block),
                )
            )
            pending = None
    frames = sorted([*client, *server], key=lambda frame: frame.received)
    return Http2Analysis(
        frames=tuple(frames),
        client_headers=tuple(blocks),
        stream_data={key: bytes(value) for key, value in stream_data.items()},
        client_trailing=trailing,
    )


def frame_details(frame: Http2Frame) -> list[str]:
    """Render the ordered, non-random fields of one frame for a fixture."""
    details = []
    kind = frame.frame_type
    if kind == 0x0:
        _, payload = strip_padding(frame)
        details.append(f"data_length:{len(payload)}")
    elif kind == 0x1:
        priority, fragment = headers_priority(frame)
        if priority is not None:
            details.append(priority_text(priority))
        details.append(f"block_length:{len(fragment)}")
    elif kind == 0x2:
        details.append(priority_text(parse_priority(frame.payload)))
    elif kind == 0x3:
        details.append(f"error:{error_name(frame.payload)}")
    elif kind == 0x4 and not frame.flags & FLAG_ACK:
        pairs = [
            f"{int.from_bytes(frame.payload[offset : offset + 2], 'big')}="
            f"{int.from_bytes(frame.payload[offset + 2 : offset + 6], 'big')}"
            for offset in range(0, len(frame.payload) - 5, 6)
        ]
        details.append("settings:" + ";".join(pairs))
    elif kind == 0x7:
        last = int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
        details.append(f"last_stream:{last},error:{error_name(frame.payload[4:8])}")
        details.append(f"debug_length:{max(0, len(frame.payload) - 8)}")
    elif kind == 0x8:
        increment = int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
        details.append(f"increment:{increment}")
    return details


def priority_text(priority: Priority) -> str:
    return (
        f"exclusive:{str(priority.exclusive).lower()},"
        f"depends_on:{priority.depends_on},weight:{priority.weight}"
    )


def error_name(payload: bytes) -> str:
    code = int.from_bytes(payload[:4], "big")
    return ERROR_CODES.get(code, f"0x{code:x}")
