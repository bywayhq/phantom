"""Strict QUIC and HTTP/3 wire parsing used by the Chrome capture."""

from dataclasses import dataclass

CONTROL_STREAM = 0
SETTINGS_FRAME = 4
HEADERS_FRAME = 1
INITIAL_SOURCE_CONNECTION_ID = 0x0F
VERSION_INFORMATION = 0x11
QPACK_ENCODER_STREAM = 2
QPACK_DECODER_STREAM = 3
SENSITIVE_REQUEST_HEADERS = {b"authorization", b"cookie", b"proxy-authorization"}


def pull_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    width = 1 << (data[offset] >> 6)
    if offset + width > len(data):
        return None
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, width


def push_varint(value: int, width: int) -> bytes:
    maximum = (1 << (width * 8 - 2)) - 1
    if width not in (1, 2, 4, 8) or not 0 <= value <= maximum:
        raise ValueError(f"{value} does not fit in a {width}-byte QUIC varint")
    encoded = bytearray(value.to_bytes(width, "big"))
    encoded[0] |= {1: 0x00, 2: 0x40, 4: 0x80, 8: 0xC0}[width]
    return bytes(encoded)


def grease_value(width: int, remainder: int) -> int:
    minimum = {1: 0, 2: 1 << 6, 4: 1 << 14, 8: 1 << 30}[width]
    value = remainder
    if value < minimum:
        value += ((minimum - value + 30) // 31) * 31
    return value


def is_quic_grease(identifier: int) -> bool:
    return identifier >= 27 and (identifier - 27) % 31 == 0


def is_h3_grease(identifier: int) -> bool:
    return identifier >= 33 and (identifier - 33) % 31 == 0


@dataclass(frozen=True)
class Parameter:
    identifier: int
    identifier_width: int
    length_width: int
    value: bytes
    start: int
    value_start: int
    end: int


@dataclass(frozen=True)
class RequestSnapshot:
    stream_id: int
    headers_frame: bytes
    headers_payload: bytes
    qpack_encoder_stream_prefix: bytes
    qpack_decoder_stream_prefix: bytes


def parse_parameters(data: bytes) -> list[Parameter]:
    parameters = []
    offset = 0
    while offset < len(data):
        start = offset
        identifier_field = pull_varint(data, offset)
        if identifier_field is None:
            raise ValueError("truncated parameter identifier")
        identifier, identifier_width = identifier_field
        offset += identifier_width
        length_field = pull_varint(data, offset)
        if length_field is None:
            raise ValueError("truncated parameter length")
        length, length_width = length_field
        offset += length_width
        value_start = offset
        end = offset + length
        if end > len(data):
            raise ValueError("truncated parameter value")
        parameters.append(
            Parameter(
                identifier,
                identifier_width,
                length_width,
                data[value_start:end],
                start,
                value_start,
                end,
            )
        )
        offset = end
    return parameters


def normalize_transport_parameters(data: bytes, parameters: list[Parameter]) -> bytes:
    normalized = bytearray(data)
    for parameter in parameters:
        if parameter.identifier == INITIAL_SOURCE_CONNECTION_ID:
            normalized[parameter.value_start : parameter.end] = bytes(
                len(parameter.value)
            )
        elif parameter.identifier == VERSION_INFORMATION:
            if len(parameter.value) % 4 != 0:
                raise ValueError("version_information is not a sequence of u32 values")
            for offset in range(parameter.value_start, parameter.end, 4):
                version = int.from_bytes(normalized[offset : offset + 4], "big")
                if version & 0x0F0F0F0F == 0x0A0A0A0A:
                    normalized[offset : offset + 4] = bytes.fromhex("0a0a0a0a")
        elif is_quic_grease(parameter.identifier):
            normalized[
                parameter.start : parameter.start + parameter.identifier_width
            ] = push_varint(
                grease_value(parameter.identifier_width, 27), parameter.identifier_width
            )
            normalized[parameter.value_start : parameter.end] = bytes(
                len(parameter.value)
            )
    return bytes(normalized)


def parse_settings(data: bytes) -> list[tuple[int, int, int, int]]:
    settings = []
    offset = 0
    while offset < len(data):
        identifier_field = pull_varint(data, offset)
        if identifier_field is None:
            raise ValueError("truncated setting identifier")
        identifier, identifier_width = identifier_field
        offset += identifier_width
        value_field = pull_varint(data, offset)
        if value_field is None:
            raise ValueError("truncated setting value")
        value, value_width = value_field
        offset += value_width
        settings.append((identifier, identifier_width, value, value_width))
    return settings


def normalize_settings(data: bytes) -> bytes:
    normalized = bytearray()
    offset = 0
    while offset < len(data):
        identifier_field = pull_varint(data, offset)
        if identifier_field is None:
            raise ValueError("truncated setting identifier")
        identifier, identifier_width = identifier_field
        offset += identifier_width
        value_field = pull_varint(data, offset)
        if value_field is None:
            raise ValueError("truncated setting value")
        value, value_width = value_field
        offset += value_width
        if is_h3_grease(identifier):
            identifier = grease_value(identifier_width, 33)
            value = 0
        normalized += push_varint(identifier, identifier_width)
        normalized += push_varint(value, value_width)
    return bytes(normalized)


def first_frame(
    data: bytes, *, has_stream_type: bool
) -> tuple[int, bytes, bytes] | None:
    offset = 0
    if has_stream_type:
        stream_type_field = pull_varint(data, offset)
        if stream_type_field is None or stream_type_field[0] != CONTROL_STREAM:
            return None
        offset += stream_type_field[1]
    frame_start = offset
    type_field = pull_varint(data, offset)
    if type_field is None:
        return None
    frame_type, type_width = type_field
    offset += type_width
    length_field = pull_varint(data, offset)
    if length_field is None:
        return None
    length, length_width = length_field
    offset += length_width
    end = offset + length
    if end > len(data):
        return None
    return frame_type, data[frame_start:end], data[offset:end]


def unidirectional_stream(streams: dict[int, bytearray], stream_type: int) -> bytes:
    for stream_id, data in streams.items():
        if stream_id % 4 != 2:
            continue
        parsed_type = pull_varint(data, 0)
        if parsed_type is not None and parsed_type[0] == stream_type:
            return bytes(data)
    return b""


def unidirectional_stream_id(streams: dict[int, bytearray], stream_type: int) -> int:
    matches = []
    for stream_id, data in streams.items():
        if stream_id % 4 != 2:
            continue
        parsed_type = pull_varint(data, 0)
        if parsed_type is not None and parsed_type[0] == stream_type:
            matches.append(stream_id)
    if len(matches) != 1:
        raise ValueError(
            f"expected one client stream of type {stream_type}, found {len(matches)}"
        )
    return matches[0]


def capture_request_snapshot(
    streams: dict[int, bytearray], stream_id: int
) -> RequestSnapshot:
    raw = bytes(streams.get(stream_id, b""))
    frame = first_frame(raw, has_stream_type=False)
    if frame is None or frame[0] != HEADERS_FRAME:
        raise ValueError("decoded request has no complete first HEADERS frame")

    _, headers_frame, headers_payload = frame
    return RequestSnapshot(
        stream_id=stream_id,
        headers_frame=headers_frame,
        headers_payload=headers_payload,
        qpack_encoder_stream_prefix=unidirectional_stream(
            streams, QPACK_ENCODER_STREAM
        ),
        qpack_decoder_stream_prefix=unidirectional_stream(
            streams, QPACK_DECODER_STREAM
        ),
    )
