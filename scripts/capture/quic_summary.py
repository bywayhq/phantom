"""Strict payload-free data model for QUIC packet summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PACKET_SUMMARY_FORMAT = "phantom-quic-packet-summary-v2"
REQUIRED_PACKET_SPACES = ("initial", "handshake", "1rtt")
_FRAME_KINDS = {
    "ack",
    "ack_ecn",
    "application_close",
    "crypto",
    "data_blocked",
    "datagram",
    "handshake_done",
    "max_data",
    "max_stream_data",
    "max_streams_bidi",
    "max_streams_uni",
    "new_connection_id",
    "new_token",
    "padding",
    "path_challenge",
    "path_response",
    "ping",
    "reset_stream",
    "retire_connection_id",
    "stop_sending",
    "stream_data_blocked",
    "streams_blocked_bidi",
    "streams_blocked_uni",
    "transport_close",
}
_FORBIDDEN_LABEL_PARTS = {
    "authorization",
    "ciphertext",
    "cookie",
    "keylog",
    "payload",
    "proxy_authorization",
    "secret",
}


@dataclass(frozen=True)
class SymbolicSpan:
    """A semantic label for a half-open range on a QUIC stream."""

    label: str
    stream_id: int
    start: int
    end: int

    def __post_init__(self) -> None:
        if not is_safe_label(self.label):
            raise ValueError("symbolic span label is invalid")
        if self.stream_id < 0 or self.start < 0 or self.end <= self.start:
            raise ValueError("symbolic span must describe a non-empty stream range")

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {
            "label": self.label,
            "stream_id": self.stream_id,
            "start": self.start,
            "end": self.end,
        }

    @classmethod
    def from_dict(cls, value: object) -> SymbolicSpan:
        """Parses one serialized symbolic span."""

        mapping = mapping_with_keys(
            value, {"label", "stream_id", "start", "end"}, "symbolic span"
        )
        label = mapping["label"]
        if not isinstance(label, str):
            raise ValueError("symbolic span label must be a string")
        return cls(
            label,
            nonnegative_int(mapping["stream_id"], "symbolic span stream ID"),
            nonnegative_int(mapping["start"], "symbolic span start"),
            nonnegative_int(mapping["end"], "symbolic span end"),
        )


@dataclass(frozen=True)
class FrameKind:
    """A normalized non-STREAM QUIC frame."""

    kind: str

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {"kind": self.kind}

    @classmethod
    def from_dict(cls, value: object) -> FrameKind:
        """Parses one serialized non-STREAM frame."""

        mapping = mapping_with_keys(value, {"kind"}, "frame")
        kind = mapping["kind"]
        if not isinstance(kind, str) or kind not in _FRAME_KINDS:
            raise ValueError("frame kind is invalid")
        return cls(kind)


@dataclass(frozen=True)
class StreamFrame:
    """Payload-free metadata for one STREAM frame."""

    kind: str
    stream_id: int
    offset: int
    length: int
    fin: bool
    overlaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {
            "kind": self.kind,
            "stream_id": self.stream_id,
            "offset": self.offset,
            "length": self.length,
            "fin": self.fin,
            "overlaps": list(self.overlaps),
        }

    @classmethod
    def from_dict(cls, value: object) -> StreamFrame:
        """Parses one serialized STREAM frame."""

        mapping = mapping_with_keys(
            value,
            {"kind", "stream_id", "offset", "length", "fin", "overlaps"},
            "STREAM frame",
        )
        if mapping["kind"] != "stream":
            raise ValueError("STREAM frame kind is invalid")
        fin = mapping["fin"]
        overlaps_value = mapping["overlaps"]
        if not isinstance(fin, bool):
            raise ValueError("STREAM FIN flag must be boolean")
        if not isinstance(overlaps_value, list) or not all(
            isinstance(label, str) and is_safe_label(label) for label in overlaps_value
        ):
            raise ValueError("STREAM overlaps must be a safe label list")
        overlaps = tuple(overlaps_value)
        if len(overlaps) != len(set(overlaps)):
            raise ValueError("STREAM overlaps must be unique")
        return cls(
            "stream",
            nonnegative_int(mapping["stream_id"], "STREAM ID"),
            nonnegative_int(mapping["offset"], "STREAM offset"),
            nonnegative_int(mapping["length"], "STREAM length"),
            fin,
            overlaps,
        )


@dataclass(frozen=True)
class NormalizedPacket:
    """Payload-free metadata for one authenticated QUIC packet."""

    space: str
    frames: tuple[FrameKind | StreamFrame, ...]

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {
            "space": self.space,
            "frames": [frame.as_dict() for frame in self.frames],
        }

    @classmethod
    def from_dict(cls, value: object) -> NormalizedPacket:
        """Parses one serialized normalized packet."""

        mapping = mapping_with_keys(value, {"space", "frames"}, "packet")
        space = mapping["space"]
        frames_value = mapping["frames"]
        if space not in REQUIRED_PACKET_SPACES:
            raise ValueError("packet space is unsupported")
        if not isinstance(frames_value, list):
            raise ValueError("packet frames must be a list")
        frames = []
        for frame in frames_value:
            if isinstance(frame, dict) and frame.get("kind") == "stream":
                frames.append(StreamFrame.from_dict(frame))
            else:
                frames.append(FrameKind.from_dict(frame))
        if space != "1rtt" and any(isinstance(frame, StreamFrame) for frame in frames):
            raise ValueError("STREAM frames must be carried in 1-RTT")
        return cls(space, tuple(frames))


def is_safe_label(label: str) -> bool:
    """Returns whether a label is structured and cannot name sensitive material."""

    return (
        bool(label)
        and all(
            character.islower() or character.isdigit() or character == "_"
            for character in label
        )
        and not set(label.split("_")) & _FORBIDDEN_LABEL_PARTS
    )


def nonnegative_int(value: object, description: str) -> int:
    """Parses a JSON integer without accepting booleans."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{description} must be a nonnegative integer")
    return value


def mapping_with_keys(
    value: object, expected: set[str], description: str
) -> dict[str, Any]:
    """Returns a mapping only when it has the exact expected schema."""

    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{description} has an invalid schema")
    return value
