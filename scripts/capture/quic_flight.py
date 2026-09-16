"""Stable logical projection and comparison for QUIC packet summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .quic_summary import (
    PACKET_SUMMARY_FORMAT,
    REQUIRED_PACKET_SPACES,
    FrameKind,
    NormalizedPacket,
    SymbolicSpan,
    is_safe_label,
    mapping_with_keys,
)

_TERMINAL_FRAME_KINDS = {
    "application_close",
    "reset_stream",
    "stop_sending",
    "transport_close",
}


@dataclass(frozen=True)
class MarkerCoverage:
    """Packetization-independent coverage of one symbolic stream span."""

    label: str
    length: int
    coverage: tuple[tuple[int, int], ...]
    complete: bool
    fin_at_end: bool
    spaces: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {
            "label": self.label,
            "length": self.length,
            "coverage": [{"start": start, "end": end} for start, end in self.coverage],
            "complete": self.complete,
            "fin_at_end": self.fin_at_end,
            "spaces": list(self.spaces),
        }

    @classmethod
    def from_dict(cls, value: object) -> MarkerCoverage:
        """Parses and validates one serialized marker."""

        mapping = mapping_with_keys(
            value,
            {"label", "length", "coverage", "complete", "fin_at_end", "spaces"},
            "logical marker",
        )
        label = mapping["label"]
        length = mapping["length"]
        complete = mapping["complete"]
        fin_at_end = mapping["fin_at_end"]
        if not isinstance(label, str) or not is_safe_label(label):
            raise ValueError("logical marker label is invalid")
        if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
            raise ValueError("logical marker length must be a positive integer")
        if not isinstance(complete, bool) or not isinstance(fin_at_end, bool):
            raise ValueError("logical marker flags must be booleans")
        coverage_value = mapping["coverage"]
        if not isinstance(coverage_value, list):
            raise ValueError("logical marker coverage must be a list")
        coverage = tuple(_coverage_range(item, length) for item in coverage_value)
        if coverage != _merge_ranges(coverage):
            raise ValueError("logical marker coverage must be sorted and disjoint")
        if complete != (coverage == ((0, length),)):
            raise ValueError("logical marker completeness disagrees with its coverage")
        spaces = _packet_spaces(mapping["spaces"], "logical marker spaces")
        if complete and spaces != ("1rtt",):
            raise ValueError("a complete logical marker must be carried in 1-RTT")
        return cls(label, length, coverage, complete, fin_at_end, spaces)


@dataclass(frozen=True)
class TerminalFrame:
    """A request-ending frame and the authenticated space carrying it."""

    space: str
    kind: str

    def as_dict(self) -> dict[str, str]:
        """Returns the stable JSON representation."""

        return {"space": self.space, "kind": self.kind}

    @classmethod
    def from_dict(cls, value: object) -> TerminalFrame:
        """Parses one serialized terminal frame."""

        mapping = mapping_with_keys(value, {"space", "kind"}, "terminal frame")
        space = mapping["space"]
        kind = mapping["kind"]
        if space not in REQUIRED_PACKET_SPACES:
            raise ValueError("terminal frame packet space is unsupported")
        if not isinstance(kind, str) or kind not in _TERMINAL_FRAME_KINDS:
            raise ValueError("logical flight contains an unknown terminal frame")
        return cls(space, kind)


@dataclass(frozen=True)
class LogicalFlight:
    """Stable request-flight facts independent of QUIC packetization."""

    packet_spaces: tuple[str, ...]
    markers: tuple[MarkerCoverage, ...]
    stream_retransmission_observed: bool
    terminal_frames: tuple[TerminalFrame, ...]

    def as_dict(self) -> dict[str, Any]:
        """Returns the stable JSON representation."""

        return {
            "packet_spaces": list(self.packet_spaces),
            "markers": [marker.as_dict() for marker in self.markers],
            "stream_retransmission_observed": self.stream_retransmission_observed,
            "terminal_frames": [frame.as_dict() for frame in self.terminal_frames],
        }

    @classmethod
    def from_dict(cls, value: object) -> LogicalFlight:
        """Parses and validates a serialized logical flight."""

        mapping = mapping_with_keys(
            value,
            {
                "packet_spaces",
                "markers",
                "stream_retransmission_observed",
                "terminal_frames",
            },
            "logical flight",
        )
        packet_spaces = _packet_spaces(
            mapping["packet_spaces"], "logical flight packet spaces"
        )
        markers_value = mapping["markers"]
        if not isinstance(markers_value, list):
            raise ValueError("logical flight markers must be a list")
        markers = tuple(MarkerCoverage.from_dict(item) for item in markers_value)
        labels = [marker.label for marker in markers]
        if labels != sorted(labels) or len(labels) != len(set(labels)):
            raise ValueError("logical flight markers must have unique sorted labels")
        retransmission = mapping["stream_retransmission_observed"]
        if not isinstance(retransmission, bool):
            raise ValueError(
                "logical flight stream retransmission flag must be boolean"
            )
        terminal_value = mapping["terminal_frames"]
        if not isinstance(terminal_value, list):
            raise ValueError("logical flight terminal frames must be a list")
        terminal_frames = tuple(
            TerminalFrame.from_dict(frame) for frame in terminal_value
        )
        if terminal_frames != tuple(
            sorted(
                set(terminal_frames),
                key=lambda frame: (
                    REQUIRED_PACKET_SPACES.index(frame.space),
                    frame.kind,
                ),
            )
        ):
            raise ValueError("logical flight terminal frames must be unique and sorted")
        return cls(packet_spaces, markers, retransmission, terminal_frames)


@dataclass(frozen=True)
class PacketSummary:
    """Packet telemetry plus its stable logical request-flight projection."""

    packets: tuple[NormalizedPacket, ...]
    spans: tuple[SymbolicSpan, ...]
    logical_flight: LogicalFlight

    @classmethod
    def build(
        cls,
        packets: tuple[NormalizedPacket, ...],
        spans: tuple[SymbolicSpan, ...],
    ) -> PacketSummary:
        """Builds telemetry and the logical projection from authenticated packets."""

        return cls(packets, spans, _project_logical_flight(packets, spans))

    def as_dict(self) -> dict[str, Any]:
        """Returns a serialization containing only the documented safe fields."""

        return {
            "format": PACKET_SUMMARY_FORMAT,
            "logical_flight": self.logical_flight.as_dict(),
            "spans": [span.as_dict() for span in self.spans],
            "packets": [packet.as_dict() for packet in self.packets],
        }


def parse_logical_flight_summary(value: object) -> LogicalFlight:
    """Extracts a logical flight from a strict packet-summary document."""

    mapping = mapping_with_keys(
        value,
        {"format", "logical_flight", "spans", "packets"},
        "packet summary",
    )
    if mapping["format"] != PACKET_SUMMARY_FORMAT:
        raise ValueError("packet summary format is unsupported")
    spans_value = mapping["spans"]
    packets_value = mapping["packets"]
    if not isinstance(spans_value, list):
        raise ValueError("packet summary spans must be a list")
    if not isinstance(packets_value, list):
        raise ValueError("packet summary packets must be a list")
    spans = tuple(SymbolicSpan.from_dict(span) for span in spans_value)
    packets = tuple(NormalizedPacket.from_dict(packet) for packet in packets_value)
    projected = PacketSummary.build(packets, spans).logical_flight
    serialized = LogicalFlight.from_dict(mapping["logical_flight"])
    if projected != serialized:
        raise ValueError("logical flight disagrees with packet and span data")
    return projected


def compare_logical_flights(
    left: LogicalFlight, right: LogicalFlight
) -> tuple[str, ...]:
    """Returns actionable incompatibilities, ignoring retransmission telemetry."""

    errors = []
    for side, flight in (("left", left), ("right", right)):
        if flight.packet_spaces != REQUIRED_PACKET_SPACES:
            errors.append(
                f"{side} packet spaces are {flight.packet_spaces!r}, "
                f"expected {REQUIRED_PACKET_SPACES!r}"
            )
        if flight.terminal_frames:
            errors.append(f"{side} contains terminal frames {flight.terminal_frames!r}")
        if not flight.markers:
            errors.append(f"{side} contains no symbolic markers")
        incomplete = tuple(
            marker.label for marker in flight.markers if not marker.complete
        )
        if incomplete:
            errors.append(f"{side} has incomplete markers {incomplete!r}")
        wrong_spaces = tuple(
            marker.label
            for marker in flight.markers
            if marker.complete and marker.spaces != ("1rtt",)
        )
        if wrong_spaces:
            errors.append(f"{side} has markers outside 1-RTT {wrong_spaces!r}")

    if left.terminal_frames != right.terminal_frames:
        errors.append(
            "terminal frames differ: "
            f"left={left.terminal_frames!r}, right={right.terminal_frames!r}"
        )

    left_markers = {marker.label: marker for marker in left.markers}
    right_markers = {marker.label: marker for marker in right.markers}
    if left_markers.keys() != right_markers.keys():
        errors.append(
            "marker labels differ: "
            f"left={tuple(left_markers)!r}, right={tuple(right_markers)!r}"
        )
    for label in sorted(left_markers.keys() & right_markers.keys()):
        left_marker = left_markers[label]
        right_marker = right_markers[label]
        if left_marker != right_marker:
            errors.append(
                f"marker {label!r} differs: "
                f"left={left_marker.as_dict()!r}, right={right_marker.as_dict()!r}"
            )
    return tuple(errors)


def _project_logical_flight(
    packets: tuple[NormalizedPacket, ...], spans: tuple[SymbolicSpan, ...]
) -> LogicalFlight:
    labels = [span.label for span in spans]
    if len(labels) != len(set(labels)):
        raise ValueError("symbolic span labels must be unique")
    spans_by_label = {span.label: span for span in spans}
    coverage: dict[str, list[tuple[int, int]]] = {label: [] for label in labels}
    marker_spaces: dict[str, set[str]] = {label: set() for label in labels}
    fin_offsets: dict[int, set[int]] = {}
    stream_coverage: dict[int, tuple[tuple[int, int], ...]] = {}
    packet_spaces = set()
    terminal_frames: set[TerminalFrame] = set()
    retransmission = False

    for packet in packets:
        if packet.space not in REQUIRED_PACKET_SPACES:
            raise ValueError(f"unsupported packet space {packet.space!r}")
        packet_spaces.add(packet.space)
        for frame in packet.frames:
            if isinstance(frame, FrameKind):
                if frame.kind in _TERMINAL_FRAME_KINDS:
                    terminal_frames.add(TerminalFrame(packet.space, frame.kind))
                continue
            start = frame.offset
            end = frame.offset + frame.length
            previous = stream_coverage.get(frame.stream_id, ())
            if frame.length and any(
                start < old_end and old_start < end for old_start, old_end in previous
            ):
                retransmission = True
            stream_coverage[frame.stream_id] = _merge_ranges((*previous, (start, end)))
            if frame.fin:
                observed_fin_offsets = fin_offsets.setdefault(frame.stream_id, set())
                if end in observed_fin_offsets:
                    retransmission = True
                observed_fin_offsets.add(end)
            for label in frame.overlaps:
                span = spans_by_label.get(label)
                if span is None:
                    raise ValueError(
                        f"stream frame refers to unknown symbolic span {label!r}"
                    )
                if span.stream_id != frame.stream_id:
                    raise ValueError(
                        f"stream frame refers to span {label!r} on another stream"
                    )
                overlap_start = max(start, span.start)
                overlap_end = min(end, span.end)
                if overlap_start < overlap_end:
                    coverage[label].append(
                        (overlap_start - span.start, overlap_end - span.start)
                    )
                    marker_spaces[label].add(packet.space)

    markers = []
    for span in sorted(spans, key=lambda item: item.label):
        length = span.end - span.start
        ranges = _merge_ranges(tuple(coverage[span.label]))
        markers.append(
            MarkerCoverage(
                label=span.label,
                length=length,
                coverage=ranges,
                complete=ranges == ((0, length),),
                fin_at_end=span.end in fin_offsets.get(span.stream_id, set()),
                spaces=tuple(
                    space
                    for space in REQUIRED_PACKET_SPACES
                    if space in marker_spaces[span.label]
                ),
            )
        )
    return LogicalFlight(
        packet_spaces=tuple(
            space for space in REQUIRED_PACKET_SPACES if space in packet_spaces
        ),
        markers=tuple(markers),
        stream_retransmission_observed=retransmission,
        terminal_frames=tuple(
            sorted(
                terminal_frames,
                key=lambda frame: (
                    REQUIRED_PACKET_SPACES.index(frame.space),
                    frame.kind,
                ),
            )
        ),
    )


def _merge_ranges(ranges: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if start == end:
            continue
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)


def _packet_spaces(value: object, description: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{description} must be a string list")
    spaces = tuple(value)
    expected = tuple(space for space in REQUIRED_PACKET_SPACES if space in spaces)
    if spaces != expected:
        raise ValueError(f"{description} must be unique and canonically ordered")
    return spaces


def _coverage_range(value: object, length: int) -> tuple[int, int]:
    mapping = mapping_with_keys(value, {"start", "end"}, "coverage range")
    start = mapping["start"]
    end = mapping["end"]
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
        or end > length
    ):
        raise ValueError("coverage range is outside its marker")
    return start, end
