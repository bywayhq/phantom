"""Closed HTTP/3 settings and pseudo-header vocabulary."""

from .declarations import (
    MAX_VARINT,
    PSEUDO_HEADERS,
    DeclarationError,
    boolean,
    choice,
    keys,
)

MAX_QPACK_TABLE_CAPACITY = (1 << 30) - 1


COMPONENT_ENUMS = {
    "setting_order": ("Http3SettingOrder", ("Fixed", "Ascending")),
    "qpack_encoding": (
        "Http3QpackEncoding",
        ("Stateless", "Dynamic", "DynamicUnmatchedNames"),
    ),
    "qpack_decoder_stream": ("Http3QpackDecoderStream", ("Eager", "OnFeedback")),
    "qpack_encoder_stream": (
        "Http3QpackEncoderStream",
        ("Eager", "OnFirstInstruction"),
    ),
    "qpack_stream_order": ("Http3QpackStreamOrder", ("EncoderFirst", "DecoderFirst")),
    "cookie_crumbs": ("Http3CookieCrumbs", ("Whole", "Split")),
    "alt_used": ("Http3AltUsed", ("Omit", "Append", "ValidatedMapping")),
    "alt_used_port": ("Http3AltUsedPort", ("Explicit", "OmitDefault")),
}


SETTING_BOUNDS = {
    "QpackMaxTableCapacity": MAX_QPACK_TABLE_CAPACITY,
    "MaxFieldSectionSize": MAX_VARINT,
    "QpackBlockedStreams": MAX_VARINT,
}


BOOL_SETTINGS = {
    "H3Datagram",
    "EnableConnectProtocol",
    "EnableWebTransportDraft02",
    "H3DatagramDraft04",
}


def validate_initial_settings(settings):
    if not isinstance(settings, list) or len(settings) > 64:
        raise DeclarationError("initial_settings: expected at most 64 settings")
    kinds = {}
    for setting in settings:
        keys(setting, ("kind", "value"), "HTTP/3 setting")
        kind = choice(
            setting["kind"],
            (*SETTING_BOUNDS, *BOOL_SETTINGS, "RandomizedGrease"),
            "HTTP/3 setting kind",
        )
        if kind in kinds:
            raise DeclarationError(f"duplicate HTTP/3 setting: {kind}")
        value = setting["value"]
        kinds[kind] = value
        if kind in SETTING_BOUNDS:
            if type(value) is not int or not 0 <= value <= SETTING_BOUNDS[kind]:
                raise DeclarationError(f"{kind}: HTTP/3 setting value out of range")
        elif kind in BOOL_SETTINGS:
            boolean(value, kind)
        elif value is not None:
            raise DeclarationError(
                "RandomizedGrease is a runtime policy without a value"
            )
    if kinds.get("EnableWebTransportDraft02"):
        raise DeclarationError("WebTransport is not implemented")
    if kinds.get("H3DatagramDraft04") and not kinds.get("H3Datagram"):
        raise DeclarationError("draft datagrams require final H3Datagram enabled")


def validate_pseudo_headers(order, extended):
    required = set(PSEUDO_HEADERS if extended else PSEUDO_HEADERS[:-1])
    if not isinstance(order, list) or len(order) != len(required):
        raise DeclarationError("pseudo-header order has an invalid length")
    for header in order:
        choice(header, required, "HTTP pseudo-header")
    if set(order) != required:
        raise DeclarationError("pseudo-header order must contain each header once")
