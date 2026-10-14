"""Closed QUIC transport values and ordered wire parameters."""

from .declarations import (
    MAX_VARINT,
    DeclarationError,
    boolean,
    bounded_integer,
    bounded_list,
    choice,
    keys,
)
from .rust_literals import (
    rust_option,
)

QUIC_WIDTHS = {"One": 1, "Two": 2, "Four": 4, "Eight": 8}


QUIC_SCALARS = {
    "MaxIdleTimeout": ("max_idle_timeout_ms", 0x01, 0),
    "MaxUdpPayloadSize": ("max_udp_payload_size", 0x03, 65_527),
    "InitialMaxData": ("initial_max_data", 0x04, 0),
    "InitialMaxStreamDataBidiLocal": ("initial_max_stream_data_bidi_local", 0x05, 0),
    "InitialMaxStreamDataBidiRemote": ("initial_max_stream_data_bidi_remote", 0x06, 0),
    "InitialMaxStreamDataUni": ("initial_max_stream_data_uni", 0x07, 0),
    "InitialMaxStreamsBidi": ("initial_max_streams_bidi", 0x08, 0),
    "InitialMaxStreamsUni": ("initial_max_streams_uni", 0x09, 0),
    "MaxAckDelay": ("max_ack_delay_ms", 0x0B, 25),
    "ActiveConnectionIdLimit": ("active_connection_id_limit", 0x0E, 2),
    "MaxDatagramFrameSize": ("max_datagram_frame_size", 0x20, None),
}


QUIC_PARAMETER_FIELDS = {
    **dict.fromkeys(QUIC_SCALARS, ("value_width",)),
    "ResetStreamAt": (),
    "MinAckDelay": ("draft", "value_width"),
    "InitialSourceConnectionId": ("length",),
    "VersionInformation": ("available_version_count", "grease"),
    "GoogleConnectionOptions": ("options",),
    "InitialRtt": (),
    "Grease": ("minimum_payload_length", "maximum_payload_length"),
}


def quic_width(width, value):
    size = QUIC_WIDTHS[choice(width, QUIC_WIDTHS, "QUIC integer width")]
    bounded_integer(value, 0, (1 << (size * 8 - 2)) - 1, "QUIC encoded integer")
    return size


def validate_quic_parameter(parameter, values):
    keys(parameter, ("kind", "id_width", "length_width"), "QUIC parameter")
    record = parameter["kind"]
    if not isinstance(record, dict):
        raise DeclarationError("QUIC parameter kind must be a typed record")
    kind = choice(record.get("kind"), QUIC_PARAMETER_FIELDS, "QUIC parameter kind")
    keys(record, ("kind", *QUIC_PARAMETER_FIELDS[kind]), "QUIC parameter kind")
    if kind in QUIC_SCALARS:
        field, identifier, _ = QUIC_SCALARS[kind]
        if values[field] is None:
            raise DeclarationError(f"{kind} requires {field}")
        length = quic_width(record["value_width"], values[field])
    elif kind == "MinAckDelay":
        draft = choice(record["draft"], ("Draft02", "Draft07"), "ACK frequency draft")
        identifier = 0xFF02DE1A if draft == "Draft02" else 0xFF04DE1B
        if values["min_ack_delay_us"] is None:
            raise DeclarationError("MinAckDelay requires min_ack_delay_us")
        length = quic_width(record["value_width"], values["min_ack_delay_us"])
    elif kind == "ResetStreamAt":
        identifier, length = 0x1D, 0
    elif kind == "InitialSourceConnectionId":
        identifier = 0x0F
        bounded_integer(record["length"], 0, 20, "source connection ID length")
        length = record["length"]
    elif kind == "VersionInformation":
        identifier = 0x11
        # The current provider implements QUIC v1 and v2 only.
        count = record["available_version_count"]
        bounded_integer(count, 0, 2, "available version count")
        if count == 0:
            raise DeclarationError("available versions must include the chosen version")
        grease = choice(
            record["grease"], ("Omit", "Permuted", "First"), "version GREASE"
        )
        length = 4 + 4 * (count + (grease != "Omit"))
    elif kind == "GoogleConnectionOptions":
        identifier = 0x3128
        bounded_list(record["options"], 1, 1, "Google connection options")
        choice(
            record["options"][0], ("RequestOriginFrame",), "Google connection option"
        )
        length = 4 * len(record["options"])
    elif kind == "InitialRtt":
        identifier, length = 0x3127, 8
    else:
        # A reserved identifier is drawn and encoded by the runtime.
        identifier = None
        for field in ("minimum_payload_length", "maximum_payload_length"):
            bounded_integer(record[field], 0, 15, "GREASE payload length")
        if record["minimum_payload_length"] > record["maximum_payload_length"]:
            raise DeclarationError("GREASE payload length range must not be empty")
        length = record["maximum_payload_length"]
    if identifier is None:
        choice(parameter["id_width"], QUIC_WIDTHS, "QUIC integer width")
    else:
        quic_width(parameter["id_width"], identifier)
    quic_width(parameter["length_width"], length)
    return kind


def validate_quic_values(values):
    for kind, (field, _, _) in QUIC_SCALARS.items():
        value = values[field]
        if kind == "MaxDatagramFrameSize" and value is None:
            continue
        maximum = 1 << 60 if "Streams" in kind else MAX_VARINT
        bounded_integer(value, 0, maximum, field)
    if not 1_200 <= values["max_udp_payload_size"] <= 65_527:
        raise DeclarationError("max_udp_payload_size must be in 1200..=65527")
    if values["max_ack_delay_ms"] >= 16_384:
        raise DeclarationError("max_ack_delay_ms must be below 16384")
    if not 2 <= values["active_connection_id_limit"] <= 8:
        raise DeclarationError("active_connection_id_limit must be in 2..=8")
    delay = values["min_ack_delay_us"]
    if delay is not None:
        bounded_integer(delay, 0, MAX_VARINT, "min_ack_delay_us")
        if delay != 1_000 or delay > values["max_ack_delay_ms"] * 1_000:
            raise DeclarationError(
                "provider ACK delay must be 1000 us and within max ACK delay"
            )
    mtu = values["initial_path_mtu"]
    if mtu is not None:
        bounded_integer(mtu, 0, 65_535, "initial_path_mtu")
        if not 1_248 <= mtu <= values["max_udp_payload_size"] + 28:
            raise DeclarationError("path MTU exceeds the IPv4/IPv6 payload bounds")
    cid = values["initial_destination_connection_id"]
    if cid is not None:
        if not isinstance(cid, dict):
            raise DeclarationError("connection ID length must be a typed record")
        policy = choice(
            cid.get("kind"), ("Fixed", "MaskedRandom"), "connection ID policy"
        )
        if policy == "Fixed":
            keys(cid, ("kind", "length"), "connection ID policy")
            bounded_integer(cid["length"], 0, 20, "connection ID length")
            shortest = longest = cid["length"]
        else:
            keys(cid, ("kind", "minimum", "base"), "connection ID policy")
            bounded_integer(cid["minimum"], 0, 255, "minimum connection ID length")
            bounded_integer(cid["base"], 0, 255, "base connection ID length")
            shortest = cid["minimum"]
            longest = max(shortest, min(255, cid["base"] + 15))
        if shortest < 8 or longest > 20:
            raise DeclarationError("connection ID length policy must stay in 8..=20")
    boolean(values["reset_stream_at"], "reset_stream_at")
    boolean(values["early_data"], "early_data")
    choice(values["parameter_order"], ("Fixed", "Permuted"), "parameter order")
    parameters = values["wire_parameters"]
    if not isinstance(parameters, list) or not 1 <= len(parameters) <= len(
        QUIC_PARAMETER_FIELDS
    ):
        raise DeclarationError(
            "QUIC wire parameter count is outside declaration limits"
        )
    identities = [
        validate_quic_parameter(parameter, values) for parameter in parameters
    ]
    if len(set(identities)) != len(identities):
        raise DeclarationError("QUIC wire parameter kinds must not repeat")
    if "InitialSourceConnectionId" not in identities:
        raise DeclarationError("InitialSourceConnectionId is required")
    for kind, (field, _, default) in QUIC_SCALARS.items():
        if values[field] != default and kind not in identities:
            raise DeclarationError(f"nondefault {field} must be advertised")
    for enabled, kind in (
        (values["max_datagram_frame_size"] is not None, "MaxDatagramFrameSize"),
        (delay is not None, "MinAckDelay"),
        (values["reset_stream_at"], "ResetStreamAt"),
    ):
        if enabled != (kind in identities):
            raise DeclarationError(f"{kind} must match its configured value")


def rust_quic_parameter(parameter):
    record = parameter["kind"]
    kind = record["kind"]
    expression = f"crate::QuicTransportParameterKind::{kind}"
    if kind in QUIC_SCALARS:
        expression += (
            f" {{ value_width: crate::QuicVarIntWidth::{record['value_width']} }}"
        )
    elif kind == "MinAckDelay":
        expression += (
            f" {{ draft: crate::QuicAckFrequencyDraft::{record['draft']},"
            f" value_width: crate::QuicVarIntWidth::{record['value_width']} }}"
        )
    elif kind == "InitialSourceConnectionId":
        expression += f" {{ length: {record['length']} }}"
    elif kind == "VersionInformation":
        expression += (
            "(crate::QuicVersionInformation {"
            f" available_version_count: {record['available_version_count']},"
            f" grease: crate::QuicVersionGrease::{record['grease']} }})"
        )
    elif kind == "GoogleConnectionOptions":
        options = ", ".join(
            f"crate::GoogleConnectionOption::{item}" for item in record["options"]
        )
        expression += f"(vec![{options}])"
    elif kind == "Grease":
        expression += (
            "(crate::QuicTransportGrease {"
            f" minimum_payload_length: {record['minimum_payload_length']},"
            f" maximum_payload_length: {record['maximum_payload_length']} }})"
        )
    return (
        f"crate::QuicTransportParameter {{ kind: {expression},"
        f" id_width: crate::QuicVarIntWidth::{parameter['id_width']},"
        f" length_width: crate::QuicVarIntWidth::{parameter['length_width']} }}"
    )


def rust_quic_value(field, value):
    if field == "wire_parameters":
        return "vec![" + ", ".join(rust_quic_parameter(item) for item in value) + "]"
    if field == "parameter_order":
        return f"crate::QuicTransportParameterOrder::{value}"
    if field == "initial_destination_connection_id":
        if value is None:
            return "None"
        if value["kind"] == "Fixed":
            return f"Some(crate::QuicConnectionIdLength::Fixed({value['length']}))"
        return (
            "Some(crate::QuicConnectionIdLength::MaskedRandom {"
            f" minimum: {value['minimum']}, base: {value['base']} }})"
        )
    if field in ("max_datagram_frame_size", "min_ack_delay_us", "initial_path_mtu"):
        return rust_option(value, str)
    return str(value).lower()
