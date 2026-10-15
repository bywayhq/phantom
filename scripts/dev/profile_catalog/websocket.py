"""Closed WebSocket opening fields, compression and connection policies."""

from .declarations import (
    MAX_STRING,
    DeclarationError,
    bounded_integer,
    bounded_list,
    choice,
    duration_is_zero,
    keys,
    validate_bytes,
    validate_duration,
)
from .rust_literals import rust_bytes, rust_duration, rust_option, rust_string

FIELD_KINDS = (
    "Literal",
    "Caller",
    "Authority",
    "Key",
    "PerMessageDeflate",
    "ClientCookies",
    "ByTrust",
)
DEFLATE_KINDS = (
    "ServerNoContextTakeover",
    "ClientNoContextTakeover",
    "ServerMaxWindowBits",
    "ClientMaxWindowBits",
)
TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
CONNECTION_ENUMS = {
    "without_http2_session": (
        "WebSocketNewConnection",
        ("Http1Upgrade", "Http2ExtendedConnect"),
    ),
    "with_incapable_http2_session": (
        "WebSocketNewConnection",
        ("Http1Upgrade", "Http2ExtendedConnect"),
    ),
    "refused_stream_retry": (
        "WebSocketRefusedStreamRetry",
        ("None", "SameSessionOnce", "ReacquireTwice"),
    ),
    "proxied_http2_session": ("WebSocketProxiedSession", ("Reuse", "Ignore")),
}


def validate_field_value(value):
    if (
        not isinstance(value, str)
        or len(value) > MAX_STRING
        or not all(char == "\t" or " " <= char <= "~" for char in value)
    ):
        raise DeclarationError(
            "WebSocket values must be bounded visible ASCII, spaces or tabs"
        )


def validate_fields(fields, http2):
    bounded_list(fields, 0, 256, "WebSocket template fields")
    counts = dict.fromkeys(
        ("Authority", "Key", "PerMessageDeflate", "ClientCookies"), 0
    )
    for field in fields:
        if not isinstance(field, dict):
            raise DeclarationError("WebSocket field must be a typed record")
        kind = choice(field.get("kind"), FIELD_KINDS, "WebSocket field kind")
        expected = ("kind", "name")
        if kind == "Literal":
            expected += ("value",)
        elif kind == "ByTrust":
            expected += ("trustworthy", "untrustworthy")
        keys(field, expected, "WebSocket field")
        name = field["name"]
        if (
            not isinstance(name, str)
            or not 0 < len(name) <= 256
            or not all(char in TOKEN_CHARACTERS for char in name)
        ):
            raise DeclarationError("WebSocket field names must be bounded ASCII tokens")
        if http2 and any("A" <= char <= "Z" for char in name):
            raise DeclarationError("HTTP/2 WebSocket field names must be lowercase")
        if kind in counts:
            counts[kind] += 1
        if kind == "Literal":
            validate_field_value(field["value"])
        elif kind == "ByTrust":
            for trust in ("trustworthy", "untrustworthy"):
                if field[trust] is not None:
                    validate_field_value(field[trust])
    generated = int(not http2)
    if counts["Authority"] != generated or counts["Key"] != generated:
        raise DeclarationError("H1 needs one authority and key; H2 needs neither")
    if counts["PerMessageDeflate"] > 1 or counts["ClientCookies"] > 1:
        raise DeclarationError(
            "WebSocket compression and cookie placeholders may occur once"
        )


def validate_connection(connection):
    keys(
        connection, (*CONNECTION_ENUMS, "http1_alpn_protocols"), "WebSocket connection"
    )
    for field, (_, variants) in CONNECTION_ENUMS.items():
        choice(connection[field], variants, field)
    protocols = connection["http1_alpn_protocols"]
    bounded_list(protocols, 1, 64, "WebSocket upgrade ALPN")
    for protocol in protocols:
        validate_bytes(protocol, 1, 255, "WebSocket upgrade ALPN")
    if list(b"http/1.1") not in protocols or list(b"h2") in protocols:
        raise DeclarationError(
            "WebSocket upgrade ALPN must include http/1.1 and exclude h2"
        )


def validate_deflate_offer(offer):
    bounded_list(offer, 0, 4, "WebSocket deflate offer")
    seen = set()
    for parameter in offer:
        if not isinstance(parameter, dict):
            raise DeclarationError("WebSocket deflate parameter must be a typed record")
        kind = choice(
            parameter.get("kind"), DEFLATE_KINDS, "WebSocket deflate parameter"
        )
        has_bits = kind in ("ServerMaxWindowBits", "ClientMaxWindowBits")
        keys(
            parameter, ("kind", "bits") if has_bits else ("kind",), "deflate parameter"
        )
        if kind in seen:
            raise DeclarationError("WebSocket deflate parameters must not repeat")
        seen.add(kind)
        if has_bits and not (
            kind == "ClientMaxWindowBits" and parameter["bits"] is None
        ):
            bounded_integer(parameter["bits"], 8, 15, "WebSocket deflate window")


def validate_websocket_values(values):
    validate_connection(values["connection"])
    validate_fields(values["http1_fields"], False)
    validate_fields(values["http2_fields"], True)
    validate_deflate_offer(values["permessage_deflate_offer"])
    choice(
        values["empty_message_compression"],
        ("Compressed", "Uncompressed"),
        "empty compression",
    )
    if values["handshake_timeout"] is not None:
        validate_duration(values["handshake_timeout"], "WebSocket timeout")
        if duration_is_zero(values["handshake_timeout"]):
            raise DeclarationError("WebSocket timeout must be positive or absent")


def rust_websocket_value(field, value):
    if field == "connection":
        fields = [
            f"{name}: crate::{kind}::{value[name]}"
            for name, (kind, _) in CONNECTION_ENUMS.items()
        ]
        fields.insert(
            2,
            "http1_alpn_protocols: vec!["
            + ", ".join(map(rust_bytes, value["http1_alpn_protocols"]))
            + "]",
        )
        return "crate::WebSocketConnectionPolicy { " + ", ".join(fields) + " }"
    if field == "empty_message_compression":
        return f"crate::WebSocketEmptyMessageCompression::{value}"
    if field == "handshake_timeout":
        return rust_option(value, rust_duration)
    if field == "permessage_deflate_offer":
        parameters = []
        for parameter in value:
            kind = parameter["kind"]
            expression = f"crate::WebSocketDeflateParameter::{kind}"
            if kind == "ServerMaxWindowBits":
                expression += f"({parameter['bits']})"
            elif kind == "ClientMaxWindowBits":
                expression += "(" + rust_option(parameter["bits"], str) + ")"
            parameters.append(expression)
        return "vec![" + ", ".join(parameters) + "]"
    records = []
    for record in value:
        fields = f"name: {rust_string(record['name'])}.into()"
        if record["kind"] == "Literal":
            fields += f", value: {rust_string(record['value'])}.into()"
        elif record["kind"] == "ByTrust":
            for trust in ("trustworthy", "untrustworthy"):
                fields += f", {trust}: " + rust_option(
                    record[trust], lambda item: rust_string(item) + ".into()"
                )
        records.append(f"crate::WebSocketField::{record['kind']} {{ {fields} }}")
    return "vec![" + ", ".join(records) + "]"
