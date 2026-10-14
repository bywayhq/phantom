"""Closed ordered CONNECT fields and proxy connection policies."""

from .declarations import MAX_STRING, DeclarationError, choice, keys, text
from .rust_literals import rust_string

FIELD_KINDS = ("Authority", "Literal", "FromRequest", "ProxyAuthorization")
TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
GENERATED_FIELDS = frozenset(
    ("host", "proxy-authorization", "content-length", "transfer-encoding")
)
CREDENTIAL_FIELDS = frozenset(("authorization", "cookie", "cookie2"))
CONNECTION_FIELDS = frozenset(
    ("connection", "keep-alive", "proxy-connection", "te", "upgrade")
)


def validate_connect_fields(fields, http2):
    if not isinstance(fields, list) or len(fields) > 64:
        raise DeclarationError("CONNECT fields must be a list of at most 64 entries")
    names = set()
    authorities = 0
    authorizations = 0
    for field in fields:
        if not isinstance(field, dict):
            raise DeclarationError("CONNECT field must be a typed record")
        kind = choice(field.get("kind"), FIELD_KINDS, "CONNECT field kind")
        keys(
            field,
            ("kind", "name", "value") if kind == "Literal" else ("kind", "name"),
            "CONNECT field",
        )
        name = text(field["name"], "CONNECT field name")
        if not all(char in TOKEN_CHARACTERS for char in name):
            raise DeclarationError("CONNECT field names must be ASCII tokens")
        if http2 and any("A" <= char <= "Z" for char in name):
            raise DeclarationError("HTTP/2 CONNECT field names must be lowercase")
        lower = name.lower()
        if lower in names:
            raise DeclarationError("CONNECT field names must not repeat")
        names.add(lower)
        if kind == "Authority":
            if http2 or lower != "host":
                raise DeclarationError(
                    "only HTTP/1.1 has an authority field named Host"
                )
            authorities += 1
        elif kind == "ProxyAuthorization":
            if lower != "proxy-authorization":
                raise DeclarationError(
                    "credentials placeholder must name Proxy-Authorization"
                )
            authorizations += 1
        else:
            if lower in GENERATED_FIELDS:
                raise DeclarationError(
                    "authority, credentials and framing fields are generated"
                )
            if kind == "FromRequest":
                if lower in CREDENTIAL_FIELDS:
                    raise DeclarationError(
                        "CONNECT must not copy origin credentials or cookies"
                    )
            else:
                value = field["value"]
                if (
                    not isinstance(value, str)
                    or len(value) > MAX_STRING
                    or not all(char == "\t" or " " <= char <= "~" for char in value)
                ):
                    raise DeclarationError(
                        "CONNECT literals must be bounded visible ASCII, spaces or tabs"
                    )
        if http2 and lower in CONNECTION_FIELDS:
            raise DeclarationError(
                "HTTP/2 CONNECT fields must not be connection-specific"
            )
    if not http2 and authorities != 1:
        raise DeclarationError("HTTP/1.1 CONNECT needs exactly one authority")
    if authorizations != 1:
        raise DeclarationError("CONNECT needs exactly one credentials placeholder")


def validate_proxy_connect_values(values):
    validate_connect_fields(values["http1_fields"], False)
    validate_connect_fields(values["http2_fields"], True)
    choice(
        values["http2_rejected"],
        ("EndStream", "LeaveOpen"),
        "rejected CONNECT stream policy",
    )
    choice(
        values["http2_connections"],
        ("Shared", "ByPurpose"),
        "proxy connection sharing policy",
    )


def rust_proxy_connect_value(field, value):
    if field == "http2_rejected":
        return f"crate::Http2RejectedConnect::{value}"
    if field == "http2_connections":
        return f"crate::Http2ProxyConnections::{value}"
    records = []
    for record in value:
        fields = f"name: {rust_string(record['name'])}.into()"
        if record["kind"] == "Literal":
            fields += f", value: {rust_string(record['value'])}.into()"
        records.append(f"crate::ProxyConnectField::{record['kind']} {{ {fields} }}")
    return "vec![" + ", ".join(records) + "]"
