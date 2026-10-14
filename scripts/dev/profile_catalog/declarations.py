"""Bounded JSON declarations and shared value validation."""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


MAX_BYTES = 16 * 1024 * 1024


MAX_PROFILES = 4096


MAX_DEPTH = 16


MAX_STRING = 4096


MAX_REFERENCES = 16


MAX_COMPONENTS = 4096


MAX_COMPONENT_CHAIN = 32


MAX_VARINT = (1 << 62) - 1


PSEUDO_HEADERS = ("Method", "Authority", "Scheme", "Path", "Protocol")


MAX_U32 = (1 << 32) - 1


MAX_U64 = (1 << 64) - 1


RUST_KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "gen",
    "macro",
    "override",
    "priv",
    "try",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    "union",
}


class DeclarationError(ValueError):
    """A declaration violates the closed schema or compiled recipe contract."""


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeclarationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def keys(value, expected, context):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise DeclarationError(f"{context}: expected keys {', '.join(expected)}")


def text(value, context):
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise DeclarationError(f"{context}: expected bounded nonempty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DeclarationError(f"{context}: control characters are forbidden")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise DeclarationError(f"{context}: invalid Unicode scalar value")
    return value


def choice(value, allowed, context):
    text(value, context)
    if value not in allowed:
        raise DeclarationError(f"{context}: unknown value {value}")
    return value


def string_list(value, context):
    if not isinstance(value, list) or len(value) > 64:
        raise DeclarationError(f"{context}: expected at most 64 strings")
    for item in value:
        text(item, context)
    if len(set(value)) != len(value):
        raise DeclarationError(f"{context}: duplicate entry")


def check_depth(value, depth=0):
    if depth > MAX_DEPTH:
        raise DeclarationError("declaration nesting limit exceeded")
    if isinstance(value, dict):
        for item in value.values():
            check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_depth(item, depth + 1)


def read_document(path):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise DeclarationError("catalog input byte limit exceeded")
    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise DeclarationError(f"invalid catalog JSON: {error}") from error


def component_identifier(value):
    text(value, "component identifier")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) or value in RUST_KEYWORDS:
        raise DeclarationError("component identifier must be a non-keyword Rust name")
    return value


def boolean(value, context):
    if type(value) is not bool:
        raise DeclarationError(f"{context}: expected boolean")


def bounded_integer(value, minimum, maximum, context):
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeclarationError(f"{context}: integer out of range")


def validate_duration(value, context):
    keys(value, ("seconds", "nanoseconds"), context)
    bounded_integer(value["seconds"], 0, MAX_U64, context)
    bounded_integer(value["nanoseconds"], 0, 999_999_999, context)


def duration_is_zero(value):
    return value["seconds"] == 0 and value["nanoseconds"] == 0


def bounded_list(value, minimum, maximum, context):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DeclarationError(f"{context}: list length out of range")


def validate_bytes(value, minimum, maximum, context):
    bounded_list(value, minimum, maximum, context)
    for byte in value:
        bounded_integer(byte, 0, 255, context)
