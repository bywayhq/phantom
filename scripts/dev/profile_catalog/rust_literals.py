"""Rust literal encoding for compiled profile settings."""

import json


def rust_byte_slice(value):
    return "&[" + ", ".join(str(byte) for byte in value) + "]"


def rust_bytes(value):
    return f"Box::<[u8]>::from({rust_byte_slice(value)}[..])"


def rust_header_order(headers, protocol="Http3"):
    return (
        "vec!["
        + ", ".join(f"crate::{protocol}PseudoHeader::{item}" for item in headers)
        + "]"
    )


def rust_duration(value):
    return f"std::time::Duration::new({value['seconds']}, {value['nanoseconds']})"


def rust_option(value, expression):
    return "None" if value is None else f"Some({expression(value)})"


def rust_nonzero_usize(value):
    # The const block rejects invalid emitted literals at compile time; no
    # runtime panic or substitution exists in a generated factory.
    return (
        f"const {{ match std::num::NonZeroUsize::new({value}) {{"
        ' Some(value) => value, None => panic!("invalid nonzero component literal") } }'
    )


def rust_string(value):
    # JSON escaping of printable ASCII matches ordinary Rust string literals.
    # Keep non-ASCII literal so JSON's \uXXXX syntax never reaches Rust.
    return json.dumps(value, ensure_ascii=False)


def rust_strings(values):
    return "&[" + ", ".join(rust_string(value) for value in values) + "]"
