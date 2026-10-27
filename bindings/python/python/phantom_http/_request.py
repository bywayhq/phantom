"""Ordered caller fields and request argument types."""

from __future__ import annotations

from collections.abc import (
    Iterable,
)
from os import PathLike
from typing import (
    Literal,
    TypeAlias,
)

from ._configuration import (
    Header,
)

_Protocol: TypeAlias = Literal["h1", "h2", "h3", "negotiated"]
_CatalogContext: TypeAlias = Literal[
    "navigation",
    "fetch",
    "fetch_no_store",
    "fetch_upload",
    "script",
    "stylesheet",
    "image",
    "font",
]
_Context: TypeAlias = _CatalogContext | Literal["profile", "raw"]
_RequestContext: TypeAlias = _CatalogContext | Literal["raw"]
_Headers: TypeAlias = Iterable[Header | tuple[str, str | bytes]]
_UploadPath: TypeAlias = str | PathLike[str]


def _request_fields(
    headers: _Headers, trailers: _Headers
) -> tuple[list[tuple[str, bytes, bool]], list[tuple[str, bytes, bool]]]:
    remaining = 65536
    count = 0
    result: list[list[tuple[str, bytes, bool]]] = []
    for fields in (headers, trailers):
        ordered = []
        for field in fields:
            count += 1
            if count > 256:
                raise ValueError("headers and trailers exceed 256 fields")
            if isinstance(field, Header):
                name, value, sensitive = field.name, field.value, field.sensitive
            else:
                name, value = field
                sensitive = False
            if not isinstance(name, str):
                raise TypeError("header and trailer names must be str")
            if not isinstance(value, (str, bytes)):
                raise TypeError("header and trailer values must be str or bytes")
            if len(name) + len(value) > remaining:
                raise ValueError("headers and trailers exceed 65536 bytes")
            remaining -= len(name.encode("utf-8")) + len(value)
            if remaining < 0:
                raise ValueError("headers and trailers exceed 65536 bytes")
            if isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except UnicodeEncodeError:
                    raise ValueError(
                        "header text must fit Latin-1; supply bytes explicitly"
                    ) from None
            ordered.append((name, value, sensitive))
        result.append(ordered)
    return result[0], result[1]
