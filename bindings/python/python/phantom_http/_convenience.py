"""Python request encoding and typed method forwarding."""

from __future__ import annotations

import json as _json
from collections.abc import AsyncIterable, Iterable, Mapping
from typing import TypeAlias, TypedDict, cast
from urllib.parse import urlencode

from . import _native
from ._bodies import PreparedBody, StreamingMultipartBody, _encoded_maximum
from ._configuration import (
    ContentDecoding,
    RedirectPolicy,
    RetryPolicy,
    TimeoutOverrides,
)
from ._diagnostics import RequestDiagnostics
from ._errors import _call
from ._request import _Headers, _UploadPath
from ._session import AttemptBudget
from ._transfer import TransferControl

_QueryValue: TypeAlias = str | int | float | bool | None
_Params: TypeAlias = Mapping[str, _QueryValue] | Iterable[tuple[str, _QueryValue]]
_Form: TypeAlias = Mapping[str, str] | Iterable[tuple[str, str]]
_DEFAULT_BODY_LIMIT = 16 * 1024 * 1024
_JSON_UNSET = object()


class _RequestOptions(TypedDict, total=False):
    params: _Params | None
    json: object
    form: _Form | None
    maximum_body_bytes: int
    headers: _Headers
    trailers: _Headers
    expect_continue_ms: int | None
    body_length: int | None
    upload: _UploadPath | None
    budget: AttemptBudget | None
    timeout_ms: int | None
    timeouts: TimeoutOverrides | None
    content_decoding: ContentDecoding | None
    redirect_policy: RedirectPolicy | None
    redirect_history_limit: int | None
    retry_policy: RetryPolicy | None
    transfer_control: TransferControl | None
    diagnostics: RequestDiagnostics | None


class _AsyncRequestOptions(_RequestOptions, total=False):
    body: bytes | PreparedBody | StreamingMultipartBody | AsyncIterable[bytes] | None


class _SyncRequestOptions(_RequestOptions, total=False):
    body: bytes | PreparedBody | StreamingMultipartBody | Iterable[bytes] | None


def _query_url(url: str, params: _Params | None) -> str:
    if params is None:
        return url
    if not isinstance(url, str):
        raise TypeError("url must be str")

    pairs: Iterable[tuple[str, _QueryValue]]
    if isinstance(params, Mapping):
        pairs = cast(Mapping[str, _QueryValue], params).items()
    else:
        pairs = params
    encoded: list[str] = []
    size = len(url.encode("utf-8"))
    for index, pair in enumerate(pairs):
        if index >= 65536:
            raise ValueError("params exceed 65536 pairs")
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise TypeError("params must contain (name, value) tuples")
        name, value = pair
        if not isinstance(name, str):
            raise TypeError("param names must be str")
        if value is None:
            continue
        if not isinstance(value, (str, int, float)):
            raise TypeError("param values must be str, int, float, bool or None")
        if isinstance(value, bool):
            value = "true" if value else "false"
        if len(name) + len(str(value)) > 65536 - size:
            raise ValueError("url and params exceed 65536 bytes")
        field = urlencode(((name, value),))
        size += len(field) + 1
        if size > 65536:
            raise ValueError("url and params exceed 65536 bytes")
        encoded.append(field)
    if not encoded:
        return url

    # Append without decoding or normalizing existing escapes or relative paths.
    target, marker, fragment = url.partition("#")
    separator = (
        "?" if "?" not in target else ("" if target.endswith(("?", "&")) else "&")
    )
    return target + separator + "&".join(encoded) + marker + fragment


def _json_body(value: object, maximum: int) -> bytes:
    _encoded_maximum(maximum)
    output = bytearray()
    encoder = _json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    for chunk in encoder.iterencode(value):
        if len(chunk) > maximum - len(output):
            raise ValueError("JSON body exceeds maximum_body_bytes")
        data = chunk.encode("utf-8")
        if len(data) > maximum - len(output):
            raise ValueError("JSON body exceeds maximum_body_bytes")
        output.extend(data)
    return bytes(output)


def _encoded_headers(headers: _Headers, content_type: str) -> _Headers:
    from ._configuration import Header
    from ._request import _request_fields

    ordered, _ = _request_fields(headers, ())
    matching = [value for name, value, _ in ordered if name.lower() == "content-type"]
    if matching and matching != [content_type.encode("ascii")]:
        raise ValueError("encoded body requires one matching Content-Type header")
    if not matching:
        ordered.append(("content-type", content_type.encode("ascii"), False))
    return tuple(
        Header(name, value, sensitive=sensitive) for name, value, sensitive in ordered
    )


def _prepare_request(
    url: str,
    headers: _Headers,
    body: bytes | PreparedBody | StreamingMultipartBody | AsyncIterable[bytes] | None,
    upload: _UploadPath | None,
    params: _Params | None,
    json: object,
    form: _Form | None,
    maximum_body_bytes: int,
) -> tuple[
    str,
    _Headers,
    bytes | PreparedBody | StreamingMultipartBody | AsyncIterable[bytes] | None,
]:
    if (
        sum(
            (
                body is not None,
                upload is not None,
                json is not _JSON_UNSET,
                form is not None,
            )
        )
        > 1
    ):
        raise ValueError("pass only one of body, upload, json or form")
    url = _query_url(url, params)
    if json is not _JSON_UNSET:
        data = _json_body(json, maximum_body_bytes)
        body = PreparedBody._wrap(
            _call(
                _native.NativePreparedBody.encoded,
                data,
                "application/json",
                maximum_body_bytes,
            )
        )
        headers = _encoded_headers(headers, "application/json")
    elif form is not None:
        pairs = form.items() if isinstance(form, Mapping) else form
        body = PreparedBody.form(pairs, maximum_bytes=maximum_body_bytes)
        headers = _encoded_headers(headers, body.content_type)
    return url, headers, body
