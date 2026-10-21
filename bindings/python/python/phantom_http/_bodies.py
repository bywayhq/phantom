"""Immutable prepared payloads and one-shot streaming multipart custody."""

from __future__ import annotations

import sys
import threading
from _thread import LockType
from collections.abc import (
    AsyncIterator,
    Iterable,
    Iterator,
)
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    cast,
)

from . import _multipart, _native
from ._errors import Error, PreparedBodyError, _call
from ._request import _UploadPath

if TYPE_CHECKING:
    from ._native import NativePreparedBody as _NativePreparedBody


@dataclass(frozen=True, slots=True, repr=False)
class MultipartPart:
    """One ordered text/byte field; files and producers are not read implicitly."""

    name: str
    value: str | bytes
    filename: str | None = None
    content_type: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("name", self.name),
            ("filename", self.filename),
            ("content_type", self.content_type),
        ):
            if value is None and name != "name":
                continue
            if not isinstance(value, str):
                raise TypeError(f"{name} must be str")
            if len(value) > 4096:
                raise PreparedBodyError("prepared_body", "too_large")
        if not isinstance(self.value, (str, bytes)):
            raise TypeError("multipart value must be str or bytes")

    def __repr__(self) -> str:
        return "MultipartPart(<redacted>)"

    @staticmethod
    def stream(
        name: str,
        source: Iterator[bytes] | AsyncIterator[bytes],
        *,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> _multipart.Part:
        """Retain a closable iterator without pulling it; use with StreamingMultipartBody."""
        return _multipart.Part(name, source, filename, content_type, 2)

    @staticmethod
    def file(
        name: str,
        path: _UploadPath,
        *,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> _multipart.Part:
        """Open a regular file only when its multipart field is demanded."""
        return _multipart.Part(name, path, filename, content_type, 3)


def _encoded_maximum(value: int) -> None:
    if type(value) is not int:
        raise TypeError("maximum_bytes must be an integer")
    if not 0 <= value <= sys.maxsize * 2 + 1:
        raise ValueError("maximum_bytes must fit an unsigned native integer")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class StreamingMultipartBody:
    """Send ordered text, bytes, files and one-shot streams within an encoded cap.

    Supply at most 1024 parts and an explicit boundary. Use closable byte iterators
    with Client, or async iterators with aclose() with AsyncClient. The first
    request owns the sources and calls each close method once, including unread
    parts on failure. Do not share a source between bodies. Noncooperative cleanup
    remains owned under the usual response/client close contract.

    Files open only on demand. The body has unknown length, rejects body_length,
    and cannot be reused or replayed. maximum_bytes includes multipart framing;
    failures may occur after earlier bytes have been sent. Place content_type in
    a caller header or a template slot, as for PreparedBody.
    """

    _parts: tuple[MultipartPart | _multipart.Part, ...]
    _boundary: str
    _maximum: int
    _content_type: str
    _lock: LockType
    _claimed: bool

    def __init__(
        self,
        parts: list[MultipartPart | _multipart.Part]
        | tuple[MultipartPart | _multipart.Part, ...],
        *,
        boundary: str,
        maximum_bytes: int,
    ) -> None:
        if type(parts) not in (list, tuple):
            raise TypeError("multipart parts must be a list or tuple")
        if len(parts) > 1024:
            raise PreparedBodyError("prepared_body", "too_many_parts")
        if any(
            not isinstance(part, (MultipartPart, _multipart.Part)) for part in parts
        ):
            raise TypeError("multipart parts must come from MultipartPart")
        _encoded_maximum(maximum_bytes)
        if not isinstance(boundary, str):
            raise TypeError("boundary must be str")
        content_type = _call(
            _native.NativeStreamingMultipart.content_type_for, boundary
        )
        object.__setattr__(
            self,
            "_parts",
            cast(tuple[MultipartPart | _multipart.Part, ...], tuple(parts)),
        )
        object.__setattr__(self, "_boundary", boundary)
        object.__setattr__(self, "_maximum", maximum_bytes)
        object.__setattr__(self, "_content_type", content_type)
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_claimed", False)

    @property
    def content_type(self) -> str:
        return self._content_type

    def __repr__(self) -> str:
        return "StreamingMultipartBody(<redacted>)"

    def _claim(self, asynchronous: bool) -> _multipart.Upload:
        with self._lock:
            if self._claimed:
                raise Error("input", "upload_used")
            object.__setattr__(self, "_claimed", True)
        sources = _multipart.Sources()
        failure: BaseException | None = None
        seen: set[int] = set()
        for index, part in enumerate(self._parts):
            if not isinstance(part, _multipart.Part):
                continue
            if not part.claim():
                if failure is None:
                    failure = Error("input", "upload_used")
                continue
            if part.kind != 2:
                continue
            source = part.value
            if id(source) in seen:
                if failure is None:
                    failure = Error("input", "duplicate_multipart_source")
                continue
            seen.add(id(source))
            sources.owned[index] = source
            try:
                valid = isinstance(source, AsyncIterator if asynchronous else Iterator)
                close = cast(
                    object,
                    getattr(
                        source,
                        "aclose" if isinstance(source, AsyncIterator) else "close",
                        None,
                    ),
                )
                if not valid or not callable(close):
                    raise TypeError(
                        "multipart stream must be a closable iterator matching the client"
                    )
            except BaseException as error:
                if failure is None:
                    failure = error
        pump = _multipart.Upload(sources)
        pump.failure = failure
        return pump

    def _prepare(self, pump: _multipart.Upload) -> None:
        if pump.failure is not None:
            raise pump.failure
        fields: list[tuple[int, str, object, str | None, str | None]] = []
        for part in self._parts:
            kind = (
                part.kind
                if isinstance(part, _multipart.Part)
                else (0 if isinstance(part.value, str) else 1)
            )
            value = part.value
            if kind == 3:
                # os.fspath accepts the existing explicit upload path contract.
                from os import fspath

                value = fspath(cast(_UploadPath, value))
            for metadata in (part.name, part.filename, part.content_type):
                if metadata is not None and (
                    not isinstance(metadata, str) or len(metadata) > 4096
                ):
                    raise PreparedBodyError("prepared_body", "too_large")
            fields.append((kind, part.name, value, part.filename, part.content_type))
        pump.prepare(self._boundary, fields, self._maximum)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class PreparedBody:
    """Immutable native-owned encoded body, reusable across clients and attempts."""

    _native: _NativePreparedBody

    def __init__(self) -> None:
        raise TypeError("use PreparedBody.form or PreparedBody.multipart")

    @classmethod
    def _wrap(cls, native: _NativePreparedBody) -> PreparedBody:
        body = object.__new__(cls)
        object.__setattr__(body, "_native", native)
        return body

    @classmethod
    def form(
        cls, pairs: Iterable[tuple[str, str]], *, maximum_bytes: int
    ) -> PreparedBody:
        """Encode ordered duplicate UTF-8 pairs with an explicit encoded-byte cap."""
        _encoded_maximum(maximum_bytes)
        ordered: list[tuple[str, str]] = []
        for pair in pairs:
            if len(ordered) >= maximum_bytes:
                raise PreparedBodyError("prepared_body", "too_large")
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError("form pairs must be (str, str) tuples")
            name, value = pair
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("form pairs must contain str")
            ordered.append((name, value))
        return cls._wrap(_call(_native.NativePreparedBody.form, ordered, maximum_bytes))

    @classmethod
    def multipart(
        cls, parts: Iterable[MultipartPart], *, boundary: str, maximum_bytes: int
    ) -> PreparedBody:
        """Encode ordered fields; text normalizes CRLF, bytes remain byte-exact."""
        _encoded_maximum(maximum_bytes)
        if not isinstance(boundary, str):
            raise TypeError("boundary must be str")
        if len(boundary) > 70:
            raise PreparedBodyError("prepared_body", "invalid_boundary")
        ordered: list[tuple[str, str | bytes, str | None, str | None]] = []
        for part in parts:
            if len(ordered) == 1024:
                raise PreparedBodyError("prepared_body", "too_many_parts")
            if not isinstance(part, MultipartPart):
                raise TypeError("multipart parts must be MultipartPart")
            ordered.append((part.name, part.value, part.filename, part.content_type))
        return cls._wrap(
            _call(
                _native.NativePreparedBody.multipart, boundary, ordered, maximum_bytes
            )
        )

    @property
    def content_type(self) -> str:
        return self._native.content_type

    @property
    def length(self) -> int:
        return self._native.length

    def to_bytes(self) -> bytes:
        """Return an explicit copy of the encoded payload."""
        return self._native.to_bytes()

    def __repr__(self) -> str:
        return f"PreparedBody(length={self.length})"
