"""Native profile authoring and strict capture imports."""

from __future__ import annotations

import json as _json
from collections.abc import (
    Callable,
)
from dataclasses import dataclass
from dataclasses import field as _field
from typing import (
    Literal,
    cast,
)

from . import _native
from ._errors import _P, _T, ProfileError, _call
from ._native import NativeProfile as _NativeProfile
from ._request import _CatalogContext


def _profile_call(
    function: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
) -> _T:
    try:
        return _call(function, *args, **kwargs)
    except _native.NativeProfileError as error:
        kind, field = cast(tuple[str, str], error.args)
        raise ProfileError(kind, field) from None


@dataclass(frozen=True, slots=True, init=False)
class Profile:
    """Immutable native settings; imports do not retain catalog identity."""

    _native: _NativeProfile = _field(repr=False)

    def __init__(self) -> None:
        raise TypeError("use Profile.from_catalog or Profile.import_json")

    @classmethod
    def _wrap(cls, native: _NativeProfile) -> Profile:
        profile = object.__new__(cls)
        object.__setattr__(profile, "_native", native)
        return profile

    @classmethod
    def from_catalog(
        cls, exact_id: str, *, context: _CatalogContext | None = None
    ) -> Profile:
        return cls._wrap(
            _profile_call(_native.NativeProfile.from_catalog, exact_id, context)
        )

    @classmethod
    def import_json(cls, document: bytes) -> Profile:
        if not isinstance(document, bytes):
            raise TypeError("profile documents must be bytes")
        return cls._wrap(_profile_call(_native.NativeProfile.import_json, document))

    @classmethod
    def import_ja3(cls, description: str, *, base: Profile) -> ImportedProfile:
        """Import raw JA3 using the base for its missing settings."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(_native.NativeProfile.import_ja3, description, base._native)
        )

    @classmethod
    def import_client_hello(cls, handshake: bytes, *, base: Profile) -> ImportedProfile:
        """Import a TCP handshake including its four-byte header, without a TLS record."""
        _import_input(handshake, bytes, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_client_hello, handshake, base._native
            )
        )

    @classmethod
    def import_akamai(cls, description: str, *, base: Profile) -> ImportedProfile:
        """Import ordered HTTP/2 settings, window update and pseudo-header order."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_akamai, description, base._native
            )
        )

    @classmethod
    def import_ja4(
        cls,
        description: str,
        *,
        format: Literal["sorted", "original"],
        base: Profile,
    ) -> ImportedProfile:
        """Import raw JA4; sorted input retains the explicit base's ordering."""
        _import_input(description, str, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_ja4, description, format, base._native
            )
        )

    @classmethod
    def import_quic_transport(
        cls, parameters: bytes, *, base: Profile
    ) -> ImportedProfile:
        """Import extension 57 payload bytes; connection IDs are generated afresh."""
        _import_input(parameters, bytes, base)
        return _imported(
            _profile_call(
                _native.NativeProfile.import_quic_transport, parameters, base._native
            )
        )

    def export_json(self) -> bytes:
        return _profile_call(self._native.export_json)

    def describe(self) -> dict[str, object]:
        """Return a fresh editable document, including literal header values."""
        return cast(dict[str, object], _json.loads(self.export_json()))

    @property
    def catalog_id(self) -> str | None:
        return self._native.catalog_id


@dataclass(frozen=True, slots=True)
class ImportedProfile:
    """Custom profile and canonical paths supplied by input or retained from its base."""

    profile: Profile
    observed_fields: tuple[str, ...]
    supplemented_fields: tuple[str, ...]


def _import_input(
    value: object, expected: type[str] | type[bytes], base: Profile
) -> None:
    if not isinstance(base, Profile):
        raise TypeError("base must be a Profile")
    if not isinstance(value, expected):
        raise TypeError(
            "description must be str" if expected is str else "input must be bytes"
        )


def _imported(result: tuple[_NativeProfile, list[str], list[str]]) -> ImportedProfile:
    profile, observed, supplemented = result
    return ImportedProfile(Profile._wrap(profile), tuple(observed), tuple(supplemented))
