"""Parsed native client-certificate ownership."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as _field
from typing import (
    TYPE_CHECKING,
)

from . import _native
from ._errors import Error, _call

if TYPE_CHECKING:
    from ._native import NativeClientCertificate as _NativeClientCertificate


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class ClientCertificate:
    """Parsed leaf-first chain and matching unencrypted key; no implicit file IO.

    Inputs total at most 16 MiB; DER chains contain one through 256 certificates.
    Parsing releases the GIL. The owner has no private-key export operation.
    Client origin mappings accept at most 256 ordered pairs, with 64 KiB per
    origin and 16 MiB aggregate UTF-8 origin bytes. The last core-normalized
    origin match wins; unmapped origins use the optional default certificate.
    """

    _native: _NativeClientCertificate = _field(repr=False)

    def __init__(self) -> None:
        raise TypeError("use ClientCertificate.from_pem or ClientCertificate.from_der")

    @classmethod
    def _wrap(cls, native: _NativeClientCertificate) -> ClientCertificate:
        certificate = object.__new__(cls)
        object.__setattr__(certificate, "_native", native)
        return certificate

    @classmethod
    def from_pem(
        cls, certificate_chain: bytes, private_key: bytes
    ) -> ClientCertificate:
        cls._check_bytes((certificate_chain,), private_key)
        return cls._wrap(
            _call(
                _native.NativeClientCertificate.from_pem, certificate_chain, private_key
            )
        )

    @classmethod
    def from_der(
        cls, certificate_chain: tuple[bytes, ...], private_key: bytes
    ) -> ClientCertificate:
        if not isinstance(certificate_chain, tuple):
            raise TypeError("certificate_chain must be a tuple of DER bytes")
        if not 1 <= len(certificate_chain) <= 256:
            raise Error("client_certificate", "invalid_chain_count")
        cls._check_bytes(certificate_chain, private_key)
        return cls._wrap(
            _call(
                _native.NativeClientCertificate.from_der, certificate_chain, private_key
            )
        )

    @staticmethod
    def _check_bytes(chain: tuple[bytes, ...], key: bytes) -> None:
        if not isinstance(key, bytes) or any(
            not isinstance(item, bytes) for item in chain
        ):
            raise TypeError("certificate chain and private key must be bytes")
        if len(key) + sum(map(len, chain)) > 16 * 1024 * 1024:
            raise Error("client_certificate", "too_large")

    def __repr__(self) -> str:
        return "ClientCertificate()"
