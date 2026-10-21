"""Native-owned shared body-byte limits, pacing and coherent counters."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import _native


@dataclass(frozen=True)
class TransferLimits:
    """Optional u64 body caps and positive byte rates; None is unlimited.

    Download caps and rates count encoded body bytes.
    """

    upload_bytes: int | None = None
    download_bytes: int | None = None
    upload_bytes_per_second: int | None = None
    download_bytes_per_second: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("upload_bytes", self.upload_bytes),
            ("download_bytes", self.download_bytes),
            ("upload_bytes_per_second", self.upload_bytes_per_second),
            ("download_bytes_per_second", self.download_bytes_per_second),
        ):
            if value is None:
                continue
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer or None")
            if not 0 <= value <= 2**64 - 1:
                raise ValueError(f"{name} must fit an unsigned 64-bit integer")
            if name.endswith("per_second") and value == 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True)
class TransferSnapshot:
    """Reserved quota survives cancellation; decoded frames can lead the buffered cursor."""

    upload_reserved_bytes: int
    upload_body_bytes: int
    download_reserved_bytes: int
    download_encoded_bytes: int
    download_decoded_bytes: int


_UNLIMITED = TransferLimits()


@dataclass(frozen=True, init=False, eq=False)
class TransferControl:
    """Share native allowances and pacing explicitly between requests or clients."""

    limits: TransferLimits
    _native: _native.NativeTransferControl = field(repr=False, compare=False)

    def __init__(self, *, limits: TransferLimits = _UNLIMITED) -> None:
        if not isinstance(limits, TransferLimits):
            raise TypeError("limits must be TransferLimits")
        object.__setattr__(self, "limits", limits)
        object.__setattr__(
            self,
            "_native",
            _native.NativeTransferControl(
                limits.upload_bytes,
                limits.download_bytes,
                limits.upload_bytes_per_second,
                limits.download_bytes_per_second,
            ),
        )

    def snapshot(self) -> TransferSnapshot:
        """Read all five counters together under the core lock."""
        return TransferSnapshot(*self._native.snapshot())
