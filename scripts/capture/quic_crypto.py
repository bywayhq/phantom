"""Check captured packet extents before aioquic removes header protection."""

# Retain the capture's original 1500-byte protected-header admission limit.
# aioquic 1.7.0 removes protection in Python, using at most four packet-number
# bytes and a sixteen-byte sample.
_MAX_HEADER_BYTES = 1500
_PACKET_NUMBER_BYTES = 4
_SAMPLE_BYTES = 16


def validate_protected_packet(packet: bytes, encrypted_offset: int) -> None:
    """Bound protected headers and require a complete protection sample."""
    if not 0 <= encrypted_offset <= _MAX_HEADER_BYTES - _PACKET_NUMBER_BYTES:
        raise ValueError("QUIC protected header exceeds the capture limit")
    if encrypted_offset + _PACKET_NUMBER_BYTES + _SAMPLE_BYTES > len(packet):
        raise ValueError("QUIC packet omits the complete header-protection sample")
