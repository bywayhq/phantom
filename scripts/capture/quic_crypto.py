"""Check captured packet extents before aioquic removes header protection."""

# aioquic 1.3.0's HeaderProtection.remove copies at most four packet-number
# bytes into a 1500-byte header buffer and reads a sixteen-byte sample.
_HEADER_BUFFER_BYTES = 1500
_PACKET_NUMBER_BYTES = 4
_SAMPLE_BYTES = 16


def validate_protected_packet(packet: bytes, encrypted_offset: int) -> None:
    """Reject extents the resolved native header-protection API cannot read."""
    if not 0 <= encrypted_offset <= _HEADER_BUFFER_BYTES - _PACKET_NUMBER_BYTES:
        raise ValueError("QUIC protected header exceeds the native buffer")
    if encrypted_offset + _PACKET_NUMBER_BYTES + _SAMPLE_BYTES > len(packet):
        raise ValueError("QUIC packet omits the complete header-protection sample")
