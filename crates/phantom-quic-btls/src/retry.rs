use crate::backend::{AeadContext, constant_time_eq};
use crate::{CryptoError, QuicVersion, Result};

const MAX_CONNECTION_ID_LEN: usize = 20;
const TAG_LEN: usize = 16;

/// Computes the integrity tag for a Retry packet without its trailing tag.
pub fn retry_integrity_tag(
    version: QuicVersion,
    original_destination_connection_id: &[u8],
    retry_without_tag: &[u8],
) -> Result<[u8; TAG_LEN]> {
    validate_connection_id(original_destination_connection_id)?;
    let capacity = 1usize
        .checked_add(original_destination_connection_id.len())
        .and_then(|length| length.checked_add(retry_without_tag.len()))
        .ok_or(CryptoError::AllocationFailed)?;
    let mut pseudo_packet = Vec::new();
    pseudo_packet
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    pseudo_packet.push(original_destination_connection_id.len() as u8);
    pseudo_packet.extend_from_slice(original_destination_connection_id);
    pseudo_packet.extend_from_slice(retry_without_tag);

    let context = AeadContext::aes_128_gcm(version.retry_key())?;
    let mut tag = [0; TAG_LEN];
    context.seal(version.retry_nonce(), &mut tag, 0, &pseudo_packet)?;
    Ok(tag)
}

/// Verifies the trailing integrity tag of a complete Retry packet.
pub fn verify_retry_integrity(
    version: QuicVersion,
    original_destination_connection_id: &[u8],
    retry_packet: &[u8],
) -> Result<bool> {
    let tag_offset = match retry_packet.len().checked_sub(TAG_LEN) {
        Some(offset) => offset,
        None => return Ok(false),
    };
    let expected = retry_integrity_tag(
        version,
        original_destination_connection_id,
        &retry_packet[..tag_offset],
    )?;
    Ok(constant_time_eq(&expected, &retry_packet[tag_offset..]))
}

fn validate_connection_id(connection_id: &[u8]) -> Result<()> {
    if connection_id.len() > MAX_CONNECTION_ID_LEN {
        return Err(CryptoError::InvalidConnectionIdLength {
            actual: connection_id.len(),
            maximum: MAX_CONNECTION_ID_LEN,
        });
    }
    Ok(())
}
