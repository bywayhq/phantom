//! Bounded configured credential input, independent of challenge state.

use btls::ssl::{SessionTransferCredential, SessionTransferError};
use zeroize::Zeroizing;

pub(super) fn frame(
    mechanism: u8,
    policy: u8,
    fields: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, SessionTransferError> {
    const DOMAIN: &[u8] = b"phantom-ticket-http-credential-v2";
    const MAX_BYTES: usize = 64 * 1024;
    let size = fields
        .iter()
        .try_fold(DOMAIN.len() + 2, |size, field| {
            size.checked_add(4)?.checked_add(field.len())
        })
        .filter(|size| *size <= MAX_BYTES)
        .ok_or(SessionTransferError::TooLarge)?;
    let mut framed = Zeroizing::new(Vec::new());
    framed
        .try_reserve_exact(size)
        .map_err(|_| SessionTransferError::Allocation)?;
    framed.extend_from_slice(DOMAIN);
    framed.extend_from_slice(&[mechanism, policy]);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| SessionTransferError::TooLarge)?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(field);
    }
    Ok(framed)
}

/// Native code recomputes the HMAC under the authenticated source owner key.
pub(super) fn credential(
    mechanism: u8,
    policy: u8,
    fields: &[&[u8]],
) -> Result<SessionTransferCredential, SessionTransferError> {
    SessionTransferCredential::from_canonical_hmac_input(&frame(mechanism, policy, fields)?)
}
