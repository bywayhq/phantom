use btls::{aead::ConcurrentAeadCtx, hash::hmac_sha256};
use zeroize::Zeroizing;

use super::{MAX_BYTES, SessionSnapshotError, SessionSnapshotErrorKind as Kind, codec};

const MAGIC: &[u8; 8] = b"PHSES001";
const HEADER: usize = 26;
const TAG: usize = 16;
const KEY_DOMAIN: &[u8] = b"phantom-client-session-checkpoint-v1";

pub(super) fn seal(
    mut plaintext: Zeroizing<Vec<u8>>,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SessionSnapshotError> {
    if plaintext.len() > MAX_BYTES - HEADER - TAG {
        return Err(SessionSnapshotError::new(Kind::TooLarge));
    }
    let mut writer = codec::Writer::new();
    writer.raw(MAGIC)?;
    writer.raw(&1_u16.to_be_bytes())?;
    let mut nonce = [0; 12];
    btls::rand::rand_bytes(&mut nonce)?;
    writer.raw(&nonce)?;
    writer.raw(&(plaintext.len() as u32).to_be_bytes())?;
    let derived = Zeroizing::new(hmac_sha256(key, KEY_DOMAIN)?);
    let cipher = ConcurrentAeadCtx::aes_256_gcm(&*derived)?;
    let mut tag = [0; TAG];
    cipher.seal_in_place(&nonce, &mut plaintext, &mut tag, &writer.0)?;
    writer.raw(&plaintext)?;
    writer.raw(&tag)?;
    Ok(writer.0)
}

pub(super) fn open(
    bytes: &[u8],
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SessionSnapshotError> {
    if bytes.len() > MAX_BYTES {
        return Err(SessionSnapshotError::new(Kind::TooLarge));
    }
    if bytes.len() < HEADER + TAG || &bytes[..8] != MAGIC {
        return Err(SessionSnapshotError::new(Kind::InvalidSnapshot));
    }
    if bytes[8..10] != [0, 1] {
        return Err(SessionSnapshotError::new(Kind::Incompatible));
    }
    let length = u32::from_be_bytes(
        bytes[22..26]
            .try_into()
            .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
    ) as usize;
    if length != bytes.len() - HEADER - TAG {
        return Err(SessionSnapshotError::new(Kind::InvalidSnapshot));
    }
    let derived = Zeroizing::new(hmac_sha256(key, KEY_DOMAIN)?);
    let cipher = ConcurrentAeadCtx::aes_256_gcm(&*derived)?;
    let mut plaintext = codec::copy(&bytes[HEADER..HEADER + length], MAX_BYTES)?;
    cipher
        .open_in_place(
            &bytes[10..22],
            &mut plaintext,
            &bytes[HEADER + length..],
            &bytes[..HEADER],
        )
        .map_err(|_| SessionSnapshotError::new(Kind::Authentication))?;
    Ok(plaintext)
}
