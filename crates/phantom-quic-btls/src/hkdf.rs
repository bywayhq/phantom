use crate::backend::{HkdfDigest, hkdf_expand};
use crate::{CryptoError, Result};

const TLS_LABEL_PREFIX: &[u8] = b"tls13 ";
const MIN_LABEL_LEN: usize = 1;
const MAX_LABEL_LEN: usize = u8::MAX as usize - TLS_LABEL_PREFIX.len();
const MAX_CONTEXT_LEN: usize = u8::MAX as usize;
const MAX_INFO_LEN: usize = 2 + 1 + u8::MAX as usize + 1 + u8::MAX as usize;

/// Applies the TLS 1.3 `HKDF-Expand-Label` construction from RFC 8446.
pub(crate) fn expand_label(
    digest: HkdfDigest,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if !(MIN_LABEL_LEN..=MAX_LABEL_LEN).contains(&label.len()) {
        return Err(CryptoError::InvalidHkdfLabelLength {
            actual: label.len(),
            minimum: MIN_LABEL_LEN,
            maximum: MAX_LABEL_LEN,
        });
    }
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::InvalidHkdfContextLength {
            actual: context.len(),
            maximum: MAX_CONTEXT_LEN,
        });
    }
    // RFC 5869 limits HKDF-Expand to 255 digest blocks. This is stricter
    // than HkdfLabel's two-byte length field for both supported hashes.
    let maximum_output_len = digest.output_len() * u8::MAX as usize;
    if output.len() > maximum_output_len {
        return Err(CryptoError::InvalidHkdfOutputLength {
            actual: output.len(),
            maximum: maximum_output_len,
        });
    }

    let full_label_len = TLS_LABEL_PREFIX.len() + label.len();
    let required = 2 + 1 + full_label_len + 1 + context.len();
    let mut info = [0; MAX_INFO_LEN];
    info[..2].copy_from_slice(&(output.len() as u16).to_be_bytes());
    info[2] = full_label_len as u8;
    let prefix_end = 3 + TLS_LABEL_PREFIX.len();
    info[3..prefix_end].copy_from_slice(TLS_LABEL_PREFIX);
    let label_end = prefix_end + label.len();
    info[prefix_end..label_end].copy_from_slice(label);
    info[label_end] = context.len() as u8;
    info[label_end + 1..required].copy_from_slice(context);

    hkdf_expand(digest, secret, &info[..required], output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_tls_hkdf_label_length_range() {
        let mut output = [0; 1];
        expand_label(
            HkdfDigest::Sha256,
            &[0; 32],
            &[0; MIN_LABEL_LEN],
            &[],
            &mut output,
        )
        .unwrap_or_else(|error| panic!("minimum HKDF label was rejected: {error}"));

        let empty_label_error = CryptoError::InvalidHkdfLabelLength {
            actual: 0,
            minimum: MIN_LABEL_LEN,
            maximum: MAX_LABEL_LEN,
        };
        assert_eq!(
            expand_label(HkdfDigest::Sha256, &[0; 32], &[], &[], &mut output),
            Err(empty_label_error)
        );
        assert_eq!(
            empty_label_error.to_string(),
            "HKDF label length 0 is outside 1..=249"
        );
        assert_eq!(
            expand_label(
                HkdfDigest::Sha256,
                &[0; 32],
                &[0; MAX_LABEL_LEN + 1],
                &[],
                &mut output,
            ),
            Err(CryptoError::InvalidHkdfLabelLength {
                actual: MAX_LABEL_LEN + 1,
                minimum: MIN_LABEL_LEN,
                maximum: MAX_LABEL_LEN,
            })
        );
    }

    #[test]
    fn rejects_context_not_representable_by_tls_hkdf_label() {
        let mut output = [0; 1];
        assert_eq!(
            expand_label(
                HkdfDigest::Sha256,
                &[0; 32],
                b"label",
                &[0; MAX_CONTEXT_LEN + 1],
                &mut output,
            ),
            Err(CryptoError::InvalidHkdfContextLength {
                actual: MAX_CONTEXT_LEN + 1,
                maximum: MAX_CONTEXT_LEN,
            })
        );
    }

    #[test]
    fn enforces_hkdf_expand_block_limit_for_each_digest() {
        for digest in [HkdfDigest::Sha256, HkdfDigest::Sha384] {
            let secret = vec![0; digest.output_len()];
            let maximum = digest.output_len() * u8::MAX as usize;
            let mut maximum_output = vec![0; maximum];
            expand_label(digest, &secret, b"label", &[], &mut maximum_output)
                .unwrap_or_else(|error| panic!("maximum HKDF output was rejected: {error}"));

            let mut oversized_output = vec![0; maximum + 1];
            assert_eq!(
                expand_label(digest, &secret, b"label", &[], &mut oversized_output),
                Err(CryptoError::InvalidHkdfOutputLength {
                    actual: maximum + 1,
                    maximum,
                })
            );
        }
    }
}
