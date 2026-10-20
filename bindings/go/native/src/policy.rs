use crate::timeouts::Timeouts;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ContentDecoding {
    None {},
    Advertised { maximum_decoded_bytes: u64 },
}

impl Default for ContentDecoding {
    fn default() -> Self {
        Self::None {}
    }
}

impl ContentDecoding {
    pub(super) fn core(self) -> phantom::ContentDecoding {
        match self {
            Self::None {} => phantom::ContentDecoding::none(),
            Self::Advertised {
                maximum_decoded_bytes,
            } => phantom::ContentDecoding::advertised(maximum_decoded_bytes),
        }
    }
}

pub(super) struct RequestPolicy {
    pub(super) timeouts: Timeouts,
    pub(super) content_decoding: ContentDecoding,
}

pub(super) fn coding_name(coding: phantom::ContentCoding) -> &'static str {
    match coding {
        phantom::ContentCoding::Gzip => "gzip",
        phantom::ContentCoding::Deflate => "deflate",
        phantom::ContentCoding::Brotli => "br",
        phantom::ContentCoding::Zstd => "zstd",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_modes_preserve_zero_and_full_u64_and_reject_extra_fields()
    -> Result<(), serde_json::Error> {
        assert_eq!(
            ContentDecoding::default().core().maximum_decoded_bytes(),
            None
        );
        for maximum in [0, u64::MAX] {
            let value: ContentDecoding = serde_json::from_str(&format!(
                r#"{{"mode":"advertised","maximum_decoded_bytes":{maximum}}}"#
            ))?;
            assert_eq!(value.core().maximum_decoded_bytes(), Some(maximum));
        }
        for input in [
            r#"{"mode":"none","maximum_decoded_bytes":0}"#,
            r#"{"mode":"none","extra":true}"#,
            r#"{"mode":"advertised"}"#,
            r#"{"mode":"advertised","maximum_decoded_bytes":0,"extra":true}"#,
            r#"{"mode":"advertised","maximum_decoded_bytes":-1}"#,
            r#"{"mode":"other"}"#,
        ] {
            assert!(serde_json::from_str::<ContentDecoding>(input).is_err());
        }
        Ok(())
    }
}
