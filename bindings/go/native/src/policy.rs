use crate::{error::Failure, timeouts::Timeouts};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

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
    pub(super) redirects: Option<RedirectPolicy>,
    pub(super) history: Option<u64>,
    pub(super) retries: Option<crate::retry::RetryPolicy>,
}

impl RequestPolicy {
    pub(super) fn apply(
        self,
        mut request: phantom::RequestBuilder,
    ) -> Result<phantom::RequestBuilder, Failure> {
        request = request
            .timeouts(self.timeouts.overrides())
            .content_decoding(self.content_decoding.core());
        if let Some(policy) = self.redirects {
            request = request.redirect_policy(policy.core()?);
        }
        if let Some(policy) = self.retries {
            request = request.retry_policy(policy.core()?);
        }
        if let Some(maximum) = self.history {
            let maximum = history_maximum(maximum)?;
            request = request.redirect_history(maximum);
        }
        Ok(request)
    }
}

fn history_maximum(maximum: u64) -> Result<NonZeroUsize, Failure> {
    usize::try_from(maximum)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| Failure::new("invalid_redirect_history"))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedirectPolicy {
    #[serde(default)]
    maximum_hops: u64,
}

impl RedirectPolicy {
    pub(super) fn core(self) -> Result<phantom::RedirectPolicy, Failure> {
        let maximum = usize::try_from(self.maximum_hops)
            .map_err(|_| Failure::new("invalid_redirect_policy"))?;
        Ok(NonZeroUsize::new(maximum).map_or_else(
            phantom::RedirectPolicy::none,
            phantom::RedirectPolicy::limited,
        ))
    }
}

#[derive(Serialize)]
pub(super) struct RedirectHistory {
    entries: Vec<RedirectHop>,
    omitted_hops: usize,
}

#[derive(Serialize)]
struct RedirectHop {
    from_url: String,
    to_url: String,
    method: String,
    next_method: String,
    status: u16,
}

impl RedirectHistory {
    pub(super) fn capture(
        history: &phantom::RedirectHistory,
        maximum: usize,
    ) -> Result<Self, Failure> {
        // Reject guaranteed overflow before retaining caller-sized URI histories.
        // Final completion serialization also counts JSON escaping and structure.
        let bytes = history.entries().iter().try_fold(0usize, |size, hop| {
            size.checked_add(hop.from_uri().to_string().len())?
                .checked_add(hop.to_uri().to_string().len())?
                .checked_add(hop.method().as_str().len())?
                .checked_add(hop.next_method().as_str().len())
        });
        if bytes.is_none_or(|bytes| bytes > maximum) {
            return Err(Failure::new("metadata_limit"));
        }
        Ok(Self {
            entries: history
                .entries()
                .iter()
                .map(|hop| RedirectHop {
                    from_url: hop.from_uri().to_string(),
                    to_url: hop.to_uri().to_string(),
                    method: hop.method().to_string(),
                    next_method: hop.next_method().to_string(),
                    status: hop.status().as_u16(),
                })
                .collect(),
            omitted_hops: history.omitted_hops(),
        })
    }
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
    fn redirect_policy_rejects_unknown_and_invalid_native_values() -> Result<(), Failure> {
        for input in [
            r#"{"maximum_hops":-1}"#,
            r#"{"maximum_hops":1.5}"#,
            r#"{"maximum_hops":1,"extra":true}"#,
        ] {
            assert!(serde_json::from_str::<RedirectPolicy>(input).is_err());
        }
        assert_eq!(RedirectPolicy::default().core()?.max_hops(), None);
        let policy: RedirectPolicy = serde_json::from_str(r#"{"maximum_hops":7}"#)
            .map_err(|_| Failure::new("invalid_json"))?;
        assert_eq!(policy.core()?.max_hops().map(NonZeroUsize::get), Some(7));
        assert_eq!(
            history_maximum(0).err().map(|error| error.kind),
            Some("invalid_redirect_history")
        );
        assert_eq!(history_maximum(1)?.get(), 1);
        #[cfg(target_pointer_width = "32")]
        {
            let policy: RedirectPolicy =
                serde_json::from_str(r#"{"maximum_hops":18446744073709551615}"#)
                    .map_err(|_| Failure::new("invalid_json"))?;
            assert_eq!(
                policy.core().err().map(|error| error.kind),
                Some("invalid_redirect_policy")
            );
            assert_eq!(
                history_maximum(u64::MAX).err().map(|error| error.kind),
                Some("invalid_redirect_history")
            );
        }
        Ok(())
    }

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
