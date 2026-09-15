//! Network protocol implementations for Phantom.

pub mod http1;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the TLS seam is integrated with HTTP/1 in the immediately following slice"
    )
)]
pub(crate) mod tls;
