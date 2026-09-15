//! Public facade for Phantom.
//!
//! Current TLS, HTTP/1.1, and HTTP/2 request APIs live in `phantom-net`. This
//! crate currently re-exports profile identity; the client facade, reusable
//! sessions, and protocol routing are planned.

/// Browser-profile types used to configure observable wire behavior.
pub mod profile {
    pub use phantom_profile::{
        BrowserFamily, EmptyBrowserVersion, InvalidProfileId, Platform, ProfileId, ProfileMetadata,
    };
}
