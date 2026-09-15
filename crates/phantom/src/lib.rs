//! Public facade for Phantom.
//!
//! Networking APIs will be introduced with the first complete transport slice.
//! Profile identity is available now so browser-family assumptions can be tested
//! before transport APIs stabilize.

/// Browser-profile types used to configure observable wire behavior.
pub mod profile {
    pub use phantom_profile::{
        BrowserFamily, EmptyBrowserVersion, InvalidProfileId, Platform, ProfileId, ProfileMetadata,
    };
}
