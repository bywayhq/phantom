//! Wire settings currently consumed by the public client facade.

use crate::{Http2Settings, TlsSettings};

/// Implemented protocol settings for one client wire profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientProfile {
    tls: TlsSettings,
    http2: Option<Http2Settings>,
}

impl ClientProfile {
    /// Creates a profile with the required TLS settings.
    #[must_use]
    pub fn new(tls: TlsSettings) -> Self {
        Self { tls, http2: None }
    }

    /// Adds HTTP/2 settings to the profile.
    #[must_use]
    pub fn with_http2(mut self, http2: Http2Settings) -> Self {
        self.http2 = Some(http2);
        self
    }

    /// Returns the profile's TLS settings.
    #[must_use]
    pub fn tls(&self) -> &TlsSettings {
        &self.tls
    }

    /// Returns the profile's HTTP/2 settings when configured.
    #[must_use]
    pub fn http2(&self) -> Option<&Http2Settings> {
        self.http2.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClientProfile, chromium};

    #[test]
    fn new_owns_tls_settings_without_enabling_http2() {
        let tls = chromium::v152_macos_tls();
        let profile = ClientProfile::new(tls.clone());

        assert_eq!(profile.tls(), &tls);
        assert_eq!(profile.http2(), None);
    }

    #[test]
    fn with_http2_owns_and_exposes_http2_settings() {
        let tls = chromium::v152_macos_tls();
        let http2 = chromium::v152_macos_http2();
        let profile = ClientProfile::new(tls.clone()).with_http2(http2.clone());

        assert_eq!(profile.tls(), &tls);
        assert_eq!(profile.http2(), Some(&http2));
    }
}
