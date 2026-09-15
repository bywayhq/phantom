//! Browser-neutral profile identity and provenance.
//!
//! Protocol-specific profile fields will be added alongside the first transport
//! that consumes and verifies them.

use std::{error::Error, fmt, str::FromStr};

/// Stable identifier for a built-in or user-defined browser profile.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileId(Box<str>);

impl ProfileId {
    /// Creates a profile identifier.
    ///
    /// Identifiers use lowercase ASCII components separated by `/`, for example
    /// `firefox/145/linux`.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, InvalidProfileId> {
        let value = value.into();
        let components_are_safe = value.split('/').all(|part| !matches!(part, "." | ".."));
        let valid = !value.is_empty()
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains("//")
            && components_are_safe
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'-' | b'_' | b'.')
            });

        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidProfileId)
        }
    }

    /// Returns the identifier as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ProfileId {
    type Err = InvalidProfileId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Error returned when a profile identifier is empty or not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidProfileId;

impl fmt::Display for InvalidProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("profile IDs must contain lowercase ASCII components separated by `/`")
    }
}

impl Error for InvalidProfileId {}

/// Browser engine family represented by a profile.
///
/// This value is descriptive. Transports must consume protocol fields rather
/// than branching on the browser family.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BrowserFamily {
    /// A Chromium-family browser.
    Chromium,
    /// Mozilla Firefox.
    Firefox,
    /// Apple Safari.
    Safari,
    /// A browser family not built into Phantom.
    Other(Box<str>),
}

/// Operating-system family associated with a captured profile.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Platform {
    /// Android.
    Android,
    /// Apple iOS or iPadOS.
    Ios,
    /// Linux.
    Linux,
    /// Apple macOS.
    MacOs,
    /// Microsoft Windows.
    Windows,
    /// A platform not built into Phantom.
    Other(Box<str>),
}

/// Strength of evidence supporting a profile's compatibility claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerificationLevel {
    /// The profile has not been compared with a browser capture.
    #[default]
    Experimental,
    /// Deterministic local protocol assertions cover the profile.
    LocallyVerified,
    /// A normalized differential matches a pinned browser capture.
    DifferentiallyVerified,
}

/// Identity and provenance shared by every browser profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileMetadata {
    id: ProfileId,
    family: BrowserFamily,
    version: Box<str>,
    platform: Platform,
    verification: VerificationLevel,
}

impl ProfileMetadata {
    /// Creates metadata for an experimental profile.
    pub fn experimental(
        id: ProfileId,
        family: BrowserFamily,
        version: impl Into<Box<str>>,
        platform: Platform,
    ) -> Result<Self, EmptyBrowserVersion> {
        let version = version.into();
        if version.trim().is_empty() {
            return Err(EmptyBrowserVersion);
        }

        Ok(Self {
            id,
            family,
            version,
            platform,
            verification: VerificationLevel::Experimental,
        })
    }

    /// Returns the stable profile identifier.
    #[must_use]
    pub fn id(&self) -> &ProfileId {
        &self.id
    }

    /// Returns the browser family.
    #[must_use]
    pub fn family(&self) -> &BrowserFamily {
        &self.family
    }

    /// Returns the browser version as captured by the profile source.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the profile platform.
    #[must_use]
    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    /// Returns the profile's current evidence level.
    #[must_use]
    pub fn verification(&self) -> VerificationLevel {
        self.verification
    }
}

/// Error returned when browser-version metadata is empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyBrowserVersion;

impl fmt::Display for EmptyBrowserVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("browser version must not be empty")
    }
}

impl Error for EmptyBrowserVersion {}

#[cfg(test)]
mod tests {
    use super::{BrowserFamily, Platform, ProfileId, ProfileMetadata, VerificationLevel};

    #[test]
    fn accepts_builtin_and_custom_profile_identity() -> Result<(), Box<dyn std::error::Error>> {
        let id = ProfileId::new("safari/26.0/macos-26")?;
        let metadata =
            ProfileMetadata::experimental(id, BrowserFamily::Safari, "26.0", Platform::MacOs)?;

        assert_eq!(metadata.id().as_str(), "safari/26.0/macos-26");
        assert_eq!(metadata.verification(), VerificationLevel::Experimental);

        let custom = BrowserFamily::Other("ladybird".into());
        assert_eq!(custom, BrowserFamily::Other("ladybird".into()));

        Ok(())
    }

    #[test]
    fn rejects_noncanonical_profile_ids() {
        for value in [
            "",
            "/firefox/145/linux",
            "Firefox/145",
            "a//b",
            "a/./b",
            "a/../b",
            "a b",
        ] {
            assert!(ProfileId::new(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rejects_empty_browser_versions() -> Result<(), Box<dyn std::error::Error>> {
        let id = ProfileId::new("custom/development/linux")?;
        let result = ProfileMetadata::experimental(
            id,
            BrowserFamily::Other("custom".into()),
            "  ",
            Platform::Linux,
        );

        assert!(result.is_err());
        Ok(())
    }
}
