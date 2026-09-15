//! Client profile identity and provenance.

use std::{error::Error, fmt, str::FromStr};

/// Stable identifier for a built-in or user-defined client profile.
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

/// Client implementation family represented by a profile.
///
/// This value is descriptive. Transports must consume protocol fields rather
/// than branching on the client family.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientFamily {
    /// A Chromium-family browser.
    Chromium,
    /// Mozilla Firefox.
    Firefox,
    /// Apple Safari.
    Safari,
    /// A client family not built into Phantom.
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

/// Identity and provenance shared by every client profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileMetadata {
    id: ProfileId,
    family: ClientFamily,
    version: Box<str>,
    platform: Platform,
}

impl ProfileMetadata {
    /// Creates client-profile metadata.
    pub fn new(
        id: ProfileId,
        family: ClientFamily,
        version: impl Into<Box<str>>,
        platform: Platform,
    ) -> Result<Self, EmptyClientVersion> {
        let version = version.into();
        if version.trim().is_empty() {
            return Err(EmptyClientVersion);
        }

        Ok(Self {
            id,
            family,
            version,
            platform,
        })
    }

    /// Returns the stable profile identifier.
    #[must_use]
    pub fn id(&self) -> &ProfileId {
        &self.id
    }

    /// Returns the client family.
    #[must_use]
    pub fn family(&self) -> &ClientFamily {
        &self.family
    }

    /// Returns the client version as captured by the profile source.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the profile platform.
    #[must_use]
    pub fn platform(&self) -> &Platform {
        &self.platform
    }
}

/// Error returned when client-version metadata is empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyClientVersion;

impl fmt::Display for EmptyClientVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("client version must not be empty")
    }
}

impl Error for EmptyClientVersion {}

#[cfg(test)]
mod tests;
