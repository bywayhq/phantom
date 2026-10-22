//! Caller-owned names for validated custom settings.

use super::{export_profile_json, import_profile_json};
use phantom_profile::ClientProfile;
use std::{collections::BTreeMap, error::Error, fmt};

/// Recovery category for a custom registry operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileRegistryErrorKind {
    /// A name does not match the documented syntax or length.
    InvalidName,
    /// The exact name is already registered. Its value is unchanged.
    DuplicateName,
    /// The profile failed document validation. See the error source.
    InvalidProfile,
}

/// A registry failure that omits caller-provided names and settings.
#[derive(Debug)]
pub struct ProfileRegistryError {
    kind: ProfileRegistryErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}
impl ProfileRegistryError {
    /// Returns the error's recovery category.
    #[must_use]
    pub const fn kind(&self) -> ProfileRegistryErrorKind {
        self.kind
    }

    fn name(kind: ProfileRegistryErrorKind) -> Self {
        Self { kind, source: None }
    }
    fn profile(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind: ProfileRegistryErrorKind::InvalidProfile,
            source: Some(Box::new(source)),
        }
    }
}
impl fmt::Display for ProfileRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ProfileRegistryErrorKind::InvalidName => f.write_str("profile name must be 1..=128 ASCII bytes: start with a lowercase letter or digit, then use lowercase letters, digits, '.', '_', '/' or '-'"),
            ProfileRegistryErrorKind::DuplicateName => f.write_str("profile name is already registered; remove it explicitly before replacing it"),
            ProfileRegistryErrorKind::InvalidProfile => f.write_str("profile document is invalid; inspect the error source"),
        }
    }
}
impl Error for ProfileRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Caller-owned, exact names for custom profiles, listed in sorted order.
///
/// Names are case-sensitive ASCII: 1..=128 bytes, starting with a lowercase
/// letter or digit, followed by lowercase letters, digits, `.`, `_`, `/` or `-`.
/// Names are labels. Register settings explicitly; duplicate names are rejected.
/// Cloning the registry copies its settings; it shares no client session state.
#[derive(Clone, Debug, Default)]
pub struct ProfileRegistry {
    profiles: BTreeMap<Box<str>, ClientProfile>,
}
impl ProfileRegistry {
    /// Creates an empty custom registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers owned settings after checking their editable round trip.
    ///
    /// # Errors
    ///
    /// Rejects invalid or duplicate names and non-exportable settings. A failed
    /// operation leaves the registry unchanged. Client construction still checks
    /// backend and host support.
    pub fn insert(
        &mut self,
        name: &str,
        profile: ClientProfile,
    ) -> Result<(), ProfileRegistryError> {
        self.check_name(name)?;
        export_profile_json(&profile).map_err(ProfileRegistryError::profile)?;
        self.profiles.insert(name.into(), profile);
        Ok(())
    }

    /// Imports a strict JSON document and registers it under an exact name.
    ///
    /// # Errors
    ///
    /// Rejects invalid or duplicate names and any document rejected by
    /// [`import_profile_json`]. A failed operation leaves the registry unchanged.
    pub fn import_json(&mut self, name: &str, input: &[u8]) -> Result<(), ProfileRegistryError> {
        self.check_name(name)?;
        let profile = import_profile_json(input).map_err(ProfileRegistryError::profile)?;
        self.profiles.insert(name.into(), profile);
        Ok(())
    }

    /// Looks up the exact custom name, with no built-in fallback.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ClientProfile> {
        self.profiles.get(name)
    }

    /// Removes and returns the settings registered under the exact name.
    pub fn remove(&mut self, name: &str) -> Option<ClientProfile> {
        self.profiles.remove(name)
    }

    /// Lists custom names in bytewise sorted order.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> + DoubleEndedIterator + '_ {
        self.profiles.keys().map(AsRef::as_ref)
    }

    /// Returns the number of custom profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Returns whether the registry has no custom profiles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    fn check_name(&self, name: &str) -> Result<(), ProfileRegistryError> {
        let valid = valid_name(name);
        if !valid {
            return Err(ProfileRegistryError::name(
                ProfileRegistryErrorKind::InvalidName,
            ));
        }
        if self.profiles.contains_key(name) {
            return Err(ProfileRegistryError::name(
                ProfileRegistryErrorKind::DuplicateName,
            ));
        }
        Ok(())
    }
}

// Registry and bundle labels have the same syntax; neither becomes a path.
pub(super) fn valid_name(name: &str) -> bool {
    name.len() <= 128
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._/-".contains(&b))
}
