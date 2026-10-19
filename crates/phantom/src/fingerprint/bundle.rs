//! Offline, immutable groups of complete custom settings.

use std::collections::BTreeMap;

use super::{
    FingerprintImportError, FingerprintImportErrorKind as Kind, ProfileRegistry, Result,
    import_document, json, registry::valid_name,
};

const MAX_PROFILES: usize = 64;

/// A publisher-supplied reference, not evidence verified by Phantom.
#[derive(Clone, Eq, PartialEq)]
pub struct ProfileProvenance {
    source: Box<str>,
    revision: Box<str>,
}

impl std::fmt::Debug for ProfileProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileProvenance").finish_non_exhaustive()
    }
}

impl ProfileProvenance {
    /// Returns the publisher's source reference. It is never opened or fetched.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the publisher's reference revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// A validated version-1 `phantom.profile-bundle` document.
///
/// Entries are owned custom settings with exact names. Neither bundle labels
/// nor provenance assign catalog identity or establish browser fidelity.
/// Each entry contains one complete custom-profile document, including its
/// selected request template. Catalog context associations are not included.
/// No I/O, client construction or random draws occur during import.
/// Existing clients keep the settings they were built with.
///
/// Debug formatting omits settings, labels and publisher references.
pub struct ProfileBundle {
    id: Box<str>,
    revision: u64,
    digest: String,
    profiles: ProfileRegistry,
    provenance: BTreeMap<Box<str>, Box<[ProfileProvenance]>>,
}

impl std::fmt::Debug for ProfileBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileBundle")
            .field("profiles", &self.profiles.len())
            .finish_non_exhaustive()
    }
}

impl ProfileBundle {
    /// Validates every entry before returning a bundle.
    ///
    /// The envelope requires `format`, `version`, `id`, positive `revision` and
    /// `profiles`. Each entry requires `name`, `document` and `provenance`.
    /// Each provenance reference requires `source` and `revision` strings.
    /// IDs use the registry's exact-name syntax. Labels are never file paths.
    ///
    /// Input is limited to 16 MiB and 1..=64 profiles. Each profile retains the
    /// custom importer's depth-16 limit; its other JSON bounds apply to the
    /// entire envelope. Each entry allows at most 16 provenance references,
    /// with nonempty sources of at most 2,048 UTF-8 bytes and revisions of at
    /// most 128 bytes, without control characters. Empty provenance is allowed.
    ///
    /// # Errors
    /// Rejects unsupported versions, duplicate fields/names, unknown fields,
    /// invalid labels, bounds violations and any unsupported profile. Profile
    /// errors retain their native source and entry-indexed field path, without
    /// supplied values. Backend and host support are checked when building a client.
    pub fn from_json(input: &[u8]) -> Result<Self> {
        let root = json::parse_bundle(input)?;
        root.record(
            &["format", "version", "id", "revision", "profiles"],
            "bundle",
        )?;
        if root.member("format", "format")?.text("format")? != "phantom.profile-bundle"
            || root.member("version", "version")?.number("version")? != 1
        {
            return Err(FingerprintImportError::new(
                Kind::UnsupportedFormat,
                "bundle",
            ));
        }
        let id = root.member("id", "id")?.text("id")?;
        if !valid_name(id) {
            return Err(FingerprintImportError::new(Kind::InvalidValue, "id"));
        }
        let revision = root.member("revision", "revision")?.number("revision")?;
        if revision == 0 {
            return Err(FingerprintImportError::new(Kind::InvalidValue, "revision"));
        }
        let entries = root.member("profiles", "profiles")?.array("profiles")?;
        if entries.is_empty() || entries.len() > MAX_PROFILES {
            return Err(FingerprintImportError::new(Kind::TooLarge, "profiles"));
        }
        let mut profiles = ProfileRegistry::new();
        let mut provenance = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            let field = format!("profiles[{index}]");
            entry.record(&["name", "document", "provenance"], &field)?;
            let name_field = format!("{field}.name");
            let name = entry.member("name", &name_field)?.text(&name_field)?;
            if !valid_name(name) {
                return Err(FingerprintImportError::new(Kind::InvalidValue, &name_field));
            }
            if profiles.get(name).is_some() {
                return Err(FingerprintImportError::new(
                    Kind::DuplicateField,
                    &name_field,
                ));
            }
            let document = entry.member("document", &format!("{field}.document"))?;
            let profile = document
                .profile_depth()
                .and_then(|()| import_document(document))
                .map_err(|mut error| {
                    error.field = if &*error.field == "document" {
                        format!("{field}.document").into()
                    } else {
                        format!("{field}.document.{}", error.field).into()
                    };
                    error
                })?;
            let references = parse_provenance(entry, &field)?;
            profiles.insert(name, profile).map_err(|error| {
                FingerprintImportError::native(&format!("{field}.document"), error)
            })?;
            provenance.insert(name.into(), references);
        }
        let digest = btls::sha::sha256(input)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Self {
            id: id.into(),
            revision,
            digest,
            profiles,
            provenance,
        })
    }

    /// Returns the publisher's bundle label, not a filesystem path.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the publisher's positive revision, with no implicit ordering policy.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns lowercase SHA-256 of the exact input bytes, including whitespace.
    /// This identifies content; it does not authenticate its publisher.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.digest
    }

    /// Returns the exact-name registry. Lookup never falls back to the catalog.
    #[must_use]
    pub fn profiles(&self) -> &ProfileRegistry {
        &self.profiles
    }

    /// Returns publisher references for an exact entry name.
    #[must_use]
    pub fn provenance(&self, name: &str) -> Option<&[ProfileProvenance]> {
        self.provenance.get(name).map(AsRef::as_ref)
    }
}

fn parse_provenance(entry: &json::Value, field: &str) -> Result<Box<[ProfileProvenance]>> {
    let field = format!("{field}.provenance");
    let values = entry.member("provenance", &field)?.array(&field)?;
    if values.len() > 16 {
        return Err(FingerprintImportError::new(Kind::TooLarge, &field));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let field = format!("{field}[{index}]");
            value.record(&["source", "revision"], &field)?;
            let text = |key: &str, maximum| {
                let field = format!("{field}.{key}");
                let text = value.member(key, &field)?.text(&field)?;
                if text.is_empty() || text.len() > maximum || text.chars().any(char::is_control) {
                    return Err(FingerprintImportError::new(Kind::InvalidValue, &field));
                }
                Ok(Box::<str>::from(text))
            };
            Ok(ProfileProvenance {
                source: text("source", 2048)?,
                revision: text("revision", 128)?,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

#[cfg(test)]
mod tests;
