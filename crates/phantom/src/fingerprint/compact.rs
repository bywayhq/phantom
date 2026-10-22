//! Compact descriptions combined with explicitly supplied settings.

use std::fmt;

use phantom_profile::ClientProfile;
use serde_json::{Value, json};

use super::{FingerprintImportError, FingerprintImportErrorKind as Kind, Result};

const OBSERVED_HTTP2: &[&str] = &[
    "http2.initial_settings",
    "http2.initial_connection_window_size",
    "http2.pseudo_header_order",
];

/// Custom settings and the fields supplied by each import input.
///
/// Field paths name complete layers or individual settings. Inspect values
/// with [`super::describe_profile`]. Debug output omits those values.
#[derive(Clone)]
pub struct ImportedProfile {
    profile: ClientProfile,
    observed: Vec<&'static str>,
    supplemented: Vec<Box<str>>,
}

impl ImportedProfile {
    pub(super) fn from_document(document: Value, observed: &[&'static str]) -> Result<Self> {
        let layers = document["profile"]
            .as_object()
            .ok_or_else(|| error(Kind::InvalidValue, "profile"))?;
        let mut supplemented = Vec::new();
        for (layer, value) in layers {
            collect_supplements(value, layer, observed, &mut supplemented);
        }
        let bytes = serde_json::to_vec(&document)
            .map_err(|source| FingerprintImportError::native("document", source))?;
        Ok(Self {
            profile: super::import_profile_json(&bytes)?,
            observed: observed.to_vec(),
            supplemented,
        })
    }

    /// Returns the resulting custom settings.
    #[must_use]
    pub fn profile(&self) -> &ClientProfile {
        &self.profile
    }

    /// Takes ownership of the resulting custom settings.
    #[must_use]
    pub fn into_profile(self) -> ClientProfile {
        self.profile
    }

    /// Lists configured fields taken from the compact description.
    pub fn observed_fields(&self) -> impl ExactSizeIterator<Item = &'static str> {
        self.observed.iter().copied()
    }

    /// Lists fields retained from the explicitly supplied base profile.
    ///
    /// An absent optional layer is retained too. No default profile is chosen.
    pub fn supplemented_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.supplemented.iter().map(AsRef::as_ref)
    }
}

impl fmt::Debug for ImportedProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedProfile")
            .field("observed_fields", &self.observed)
            .field("supplemented_fields", &self.supplemented)
            .finish_non_exhaustive()
    }
}

/// Imports an Akamai HTTP/2 string using an explicit base profile.
///
/// Replaces ordered initial SETTINGS, the initial connection window and
/// ordinary pseudo-header order. All other settings come from `base`, which
/// must include HTTP/2. The result lists the supplemented fields.
///
/// Input has four sections: `settings|window_update|priority|pseudo_headers`.
/// SETTINGS uses decimal `id:value` pairs separated by `;`. WINDOW_UPDATE is
/// the initial connection increment, or `0` for none. Nonzero increments must
/// be at least 32,767; smaller updates are deferred by the backend. The priority
/// section must be `0`: the backend cannot emit standalone preface PRIORITY frames.
/// Pseudo-headers use each of `m,a,s,p` once, in the supplied order.
/// HEADERS priority, HPACK, stream numbering and later flow control remain
/// explicit base settings. The base's extended CONNECT order is retained.
///
/// # Errors
///
/// Rejects input over 32 KiB or 64 SETTINGS entries, malformed sections,
/// hash-only input, unsupported setting identifiers and nonzero PRIORITY.
/// SETTINGS must include identifier `4`; the backend cannot omit that field.
/// Conflicting or unsupported settings pass through the complete-profile
/// validators. Diagnostics omit supplied values. No I/O occurs.
///
/// # Examples
///
/// ```
/// use phantom::{fingerprint::import_akamai_profile, profile::browser::chrome};
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let base = chrome::v154_windows();
/// let imported = import_akamai_profile("4:16777216|16711681|0|m,p,a,s", &base)?;
/// let profile = imported.into_profile();
/// # let _ = profile;
/// # Ok(())
/// # }
/// ```
pub fn import_akamai_profile(input: &str, base: &ClientProfile) -> Result<ImportedProfile> {
    if input.len() > 32 * 1024 {
        return Err(error(Kind::TooLarge, "akamai"));
    }
    if matches!(input.len(), 32 | 64) && input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error(Kind::LossyDescription, "akamai"));
    }
    let mut sections = input.split('|');
    let settings = sections.next().unwrap_or_default();
    let window = sections
        .next()
        .ok_or_else(|| error(Kind::MalformedDescription, "akamai"))?;
    let priority = sections
        .next()
        .ok_or_else(|| error(Kind::MalformedDescription, "akamai"))?;
    let pseudo = sections
        .next()
        .filter(|_| sections.next().is_none())
        .ok_or_else(|| error(Kind::MalformedDescription, "akamai"))?;
    if priority != "0" {
        return Err(error(Kind::UnsupportedSetting, "akamai.priority"));
    }
    let settings = parse_settings(settings)?;
    let increment = decimal(window, "akamai.window_update")?;
    let connection_window = 65_535_u32
        .checked_add(increment)
        .filter(|window| *window <= 0x7fff_ffff)
        .ok_or_else(|| error(Kind::InvalidValue, "akamai.window_update"))?;
    // The backend sends unclaimed capacity at half its current window:
    // vendor/http2/src/proto/streams/flow_control.rs::unclaimed_capacity.
    if (1..32_767).contains(&increment) {
        return Err(error(Kind::UnsupportedSetting, "akamai.window_update"));
    }
    let pseudo = parse_pseudo(pseudo)?;
    let (mut document, _) = super::export::describe(base)?;
    let http2 = document
        .get_mut("profile")
        .and_then(|profile| profile.get_mut("http2"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| error(Kind::MissingField, "http2"))?;
    http2.insert("initial_settings".into(), settings.into());
    http2.insert(
        "initial_connection_window_size".into(),
        connection_window.into(),
    );
    http2.insert("pseudo_header_order".into(), pseudo.into());
    ImportedProfile::from_document(document, OBSERVED_HTTP2)
}

fn collect_supplements(value: &Value, path: &str, observed: &[&str], fields: &mut Vec<Box<str>>) {
    if observed.contains(&path) {
        return;
    }
    let prefix = format!("{path}.");
    if let Some(object) = value
        .as_object()
        .filter(|_| observed.iter().any(|field| field.starts_with(&prefix)))
    {
        for (name, value) in object {
            collect_supplements(value, &format!("{path}.{name}"), observed, fields);
        }
        return;
    }
    fields.push(path.into());
}

fn parse_settings(input: &str) -> Result<Vec<Value>> {
    let mut settings = Vec::new();
    let mut has_initial_window = false;
    for pair in input.split(';').filter(|_| !input.is_empty()) {
        if settings.len() == 64 {
            return Err(error(Kind::TooLarge, "akamai.settings"));
        }
        let (id, value) = pair
            .split_once(':')
            .ok_or_else(|| error(Kind::MalformedDescription, "akamai.settings"))?;
        let id = decimal(id, "akamai.settings.id")?;
        let value = decimal(value, "akamai.settings.value")?;
        let kind = match id {
            1 => "HeaderTableSize",
            2 => "EnablePush",
            3 => "MaxConcurrentStreams",
            4 => {
                has_initial_window = true;
                "InitialWindowSize"
            }
            5 => "MaxFrameSize",
            6 => "MaxHeaderListSize",
            8 => "EnableConnectProtocol",
            9 => "NoRfc7540Priorities",
            _ => return Err(error(Kind::UnsupportedSetting, "akamai.settings.id")),
        };
        let value = if matches!(id, 2 | 8 | 9) {
            if value > 1 {
                return Err(error(Kind::InvalidValue, "akamai.settings.value"));
            }
            Value::Bool(value == 1)
        } else {
            value.into()
        };
        settings.push(json!({ "kind": kind, "value": value }));
    }
    if !has_initial_window {
        return Err(error(
            Kind::UnsupportedSetting,
            "akamai.settings.initial_window_size",
        ));
    }
    Ok(settings)
}

fn parse_pseudo(input: &str) -> Result<Vec<Value>> {
    let mut values = Vec::with_capacity(4);
    for name in input.split(',') {
        if values.len() == 4 {
            return Err(error(Kind::InvalidValue, "akamai.pseudo_headers"));
        }
        values.push(Value::from(match name {
            "m" => "Method",
            "a" => "Authority",
            "s" => "Scheme",
            "p" => "Path",
            _ => return Err(error(Kind::InvalidValue, "akamai.pseudo_headers")),
        }));
    }
    Ok(values)
}

fn decimal(input: &str, field: &str) -> Result<u32> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error(Kind::InvalidValue, field));
    }
    input.parse().map_err(|_| error(Kind::InvalidValue, field))
}

fn error(kind: Kind, field: &str) -> FingerprintImportError {
    FingerprintImportError::new(kind, field)
}
