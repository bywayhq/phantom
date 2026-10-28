//! Inspect, edit and name custom profiles.
//!
//! Enable `fingerprint-import` to edit complete settings with
//! [`describe_profile`](crate::fingerprint::describe_profile) and [`import_profile_json`](crate::fingerprint::import_profile_json). Compact observations need
//! an explicit base for the fields they omit. Use [`import_ja3_profile`](crate::fingerprint::import_ja3_profile),
//! [`import_ja4_profile`](crate::fingerprint::import_ja4_profile), [`import_client_hello_profile`](crate::fingerprint::import_client_hello_profile),
//! [`import_quic_transport_profile`](crate::fingerprint::import_quic_transport_profile) or [`import_akamai_profile`](crate::fingerprint::import_akamai_profile), then inspect
//! [`ImportedProfile::supplemented_fields`](crate::fingerprint::ImportedProfile::supplemented_fields) before using the result.
//!
//! JA3 and JA4 hashes cannot recover settings. Raw fingerprints describe only
//! part of a profile; imports take the remaining settings from your base.

use phantom_profile::ClientProfile;
use std::{error::Error, fmt};

mod bundle;
mod client_hints;
mod compact;
mod cookie;
mod dns_cache;
mod export;
mod http1;
mod http2;
mod http3;
mod ja4;
mod json;
mod proxy_connect;
mod quic;
mod quic_import;
mod registry;
mod request_contexts;
mod request_template;
mod tcp;
mod tls;
mod tls_import;
mod udp;
mod websocket;

pub use bundle::{ProfileBundle, ProfileProvenance};
pub use compact::{ImportedProfile, import_akamai_profile};
pub use ja4::{Ja4RawFormat, import_ja4_profile};
pub use quic_import::import_quic_transport_profile;
pub use registry::{ProfileRegistry, ProfileRegistryError, ProfileRegistryErrorKind};
pub use tls_import::{import_client_hello_profile, import_ja3_profile};

/// Recovery category for a custom-profile document error.
///
/// Match variants instead of numeric casts; this enum has no stable numeric
/// representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FingerprintImportErrorKind {
    /// Input does not contain one valid JSON document.
    MalformedJson,
    /// Input does not contain one well-formed compact description.
    MalformedDescription,
    /// Input exceeds a declared import resource bound.
    TooLarge,
    /// A required field is absent.
    MissingField,
    /// An object repeats a field.
    DuplicateField,
    /// The document format or version is not supported.
    UnsupportedFormat,
    /// A compact fingerprint omits required settings.
    LossyDescription,
    /// A field or policy is not supported.
    UnsupportedSetting,
    /// A value has the wrong type or representation.
    InvalidValue,
    /// A native settings validator rejected the description.
    InvalidSettings,
}

/// An import failure with a canonical field path and an optional native cause.
/// Diagnostics do not contain supplied values or the original document.
pub struct FingerprintImportError {
    kind: FingerprintImportErrorKind,
    field: Box<str>,
    source: Option<Box<dyn Error + Send + Sync>>,
}
impl FingerprintImportError {
    fn new(kind: FingerprintImportErrorKind, field: &str) -> Self {
        Self {
            kind,
            field: field.into(),
            source: None,
        }
    }
    fn native(field: &str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind: FingerprintImportErrorKind::InvalidSettings,
            field: field.into(),
            source: Some(Box::new(source)),
        }
    }
    /// Returns the error's recovery category.
    #[must_use]
    pub const fn kind(&self) -> FingerprintImportErrorKind {
        self.kind
    }
    /// Returns the canonical known field path, without supplied values.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }
}
impl fmt::Debug for FingerprintImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FingerprintImportError")
            .field("kind", &self.kind)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for FingerprintImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            FingerprintImportErrorKind::LossyDescription => write!(
                f,
                "fingerprint omits required settings; supply raw observations with an explicit base or complete phantom.custom-profile JSON at {}",
                self.field
            ),
            FingerprintImportErrorKind::MalformedJson => f.write_str(
                "expected one complete JSON document in the selected profile or bundle format",
            ),
            _ => write!(f, "custom-profile import {:?} at {}", self.kind, self.field),
        }
    }
}
impl Error for FingerprintImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn Error + 'static))
    }
}
type Result<T> = std::result::Result<T, FingerprintImportError>;

/// An export failure with a canonical field path and the document error cause.
#[derive(Debug)]
pub struct FingerprintExportError(FingerprintImportError);

impl FingerprintExportError {
    /// Returns the document error's recovery category.
    #[must_use]
    pub const fn kind(&self) -> FingerprintImportErrorKind {
        self.0.kind()
    }
    /// Returns the canonical field path, without supplied values.
    #[must_use]
    pub fn field(&self) -> &str {
        self.0.field()
    }
}
impl fmt::Display for FingerprintExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "custom-profile export {:?} at {}",
            self.kind(),
            self.field()
        )
    }
}
impl Error for FingerprintExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Describes all configured settings as an editable version-2 JSON document.
///
/// Uses the same format as [`import_profile_json`]. Arrays retain their order,
/// duplicate candidate slots and raw bytes. Optional layers remain explicit
/// `null`. The document includes configured literal header values and omits
/// catalog identity. Available request contexts are included as owned templates,
/// so imports need no catalog lookup. Export draws no random values.
///
/// # Errors
///
/// Rejects settings that cannot round-trip through the strict importer, native
/// validation failures and documents exceeding the import resource bounds.
/// Backend and host support are still checked when building a client.
pub fn describe_profile(
    profile: &ClientProfile,
) -> std::result::Result<serde_json::Value, FingerprintExportError> {
    export::describe(profile)
        .map(|(document, _)| document)
        .map_err(FingerprintExportError)
}

/// Exports a complete profile as indented, UTF-8 JSON for editing or storage.
///
/// See [`describe_profile`] for the document's contents.
/// Export performs no I/O and does not mutate the profile or a running client.
///
/// # Errors
///
/// Returns the same validation and resource-bound errors as [`describe_profile`].
pub fn export_profile_json(
    profile: &ClientProfile,
) -> std::result::Result<Vec<u8>, FingerprintExportError> {
    export::describe(profile)
        .map(|(_, bytes)| bytes)
        .map_err(FingerprintExportError)
}

/// Imports a version-1 or version-2 `phantom.custom-profile` JSON document.
///
/// Returns owned custom settings.
/// Arrays preserve their supplied order. Optional layers require explicit
/// `null`; present layers require all their fields. Import performs no I/O,
/// client construction, catalog selection or random draws. Backend and host
/// support are checked when the caller builds a client.
/// Version 2 includes a `request_contexts` object with up to eight named
/// templates. Version 1 retains only the selected default template.
///
/// Input is limited to 16 MiB, nesting to 16, strings to 64 KiB, object fields
/// to 64, arrays to 65,535 elements and total values to 1,048,576.
///
/// # Errors
///
/// Rejects malformed, incomplete, oversized or unsupported settings. JA3/JA4
/// descriptions cannot reconstruct a profile. Native validation errors retain
/// their typed source. Supplied header values are absent from diagnostics.
pub fn import_profile_json(input: &[u8]) -> Result<ClientProfile> {
    let document = json::parse(input)?;
    import_document(&document)
}

fn import_document(document: &json::Value) -> Result<ClientProfile> {
    let format = document.member("format", "format")?.text("format")?;
    if matches!(format, "ja3" | "ja3n" | "ja4" | "ja4_r" | "ja4_ro") {
        return Err(FingerprintImportError::new(
            FingerprintImportErrorKind::LossyDescription,
            "format",
        ));
    }
    if format != "phantom.custom-profile" {
        return Err(FingerprintImportError::new(
            FingerprintImportErrorKind::UnsupportedFormat,
            "format",
        ));
    }
    document.record(&["format", "version", "profile"], "document")?;
    let version = document.member("version", "version")?.number("version")?;
    if !matches!(version, 1 | 2) {
        return Err(FingerprintImportError::new(
            FingerprintImportErrorKind::UnsupportedFormat,
            "version",
        ));
    }
    let p = document.member("profile", "profile")?;
    let mut fields = vec![
        "tls",
        "tcp",
        "udp",
        "dns_cache",
        "http1",
        "http2",
        "http3",
        "client_hints",
        "websocket",
        "proxy_connect",
        "cookie_placement",
        "request_template",
    ];
    if version == 2 {
        fields.push("request_contexts");
    }
    p.record(&fields, "profile")?;
    let mut profile = ClientProfile::new(tls::parse(p.member("tls", "tls")?)?);
    macro_rules! optional_layer {
        ($name:literal, $module:ident, $method:ident) => {
            if let Some(value) = p.member($name, $name)?.optional($module::parse)? {
                profile = profile.$method(value);
            }
        };
    }
    optional_layer!("tcp", tcp, with_tcp);
    optional_layer!("udp", udp, with_udp);
    optional_layer!("dns_cache", dns_cache, with_dns_cache);
    optional_layer!("http1", http1, with_http1);
    optional_layer!("http2", http2, with_http2);
    optional_layer!("http3", http3, with_http3);
    optional_layer!("client_hints", client_hints, with_client_hints);
    optional_layer!("websocket", websocket, with_websocket);
    optional_layer!("proxy_connect", proxy_connect, with_proxy_connect);
    optional_layer!("request_template", request_template, with_request_template);
    if version == 2 {
        profile = profile.with_request_contexts(request_contexts::parse(
            p.member("request_contexts", "request_contexts")?,
        )?);
    }
    Ok(profile.with_cookie_placement(cookie::parse(
        p.member("cookie_placement", "cookie_placement")?,
    )?))
}

#[cfg(test)]
mod tests;
