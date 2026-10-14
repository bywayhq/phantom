//! Import complete custom settings without assigning catalog evidence.

use phantom_profile::ClientProfile;
use std::{error::Error, fmt};

mod client_hints;
mod cookie;
mod dns_cache;
mod http1;
mod http2;
mod http3;
mod json;
mod proxy_connect;
mod quic;
mod request_template;
mod tcp;
mod tls;
mod udp;
mod websocket;

/// Recovery category for a custom-profile import error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FingerprintImportErrorKind {
    /// Input does not contain one valid JSON document.
    MalformedJson,
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
            FingerprintImportErrorKind::LossyDescription => write!(f, "compact fingerprints omit required settings; provide complete phantom.custom-profile JSON at {}", self.field),
            FingerprintImportErrorKind::MalformedJson => f.write_str("expected one complete phantom.custom-profile JSON document; JA3/JA4 fingerprints cannot reconstruct settings"),
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

/// Imports a version-1 `phantom.custom-profile` JSON document.
///
/// Returns owned custom settings, without browser identity or evidence.
/// Arrays preserve their supplied order. Optional layers require explicit
/// `null`; present layers require all their fields. Import performs no I/O,
/// client construction, catalog selection or random draws. Backend and host
/// support are checked when the caller builds a client.
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
    if document.member("version", "version")?.number("version")? != 1 {
        return Err(FingerprintImportError::new(
            FingerprintImportErrorKind::UnsupportedFormat,
            "version",
        ));
    }
    let p = document.member("profile", "profile")?;
    p.record(
        &[
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
        ],
        "profile",
    )?;
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
    Ok(profile.with_cookie_placement(cookie::parse(
        p.member("cookie_placement", "cookie_placement")?,
    )?))
}

#[cfg(test)]
mod tests;
