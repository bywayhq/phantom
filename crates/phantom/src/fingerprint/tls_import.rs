//! Bounded TLS observations applied to explicit complete settings.

use phantom_profile::client_hello::{ClientHelloSummary, is_grease};
use phantom_profile::{
    ClientHelloExtensionOrder, ClientProfile, TlsSettings, TlsVersion, TlsVersionRange,
};

use super::{FingerprintImportError, FingerprintImportErrorKind as Kind, ImportedProfile, Result};

pub(super) mod identifiers;
use identifiers::{cipher, extension, group, signature};

const JA3_FIELDS: &[&str] = &["tls.cipher_suites", "tls.groups", "tls.extension_order"];
const CAPTURE_FIELDS: &[&str] = &[
    "tls.cipher_suites",
    "tls.groups",
    "tls.extension_order",
    "tls.versions",
    "tls.signature_schemes",
    "tls.alpn_protocols",
    "tls.key_shares",
];

/// Imports a raw five-section JA3 string with explicitly supplied base settings.
///
/// Applies ordered ciphers, groups and extensions to TCP TLS. Other settings,
/// including TLS version policy, extension payloads and GREASE policy, come
/// from `base` and are listed as supplements. The JA3 version is the legacy
/// ClientHello field, not the highest supported version. HTTP/3 is retained.
///
/// A fresh ClientHello is generated in memory to check every JA3 field.
/// Extension membership must agree with the base's configured payloads.
/// Successful import reproduces this projection, not a complete browser.
///
/// # Errors
///
/// Rejects hashes, malformed strings, input over 32 KiB, more than 256 values
/// per section, GREASE identifiers, duplicates, unknown identifiers, and fields
/// the backend cannot reproduce. No network I/O occurs. Captured PSK, early
/// data, retry-handshake and QUIC extensions are outside this TCP import.
pub fn import_ja3_profile(input: &str, base: &ClientProfile) -> Result<ImportedProfile> {
    let observed = Ja3::parse(input)?;
    let settings = observed.apply(base.tls())?;
    let name = if observed.extensions.contains(&0) {
        "import.invalid"
    } else {
        "127.0.0.1"
    };
    observed.verify(&preview(&settings, name)?)?;
    finish(base, &settings, JA3_FIELDS)
}

/// Imports supported fields from a complete TCP ClientHello handshake message.
///
/// Input includes the four-byte handshake header and excludes TLS record
/// headers. Applies ordered ciphers, groups, signatures, ALPN, versions, key
/// share groups and extensions. Other payload settings and all other layers
/// come from `base`; inspect the result's supplemented fields before use.
/// Captured randoms, keys, session IDs and SNI are never stored in the profile.
/// GREASE values are normalized and the base's GREASE policy is retained.
///
/// A fresh in-memory ClientHello must reproduce the imported projection.
/// This does not establish browser identity or replay arbitrary TLS bytes.
///
/// # Errors
///
/// Rejects malformed messages, input over 64 KiB, unsupported identifiers,
/// non-contiguous version lists, and settings the backend cannot reproduce.
/// PSK, early data, retry cookies and QUIC are unsupported by this TCP import.
/// No network I/O occurs.
pub fn import_client_hello_profile(input: &[u8], base: &ClientProfile) -> Result<ImportedProfile> {
    if input.len() > 64 * 1024 {
        return Err(error(Kind::TooLarge, "client_hello"));
    }
    let captured = ClientHelloSummary::from_handshake_bytes(input)
        .map_err(|_| error(Kind::MalformedDescription, "client_hello"))?;
    let ja3 = Ja3::from_summary(&captured);
    let mut settings = ja3.apply(base.tls())?;
    settings.signature_schemes = normalized(captured.signature_algorithms())
        .into_iter()
        .map(signature)
        .collect::<Result<_>>()?;
    settings.alpn_protocols = captured.alpn_protocols().to_vec();
    settings.key_shares = normalized(captured.key_share_groups())
        .into_iter()
        .map(group)
        .collect::<Result<_>>()?;
    let versions = normalized(captured.supported_versions());
    if !versions.is_empty() {
        let parsed = versions
            .iter()
            .copied()
            .map(|id| {
                TlsVersion::from_protocol_id(id)
                    .ok_or_else(|| error(Kind::UnsupportedSetting, "tls.versions"))
            })
            .collect::<Result<Vec<_>>>()?;
        let min = *parsed
            .last()
            .ok_or_else(|| error(Kind::MissingField, "tls.versions"))?;
        let max = parsed[0];
        settings.versions = TlsVersionRange::new(min, max)
            .map_err(|source| FingerprintImportError::native("tls.versions", source))?;
    } else {
        let version = TlsVersion::from_protocol_id(captured.legacy_version())
            .ok_or_else(|| error(Kind::UnsupportedSetting, "tls.versions"))?;
        settings.versions = TlsVersionRange::new(version, version)
            .map_err(|source| FingerprintImportError::native("tls.versions", source))?;
    }
    let name = captured
        .server_name()
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| error(Kind::InvalidValue, "client_hello.server_name"))?
        .unwrap_or("127.0.0.1");
    let generated = preview(&settings, name)?;
    ja3.verify(&generated)?;
    equal(
        normalized(generated.supported_versions()),
        versions,
        "tls.versions",
    )?;
    equal(
        normalized(generated.signature_algorithms()),
        normalized(captured.signature_algorithms()),
        "tls.signature_schemes",
    )?;
    equal(
        generated.alpn_protocols(),
        captured.alpn_protocols(),
        "tls.alpn_protocols",
    )?;
    equal(
        normalized(generated.key_share_groups()),
        normalized(captured.key_share_groups()),
        "tls.key_shares",
    )?;
    finish(base, &settings, CAPTURE_FIELDS)
}

pub(super) fn finish(
    base: &ClientProfile,
    tls: &TlsSettings,
    fields: &'static [&'static str],
) -> Result<ImportedProfile> {
    let mut document = super::export::describe(base)?.0;
    document["profile"]["tls"] = super::export::tls_settings(tls)?;
    ImportedProfile::from_document(document, fields)
}

pub(super) fn preview(settings: &TlsSettings, name: &str) -> Result<ClientHelloSummary> {
    let bytes = phantom_net::preview_client_hello(settings, name)
        .map_err(|source| FingerprintImportError::native("tls", source))?;
    ClientHelloSummary::from_handshake_bytes(&bytes)
        .map_err(|_| error(Kind::InvalidSettings, "tls"))
}

pub(super) fn normalized(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|id| !is_grease(*id))
        .collect()
}

pub(super) fn equal<T: PartialEq>(actual: T, expected: T, field: &str) -> Result<()> {
    if actual != expected {
        return Err(error(Kind::UnsupportedSetting, field));
    }
    Ok(())
}

#[derive(Debug)]
struct Ja3 {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    points: Vec<u16>,
}

impl Ja3 {
    fn parse(input: &str) -> Result<Self> {
        if input.len() > 32 * 1024 {
            return Err(error(Kind::TooLarge, "ja3"));
        }
        if input.len() == 32 && input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(error(Kind::LossyDescription, "ja3"));
        }
        let mut sections = input.split(',');
        let mut next = |field| {
            sections
                .next()
                .ok_or_else(|| error(Kind::MalformedDescription, field))
        };
        let version = number(next("ja3.version")?, "ja3.version")?;
        let ciphers = numbers(next("ja3.ciphers")?, "ja3.ciphers")?;
        let extensions = numbers(next("ja3.extensions")?, "ja3.extensions")?;
        let groups = numbers(next("ja3.groups")?, "ja3.groups")?;
        let points = numbers(next("ja3.point_formats")?, "ja3.point_formats")?;
        if sections.next().is_some() {
            return Err(error(Kind::MalformedDescription, "ja3"));
        }
        Ok(Self {
            version,
            ciphers,
            extensions,
            groups,
            points,
        })
    }

    fn from_summary(summary: &ClientHelloSummary) -> Self {
        Self {
            version: summary.legacy_version(),
            ciphers: normalized(summary.cipher_suites()),
            extensions: normalized(summary.extension_types()),
            groups: normalized(summary.supported_groups()),
            points: summary
                .ec_point_formats()
                .iter()
                .copied()
                .map(u16::from)
                .collect(),
        }
    }

    fn apply(&self, base: &TlsSettings) -> Result<TlsSettings> {
        let mut settings = base.clone();
        settings.cipher_suites = self
            .ciphers
            .iter()
            .copied()
            .map(cipher)
            .collect::<Result<_>>()?;
        settings.groups = self
            .groups
            .iter()
            .copied()
            .map(group)
            .collect::<Result<_>>()?;
        settings.extension_order = ClientHelloExtensionOrder::Fixed(
            self.extensions
                .iter()
                .copied()
                .map(extension)
                .collect::<Result<_>>()?,
        );
        Ok(settings)
    }

    fn verify(&self, summary: &ClientHelloSummary) -> Result<()> {
        equal(summary.legacy_version(), self.version, "ja3.version")?;
        equal(
            normalized(summary.cipher_suites()),
            self.ciphers.clone(),
            "ja3.ciphers",
        )?;
        equal(
            normalized(summary.extension_types()),
            self.extensions.clone(),
            "ja3.extensions",
        )?;
        equal(
            normalized(summary.supported_groups()),
            self.groups.clone(),
            "ja3.groups",
        )?;
        equal(
            summary
                .ec_point_formats()
                .iter()
                .copied()
                .map(u16::from)
                .collect::<Vec<_>>(),
            self.points.clone(),
            "ja3.point_formats",
        )
    }
}

fn numbers(input: &str, field: &str) -> Result<Vec<u16>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for part in input.split('-') {
        if result.len() == 256 {
            return Err(error(Kind::TooLarge, field));
        }
        let id = number(part, field)?;
        if is_grease(id) {
            return Err(error(Kind::InvalidValue, field));
        }
        if result.contains(&id) {
            return Err(error(Kind::DuplicateField, field));
        }
        result.push(id);
    }
    Ok(result)
}

fn number(input: &str, field: &str) -> Result<u16> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error(Kind::InvalidValue, field));
    }
    input.parse().map_err(|_| error(Kind::InvalidValue, field))
}

pub(super) fn error(kind: Kind, field: &str) -> FingerprintImportError {
    FingerprintImportError::new(kind, field)
}

#[cfg(test)]
mod tests;
