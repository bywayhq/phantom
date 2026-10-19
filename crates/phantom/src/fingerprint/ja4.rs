//! Explicit interpretation of sorted and original JA4 raw observations.

use phantom_profile::ClientProfile;
use phantom_profile::client_hello::ClientHelloSummary;

use super::tls_import::identifiers::{cipher, signature};
use super::tls_import::{equal, error, extension_order, finish, normalized, preview};
use super::{FingerprintImportErrorKind as Kind, ImportedProfile, Result};

/// Ordering carried by the caller's JA4 raw representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ja4RawFormat {
    /// JA4_r: sorted ciphers and extensions, excluding SNI and ALPN identifiers.
    /// Cipher and extension ordering must be supplied by the explicit base.
    Sorted,
    /// JA4_ro: original cipher and extension order, including SNI and ALPN.
    Original,
}

/// Imports a raw TCP JA4 description with an explicit format and base profile.
///
/// `Original` applies ordered ciphers, extensions and signatures. `Sorted`
/// applies signatures and checks cipher/extension membership against the base,
/// whose ordering is retained. Both check version, SNI, counts and the ALPN
/// abbreviation against a fresh in-memory ClientHello. Other settings remain
/// supplemented, including the complete ALPN list and supported groups.
///
/// Pass the raw value without a `JA4_r =` or `JA4_ro =` label. Hashes cannot
/// reconstruct settings. This produces custom settings, not browser evidence.
/// Verification covers a fresh direct TCP handshake in the indicated DNS-name
/// or IP context. Destination type, protocol-specific ALPN, discovery and
/// resumption can change the projection on a later request.
///
/// # Errors
///
/// Rejects hashed JA4, non-TCP prefixes, malformed or inconsistent fields,
/// unsupported identifiers, input over 32 KiB, and more than 256 identifiers
/// per list. Each identifier must contain four hexadecimal digits. No network
/// I/O occurs. QUIC descriptions use their own transport import.
pub fn import_ja4_profile(
    input: &str,
    format: Ja4RawFormat,
    base: &ClientProfile,
) -> Result<ImportedProfile> {
    if input.len() > 32 * 1024 {
        return Err(error(Kind::TooLarge, "ja4"));
    }
    let sections = input.split('_').collect::<Vec<_>>();
    if sections.len() == 3
        && sections[1..]
            .iter()
            .all(|value| value.len() == 12 && value.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(error(Kind::LossyDescription, "ja4"));
    }
    if !(3..=4).contains(&sections.len()) || sections[0].len() != 10 || !sections[0].is_ascii() {
        return Err(error(Kind::MalformedDescription, "ja4"));
    }
    let header = sections[0];
    if &header[..1] != "t" {
        return Err(error(Kind::UnsupportedSetting, "ja4.transport"));
    }
    let ciphers = hex_list(sections[1], "ja4.ciphers")?;
    let extensions = hex_list(sections[2], "ja4.extensions")?;
    let signatures = hex_list(sections.get(3).copied().unwrap_or(""), "ja4.signatures")?;
    let mut settings = base.tls().clone();
    settings.signature_schemes = signatures
        .iter()
        .copied()
        .map(signature)
        .collect::<Result<_>>()?;
    let fields: &'static [&'static str] = match format {
        Ja4RawFormat::Original => {
            settings.cipher_suites = ciphers.iter().copied().map(cipher).collect::<Result<_>>()?;
            settings.extension_order = extension_order(&extensions)?;
            &[
                "tls.cipher_suites",
                "tls.extension_order",
                "tls.signature_schemes",
            ]
        }
        Ja4RawFormat::Sorted => {
            if !ciphers.windows(2).all(|pair| pair[0] < pair[1])
                || !extensions.windows(2).all(|pair| pair[0] < pair[1])
                || extensions.iter().any(|id| matches!(id, 0 | 16))
            {
                return Err(error(Kind::InvalidValue, "ja4.sorted"));
            }
            &["tls.signature_schemes"]
        }
    };
    let name = match &header[3..4] {
        "d" => "import.invalid",
        "i" => "127.0.0.1",
        _ => return Err(error(Kind::InvalidValue, "ja4.sni")),
    };
    let hello = preview(&settings, name)?;
    verify_header(header, &hello)?;
    let mut actual_ciphers = normalized(hello.cipher_suites());
    let mut actual_extensions = normalized(hello.extension_types());
    if format == Ja4RawFormat::Sorted {
        actual_ciphers.sort_unstable();
        actual_extensions.retain(|id| !matches!(id, 0 | 16));
        actual_extensions.sort_unstable();
    }
    equal(actual_ciphers, ciphers, "ja4.ciphers")?;
    equal(actual_extensions, extensions, "ja4.extensions")?;
    equal(
        normalized(hello.signature_algorithms()),
        signatures,
        "ja4.signatures",
    )?;
    finish(base, &settings, fields)
}

fn hex_list(input: &str, field: &str) -> Result<Vec<u16>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for part in input.split(',') {
        if values.len() == 256 {
            return Err(error(Kind::TooLarge, field));
        }
        if part.len() != 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(error(Kind::MalformedDescription, field));
        }
        let value = u16::from_str_radix(part, 16).map_err(|_| error(Kind::InvalidValue, field))?;
        if phantom_profile::client_hello::is_grease(value) {
            return Err(error(Kind::InvalidValue, field));
        }
        if values.contains(&value) {
            return Err(error(Kind::DuplicateField, field));
        }
        values.push(value);
    }
    Ok(values)
}

fn verify_header(header: &str, hello: &ClientHelloSummary) -> Result<()> {
    let version = normalized(hello.supported_versions())
        .into_iter()
        .max()
        .unwrap_or(hello.legacy_version());
    let version = match version {
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    };
    equal(&header[1..3], version, "ja4.version")?;
    equal(
        &header[3..4],
        if hello.extension_types().contains(&0) {
            "d"
        } else {
            "i"
        },
        "ja4.sni",
    )?;
    for (text, count, field) in [
        (
            &header[4..6],
            normalized(hello.cipher_suites()).len(),
            "ja4.cipher_count",
        ),
        (
            &header[6..8],
            normalized(hello.extension_types()).len(),
            "ja4.extension_count",
        ),
    ] {
        equal(text, format!("{:02}", count.min(99)).as_str(), field)?;
    }
    equal(&header[8..], alpn_tag(hello).as_str(), "ja4.alpn")
}

fn alpn_tag(hello: &ClientHelloSummary) -> String {
    let Some((first, last)) = hello
        .alpn_protocols()
        .first()
        .and_then(|value| Some((*value.first()?, *value.last()?)))
    else {
        return "00".into();
    };
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        String::from_iter([char::from(first), char::from(last)])
    } else {
        let hex = b"0123456789abcdef";
        String::from_iter([
            char::from(hex[usize::from(first >> 4)]),
            char::from(hex[usize::from(last & 15)]),
        ])
    }
}

#[cfg(test)]
mod tests;
