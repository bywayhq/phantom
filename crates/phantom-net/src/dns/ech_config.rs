//! `ECHConfigList` parsing (RFC 9849 section 4).
//!
//! The rules follow the pinned BoringSSL's client, which Chromium hands the
//! record's bytes to unchanged: `ssl_is_valid_ech_config_list` decides
//! whether a list is well formed, and `ssl_select_ech_config` which of its
//! configurations the client can use (`ssl/encrypted_client_hello.cc` at
//! submodule commit `f1f2556a`).

use std::{error::Error as StdError, fmt};

/// `ECHConfig.version` of RFC 9849, which reuses the extension code point.
const VERSION: u16 = 0xfe0d;
/// `DHKEM(X25519, HKDF-SHA256)` (RFC 9180 section 7.1).
const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// `HKDF-SHA256` (RFC 9180 section 7.2).
const KDF_HKDF_SHA256: u16 = 0x0001;
/// AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 (RFC 9180 section 7.3).
const SUPPORTED_AEADS: [u16; 3] = [0x0001, 0x0002, 0x0003];
/// Longest DNS label (RFC 1035 section 2.3.4).
const MAX_LABEL_LENGTH: usize = 63;

/// One `ECHConfig` from an `ECHConfigList`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchConfig {
    version: u16,
    contents: Option<EchConfigContents>,
}

/// The fields of an `ECHConfig` whose version is `0xfe0d`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EchConfigContents {
    config_id: u8,
    kem_id: u16,
    public_key: Box<[u8]>,
    cipher_suites: Box<[EchCipherSuite]>,
    maximum_name_length: u8,
    public_name: Box<[u8]>,
    extensions: Box<[EchConfigExtension]>,
}

impl EchConfig {
    /// Returns `ECHConfig.version`.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns `config_id`, or `None` for a version other than `0xfe0d`.
    #[must_use]
    pub fn config_id(&self) -> Option<u8> {
        self.contents.as_ref().map(|contents| contents.config_id)
    }

    /// Returns the HPKE KEM identifier, or `None` for another version.
    #[must_use]
    pub fn kem_id(&self) -> Option<u16> {
        self.contents.as_ref().map(|contents| contents.kem_id)
    }

    /// Returns the HPKE public key; empty for another version.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.contents
            .as_ref()
            .map_or(&[], |contents| &contents.public_key)
    }

    /// Returns the HPKE cipher suites in list order; empty for another version.
    #[must_use]
    pub fn cipher_suites(&self) -> &[EchCipherSuite] {
        self.contents
            .as_ref()
            .map_or(&[], |contents| &contents.cipher_suites)
    }

    /// Returns `maximum_name_length`, or `None` for another version.
    #[must_use]
    pub fn maximum_name_length(&self) -> Option<u8> {
        self.contents
            .as_ref()
            .map(|contents| contents.maximum_name_length)
    }

    /// Returns `public_name`, the outer SNI when this configuration is used.
    #[must_use]
    pub fn public_name(&self) -> Option<&[u8]> {
        self.contents
            .as_ref()
            .map(|contents| &*contents.public_name)
    }

    /// Returns the configuration's extensions in list order.
    ///
    /// They are not read, and this is empty, when the public name is invalid:
    /// the client ignores such a configuration without looking further.
    #[must_use]
    pub fn extensions(&self) -> &[EchConfigExtension] {
        self.contents
            .as_ref()
            .map_or(&[], |contents| &contents.extensions)
    }

    /// Returns whether the TLS client can encrypt a ClientHello with this
    /// configuration.
    ///
    /// As in BoringSSL's `ssl_select_ech_config`, that needs version
    /// `0xfe0d`, the X25519 HKDF-SHA256 KEM, a cipher suite pairing
    /// HKDF-SHA256 with AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305, a
    /// public name made of LDH labels whose last label is not numeric, and no
    /// mandatory extension, whose type has the high bit set.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        let Some(contents) = &self.contents else {
            return false;
        };
        contents.kem_id == KEM_X25519_HKDF_SHA256
            && contents.cipher_suites.iter().any(|suite| {
                suite.kdf_id == KDF_HKDF_SHA256 && SUPPORTED_AEADS.contains(&suite.aead_id)
            })
            && is_valid_public_name(&contents.public_name)
            && contents
                .extensions
                .iter()
                .all(|extension| extension.extension_type & 0x8000 == 0)
    }
}

/// One `HpkeSymmetricCipherSuite` of an `ECHConfig`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchCipherSuite {
    kdf_id: u16,
    aead_id: u16,
}

impl EchCipherSuite {
    /// Returns the HPKE KDF identifier.
    #[must_use]
    pub const fn kdf_id(self) -> u16 {
        self.kdf_id
    }

    /// Returns the HPKE AEAD identifier.
    #[must_use]
    pub const fn aead_id(self) -> u16 {
        self.aead_id
    }
}

/// One `ECHConfigExtension`, kept verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchConfigExtension {
    extension_type: u16,
    data: Box<[u8]>,
}

impl EchConfigExtension {
    /// Returns the extension type.
    #[must_use]
    pub const fn extension_type(&self) -> u16 {
        self.extension_type
    }

    /// Returns the extension data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Stable category of a malformed `ECHConfigList`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchConfigListErrorKind {
    /// The list's length prefix does not cover exactly the rest of the bytes.
    ListLength,
    /// The list holds no configuration.
    Empty,
    /// A configuration is truncated, has an empty required field, a cipher
    /// suite list whose length is not a multiple of four, or bytes left over
    /// after its extensions.
    MalformedConfig,
}

/// A malformed `ECHConfigList`.
///
/// Chrome fails the connection with `ERR_INVALID_ECH_CONFIG_LIST` for a list
/// BoringSSL does not accept, so Phantom does the same.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchConfigListError {
    kind: EchConfigListErrorKind,
}

impl EchConfigListError {
    const fn new(kind: EchConfigListErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> EchConfigListErrorKind {
        self.kind
    }
}

impl fmt::Display for EchConfigListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            EchConfigListErrorKind::ListLength => "ECHConfigList length prefix does not match",
            EchConfigListErrorKind::Empty => "ECHConfigList holds no configuration",
            EchConfigListErrorKind::MalformedConfig => "malformed ECHConfig",
        })
    }
}

impl StdError for EchConfigListError {}

/// Parses an `ECHConfigList`.
///
/// A configuration of another version is kept with its version only. A
/// configuration the client cannot use is kept too; see
/// [`EchConfig::is_supported`].
///
/// # Errors
///
/// Returns [`EchConfigListError`] where BoringSSL's
/// `ssl_is_valid_ech_config_list` would reject the list.
pub(super) fn parse(bytes: &[u8]) -> Result<Box<[EchConfig]>, EchConfigListError> {
    let mut outer = Reader::new(bytes);
    let list = outer
        .u16_prefixed()
        .ok_or(EchConfigListError::new(EchConfigListErrorKind::ListLength))?;
    if !outer.is_empty() {
        return Err(EchConfigListError::new(EchConfigListErrorKind::ListLength));
    }
    if list.is_empty() {
        return Err(EchConfigListError::new(EchConfigListErrorKind::Empty));
    }
    let mut reader = Reader::new(list);
    let mut configs = Vec::new();
    while !reader.is_empty() {
        configs.push(parse_config(&mut reader).ok_or(EchConfigListError::new(
            EchConfigListErrorKind::MalformedConfig,
        ))?);
    }
    Ok(configs.into_boxed_slice())
}

fn parse_config(reader: &mut Reader<'_>) -> Option<EchConfig> {
    let version = reader.u16()?;
    let body = reader.u16_prefixed()?;
    if version != VERSION {
        return Some(EchConfig {
            version,
            contents: None,
        });
    }
    let mut body = Reader::new(body);
    let config_id = body.u8()?;
    let kem_id = body.u16()?;
    let public_key = body.u16_prefixed().filter(|key| !key.is_empty())?;
    let suites = body
        .u16_prefixed()
        .filter(|suites| !suites.is_empty() && suites.len() % 4 == 0)?;
    let maximum_name_length = body.u8()?;
    let public_name = body.u8_prefixed().filter(|name| !name.is_empty())?;
    let mut extensions_reader = Reader::new(body.u16_prefixed()?);
    if !body.is_empty() {
        return None;
    }
    let mut extensions = Vec::new();
    // BoringSSL stops at an invalid public name and marks the configuration
    // unsupported without reading its extensions, so malformed extensions
    // after one do not make the list invalid (`parse_ech_config`,
    // `ssl/encrypted_client_hello.cc` lines 467-473).
    while is_valid_public_name(public_name) && !extensions_reader.is_empty() {
        let extension_type = extensions_reader.u16()?;
        let data = extensions_reader.u16_prefixed()?;
        extensions.push(EchConfigExtension {
            extension_type,
            data: data.into(),
        });
    }
    let cipher_suites = suites
        .as_chunks::<4>()
        .0
        .iter()
        .map(|suite| EchCipherSuite {
            kdf_id: u16::from_be_bytes([suite[0], suite[1]]),
            aead_id: u16::from_be_bytes([suite[2], suite[3]]),
        })
        .collect();
    Some(EchConfig {
        version,
        contents: Some(EchConfigContents {
            config_id,
            kem_id,
            public_key: public_key.into(),
            cipher_suites,
            maximum_name_length,
            public_name: public_name.into(),
            extensions: extensions.into_boxed_slice(),
        }),
    })
}

/// BoringSSL's `ssl_is_valid_ech_public_name`: dot-separated LDH labels of
/// 1 to 63 bytes, no leading, trailing, or doubled dot, and a last label
/// that is neither all decimal digits nor `0x` followed by hex digits, which
/// the WHATWG URL parser would read as an IPv4 address.
fn is_valid_public_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut last: &[u8] = &[];
    for label in name.split(|byte| *byte == b'.') {
        let ldh = !label.is_empty()
            && label.len() <= MAX_LABEL_LENGTH
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
            && label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        if !ldh {
            return false;
        }
        last = label;
    }
    let decimal = last.iter().all(u8::is_ascii_digit);
    let hex = last.len() >= 2
        && last[0] == b'0'
        && matches!(last[1], b'x' | b'X')
        && last[2..].iter().all(u8::is_ascii_hexdigit);
    !decimal && !hex
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (taken, remaining) = self.remaining.split_at_checked(length)?;
        self.remaining = remaining;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|byte| byte[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
    }

    fn u8_prefixed(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()?;
        self.take(usize::from(length))
    }

    fn u16_prefixed(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
}

#[cfg(test)]
mod tests;
