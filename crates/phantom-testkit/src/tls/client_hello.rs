//! Semantic decoding for captured TLS ClientHello messages.

use std::{error::Error, fmt};

const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const RANDOM_LENGTH: usize = 32;

const SERVER_NAME_EXTENSION: u16 = 0;
const SUPPORTED_GROUPS_EXTENSION: u16 = 10;
const EC_POINT_FORMATS_EXTENSION: u16 = 11;
const SIGNATURE_ALGORITHMS_EXTENSION: u16 = 13;
const ALPN_EXTENSION: u16 = 16;
const SUPPORTED_VERSIONS_EXTENSION: u16 = 43;
const KEY_SHARE_EXTENSION: u16 = 51;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

/// The ordered fingerprint-relevant fields decoded from a TLS ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSummary {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extension_types: Vec<u16>,
    extension_payload_lengths: Vec<usize>,
    server_name: Option<Vec<u8>>,
    supported_groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<Vec<u8>>,
    supported_versions: Vec<u16>,
    key_share_groups: Vec<u16>,
    requested_trust_anchor_ids: Option<Vec<Vec<u8>>>,
}

impl ClientHelloSummary {
    pub(super) fn decode(handshake: &[u8]) -> Result<Self, ClientHelloDecodeError> {
        let mut message = Cursor::new(handshake);
        let handshake_type = message.read_u8("handshake type")?;
        if handshake_type != CLIENT_HELLO_HANDSHAKE_TYPE {
            return Err(ClientHelloDecodeError::UnexpectedHandshakeType { handshake_type });
        }

        let body_length = message.read_u24("ClientHello body length")?;
        let body_bytes = message.take(body_length, "ClientHello body")?;
        if message.remaining() != 0 {
            return Err(ClientHelloDecodeError::TrailingHandshakeBytes {
                count: message.remaining(),
            });
        }

        let mut body = Cursor::new(body_bytes);
        let legacy_version = body.read_u16("legacy version")?;
        body.take(RANDOM_LENGTH, "random")?;

        let session_id_length = usize::from(body.read_u8("session ID length")?);
        if session_id_length > 32 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "session ID",
                length: session_id_length,
                minimum: 0,
                maximum: 32,
            });
        }
        body.take(session_id_length, "session ID")?;

        let cipher_suites_length = usize::from(body.read_u16("cipher suites length")?);
        require_nonempty_even("cipher suites", cipher_suites_length, u16::MAX as usize - 1)?;
        let cipher_suites = parse_u16_values(
            body.take(cipher_suites_length, "cipher suites")?,
            "cipher suites",
        )?;

        let compression_methods_length = usize::from(body.read_u8("compression methods length")?);
        if compression_methods_length == 0 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "compression methods",
                length: 0,
                minimum: 1,
                maximum: u8::MAX as usize,
            });
        }
        body.take(compression_methods_length, "compression methods")?;

        let mut summary = Self {
            legacy_version,
            cipher_suites,
            extension_types: Vec::new(),
            extension_payload_lengths: Vec::new(),
            server_name: None,
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn_protocols: Vec::new(),
            supported_versions: Vec::new(),
            key_share_groups: Vec::new(),
            requested_trust_anchor_ids: None,
        };

        if body.remaining() == 0 {
            return Ok(summary);
        }

        let extensions_length = usize::from(body.read_u16("extensions length")?);
        let extensions_bytes = body.take(extensions_length, "extensions")?;
        if body.remaining() != 0 {
            return Err(ClientHelloDecodeError::TrailingClientHelloBytes {
                count: body.remaining(),
            });
        }

        let mut extensions = Cursor::new(extensions_bytes);
        let mut seen_extensions = Vec::new();
        while extensions.remaining() != 0 {
            let extension_type = extensions.read_u16("extension type")?;
            let extension_length = usize::from(extensions.read_u16("extension length")?);
            let extension_data = extensions.take(extension_length, "extension data")?;
            if seen_extensions.contains(&extension_type) {
                return Err(ClientHelloDecodeError::DuplicateExtension { extension_type });
            }
            seen_extensions.push(extension_type);
            summary.extension_types.push(extension_type);
            summary.extension_payload_lengths.push(extension_length);

            match extension_type {
                SERVER_NAME_EXTENSION => {
                    summary.server_name = parse_server_name(extension_data, extension_type)?;
                }
                SUPPORTED_GROUPS_EXTENSION => {
                    summary.supported_groups = parse_u16_length_prefixed(
                        extension_data,
                        "supported groups",
                        extension_type,
                    )?;
                }
                EC_POINT_FORMATS_EXTENSION => {
                    summary.ec_point_formats =
                        parse_ec_point_formats(extension_data, extension_type)?;
                }
                SIGNATURE_ALGORITHMS_EXTENSION => {
                    summary.signature_algorithms = parse_u16_length_prefixed(
                        extension_data,
                        "signature algorithms",
                        extension_type,
                    )?;
                }
                ALPN_EXTENSION => {
                    summary.alpn_protocols = parse_alpn(extension_data, extension_type)?;
                }
                SUPPORTED_VERSIONS_EXTENSION => {
                    summary.supported_versions =
                        parse_supported_versions(extension_data, extension_type)?;
                }
                KEY_SHARE_EXTENSION => {
                    summary.key_share_groups =
                        parse_key_share_groups(extension_data, extension_type)?;
                }
                TRUST_ANCHORS_EXTENSION => {
                    summary.requested_trust_anchor_ids =
                        Some(parse_trust_anchor_ids(extension_data, extension_type)?);
                }
                _ => {}
            }
        }

        Ok(summary)
    }

    /// Returns the ClientHello legacy version without normalization.
    #[must_use]
    pub fn legacy_version(&self) -> u16 {
        self.legacy_version
    }

    /// Returns cipher suites in their exact wire order.
    #[must_use]
    pub fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    /// Returns extension types in their exact wire order, including unknown extensions.
    #[must_use]
    pub fn extension_types(&self) -> &[u16] {
        &self.extension_types
    }

    /// Returns extension types and payload lengths in their exact wire order.
    pub fn extension_layout(&self) -> impl Iterator<Item = (u16, usize)> + '_ {
        self.extension_types
            .iter()
            .copied()
            .zip(self.extension_payload_lengths.iter().copied())
    }

    /// Returns the host name from the SNI extension as its exact wire bytes.
    #[must_use]
    pub fn server_name(&self) -> Option<&[u8]> {
        self.server_name.as_deref()
    }

    /// Returns supported groups in their exact wire order.
    #[must_use]
    pub fn supported_groups(&self) -> &[u16] {
        &self.supported_groups
    }

    /// Returns EC point formats in their exact wire order.
    #[must_use]
    pub fn ec_point_formats(&self) -> &[u8] {
        &self.ec_point_formats
    }

    /// Returns signature algorithms in their exact wire order.
    #[must_use]
    pub fn signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    /// Returns ALPN protocol identifiers as their exact wire bytes.
    #[must_use]
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Returns supported TLS versions in their exact wire order.
    #[must_use]
    pub fn supported_versions(&self) -> &[u16] {
        &self.supported_versions
    }

    /// Returns key-share groups in their exact wire order.
    #[must_use]
    pub fn key_share_groups(&self) -> &[u16] {
        &self.key_share_groups
    }

    /// Returns requested trust anchor IDs as their exact wire bytes.
    ///
    /// `None` means the extension was absent. `Some(&[])` means the extension
    /// was present with an explicitly empty ID list.
    #[must_use]
    pub fn requested_trust_anchor_ids(&self) -> Option<&[Vec<u8>]> {
        self.requested_trust_anchor_ids.as_deref()
    }
}

/// Failure returned while decoding a captured TLS ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloDecodeError {
    /// The handshake message was not a ClientHello.
    UnexpectedHandshakeType {
        /// The observed TLS handshake type.
        handshake_type: u8,
    },
    /// A field ended before its declared or required length.
    Truncated {
        /// Field being decoded.
        field: &'static str,
        /// Bytes required by the field.
        needed: usize,
        /// Bytes still available.
        remaining: usize,
    },
    /// A field length fell outside the range allowed by TLS.
    LengthOutOfRange {
        /// Field being decoded.
        field: &'static str,
        /// Observed length.
        length: usize,
        /// Smallest permitted length.
        minimum: usize,
        /// Largest permitted length.
        maximum: usize,
    },
    /// A fixed-width vector did not contain a whole number of elements.
    InvalidVectorLength {
        /// Vector being decoded.
        field: &'static str,
        /// Observed byte length.
        length: usize,
        /// Width of one vector element.
        element_width: usize,
    },
    /// A decoded singleton extension appeared more than once.
    DuplicateExtension {
        /// Duplicate TLS extension type.
        extension_type: u16,
    },
    /// Bytes followed the handshake body declared by the handshake header.
    TrailingHandshakeBytes {
        /// Number of unexpected bytes.
        count: usize,
    },
    /// Bytes followed the extension block at the end of the ClientHello body.
    TrailingClientHelloBytes {
        /// Number of unexpected bytes.
        count: usize,
    },
    /// A decoded extension contained bytes outside its nested vector.
    TrailingExtensionBytes {
        /// TLS extension type being decoded.
        extension_type: u16,
        /// Number of unexpected bytes.
        count: usize,
    },
    /// ALPN contained an empty protocol identifier.
    EmptyAlpnProtocol,
    /// An SNI name contained an empty value.
    EmptyServerName {
        /// SNI name type whose value was empty.
        name_type: u8,
    },
    /// An SNI list contained the same name type more than once.
    DuplicateServerNameType {
        /// Repeated SNI name type.
        name_type: u8,
    },
}

impl fmt::Display for ClientHelloDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedHandshakeType { handshake_type } => write!(
                formatter,
                "TLS handshake type is {handshake_type}, not ClientHello"
            ),
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                formatter,
                "{field} needs {needed} bytes, but only {remaining} remain"
            ),
            Self::LengthOutOfRange {
                field,
                length,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field} length is {length}; expected {minimum}..={maximum}"
            ),
            Self::InvalidVectorLength {
                field,
                length,
                element_width,
            } => write!(
                formatter,
                "{field} length is {length}; expected a multiple of {element_width}"
            ),
            Self::DuplicateExtension { extension_type } => {
                write!(
                    formatter,
                    "TLS extension {extension_type} appears more than once"
                )
            }
            Self::TrailingHandshakeBytes { count } => {
                write!(
                    formatter,
                    "{count} bytes follow the declared ClientHello handshake"
                )
            }
            Self::TrailingClientHelloBytes { count } => {
                write!(
                    formatter,
                    "{count} bytes follow the ClientHello extension block"
                )
            }
            Self::TrailingExtensionBytes {
                extension_type,
                count,
            } => write!(
                formatter,
                "TLS extension {extension_type} contains {count} trailing bytes"
            ),
            Self::EmptyAlpnProtocol => formatter.write_str("ALPN contains an empty protocol name"),
            Self::EmptyServerName { name_type } => {
                write!(
                    formatter,
                    "SNI name type {name_type} contains an empty value"
                )
            }
            Self::DuplicateServerNameType { name_type } => {
                write!(
                    formatter,
                    "SNI name type {name_type} appears more than once"
                )
            }
        }
    }
}

impl Error for ClientHelloDecodeError {}

/// Reports whether a 16-bit value is reserved for GREASE.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

fn require_nonempty_even(
    field: &'static str,
    length: usize,
    maximum: usize,
) -> Result<(), ClientHelloDecodeError> {
    if length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field,
            length,
            minimum: 2,
            maximum,
        });
    }
    if length % 2 != 0 {
        return Err(ClientHelloDecodeError::InvalidVectorLength {
            field,
            length,
            element_width: 2,
        });
    }
    Ok(())
}

fn parse_ec_point_formats(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<u8>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let length = usize::from(extension.read_u8("EC point formats")?);
    if length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "EC point formats",
            length: 0,
            minimum: 1,
            maximum: u8::MAX as usize,
        });
    }
    let values = extension.take(length, "EC point formats")?.to_vec();
    require_exhausted(&extension, extension_type)?;
    Ok(values)
}

fn parse_server_name(
    data: &[u8],
    extension_type: u16,
) -> Result<Option<Vec<u8>>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("server name list")?);
    if list_length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "server name list",
            length: 0,
            minimum: 1,
            maximum: u16::MAX as usize,
        });
    }
    let mut names = Cursor::new(extension.take(list_length, "server name list")?);
    require_exhausted(&extension, extension_type)?;

    let mut seen_types = [false; 256];
    let mut host_name = None;
    while names.remaining() != 0 {
        let name_type = names.read_u8("server name type")?;
        if seen_types[usize::from(name_type)] {
            return Err(ClientHelloDecodeError::DuplicateServerNameType { name_type });
        }
        seen_types[usize::from(name_type)] = true;

        let name_length = usize::from(names.read_u16("server name length")?);
        if name_length == 0 {
            return Err(ClientHelloDecodeError::EmptyServerName { name_type });
        }
        let name = names.take(name_length, "server name")?;
        if name_type == 0 {
            host_name = Some(name.to_vec());
        }
    }
    Ok(host_name)
}

fn parse_u16_values(bytes: &[u8], field: &'static str) -> Result<Vec<u16>, ClientHelloDecodeError> {
    if bytes.len() % 2 != 0 {
        return Err(ClientHelloDecodeError::InvalidVectorLength {
            field,
            length: bytes.len(),
            element_width: 2,
        });
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect())
}

fn parse_u16_length_prefixed(
    data: &[u8],
    field: &'static str,
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let length = usize::from(extension.read_u16(field)?);
    require_nonempty_even(field, length, u16::MAX as usize - 1)?;
    let values = parse_u16_values(extension.take(length, field)?, field)?;
    require_exhausted(&extension, extension_type)?;
    Ok(values)
}

fn parse_supported_versions(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let length = usize::from(extension.read_u8("supported versions")?);
    require_nonempty_even("supported versions", length, u8::MAX as usize - 1)?;
    let values = parse_u16_values(
        extension.take(length, "supported versions")?,
        "supported versions",
    )?;
    require_exhausted(&extension, extension_type)?;
    Ok(values)
}

fn parse_alpn(data: &[u8], extension_type: u16) -> Result<Vec<Vec<u8>>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("ALPN protocol list")?);
    if list_length == 0 {
        return Err(ClientHelloDecodeError::LengthOutOfRange {
            field: "ALPN protocol list",
            length: 0,
            minimum: 2,
            maximum: u16::MAX as usize,
        });
    }
    let mut protocols = Cursor::new(extension.take(list_length, "ALPN protocol list")?);
    require_exhausted(&extension, extension_type)?;

    let mut values = Vec::new();
    while protocols.remaining() != 0 {
        let length = usize::from(protocols.read_u8("ALPN protocol length")?);
        if length == 0 {
            return Err(ClientHelloDecodeError::EmptyAlpnProtocol);
        }
        values.push(protocols.take(length, "ALPN protocol")?.to_vec());
    }
    Ok(values)
}

fn parse_key_share_groups(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<u16>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("key share list")?);
    let mut entries = Cursor::new(extension.take(list_length, "key share list")?);
    require_exhausted(&extension, extension_type)?;

    let mut groups = Vec::new();
    while entries.remaining() != 0 {
        groups.push(entries.read_u16("key share group")?);
        let key_exchange_length = usize::from(entries.read_u16("key exchange length")?);
        if key_exchange_length == 0 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "key exchange",
                length: 0,
                minimum: 1,
                maximum: u16::MAX as usize,
            });
        }
        entries.take(key_exchange_length, "key exchange")?;
    }
    Ok(groups)
}

fn parse_trust_anchor_ids(
    data: &[u8],
    extension_type: u16,
) -> Result<Vec<Vec<u8>>, ClientHelloDecodeError> {
    let mut extension = Cursor::new(data);
    let list_length = usize::from(extension.read_u16("trust anchor ID list")?);
    let mut ids = Cursor::new(extension.take(list_length, "trust anchor ID list")?);
    require_exhausted(&extension, extension_type)?;

    let mut values = Vec::new();
    while ids.remaining() != 0 {
        let length = usize::from(ids.read_u8("trust anchor ID length")?);
        if length == 0 {
            return Err(ClientHelloDecodeError::LengthOutOfRange {
                field: "trust anchor ID",
                length: 0,
                minimum: 1,
                maximum: u8::MAX as usize,
            });
        }
        values.push(ids.take(length, "trust anchor ID")?.to_vec());
    }
    Ok(values)
}

fn require_exhausted(
    cursor: &Cursor<'_>,
    extension_type: u16,
) -> Result<(), ClientHelloDecodeError> {
    if cursor.remaining() == 0 {
        Ok(())
    } else {
        Err(ClientHelloDecodeError::TrailingExtensionBytes {
            extension_type,
            count: cursor.remaining(),
        })
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], ClientHelloDecodeError> {
        if self.remaining.len() < length {
            return Err(ClientHelloDecodeError::Truncated {
                field,
                needed: length,
                remaining: self.remaining.len(),
            });
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, ClientHelloDecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ClientHelloDecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self, field: &'static str) -> Result<usize, ClientHelloDecodeError> {
        let bytes = self.take(3, field)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }
}

#[cfg(test)]
mod tests;
