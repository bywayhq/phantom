//! TLS wire-capture helpers.

mod client_hello;
mod ech;

pub use client_hello::{ClientHelloDecodeError, ClientHelloSummary, is_grease};
pub use ech::{EchOuterExtension, EchTestKey, TEST_ECH_KEYS, ech_config, ech_config_list};

use std::{error::Error, fmt, io};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{Instant, timeout_at},
};

const RECORD_HEADER_LENGTH: usize = 5;
const HANDSHAKE_HEADER_LENGTH: usize = 4;
const HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;

/// Maximum fragment length permitted by the TLSPlaintext record format.
pub const TLS_PLAINTEXT_FRAGMENT_LIMIT: usize = 16_384;

/// Resource limits applied while capturing a ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    max_handshake_bytes: usize,
    max_wire_bytes: usize,
    max_records: usize,
}

impl CaptureLimits {
    /// Creates explicit limits for one capture.
    ///
    /// `max_handshake_bytes` includes the four-byte TLS handshake header, and
    /// `max_wire_bytes` includes every captured TLS record header and fragment.
    #[must_use]
    pub const fn new(
        max_handshake_bytes: usize,
        max_wire_bytes: usize,
        max_records: usize,
    ) -> Self {
        Self {
            max_handshake_bytes,
            max_wire_bytes,
            max_records,
        }
    }
}

/// One TLS record exactly as received from the input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTlsRecord {
    wire: Vec<u8>,
}

impl CapturedTlsRecord {
    /// Returns the exact record header and fragment.
    #[must_use]
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the record content type.
    #[must_use]
    pub fn content_type(&self) -> u8 {
        self.wire[0]
    }

    /// Returns the legacy record version without normalizing it.
    #[must_use]
    pub fn legacy_version(&self) -> u16 {
        u16::from_be_bytes([self.wire[1], self.wire[2]])
    }

    /// Returns the exact record fragment.
    #[must_use]
    pub fn fragment(&self) -> &[u8] {
        &self.wire[RECORD_HEADER_LENGTH..]
    }
}

/// A captured ClientHello and the TLS records that carried it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloCapture {
    records: Vec<CapturedTlsRecord>,
    handshake: Vec<u8>,
}

impl ClientHelloCapture {
    /// Returns the TLS records through the record that completed the ClientHello.
    #[must_use]
    pub fn records(&self) -> &[CapturedTlsRecord] {
        &self.records
    }

    /// Returns the exact reassembled handshake header and ClientHello body.
    #[must_use]
    pub fn handshake_bytes(&self) -> &[u8] {
        &self.handshake
    }

    /// Decodes the ordered fingerprint-relevant fields in this ClientHello.
    pub fn summary(&self) -> Result<ClientHelloSummary, ClientHelloDecodeError> {
        ClientHelloSummary::decode(&self.handshake)
    }
}

/// Failure returned while capturing a TLS ClientHello.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureError {
    /// The overall capture deadline elapsed.
    DeadlineExceeded,
    /// The input ended before a complete record or ClientHello was received.
    TruncatedInput,
    /// Reading the input failed for a reason other than truncation.
    Io(io::Error),
    /// A TLS record declared a fragment larger than TLSPlaintext permits.
    RecordTooLarge {
        /// Declared fragment length.
        length: usize,
        /// Maximum permitted fragment length.
        maximum: usize,
    },
    /// Capturing another record would exceed the configured record count.
    RecordLimitExceeded {
        /// Configured maximum record count.
        maximum: usize,
    },
    /// A record would exceed the configured wire-byte limit.
    WireLimitExceeded {
        /// Total wire bytes that the record would produce.
        attempted: usize,
        /// Configured maximum wire bytes.
        maximum: usize,
    },
    /// Handshake bytes would exceed the configured handshake limit.
    HandshakeLimitExceeded {
        /// Total handshake bytes that the fragment would produce.
        attempted: usize,
        /// Configured maximum handshake bytes.
        maximum: usize,
    },
    /// A non-handshake TLS record appeared before the ClientHello completed.
    NonHandshakeRecord {
        /// Unexpected TLS content type.
        content_type: u8,
    },
    /// A handshake record had an empty fragment.
    EmptyHandshakeFragment,
    /// The first handshake message was not a ClientHello.
    UnexpectedHandshakeType {
        /// Unexpected TLS handshake type.
        handshake_type: u8,
    },
    /// The final TLS record contained bytes after the ClientHello.
    TrailingBytes {
        /// Number of bytes following the ClientHello in the final record.
        count: usize,
    },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => formatter.write_str("ClientHello capture deadline exceeded"),
            Self::TruncatedInput => {
                formatter.write_str("input ended before the ClientHello completed")
            }
            Self::Io(error) => write!(formatter, "failed to read ClientHello input: {error}"),
            Self::RecordTooLarge { length, maximum } => write!(
                formatter,
                "TLS record fragment is {length} bytes; maximum is {maximum}"
            ),
            Self::RecordLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "ClientHello requires more than {maximum} TLS records"
                )
            }
            Self::WireLimitExceeded { attempted, maximum } => write!(
                formatter,
                "capturing the TLS record would use {attempted} wire bytes; maximum is {maximum}"
            ),
            Self::HandshakeLimitExceeded { attempted, maximum } => write!(
                formatter,
                "capturing the ClientHello would use {attempted} handshake bytes; maximum is {maximum}"
            ),
            Self::NonHandshakeRecord { content_type } => write!(
                formatter,
                "TLS content type {content_type} interrupted the ClientHello"
            ),
            Self::EmptyHandshakeFragment => {
                formatter.write_str("ClientHello handshake record has an empty fragment")
            }
            Self::UnexpectedHandshakeType { handshake_type } => write!(
                formatter,
                "first TLS handshake type is {handshake_type}, not ClientHello"
            ),
            Self::TrailingBytes { count } => write!(
                formatter,
                "final TLS record contains {count} bytes after the ClientHello"
            ),
        }
    }
}

impl Error for CaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Captures the first complete TLS ClientHello from an asynchronous byte stream.
///
/// `deadline` bounds the entire operation rather than each individual read.
/// Records are accepted only while the first handshake message is incomplete.
/// After any error, the reader may be partially consumed and must be discarded
/// or reset to a known boundary before it is reused.
pub async fn capture_client_hello<R>(
    reader: &mut R,
    deadline: Instant,
    limits: CaptureLimits,
) -> Result<ClientHelloCapture, CaptureError>
where
    R: AsyncRead + Unpin,
{
    match timeout_at(deadline, capture_client_hello_inner(reader, limits)).await {
        Ok(result) => result,
        Err(_) => Err(CaptureError::DeadlineExceeded),
    }
}

async fn capture_client_hello_inner<R>(
    reader: &mut R,
    limits: CaptureLimits,
) -> Result<ClientHelloCapture, CaptureError>
where
    R: AsyncRead + Unpin,
{
    let mut records = Vec::new();
    let mut handshake = Vec::new();
    let mut expected_handshake_length = None;
    let mut wire_bytes = 0usize;

    loop {
        if records.len() >= limits.max_records {
            return Err(CaptureError::RecordLimitExceeded {
                maximum: limits.max_records,
            });
        }

        let mut header = [0u8; RECORD_HEADER_LENGTH];
        read_exact(reader, &mut header).await?;

        if header[0] != HANDSHAKE_CONTENT_TYPE {
            return Err(CaptureError::NonHandshakeRecord {
                content_type: header[0],
            });
        }

        let fragment_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if fragment_length > TLS_PLAINTEXT_FRAGMENT_LIMIT {
            return Err(CaptureError::RecordTooLarge {
                length: fragment_length,
                maximum: TLS_PLAINTEXT_FRAGMENT_LIMIT,
            });
        }
        if fragment_length == 0 {
            return Err(CaptureError::EmptyHandshakeFragment);
        }

        let record_length = RECORD_HEADER_LENGTH.checked_add(fragment_length).ok_or(
            CaptureError::WireLimitExceeded {
                attempted: usize::MAX,
                maximum: limits.max_wire_bytes,
            },
        )?;
        let attempted_wire_bytes =
            wire_bytes
                .checked_add(record_length)
                .ok_or(CaptureError::WireLimitExceeded {
                    attempted: usize::MAX,
                    maximum: limits.max_wire_bytes,
                })?;
        if attempted_wire_bytes > limits.max_wire_bytes {
            return Err(CaptureError::WireLimitExceeded {
                attempted: attempted_wire_bytes,
                maximum: limits.max_wire_bytes,
            });
        }

        let attempted_handshake_bytes = handshake.len().checked_add(fragment_length).ok_or(
            CaptureError::HandshakeLimitExceeded {
                attempted: usize::MAX,
                maximum: limits.max_handshake_bytes,
            },
        )?;
        if attempted_handshake_bytes > limits.max_handshake_bytes {
            return Err(CaptureError::HandshakeLimitExceeded {
                attempted: attempted_handshake_bytes,
                maximum: limits.max_handshake_bytes,
            });
        }

        let mut wire = vec![0; record_length];
        wire[..RECORD_HEADER_LENGTH].copy_from_slice(&header);
        read_exact(reader, &mut wire[RECORD_HEADER_LENGTH..]).await?;
        handshake.extend_from_slice(&wire[RECORD_HEADER_LENGTH..]);
        records.push(CapturedTlsRecord { wire });
        wire_bytes = attempted_wire_bytes;

        if handshake[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
            return Err(CaptureError::UnexpectedHandshakeType {
                handshake_type: handshake[0],
            });
        }

        if expected_handshake_length.is_none() && handshake.len() >= HANDSHAKE_HEADER_LENGTH {
            let body_length = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            let full_length = HANDSHAKE_HEADER_LENGTH.checked_add(body_length).ok_or(
                CaptureError::HandshakeLimitExceeded {
                    attempted: usize::MAX,
                    maximum: limits.max_handshake_bytes,
                },
            )?;
            if full_length > limits.max_handshake_bytes {
                return Err(CaptureError::HandshakeLimitExceeded {
                    attempted: full_length,
                    maximum: limits.max_handshake_bytes,
                });
            }
            expected_handshake_length = Some(full_length);
        }

        if let Some(expected) = expected_handshake_length {
            match handshake.len().cmp(&expected) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Ok(ClientHelloCapture { records, handshake }),
                std::cmp::Ordering::Greater => {
                    return Err(CaptureError::TrailingBytes {
                        count: handshake.len() - expected,
                    });
                }
            }
        }
    }
}

async fn read_exact<R>(reader: &mut R, bytes: &mut [u8]) -> Result<(), CaptureError>
where
    R: AsyncRead + Unpin,
{
    reader.read_exact(bytes).await.map(|_| ()).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            CaptureError::TruncatedInput
        } else {
            CaptureError::Io(error)
        }
    })
}

#[cfg(test)]
mod tests;
