use std::fmt;

/// A failure while deriving or applying QUIC packet protection.
///
/// Error values report dimensions and operations only. They never contain key
/// material, nonces, packet contents, or backend error-stack data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A negotiated TLS cipher suite has no QUIC key schedule in this adapter.
    UnsupportedCipherSuite {
        /// TLS cipher-suite identifier supplied by the TLS backend.
        id: u16,
    },
    /// A connection ID exceeds QUIC's protocol limit.
    InvalidConnectionIdLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Maximum accepted length.
        maximum: usize,
    },
    /// A key has the wrong length for its algorithm.
    InvalidKeyLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Required length.
        expected: usize,
    },
    /// A nonce or IV has the wrong length for its algorithm.
    InvalidNonceLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Required length.
        expected: usize,
    },
    /// A message authentication signature has the wrong length.
    InvalidSignatureLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Required length.
        expected: usize,
    },
    /// A TLS 1.3 HKDF label is outside its permitted length range.
    InvalidHkdfLabelLength {
        /// Length supplied by the caller, excluding the mandatory prefix.
        actual: usize,
        /// Minimum accepted label length, excluding the mandatory prefix.
        minimum: usize,
        /// Maximum accepted label length, excluding the mandatory prefix.
        maximum: usize,
    },
    /// A TLS 1.3 HKDF context is too long for its one-byte encoding.
    InvalidHkdfContextLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Maximum accepted context length.
        maximum: usize,
    },
    /// A TLS 1.3 HKDF output exceeds the hash or encoding limit.
    InvalidHkdfOutputLength {
        /// Length supplied by the caller.
        actual: usize,
        /// Maximum accepted output length.
        maximum: usize,
    },
    /// A header-protection sample is not fully present.
    InvalidSampleBounds {
        /// Offset at which the sample was expected to start.
        offset: usize,
        /// Required sample length.
        required: usize,
        /// Packet length supplied by the caller.
        packet_len: usize,
    },
    /// A packet-number offset does not identify bytes inside the packet.
    InvalidPacketNumberOffset {
        /// Offset supplied by the caller.
        offset: usize,
        /// Packet length supplied by the caller.
        packet_len: usize,
    },
    /// A packet buffer does not contain the required authentication tag space.
    InsufficientOutputCapacity {
        /// Capacity available after the header.
        actual: usize,
        /// Minimum capacity required.
        required: usize,
    },
    /// Packet authentication failed.
    AuthenticationFailed,
    /// A message authentication signature does not match.
    SignatureMismatch,
    /// The backend rejected an otherwise well-formed operation.
    BackendFailure(&'static str),
    /// Temporary memory for a bounded protocol operation could not be reserved.
    AllocationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCipherSuite { id } => {
                write!(formatter, "TLS cipher suite 0x{id:04x} is not supported")
            }
            Self::InvalidConnectionIdLength { actual, maximum } => {
                write!(formatter, "connection ID length {actual} exceeds {maximum}")
            }
            Self::InvalidKeyLength { actual, expected } => {
                write!(formatter, "key length {actual} does not match {expected}")
            }
            Self::InvalidNonceLength { actual, expected } => {
                write!(formatter, "nonce length {actual} does not match {expected}")
            }
            Self::InvalidSignatureLength { actual, expected } => {
                write!(
                    formatter,
                    "signature length {actual} does not match {expected}"
                )
            }
            Self::InvalidHkdfLabelLength {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "HKDF label length {actual} is outside {minimum}..={maximum}"
            ),
            Self::InvalidHkdfContextLength { actual, maximum } => write!(
                formatter,
                "HKDF context length {actual} exceeds encoding limit {maximum}"
            ),
            Self::InvalidHkdfOutputLength { actual, maximum } => write!(
                formatter,
                "HKDF output length {actual} exceeds encoding limit {maximum}"
            ),
            Self::InvalidSampleBounds {
                offset,
                required,
                packet_len,
            } => write!(
                formatter,
                "header sample of {required} bytes at offset {offset} exceeds packet length {packet_len}"
            ),
            Self::InvalidPacketNumberOffset { offset, packet_len } => write!(
                formatter,
                "packet-number offset {offset} is invalid for packet length {packet_len}"
            ),
            Self::InsufficientOutputCapacity { actual, required } => write!(
                formatter,
                "packet output capacity {actual} is smaller than required {required}"
            ),
            Self::AuthenticationFailed => formatter.write_str("packet authentication failed"),
            Self::SignatureMismatch => formatter.write_str("signature verification failed"),
            Self::BackendFailure(operation) => {
                write!(formatter, "cryptographic backend failed during {operation}")
            }
            Self::AllocationFailed => {
                formatter.write_str("temporary protocol buffer allocation failed")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for QUIC packet-cryptography operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
