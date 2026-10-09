//! Backend-neutral QUIC transport settings and wire layout.

use std::{error::Error, fmt};

const MAX_VARINT: u64 = (1 << 62) - 1;
const MAX_STREAM_COUNT: u64 = 1 << 60;
const MIN_UDP_PAYLOAD_SIZE: u64 = 1_200;
const MAX_UDP_PAYLOAD_SIZE: u64 = 65_527;
const MAX_CONNECTION_ID_LENGTH: u8 = 20;
const MAX_CAPTURED_GREASE_PAYLOAD_LENGTH: u8 = 15;
const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
/// IPv4 and UDP header bytes.
const IPV4_UDP_HEADERS: u64 = 20 + 8;
/// IPv6 and UDP header bytes.
const IPV6_UDP_HEADERS: u64 = 40 + 8;
const MAX_ACK_DELAY_LIMIT_MS: u64 = 1 << 14;
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const MIN_INITIAL_DESTINATION_CONNECTION_ID_LENGTH: u8 = 8;

/// Width of one QUIC variable-length integer on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicVarIntWidth {
    /// One-byte encoding with six value bits.
    One,
    /// Two-byte encoding with fourteen value bits.
    Two,
    /// Four-byte encoding with thirty value bits.
    Four,
    /// Eight-byte encoding with sixty-two value bits.
    Eight,
}

impl QuicVarIntWidth {
    /// Returns the encoded width in bytes.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// Returns the greatest value that fits this width.
    #[must_use]
    pub const fn maximum_value(self) -> u64 {
        match self {
            Self::One => (1 << 6) - 1,
            Self::Two => (1 << 14) - 1,
            Self::Four => (1 << 30) - 1,
            Self::Eight => MAX_VARINT,
        }
    }

    /// Returns whether `value` can be encoded at this width.
    #[must_use]
    pub const fn can_encode(self, value: u64) -> bool {
        value <= self.maximum_value()
    }
}

/// Controls the order of the configured QUIC transport parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicTransportParameterOrder {
    /// Preserve the order of [`QuicTransportSettings::wire_parameters`].
    Fixed,
    /// Permute all configured parameters independently for each connection.
    Permuted,
}

/// Placement policy for one reserved version in RFC 9368 Version Information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicVersionGrease {
    /// Do not add a reserved version.
    Omit,
    /// Permute the reserved version with runtime-supported versions.
    Permuted,
    /// Place the reserved version first, before the runtime-supported versions.
    First,
}

/// Wire policy for RFC 9368 Version Information.
///
/// The selected version and the versions actually supported by the transport
/// remain runtime-owned and are deliberately absent from this profile type.
///
/// Phantom's QUIC runtime implements QUIC v1 and QUIC v2 (RFC 9369) and lists
/// them most preferred first: v2, then v1. A count of 1 lists v1 alone and
/// keeps every connection in v1. A count of 2 lists v2 and v1 and lets a server
/// move a connection that started in v1 to v2 by compatible version
/// negotiation (RFC 9368 section 2.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicVersionInformation {
    /// Number of non-reserved versions the runtime must place after the chosen version.
    ///
    /// The chosen version must appear in that list. A generated reserved
    /// version controlled by [`Self::grease`] is additional to this count.
    pub available_version_count: u8,
    /// Whether and where to add one runtime-generated reserved version.
    pub grease: QuicVersionGrease,
}

/// Draft of the QUIC ACK frequency extension whose `min_ack_delay` is advertised.
///
/// The drafts use different transport parameter identifiers and give the
/// fields of the `ACK_FREQUENCY` frame (`0xaf`) different meanings; the runtime
/// reads frames from the peer in the advertised draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicAckFrequencyDraft {
    /// draft-ietf-quic-ack-frequency-02: identifier `0xff02de1a`.
    Draft02,
    /// draft-ietf-quic-ack-frequency-07: identifier `0xff04de1b`.
    Draft07,
}

impl QuicAckFrequencyDraft {
    const fn identifier(self) -> u64 {
        match self {
            Self::Draft02 => 0xff02_de1a,
            Self::Draft07 => 0xff04_de1b,
        }
    }
}

/// Length policy for the random Destination Connection ID of a client's first Initial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicConnectionIdLength {
    /// Always this many random bytes, from 8 through 20.
    Fixed(u8),
    /// `max(minimum, base + (b & (b >> 4)))` random bytes for one random byte `b`.
    ///
    /// The masked term is 0 to 15 and is small more often than large, so short
    /// lengths dominate.
    MaskedRandom {
        /// Shortest length, at least 8.
        minimum: u8,
        /// Length before the masked term is added; `base + 15` must not exceed 20.
        base: u8,
    },
}

impl QuicConnectionIdLength {
    fn validate(self) -> Result<(), InvalidQuicTransportSettings> {
        let (shortest, longest) = match self {
            Self::Fixed(length) => (length, length),
            Self::MaskedRandom { minimum, base } => (minimum, minimum.max(base.saturating_add(15))),
        };
        if shortest < MIN_INITIAL_DESTINATION_CONNECTION_ID_LENGTH
            || longest > MAX_CONNECTION_ID_LENGTH
        {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "initial_destination_connection_id",
                "Initial Destination Connection IDs must be 8 to 20 bytes",
            ));
        }
        Ok(())
    }
}

/// A named Google QUIC connection option with understood semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GoogleConnectionOption {
    /// Request that the server send the HTTP/3 ORIGIN frame (`ORIG`).
    RequestOriginFrame,
}

/// Policy for one runtime-generated reserved QUIC transport parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTransportGrease {
    /// Smallest generated payload length, inclusive.
    pub minimum_payload_length: u8,
    /// Largest generated payload length, inclusive.
    pub maximum_payload_length: u8,
}

/// One supported transport parameter in the outgoing wire layout.
///
/// Scalar values live on [`QuicTransportSettings`]. This enum controls only
/// which values are advertised and how their value bytes are encoded. Values
/// that vary for every connection are represented by policy or marker variants
/// rather than captured bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicTransportParameterKind {
    /// `max_idle_timeout` (`0x01`).
    MaxIdleTimeout {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `max_udp_payload_size` (`0x03`).
    MaxUdpPayloadSize {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_data` (`0x04`).
    InitialMaxData {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_stream_data_bidi_local` (`0x05`).
    InitialMaxStreamDataBidiLocal {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_stream_data_bidi_remote` (`0x06`).
    InitialMaxStreamDataBidiRemote {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_stream_data_uni` (`0x07`).
    InitialMaxStreamDataUni {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_streams_bidi` (`0x08`).
    InitialMaxStreamsBidi {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_max_streams_uni` (`0x09`).
    InitialMaxStreamsUni {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `max_ack_delay` (`0x0b`), from [`QuicTransportSettings::max_ack_delay_ms`].
    MaxAckDelay {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `active_connection_id_limit` (`0x0e`), from
    /// [`QuicTransportSettings::active_connection_id_limit`].
    ActiveConnectionIdLimit {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// `initial_source_connection_id` (`0x0f`).
    ///
    /// The connection ID bytes are supplied by the running QUIC connection.
    InitialSourceConnectionId {
        /// Exact number of runtime-generated connection-ID bytes.
        length: u8,
    },
    /// `version_information` (`0x11`).
    VersionInformation(QuicVersionInformation),
    /// `max_datagram_frame_size` (`0x20`).
    MaxDatagramFrameSize {
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// The empty `reset_stream_at` parameter (`0x1d`), sent when
    /// [`QuicTransportSettings::reset_stream_at`] is set.
    ResetStreamAt,
    /// `min_ack_delay`, from [`QuicTransportSettings::min_ack_delay_us`].
    MinAckDelay {
        /// ACK frequency draft, which selects the identifier.
        draft: QuicAckFrequencyDraft,
        /// Width of the integer value.
        value_width: QuicVarIntWidth,
    },
    /// Google connection options (`0x3128`).
    GoogleConnectionOptions(Vec<GoogleConnectionOption>),
    /// `initial_rtt_us` (`0x3127`), sent only on a connection that resumes a
    /// session.
    ///
    /// The value is the round-trip time, in microseconds, that the runtime
    /// last measured to the same server, encoded as a minimal-length varint.
    /// A connection that presents no ticket, or that has no measurement to
    /// send, omits the parameter, and the remaining parameters keep their
    /// order policy.
    InitialRtt,
    /// One reserved parameter whose identifier and payload are generated at runtime.
    Grease(QuicTransportGrease),
}

impl QuicTransportParameterKind {
    fn identity(&self) -> ParameterIdentity {
        match self {
            Self::MaxIdleTimeout { .. } => ParameterIdentity::MaxIdleTimeout,
            Self::MaxUdpPayloadSize { .. } => ParameterIdentity::MaxUdpPayloadSize,
            Self::InitialMaxData { .. } => ParameterIdentity::InitialMaxData,
            Self::InitialMaxStreamDataBidiLocal { .. } => {
                ParameterIdentity::InitialMaxStreamDataBidiLocal
            }
            Self::InitialMaxStreamDataBidiRemote { .. } => {
                ParameterIdentity::InitialMaxStreamDataBidiRemote
            }
            Self::InitialMaxStreamDataUni { .. } => ParameterIdentity::InitialMaxStreamDataUni,
            Self::InitialMaxStreamsBidi { .. } => ParameterIdentity::InitialMaxStreamsBidi,
            Self::InitialMaxStreamsUni { .. } => ParameterIdentity::InitialMaxStreamsUni,
            Self::MaxAckDelay { .. } => ParameterIdentity::MaxAckDelay,
            Self::ActiveConnectionIdLimit { .. } => ParameterIdentity::ActiveConnectionIdLimit,
            Self::InitialSourceConnectionId { .. } => ParameterIdentity::InitialSourceConnectionId,
            Self::VersionInformation(_) => ParameterIdentity::VersionInformation,
            Self::MaxDatagramFrameSize { .. } => ParameterIdentity::MaxDatagramFrameSize,
            Self::ResetStreamAt => ParameterIdentity::ResetStreamAt,
            Self::MinAckDelay { .. } => ParameterIdentity::MinAckDelay,
            Self::GoogleConnectionOptions(_) => ParameterIdentity::GoogleConnectionOptions,
            Self::InitialRtt => ParameterIdentity::InitialRtt,
            Self::Grease(_) => ParameterIdentity::Grease,
        }
    }

    const fn identifier(&self) -> Option<u64> {
        match self {
            Self::MaxIdleTimeout { .. } => Some(0x01),
            Self::MaxUdpPayloadSize { .. } => Some(0x03),
            Self::InitialMaxData { .. } => Some(0x04),
            Self::InitialMaxStreamDataBidiLocal { .. } => Some(0x05),
            Self::InitialMaxStreamDataBidiRemote { .. } => Some(0x06),
            Self::InitialMaxStreamDataUni { .. } => Some(0x07),
            Self::InitialMaxStreamsBidi { .. } => Some(0x08),
            Self::InitialMaxStreamsUni { .. } => Some(0x09),
            Self::MaxAckDelay { .. } => Some(0x0b),
            Self::ActiveConnectionIdLimit { .. } => Some(0x0e),
            Self::InitialSourceConnectionId { .. } => Some(0x0f),
            Self::VersionInformation(_) => Some(0x11),
            Self::MaxDatagramFrameSize { .. } => Some(0x20),
            Self::ResetStreamAt => Some(0x1d),
            Self::MinAckDelay { draft, .. } => Some(draft.identifier()),
            Self::GoogleConnectionOptions(_) => Some(0x3128),
            Self::InitialRtt => Some(0x3127),
            Self::Grease(_) => None,
        }
    }
}

/// Wire encoding for one configured QUIC transport parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportParameter {
    /// Parameter identifier and value policy.
    pub kind: QuicTransportParameterKind,
    /// Width of the parameter identifier.
    pub id_width: QuicVarIntWidth,
    /// Width of the parameter value-length field.
    pub length_width: QuicVarIntWidth,
}

/// QUIC transport semantics and their independent ordered wire layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportSettings {
    /// Maximum accepted idle time in milliseconds; zero omits the local limit.
    ///
    /// The connection has no idle timeout only when the peer also omits its
    /// limit or advertises zero.
    pub max_idle_timeout_ms: u64,
    /// Largest UDP payload the endpoint is willing to receive.
    pub max_udp_payload_size: u64,
    /// Initial connection-wide receive credit.
    pub initial_max_data: u64,
    /// Initial receive credit for locally initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial receive credit for remotely initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial receive credit for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Initial maximum number of remotely initiated bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// Initial maximum number of remotely initiated unidirectional streams.
    pub initial_max_streams_uni: u64,
    /// Maximum accepted DATAGRAM frame size, or `None` to omit DATAGRAM support.
    pub max_datagram_frame_size: Option<u64>,
    /// Largest delay, in milliseconds, before acknowledging an ack-eliciting packet.
    ///
    /// Below 2^14. The protocol default, 25, needs no wire entry.
    pub max_ack_delay_ms: u64,
    /// Number of the peer's connection IDs the endpoint stores, from 2 through 8.
    ///
    /// The protocol default, 2, needs no wire entry.
    pub active_connection_id_limit: u64,
    /// Smallest ACK delay, in microseconds, the endpoint can honor when a peer
    /// asks for one with ACK_FREQUENCY, or `None` to leave the ACK frequency
    /// extension unadvertised.
    ///
    /// The runtime's timer granularity is 1000 microseconds, the only value it
    /// can advertise.
    pub min_ack_delay_us: Option<u64>,
    /// Whether the endpoint accepts `RESET_STREAM_AT` frames
    /// (draft-ietf-quic-reliable-stream-reset), which deliver a stream's
    /// first bytes before a reset.
    pub reset_stream_at: bool,
    /// IP packet size the connection starts with, headers included.
    ///
    /// Every client datagram that carries an Initial packet is padded to it.
    /// The UDP payload is this size less the IP and UDP headers: 28 bytes over
    /// IPv4 and 48 over IPv6. `None` keeps the runtime's 1200-byte Initial
    /// datagrams.
    pub initial_path_mtu: Option<u16>,
    /// Length of the random Destination Connection ID of the first Initial.
    ///
    /// `None` keeps the runtime's 20 random bytes.
    pub initial_destination_connection_id: Option<QuicConnectionIdLength>,
    /// Parameters to advertise and their fixed/template wire order.
    pub wire_parameters: Vec<QuicTransportParameter>,
    /// Whether to preserve or permute the configured parameter order.
    pub parameter_order: QuicTransportParameterOrder,
    /// Whether a connection that resumes a TLS session offers early (0-RTT)
    /// data.
    ///
    /// When set, a resumed connection's ClientHello carries the TLS
    /// `early_data` extension whenever its ticket permits early data. Which
    /// requests travel as early data is the runtime's replay policy, not
    /// profile data. Only a resumed connection can offer early data, so this
    /// has no effect unless the TLS settings enable session tickets.
    pub early_data: bool,
}

impl QuicTransportSettings {
    /// Validates settings independent of a concrete QUIC backend.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidQuicTransportSettings`] for invalid transport limits,
    /// ACK delays, path MTU, connection IDs, or parameter encodings. It also
    /// rejects repeated parameter kinds and missing parameters required by
    /// nondefault values. The error identifies the setting that failed.
    pub fn validate(&self) -> Result<(), InvalidQuicTransportSettings> {
        validate_varint("max_idle_timeout_ms", self.max_idle_timeout_ms)?;
        if !(MIN_UDP_PAYLOAD_SIZE..=MAX_UDP_PAYLOAD_SIZE).contains(&self.max_udp_payload_size) {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "max_udp_payload_size",
                "UDP payload size must be in 1200..=65527 bytes",
            ));
        }
        validate_varint("initial_max_data", self.initial_max_data)?;
        validate_varint(
            "initial_max_stream_data_bidi_local",
            self.initial_max_stream_data_bidi_local,
        )?;
        validate_varint(
            "initial_max_stream_data_bidi_remote",
            self.initial_max_stream_data_bidi_remote,
        )?;
        validate_varint(
            "initial_max_stream_data_uni",
            self.initial_max_stream_data_uni,
        )?;
        validate_stream_count("initial_max_streams_bidi", self.initial_max_streams_bidi)?;
        validate_stream_count("initial_max_streams_uni", self.initial_max_streams_uni)?;
        if let Some(value) = self.max_datagram_frame_size {
            validate_varint("max_datagram_frame_size", value)?;
        }
        if self.max_ack_delay_ms >= MAX_ACK_DELAY_LIMIT_MS {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "max_ack_delay_ms",
                "max_ack_delay must be below 16384 milliseconds",
            ));
        }
        if !(2..=8).contains(&self.active_connection_id_limit) {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "active_connection_id_limit",
                "active_connection_id_limit must be 2 through 8",
            ));
        }
        if let Some(value) = self.min_ack_delay_us
            && value > self.max_ack_delay_ms * 1_000
        {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::Inconsistent,
                "min_ack_delay_us",
                "min_ack_delay must not exceed max_ack_delay",
            ));
        }
        if let Some(mtu) = self.initial_path_mtu
            && !(MIN_UDP_PAYLOAD_SIZE + IPV6_UDP_HEADERS
                ..=self.max_udp_payload_size + IPV4_UDP_HEADERS)
                .contains(&u64::from(mtu))
        {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::Inconsistent,
                "initial_path_mtu",
                "the path MTU must leave 1200-byte Initial datagrams over IPv6 and at most max_udp_payload_size over IPv4",
            ));
        }
        if let Some(length) = self.initial_destination_connection_id {
            length.validate()?;
        }
        self.validate_wire_parameters()
    }

    fn validate_wire_parameters(&self) -> Result<(), InvalidQuicTransportSettings> {
        let mut identities = Vec::with_capacity(self.wire_parameters.len());

        for parameter in &self.wire_parameters {
            let identity = parameter.kind.identity();
            if identities.contains(&identity) {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::Duplicate,
                    "wire_parameters",
                    format!("{identity:?} must not repeat"),
                ));
            }
            identities.push(identity);

            if parameter
                .kind
                .identifier()
                .is_some_and(|identifier| !parameter.id_width.can_encode(identifier))
            {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::OutOfRange,
                    "wire_parameters.id_width",
                    format!("{identity:?} identifier does not fit its configured width"),
                ));
            }

            self.validate_parameter_encoding(parameter)?;
        }

        self.validate_required_parameters(&identities)
    }

    fn validate_parameter_encoding(
        &self,
        parameter: &QuicTransportParameter,
    ) -> Result<(), InvalidQuicTransportSettings> {
        let payload_length = match &parameter.kind {
            QuicTransportParameterKind::MaxIdleTimeout { value_width } => {
                validate_value_width(*value_width, self.max_idle_timeout_ms)?
            }
            QuicTransportParameterKind::MaxUdpPayloadSize { value_width } => {
                validate_value_width(*value_width, self.max_udp_payload_size)?
            }
            QuicTransportParameterKind::InitialMaxData { value_width } => {
                validate_value_width(*value_width, self.initial_max_data)?
            }
            QuicTransportParameterKind::InitialMaxStreamDataBidiLocal { value_width } => {
                validate_value_width(*value_width, self.initial_max_stream_data_bidi_local)?
            }
            QuicTransportParameterKind::InitialMaxStreamDataBidiRemote { value_width } => {
                validate_value_width(*value_width, self.initial_max_stream_data_bidi_remote)?
            }
            QuicTransportParameterKind::InitialMaxStreamDataUni { value_width } => {
                validate_value_width(*value_width, self.initial_max_stream_data_uni)?
            }
            QuicTransportParameterKind::InitialMaxStreamsBidi { value_width } => {
                validate_value_width(*value_width, self.initial_max_streams_bidi)?
            }
            QuicTransportParameterKind::InitialMaxStreamsUni { value_width } => {
                validate_value_width(*value_width, self.initial_max_streams_uni)?
            }
            QuicTransportParameterKind::MaxAckDelay { value_width } => {
                validate_value_width(*value_width, self.max_ack_delay_ms)?
            }
            QuicTransportParameterKind::ActiveConnectionIdLimit { value_width } => {
                validate_value_width(*value_width, self.active_connection_id_limit)?
            }
            QuicTransportParameterKind::ResetStreamAt => 0,
            QuicTransportParameterKind::MinAckDelay { value_width, .. } => {
                let value = self.min_ack_delay_us.ok_or_else(|| {
                    InvalidQuicTransportSettings::new(
                        crate::ValidationErrorKind::Inconsistent,
                        "wire_parameters",
                        "MinAckDelay requires min_ack_delay_us",
                    )
                })?;
                validate_value_width(*value_width, value)?
            }
            QuicTransportParameterKind::InitialSourceConnectionId { length } => {
                if *length > MAX_CONNECTION_ID_LENGTH {
                    return Err(InvalidQuicTransportSettings::new(
                        crate::ValidationErrorKind::OutOfRange,
                        "wire_parameters.initial_source_connection_id",
                        "connection ID length must not exceed 20 bytes",
                    ));
                }
                u64::from(*length)
            }
            QuicTransportParameterKind::VersionInformation(settings) => {
                validate_version_information(settings)?
            }
            QuicTransportParameterKind::MaxDatagramFrameSize { value_width } => {
                let value = self.max_datagram_frame_size.ok_or_else(|| {
                    InvalidQuicTransportSettings::new(
                        crate::ValidationErrorKind::Inconsistent,
                        "wire_parameters",
                        "MaxDatagramFrameSize requires max_datagram_frame_size",
                    )
                })?;
                validate_value_width(*value_width, value)?
            }
            QuicTransportParameterKind::GoogleConnectionOptions(options) => {
                validate_google_connection_options(options)?
            }
            // The longest varint the runtime may encode.
            QuicTransportParameterKind::InitialRtt => QuicVarIntWidth::Eight.encoded_len() as u64,
            QuicTransportParameterKind::Grease(grease) => validate_grease(grease)?,
        };

        if !parameter.length_width.can_encode(payload_length) {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "wire_parameters.length_width",
                "parameter payload length does not fit its configured width",
            ));
        }

        Ok(())
    }

    fn validate_required_parameters(
        &self,
        identities: &[ParameterIdentity],
    ) -> Result<(), InvalidQuicTransportSettings> {
        let required_non_defaults = [
            (
                self.max_idle_timeout_ms != 0,
                ParameterIdentity::MaxIdleTimeout,
            ),
            (
                self.max_udp_payload_size != MAX_UDP_PAYLOAD_SIZE,
                ParameterIdentity::MaxUdpPayloadSize,
            ),
            (
                self.initial_max_data != 0,
                ParameterIdentity::InitialMaxData,
            ),
            (
                self.initial_max_stream_data_bidi_local != 0,
                ParameterIdentity::InitialMaxStreamDataBidiLocal,
            ),
            (
                self.initial_max_stream_data_bidi_remote != 0,
                ParameterIdentity::InitialMaxStreamDataBidiRemote,
            ),
            (
                self.initial_max_stream_data_uni != 0,
                ParameterIdentity::InitialMaxStreamDataUni,
            ),
            (
                self.initial_max_streams_bidi != 0,
                ParameterIdentity::InitialMaxStreamsBidi,
            ),
            (
                self.initial_max_streams_uni != 0,
                ParameterIdentity::InitialMaxStreamsUni,
            ),
            (
                self.max_ack_delay_ms != DEFAULT_MAX_ACK_DELAY_MS,
                ParameterIdentity::MaxAckDelay,
            ),
            (
                self.active_connection_id_limit != DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
                ParameterIdentity::ActiveConnectionIdLimit,
            ),
        ];
        for (required, identity) in required_non_defaults {
            if required && !identities.contains(&identity) {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "wire_parameters",
                    format!("non-default {identity:?} value must be advertised"),
                ));
            }
        }

        if !identities.contains(&ParameterIdentity::InitialSourceConnectionId) {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::Missing,
                "wire_parameters",
                "InitialSourceConnectionId is required",
            ));
        }
        match self.max_datagram_frame_size {
            Some(_) if !identities.contains(&ParameterIdentity::MaxDatagramFrameSize) => {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "wire_parameters",
                    "max_datagram_frame_size must be advertised when configured",
                ));
            }
            None if identities.contains(&ParameterIdentity::MaxDatagramFrameSize) => {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "wire_parameters",
                    "MaxDatagramFrameSize must be omitted when DATAGRAM support is disabled",
                ));
            }
            Some(_) | None => {}
        }
        for (configured, identity, field, message) in [
            (
                self.reset_stream_at,
                ParameterIdentity::ResetStreamAt,
                "reset_stream_at",
                "ResetStreamAt must be advertised exactly when reset_stream_at is set",
            ),
            (
                self.min_ack_delay_us.is_some(),
                ParameterIdentity::MinAckDelay,
                "min_ack_delay_us",
                "MinAckDelay must be advertised exactly when min_ack_delay_us is set",
            ),
        ] {
            if configured != identities.contains(&identity) {
                return Err(InvalidQuicTransportSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    field,
                    message,
                ));
            }
        }

        Ok(())
    }
}

/// Error returned when QUIC transport profile settings are inconsistent.
///
/// Use [`Self::kind`] for recovery and [`Self::field`] and [`Self::reason`]
/// for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidQuicTransportSettings {
    kind: crate::ValidationErrorKind,
    field: &'static str,
    message: Box<str>,
}

impl InvalidQuicTransportSettings {
    /// Returns the stable recovery category.
    #[must_use]
    pub const fn kind(&self) -> crate::ValidationErrorKind {
        self.kind
    }

    fn new(
        kind: crate::ValidationErrorKind,
        field: &'static str,
        message: impl Into<Box<str>>,
    ) -> Self {
        Self {
            kind,
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the field is invalid.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidQuicTransportSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid QUIC transport {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidQuicTransportSettings {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParameterIdentity {
    MaxIdleTimeout,
    MaxUdpPayloadSize,
    InitialMaxData,
    InitialMaxStreamDataBidiLocal,
    InitialMaxStreamDataBidiRemote,
    InitialMaxStreamDataUni,
    InitialMaxStreamsBidi,
    InitialMaxStreamsUni,
    MaxAckDelay,
    ActiveConnectionIdLimit,
    InitialSourceConnectionId,
    VersionInformation,
    MaxDatagramFrameSize,
    ResetStreamAt,
    MinAckDelay,
    GoogleConnectionOptions,
    InitialRtt,
    Grease,
}

fn validate_varint(field: &'static str, value: u64) -> Result<(), InvalidQuicTransportSettings> {
    if value > MAX_VARINT {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::OutOfRange,
            field,
            "value must be smaller than 2^62",
        ));
    }
    Ok(())
}

fn validate_stream_count(
    field: &'static str,
    value: u64,
) -> Result<(), InvalidQuicTransportSettings> {
    if value > MAX_STREAM_COUNT {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::OutOfRange,
            field,
            "stream count must not exceed 2^60",
        ));
    }
    Ok(())
}

fn validate_value_width(
    width: QuicVarIntWidth,
    value: u64,
) -> Result<u64, InvalidQuicTransportSettings> {
    if !width.can_encode(value) {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::OutOfRange,
            "wire_parameters.value_width",
            "parameter value does not fit its configured width",
        ));
    }
    Ok(width.encoded_len() as u64)
}

fn validate_google_connection_options(
    options: &[GoogleConnectionOption],
) -> Result<u64, InvalidQuicTransportSettings> {
    if options.is_empty() {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::Missing,
            "wire_parameters.google_connection_options",
            "Google connection options must not be empty",
        ));
    }
    for (index, option) in options.iter().enumerate() {
        if options[..index].contains(option) {
            return Err(InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::Duplicate,
                "wire_parameters.google_connection_options",
                "Google connection options must not repeat",
            ));
        }
    }

    u64::try_from(options.len())
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| {
            InvalidQuicTransportSettings::new(
                crate::ValidationErrorKind::TooLarge,
                "wire_parameters.google_connection_options",
                "Google connection options exceed the QUIC varint limit",
            )
        })
}

fn validate_grease(grease: &QuicTransportGrease) -> Result<u64, InvalidQuicTransportSettings> {
    if grease.minimum_payload_length > grease.maximum_payload_length {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::Missing,
            "wire_parameters.grease",
            "GREASE payload length range must not be empty",
        ));
    }
    if grease.maximum_payload_length > MAX_CAPTURED_GREASE_PAYLOAD_LENGTH {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::OutOfRange,
            "wire_parameters.grease",
            "captured GREASE payload lengths are limited to 0..=15 bytes",
        ));
    }
    Ok(u64::from(grease.maximum_payload_length))
}

fn validate_version_information(
    settings: &QuicVersionInformation,
) -> Result<u64, InvalidQuicTransportSettings> {
    if settings.available_version_count == 0 {
        return Err(InvalidQuicTransportSettings::new(
            crate::ValidationErrorKind::Inconsistent,
            "wire_parameters.version_information",
            "available versions must include the chosen version",
        ));
    }

    let grease_count = u64::from(!matches!(settings.grease, QuicVersionGrease::Omit));
    // Four bytes for the chosen version, followed by the available-version list.
    Ok(4 + 4 * (u64::from(settings.available_version_count) + grease_count))
}

#[cfg(test)]
mod tests;
