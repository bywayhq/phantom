//! Backend-neutral QUIC transport settings and wire layout.

use std::{error::Error, fmt};

const MAX_VARINT: u64 = (1 << 62) - 1;
const MAX_STREAM_COUNT: u64 = 1 << 60;
const MIN_UDP_PAYLOAD_SIZE: u64 = 1_200;
const MAX_UDP_PAYLOAD_SIZE: u64 = 65_527;
const MAX_CONNECTION_ID_LENGTH: u8 = 20;
const MAX_CAPTURED_GREASE_PAYLOAD_LENGTH: u8 = 15;

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
}

/// Wire policy for RFC 9368 Version Information.
///
/// The selected version and the versions actually supported by the transport
/// remain runtime-owned and are deliberately absent from this profile type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuicVersionInformation {
    /// Number of non-reserved versions the runtime must place after the chosen version.
    ///
    /// The chosen version must appear in that list. A generated reserved
    /// version controlled by [`Self::grease`] is additional to this count.
    pub available_version_count: u8,
    /// Whether and where to add one runtime-generated reserved version.
    pub grease: QuicVersionGrease,
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
#[non_exhaustive]
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
    /// Google connection options (`0x3128`).
    GoogleConnectionOptions(Vec<GoogleConnectionOption>),
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
            Self::InitialSourceConnectionId { .. } => ParameterIdentity::InitialSourceConnectionId,
            Self::VersionInformation(_) => ParameterIdentity::VersionInformation,
            Self::MaxDatagramFrameSize { .. } => ParameterIdentity::MaxDatagramFrameSize,
            Self::GoogleConnectionOptions(_) => ParameterIdentity::GoogleConnectionOptions,
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
            Self::InitialSourceConnectionId { .. } => Some(0x0f),
            Self::VersionInformation(_) => Some(0x11),
            Self::MaxDatagramFrameSize { .. } => Some(0x20),
            Self::GoogleConnectionOptions(_) => Some(0x3128),
            Self::Grease(_) => None,
        }
    }
}

/// Wire encoding for one configured QUIC transport parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// Parameters to advertise and their fixed/template wire order.
    pub wire_parameters: Vec<QuicTransportParameter>,
    /// Whether to preserve or permute the configured parameter order.
    pub parameter_order: QuicTransportParameterOrder,
}

impl QuicTransportSettings {
    /// Validates settings independent of a concrete QUIC backend.
    pub fn validate(&self) -> Result<(), InvalidQuicTransportSettings> {
        validate_varint("max_idle_timeout_ms", self.max_idle_timeout_ms)?;
        if !(MIN_UDP_PAYLOAD_SIZE..=MAX_UDP_PAYLOAD_SIZE).contains(&self.max_udp_payload_size) {
            return Err(InvalidQuicTransportSettings::new(
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
        self.validate_wire_parameters()
    }

    fn validate_wire_parameters(&self) -> Result<(), InvalidQuicTransportSettings> {
        let mut identities = Vec::with_capacity(self.wire_parameters.len());

        for parameter in &self.wire_parameters {
            let identity = parameter.kind.identity();
            if identities.contains(&identity) {
                return Err(InvalidQuicTransportSettings::new(
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
            QuicTransportParameterKind::InitialSourceConnectionId { length } => {
                if *length > MAX_CONNECTION_ID_LENGTH {
                    return Err(InvalidQuicTransportSettings::new(
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
                        "wire_parameters",
                        "MaxDatagramFrameSize requires max_datagram_frame_size",
                    )
                })?;
                validate_value_width(*value_width, value)?
            }
            QuicTransportParameterKind::GoogleConnectionOptions(options) => {
                validate_google_connection_options(options)?
            }
            QuicTransportParameterKind::Grease(grease) => validate_grease(grease)?,
        };

        if !parameter.length_width.can_encode(payload_length) {
            return Err(InvalidQuicTransportSettings::new(
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
        ];
        for (required, identity) in required_non_defaults {
            if required && !identities.contains(&identity) {
                return Err(InvalidQuicTransportSettings::new(
                    "wire_parameters",
                    format!("non-default {identity:?} value must be advertised"),
                ));
            }
        }

        if !identities.contains(&ParameterIdentity::InitialSourceConnectionId) {
            return Err(InvalidQuicTransportSettings::new(
                "wire_parameters",
                "InitialSourceConnectionId is required",
            ));
        }
        match self.max_datagram_frame_size {
            Some(_) if !identities.contains(&ParameterIdentity::MaxDatagramFrameSize) => {
                return Err(InvalidQuicTransportSettings::new(
                    "wire_parameters",
                    "max_datagram_frame_size must be advertised when configured",
                ));
            }
            None if identities.contains(&ParameterIdentity::MaxDatagramFrameSize) => {
                return Err(InvalidQuicTransportSettings::new(
                    "wire_parameters",
                    "MaxDatagramFrameSize must be omitted when DATAGRAM support is disabled",
                ));
            }
            Some(_) | None => {}
        }

        Ok(())
    }
}

/// Error returned when QUIC transport profile settings are inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidQuicTransportSettings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidQuicTransportSettings {
    fn new(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
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
    InitialSourceConnectionId,
    VersionInformation,
    MaxDatagramFrameSize,
    GoogleConnectionOptions,
    Grease,
}

fn validate_varint(field: &'static str, value: u64) -> Result<(), InvalidQuicTransportSettings> {
    if value > MAX_VARINT {
        return Err(InvalidQuicTransportSettings::new(
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
            "wire_parameters.google_connection_options",
            "Google connection options must not be empty",
        ));
    }
    for (index, option) in options.iter().enumerate() {
        if options[..index].contains(option) {
            return Err(InvalidQuicTransportSettings::new(
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
                "wire_parameters.google_connection_options",
                "Google connection options exceed the QUIC varint limit",
            )
        })
}

fn validate_grease(grease: &QuicTransportGrease) -> Result<u64, InvalidQuicTransportSettings> {
    if grease.minimum_payload_length > grease.maximum_payload_length {
        return Err(InvalidQuicTransportSettings::new(
            "wire_parameters.grease",
            "GREASE payload length range must not be empty",
        ));
    }
    if grease.maximum_payload_length > MAX_CAPTURED_GREASE_PAYLOAD_LENGTH {
        return Err(InvalidQuicTransportSettings::new(
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
