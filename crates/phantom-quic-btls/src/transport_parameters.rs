use std::{collections::BTreeSet, error::Error as StdError, fmt, time::Duration};

use phantom_profile::quic::{
    GoogleConnectionOption, QuicTransportParameter, QuicTransportParameterKind,
    QuicTransportParameterOrder, QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease,
};
use quinn_proto::{
    EndpointConfig, RandomConnectionIdGenerator, TransportConfig, VarInt,
    transport_parameters::TransportParameters,
};

use crate::QuicVersion;

mod wire;

#[cfg(test)]
use wire::{ENTROPY_LEN, decode_varint};
use wire::{
    ParsedTransportParameters, WireEntropy, encode_varint, is_reserved_transport_parameter,
};

const QUIC_V1: u32 = 0x0000_0001;
const MIN_ACK_DELAY_DRAFT_07: u64 = 0xff04_de1b;
const MAX_TRANSPORT_PARAMETERS_LEN: usize = u16::MAX as usize;

pub(crate) struct TransportParameterProfile {
    settings: QuicTransportSettings,
}

impl TransportParameterProfile {
    pub(crate) fn new(settings: QuicTransportSettings) -> Result<Self, QuicTransportProfileError> {
        settings
            .validate()
            .map_err(|error| profile_error(error.field(), error.reason()))?;
        let profile = Self { settings };
        profile.validate_provider_support()?;
        Ok(profile)
    }

    pub(crate) fn configure_quinn(
        &self,
        endpoint: &mut EndpointConfig,
        transport: &mut TransportConfig,
    ) -> Result<(), QuicTransportProfileError> {
        let settings = &self.settings;
        let cid_len = self.initial_source_connection_id_length()?;
        let max_udp_payload_size = u16::try_from(settings.max_udp_payload_size).map_err(|_| {
            profile_error(
                "max_udp_payload_size",
                "value cannot be represented by Quinn",
            )
        })?;
        let idle_timeout =
            match settings.max_idle_timeout_ms {
                0 => None,
                milliseconds => Some(Duration::from_millis(milliseconds).try_into().map_err(
                    |_| {
                        profile_error(
                            "max_idle_timeout_ms",
                            "value cannot be represented by Quinn",
                        )
                    },
                )?),
            };
        let receive_window = varint("initial_max_data", settings.initial_max_data)?;
        let stream_receive_window = varint(
            "initial_max_stream_data",
            settings.initial_max_stream_data_bidi_local,
        )?;
        let max_bidi_streams = varint(
            "initial_max_streams_bidi",
            settings.initial_max_streams_bidi,
        )?;
        let max_uni_streams = varint("initial_max_streams_uni", settings.initial_max_streams_uni)?;
        let datagram_frame_size = settings
            .max_datagram_frame_size
            .map(|value| varint("max_datagram_frame_size", value))
            .transpose()?;
        let datagram_buffer_size = settings
            .max_datagram_frame_size
            .map(usize::try_from)
            .transpose()
            .map_err(|_| {
                profile_error(
                    "max_datagram_frame_size",
                    "value exceeds this platform's address space",
                )
            })?;

        endpoint
            .max_udp_payload_size(max_udp_payload_size)
            .map_err(|_| {
                profile_error(
                    "max_udp_payload_size",
                    "value is outside Quinn's supported range",
                )
            })?;
        endpoint
            .cid_generator(move || Box::new(RandomConnectionIdGenerator::new(cid_len)))
            .grease_quic_bit(false)
            .supported_versions(vec![QUIC_V1]);
        transport
            .max_idle_timeout(idle_timeout)
            .receive_window(receive_window)
            .stream_receive_window(stream_receive_window)
            .max_concurrent_bidi_streams(max_bidi_streams)
            .max_concurrent_uni_streams(max_uni_streams);
        transport
            .advertised_datagram_frame_size(datagram_buffer_size, datagram_frame_size)
            .map_err(|error| profile_error("max_datagram_frame_size", error.to_string()))?;
        Ok(())
    }

    fn validate_provider_support(&self) -> Result<(), QuicTransportProfileError> {
        use QuicTransportParameterKind as Kind;

        if self.settings.initial_max_stream_data_bidi_local
            != self.settings.initial_max_stream_data_bidi_remote
            || self.settings.initial_max_stream_data_bidi_local
                != self.settings.initial_max_stream_data_uni
        {
            return Err(profile_error(
                "initial_max_stream_data",
                "Quinn requires one receive window for all local stream classes",
            ));
        }
        match self.settings.parameter_order {
            QuicTransportParameterOrder::Fixed | QuicTransportParameterOrder::Permuted => {}
            _ => {
                return Err(profile_error(
                    "parameter_order",
                    "provider does not support this ordering policy",
                ));
            }
        }
        for parameter in &self.settings.wire_parameters {
            match &parameter.kind {
                Kind::VersionInformation(settings) => {
                    if settings.available_version_count != 1 {
                        return Err(profile_error(
                            "version_information",
                            "provider requires exactly one available QUIC version",
                        ));
                    }
                    match settings.grease {
                        QuicVersionGrease::Omit | QuicVersionGrease::Permuted => {}
                        _ => {
                            return Err(profile_error(
                                "version_information",
                                "provider does not support this version GREASE policy",
                            ));
                        }
                    }
                }
                Kind::GoogleConnectionOptions(options) => {
                    for option in options {
                        match option {
                            GoogleConnectionOption::RequestOriginFrame => {}
                            _ => {
                                return Err(profile_error(
                                    "google_connection_options",
                                    "provider does not support this connection option",
                                ));
                            }
                        }
                    }
                }
                Kind::MaxIdleTimeout { .. }
                | Kind::MaxUdpPayloadSize { .. }
                | Kind::InitialMaxData { .. }
                | Kind::InitialMaxStreamDataBidiLocal { .. }
                | Kind::InitialMaxStreamDataBidiRemote { .. }
                | Kind::InitialMaxStreamDataUni { .. }
                | Kind::InitialMaxStreamsBidi { .. }
                | Kind::InitialMaxStreamsUni { .. }
                | Kind::InitialSourceConnectionId { .. }
                | Kind::MaxDatagramFrameSize { .. }
                | Kind::Grease(_) => {}
                _ => {
                    return Err(profile_error(
                        "wire_parameters",
                        "provider does not support this parameter kind",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encode(
        &self,
        params: &TransportParameters,
        version: QuicVersion,
    ) -> Result<Vec<u8>, QuicTransportProfileError> {
        let mut entropy = WireEntropy::random()?;
        self.encode_with_entropy(params, version, &mut entropy)
    }

    fn encode_with_entropy(
        &self,
        params: &TransportParameters,
        version: QuicVersion,
        entropy: &mut WireEntropy,
    ) -> Result<Vec<u8>, QuicTransportProfileError> {
        let stock = ParsedTransportParameters::new(params)?;
        self.validate_stock(&stock)?;

        let mut order: Vec<usize> = (0..self.settings.wire_parameters.len()).collect();
        if matches!(
            self.settings.parameter_order,
            QuicTransportParameterOrder::Permuted
        ) {
            entropy.shuffle(&mut order)?;
        }

        let mut output = Vec::new();
        for index in order {
            let parameter = &self.settings.wire_parameters[index];
            let (identifier, value) = self.parameter_value(parameter, &stock, version, entropy)?;
            encode_varint(identifier, parameter.id_width, &mut output)?;
            encode_varint(
                u64::try_from(value.len()).map_err(|_| {
                    profile_error("wire_parameters", "parameter value is too large")
                })?,
                parameter.length_width,
                &mut output,
            )?;
            output.extend_from_slice(&value);
            if output.len() > MAX_TRANSPORT_PARAMETERS_LEN {
                return Err(profile_error(
                    "wire_parameters",
                    "encoded parameters exceed the TLS extension limit",
                ));
            }
        }
        Ok(output)
    }

    fn validate_stock(
        &self,
        stock: &ParsedTransportParameters,
    ) -> Result<(), QuicTransportProfileError> {
        let mut expected = BTreeSet::new();
        for parameter in &self.settings.wire_parameters {
            let Some((identifier, expected_value)) = self.expected_stock_value(parameter)? else {
                continue;
            };
            expected.insert(identifier);
            if identifier == 0x0f {
                let expected_length = usize::try_from(expected_value).map_err(|_| {
                    profile_error(
                        "initial_source_connection_id",
                        "connection ID length cannot be represented",
                    )
                })?;
                if stock.value(identifier)?.len() != expected_length {
                    return Err(profile_error(
                        "initial_source_connection_id",
                        "profile length does not match Quinn's live connection ID",
                    ));
                }
                continue;
            }
            if stock.scalar(identifier)? != expected_value {
                return Err(profile_error(
                    field_for_identifier(identifier),
                    "profile value does not match Quinn's live transport state",
                ));
            }
        }

        for identifier in stock.values.keys().copied() {
            if expected.contains(&identifier)
                || identifier == MIN_ACK_DELAY_DRAFT_07
                || is_reserved_transport_parameter(identifier)
            {
                continue;
            }
            return Err(profile_error(
                "wire_parameters",
                "Quinn would advertise a parameter omitted by the profile",
            ));
        }
        Ok(())
    }

    fn expected_stock_value(
        &self,
        parameter: &QuicTransportParameter,
    ) -> Result<Option<(u64, u64)>, QuicTransportProfileError> {
        use QuicTransportParameterKind as Kind;

        let pair = match &parameter.kind {
            Kind::MaxIdleTimeout { .. } => Some((0x01, self.settings.max_idle_timeout_ms)),
            Kind::MaxUdpPayloadSize { .. } => Some((0x03, self.settings.max_udp_payload_size)),
            Kind::InitialMaxData { .. } => Some((0x04, self.settings.initial_max_data)),
            Kind::InitialMaxStreamDataBidiLocal { .. } => {
                Some((0x05, self.settings.initial_max_stream_data_bidi_local))
            }
            Kind::InitialMaxStreamDataBidiRemote { .. } => {
                Some((0x06, self.settings.initial_max_stream_data_bidi_remote))
            }
            Kind::InitialMaxStreamDataUni { .. } => {
                Some((0x07, self.settings.initial_max_stream_data_uni))
            }
            Kind::InitialMaxStreamsBidi { .. } => {
                Some((0x08, self.settings.initial_max_streams_bidi))
            }
            Kind::InitialMaxStreamsUni { .. } => {
                Some((0x09, self.settings.initial_max_streams_uni))
            }
            Kind::InitialSourceConnectionId { length } => Some((0x0f, u64::from(*length))),
            Kind::MaxDatagramFrameSize { .. } => Some((
                0x20,
                self.settings.max_datagram_frame_size.ok_or_else(|| {
                    profile_error(
                        "max_datagram_frame_size",
                        "wire parameter has no semantic value",
                    )
                })?,
            )),
            Kind::VersionInformation(_) | Kind::GoogleConnectionOptions(_) | Kind::Grease(_) => {
                None
            }
            _ => {
                return Err(profile_error(
                    "wire_parameters",
                    "parameter kind is not supported by this provider",
                ));
            }
        };
        Ok(pair)
    }

    fn parameter_value(
        &self,
        parameter: &QuicTransportParameter,
        stock: &ParsedTransportParameters,
        version: QuicVersion,
        entropy: &mut WireEntropy,
    ) -> Result<(u64, Vec<u8>), QuicTransportProfileError> {
        use QuicTransportParameterKind as Kind;

        let encoded_scalar = |identifier, value, width: QuicVarIntWidth| {
            let mut encoded = Vec::with_capacity(width.encoded_len());
            encode_varint(value, width, &mut encoded)?;
            Ok((identifier, encoded))
        };
        match &parameter.kind {
            Kind::MaxIdleTimeout { value_width } => {
                encoded_scalar(0x01, self.settings.max_idle_timeout_ms, *value_width)
            }
            Kind::MaxUdpPayloadSize { value_width } => {
                encoded_scalar(0x03, self.settings.max_udp_payload_size, *value_width)
            }
            Kind::InitialMaxData { value_width } => {
                encoded_scalar(0x04, self.settings.initial_max_data, *value_width)
            }
            Kind::InitialMaxStreamDataBidiLocal { value_width } => encoded_scalar(
                0x05,
                self.settings.initial_max_stream_data_bidi_local,
                *value_width,
            ),
            Kind::InitialMaxStreamDataBidiRemote { value_width } => encoded_scalar(
                0x06,
                self.settings.initial_max_stream_data_bidi_remote,
                *value_width,
            ),
            Kind::InitialMaxStreamDataUni { value_width } => encoded_scalar(
                0x07,
                self.settings.initial_max_stream_data_uni,
                *value_width,
            ),
            Kind::InitialMaxStreamsBidi { value_width } => {
                encoded_scalar(0x08, self.settings.initial_max_streams_bidi, *value_width)
            }
            Kind::InitialMaxStreamsUni { value_width } => {
                encoded_scalar(0x09, self.settings.initial_max_streams_uni, *value_width)
            }
            Kind::InitialSourceConnectionId { .. } => Ok((0x0f, stock.value(0x0f)?.to_vec())),
            Kind::VersionInformation(settings) => self
                .version_information(
                    version,
                    settings.grease,
                    settings.available_version_count,
                    entropy,
                )
                .map(|value| (0x11, value)),
            Kind::MaxDatagramFrameSize { value_width } => encoded_scalar(
                0x20,
                self.settings.max_datagram_frame_size.ok_or_else(|| {
                    profile_error(
                        "max_datagram_frame_size",
                        "wire parameter has no semantic value",
                    )
                })?,
                *value_width,
            ),
            Kind::GoogleConnectionOptions(options) => {
                let mut value = Vec::with_capacity(options.len() * 4);
                for option in options {
                    match option {
                        GoogleConnectionOption::RequestOriginFrame => {
                            value.extend_from_slice(b"ORIG")
                        }
                        _ => {
                            return Err(profile_error(
                                "google_connection_options",
                                "connection option is not supported by this provider",
                            ));
                        }
                    }
                }
                Ok((0x3128, value))
            }
            Kind::Grease(grease) => {
                let identifier = entropy.reserved_transport_parameter_id()?;
                let len = entropy.uniform_inclusive(
                    grease.minimum_payload_length,
                    grease.maximum_payload_length,
                )?;
                Ok((identifier, entropy.take(usize::from(len))?.to_vec()))
            }
            _ => Err(profile_error(
                "wire_parameters",
                "parameter kind is not supported by this provider",
            )),
        }
    }

    fn version_information(
        &self,
        version: QuicVersion,
        grease: QuicVersionGrease,
        available_version_count: u8,
        entropy: &mut WireEntropy,
    ) -> Result<Vec<u8>, QuicTransportProfileError> {
        if available_version_count != 1 {
            return Err(profile_error(
                "version_information",
                "provider currently supports exactly one available QUIC version",
            ));
        }
        let chosen = match version {
            QuicVersion::V1 => QUIC_V1,
        };
        let mut available = vec![chosen];
        if matches!(grease, QuicVersionGrease::Permuted) {
            let raw = u32::from_be_bytes(entropy.take_array()?);
            available.push((raw & 0xf0f0_f0f0) | 0x0a0a_0a0a);
            entropy.shuffle(&mut available)?;
        }

        let mut value = Vec::with_capacity(4 + available.len() * 4);
        value.extend_from_slice(&chosen.to_be_bytes());
        for available in available {
            value.extend_from_slice(&available.to_be_bytes());
        }
        Ok(value)
    }

    fn initial_source_connection_id_length(&self) -> Result<usize, QuicTransportProfileError> {
        self.settings
            .wire_parameters
            .iter()
            .find_map(|parameter| match &parameter.kind {
                QuicTransportParameterKind::InitialSourceConnectionId { length } => {
                    Some(usize::from(*length))
                }
                _ => None,
            })
            .ok_or_else(|| {
                profile_error(
                    "initial_source_connection_id",
                    "profile omitted the required parameter",
                )
            })
    }
}

fn varint(field: &'static str, value: u64) -> Result<VarInt, QuicTransportProfileError> {
    VarInt::from_u64(value)
        .map_err(|_| profile_error(field, "value cannot be represented by Quinn"))
}

fn field_for_identifier(identifier: u64) -> &'static str {
    match identifier {
        0x01 => "max_idle_timeout_ms",
        0x03 => "max_udp_payload_size",
        0x04 => "initial_max_data",
        0x05 => "initial_max_stream_data_bidi_local",
        0x06 => "initial_max_stream_data_bidi_remote",
        0x07 => "initial_max_stream_data_uni",
        0x08 => "initial_max_streams_bidi",
        0x09 => "initial_max_streams_uni",
        0x0f => "initial_source_connection_id",
        0x20 => "max_datagram_frame_size",
        _ => "wire_parameters",
    }
}

fn profile_error(field: &'static str, message: impl Into<Box<str>>) -> QuicTransportProfileError {
    QuicTransportProfileError {
        field,
        message: message.into(),
    }
}

/// Failure while applying or encoding a QUIC transport profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportProfileError {
    field: &'static str,
    message: Box<str>,
}

impl QuicTransportProfileError {
    /// Returns the profile field responsible for the failure.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    pub(crate) fn is_entropy_failure(&self) -> bool {
        self.field == "entropy"
    }
}

impl fmt::Display for QuicTransportProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "QUIC transport profile {}: {}",
            self.field, self.message
        )
    }
}

impl StdError for QuicTransportProfileError {}

#[cfg(test)]
mod tests;
