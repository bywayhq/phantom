use std::{
    collections::BTreeSet, error::Error as StdError, fmt, net::IpAddr, sync::Arc, time::Duration,
};

use phantom_profile::quic::{
    GoogleConnectionOption, QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportParameter,
    QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
    QuicVarIntWidth, QuicVersionGrease,
};
use quinn_proto::{
    AckFrequencyDraft, ConnectionId, ConnectionIdGenerator, EndpointConfig,
    RandomConnectionIdGenerator, TransportConfig, VarInt,
    transport_parameters::TransportParameters,
};

use crate::QuicVersion;

mod wire;

#[cfg(test)]
use wire::{ENTROPY_LEN, decode_varint};
use wire::{
    MAX_VARINT, ParsedTransportParameters, WireEntropy, encode_varint,
    is_reserved_transport_parameter,
};

const MIN_ACK_DELAY_DRAFT_07: u64 = 0xff04_de1b;
const IPV4_UDP_HEADERS: u16 = 20 + 8;
const IPV6_UDP_HEADERS: u16 = 40 + 8;
/// The only `min_ack_delay` the runtime can honor: Quinn's 1 ms timer granularity.
const RUNTIME_MIN_ACK_DELAY_US: u64 = 1_000;
const RESET_STREAM_AT: u64 = 0x1d;
const VERSION_INFORMATION: u64 = 0x11;
/// The versions the runtime implements, most preferred first.
const RUNTIME_VERSIONS: [QuicVersion; 2] = [QuicVersion::V2, QuicVersion::V1];
const MAX_TRANSPORT_PARAMETERS_LEN: usize = u16::MAX as usize;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;

#[derive(Clone)]
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
            "initial_max_stream_data_bidi_local",
            settings.initial_max_stream_data_bidi_local,
        )?;
        let bidi_remote_stream_receive_window = varint(
            "initial_max_stream_data_bidi_remote",
            settings.initial_max_stream_data_bidi_remote,
        )?;
        let uni_stream_receive_window = varint(
            "initial_max_stream_data_uni",
            settings.initial_max_stream_data_uni,
        )?;
        let active_connection_id_limit = u8::try_from(settings.active_connection_id_limit)
            .map_err(|_| {
                profile_error(
                    "active_connection_id_limit",
                    "value cannot be represented by Quinn",
                )
            })?;
        let versions = self.runtime_versions();
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
        // Oldest first, so the version a connection starts in leads the list.
        let supported = versions
            .iter()
            .rev()
            .map(|version| version.wire())
            .collect();
        let compatible = versions
            .iter()
            .filter(|version| **version != QuicVersion::V1)
            .map(|version| version.wire())
            .collect();
        endpoint
            .cid_generator(move || Box::new(RandomConnectionIdGenerator::new(cid_len)))
            .grease_quic_bit(false)
            .supported_versions(supported)
            .compatible_versions(compatible);
        transport
            .max_idle_timeout(idle_timeout)
            .receive_window(receive_window)
            .stream_receive_window(stream_receive_window)
            .bidi_remote_stream_receive_window(Some(bidi_remote_stream_receive_window))
            .uni_stream_receive_window(Some(uni_stream_receive_window))
            .max_concurrent_bidi_streams(max_bidi_streams)
            .max_concurrent_uni_streams(max_uni_streams)
            .reset_stream_at(settings.reset_stream_at)
            .ack_frequency_draft(self.ack_frequency_draft());
        transport
            .max_ack_delay(Duration::from_millis(settings.max_ack_delay_ms))
            .map_err(|error| profile_error("max_ack_delay_ms", error.to_string()))?;
        transport
            .active_connection_id_limit(Some(active_connection_id_limit))
            .map_err(|error| profile_error("active_connection_id_limit", error.to_string()))?;
        transport
            .advertised_datagram_frame_size(datagram_buffer_size, datagram_frame_size)
            .map_err(|error| profile_error("max_datagram_frame_size", error.to_string()))?;
        Ok(())
    }

    /// Returns the generator of a client's first Destination Connection ID, when the
    /// profile sets its length.
    pub(crate) fn initial_destination_connection_id(
        &self,
    ) -> Option<Arc<dyn Fn() -> ConnectionId + Send + Sync>> {
        let policy = self.settings.initial_destination_connection_id?;
        Some(Arc::new(move || {
            let length = match policy {
                QuicConnectionIdLength::Fixed(length) => length,
                QuicConnectionIdLength::MaskedRandom { minimum, base } => {
                    // One random byte from Quinn's generator drives the length.
                    let byte = RandomConnectionIdGenerator::new(1).generate_cid()[0];
                    minimum.max(base + (byte & (byte >> 4)))
                }
                _ => 20,
            };
            RandomConnectionIdGenerator::new(usize::from(length)).generate_cid()
        }))
    }

    /// Whether `version_information` lists `version` as available.
    pub(crate) fn lists_version(&self, version: QuicVersion) -> bool {
        self.runtime_versions().contains(&version)
    }

    /// Versions listed in `version_information`, most preferred first.
    fn runtime_versions(&self) -> &'static [QuicVersion] {
        let count = self
            .settings
            .wire_parameters
            .iter()
            .find_map(|parameter| match &parameter.kind {
                QuicTransportParameterKind::VersionInformation(settings) => {
                    Some(usize::from(settings.available_version_count))
                }
                _ => None,
            })
            .unwrap_or(1)
            .clamp(1, RUNTIME_VERSIONS.len());
        &RUNTIME_VERSIONS[RUNTIME_VERSIONS.len() - count..]
    }

    fn ack_frequency_draft(&self) -> AckFrequencyDraft {
        self.settings
            .wire_parameters
            .iter()
            .find_map(|parameter| match &parameter.kind {
                QuicTransportParameterKind::MinAckDelay {
                    draft: QuicAckFrequencyDraft::Draft02,
                    ..
                } => Some(AckFrequencyDraft::Draft02),
                _ => None,
            })
            .unwrap_or(AckFrequencyDraft::Draft07)
    }

    /// Applies the profile's initial path MTU for a peer at `remote`.
    ///
    /// The UDP payload of Initial datagrams is the MTU less the IP and UDP
    /// headers of `remote`'s address family, as neqo's PMTUD computes it
    /// (`neqo-transport/src/pmtud.rs`).
    pub(crate) fn configure_path(
        &self,
        transport: &mut TransportConfig,
        remote: IpAddr,
    ) -> Result<(), QuicTransportProfileError> {
        let Some(mtu) = self.settings.initial_path_mtu else {
            return Ok(());
        };
        let headers = match remote {
            IpAddr::V4(_) => IPV4_UDP_HEADERS,
            IpAddr::V6(_) => IPV6_UDP_HEADERS,
        };
        let size = mtu.checked_sub(headers).ok_or_else(|| {
            profile_error(
                "initial_path_mtu",
                "the path MTU is smaller than the headers",
            )
        })?;
        transport.initial_mtu(size);
        transport
            .min_initial_datagram_size(size)
            .map_err(|error| profile_error("initial_path_mtu", error.to_string()))?;
        Ok(())
    }

    /// Whether a connection that resumes a session offers early data.
    pub(crate) const fn early_data(&self) -> bool {
        self.settings.early_data
    }

    pub(crate) fn receives_datagrams(&self) -> bool {
        self.settings
            .max_datagram_frame_size
            .is_some_and(|size| size > 0)
    }

    fn validate_provider_support(&self) -> Result<(), QuicTransportProfileError> {
        use QuicTransportParameterKind as Kind;

        if self
            .settings
            .min_ack_delay_us
            .is_some_and(|value| value != RUNTIME_MIN_ACK_DELAY_US)
        {
            return Err(profile_error(
                "min_ack_delay_us",
                "the runtime can only advertise 1000 microseconds",
            ));
        }
        if let Some(policy) = self.settings.initial_destination_connection_id {
            match policy {
                QuicConnectionIdLength::Fixed(_) | QuicConnectionIdLength::MaskedRandom { .. } => {}
                _ => {
                    return Err(profile_error(
                        "initial_destination_connection_id",
                        "provider does not support this length policy",
                    ));
                }
            }
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
                    if usize::from(settings.available_version_count) > RUNTIME_VERSIONS.len() {
                        return Err(profile_error(
                            "version_information",
                            "provider implements QUIC v1 and v2 only",
                        ));
                    }
                    match settings.grease {
                        QuicVersionGrease::Omit
                        | QuicVersionGrease::Permuted
                        | QuicVersionGrease::First => {}
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
                | Kind::MaxAckDelay { .. }
                | Kind::ActiveConnectionIdLimit { .. }
                | Kind::InitialSourceConnectionId { .. }
                | Kind::MaxDatagramFrameSize { .. }
                | Kind::ResetStreamAt
                | Kind::InitialRtt
                | Kind::Grease(_) => {}
                Kind::MinAckDelay { draft, .. } => match draft {
                    QuicAckFrequencyDraft::Draft02 | QuicAckFrequencyDraft::Draft07 => {}
                    _ => {
                        return Err(profile_error(
                            "min_ack_delay_us",
                            "provider does not support this ACK frequency draft",
                        ));
                    }
                },
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

    /// Encodes the profile's parameters for one connection.
    ///
    /// `initial_rtt` is the round-trip time to send as `initial_rtt_us`; the
    /// caller passes it only for a connection that resumes a session. Without
    /// it, or when it rounds to zero microseconds, the parameter is omitted
    /// and the others are ordered as on a fresh connection.
    pub(crate) fn encode(
        &self,
        params: &TransportParameters,
        version: QuicVersion,
        initial_rtt: Option<Duration>,
    ) -> Result<Vec<u8>, QuicTransportProfileError> {
        let mut entropy = WireEntropy::random()?;
        self.encode_with_entropy(params, version, initial_rtt, &mut entropy)
    }

    fn encode_with_entropy(
        &self,
        params: &TransportParameters,
        version: QuicVersion,
        initial_rtt: Option<Duration>,
        entropy: &mut WireEntropy,
    ) -> Result<Vec<u8>, QuicTransportProfileError> {
        let stock = ParsedTransportParameters::new(params)?;
        self.validate_stock(&stock)?;
        let initial_rtt_us = initial_rtt
            .map(|rtt| u64::try_from(rtt.as_micros()).map_or(MAX_VARINT, |us| us.min(MAX_VARINT)))
            .filter(|us| *us > 0);

        let mut order: Vec<usize> = (0..self.settings.wire_parameters.len())
            .filter(|index| {
                initial_rtt_us.is_some()
                    || self.settings.wire_parameters[*index].kind
                        != QuicTransportParameterKind::InitialRtt
            })
            .collect();
        if matches!(
            self.settings.parameter_order,
            QuicTransportParameterOrder::Permuted
        ) {
            entropy.shuffle(&mut order)?;
        }

        let mut output = Vec::new();
        for index in order {
            let parameter = &self.settings.wire_parameters[index];
            let (identifier, value) =
                self.parameter_value(parameter, &stock, version, initial_rtt_us, entropy)?;
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
            if parameter.kind == QuicTransportParameterKind::ResetStreamAt {
                if !stock.value(RESET_STREAM_AT)?.is_empty() {
                    return Err(profile_error(
                        "reset_stream_at",
                        "Quinn encoded a malformed reset_stream_at parameter",
                    ));
                }
                expected.insert(RESET_STREAM_AT);
                continue;
            }
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
                || identifier == VERSION_INFORMATION
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
            Kind::MaxAckDelay { .. } => Some((0x0b, self.settings.max_ack_delay_ms)),
            Kind::ActiveConnectionIdLimit { .. } => {
                Some((0x0e, self.settings.active_connection_id_limit))
            }
            Kind::MinAckDelay { draft, .. } => Some((
                min_ack_delay_identifier(*draft)?,
                self.settings.min_ack_delay_us.ok_or_else(|| {
                    profile_error("min_ack_delay_us", "wire parameter has no semantic value")
                })?,
            )),
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
            Kind::VersionInformation(_)
            | Kind::ResetStreamAt
            | Kind::GoogleConnectionOptions(_)
            | Kind::InitialRtt
            | Kind::Grease(_) => None,
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
        initial_rtt_us: Option<u64>,
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
            Kind::MaxAckDelay { value_width } => {
                encoded_scalar(0x0b, self.settings.max_ack_delay_ms, *value_width)
            }
            Kind::ActiveConnectionIdLimit { value_width } => {
                encoded_scalar(0x0e, self.settings.active_connection_id_limit, *value_width)
            }
            Kind::ResetStreamAt => Ok((RESET_STREAM_AT, Vec::new())),
            Kind::MinAckDelay { draft, value_width } => encoded_scalar(
                min_ack_delay_identifier(*draft)?,
                self.settings.min_ack_delay_us.ok_or_else(|| {
                    profile_error("min_ack_delay_us", "wire parameter has no semantic value")
                })?,
                *value_width,
            ),
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
            Kind::InitialRtt => {
                let value = initial_rtt_us.ok_or_else(|| {
                    profile_error("initial_rtt", "no round-trip time to advertise")
                })?;
                encoded_scalar(0x3127, value, minimal_width(value))
            }
            Kind::Grease(grease) => {
                let identifier = entropy.reserved_transport_parameter_id(parameter.id_width)?;
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
        let count = usize::from(available_version_count);
        if count == 0 || count > RUNTIME_VERSIONS.len() {
            return Err(profile_error(
                "version_information",
                "provider implements QUIC v1 and v2 only",
            ));
        }
        let listed = &RUNTIME_VERSIONS[RUNTIME_VERSIONS.len() - count..];
        if !listed.contains(&version) {
            return Err(profile_error(
                "version_information",
                "the chosen version is not listed as available",
            ));
        }
        let mut available: Vec<u32> = listed.iter().map(|version| version.wire()).collect();
        let reserved = |entropy: &mut WireEntropy| -> Result<u32, QuicTransportProfileError> {
            let raw = u32::from_be_bytes(entropy.take_array()?);
            Ok((raw & 0xf0f0_f0f0) | 0x0a0a_0a0a)
        };
        match grease {
            QuicVersionGrease::Omit => {}
            QuicVersionGrease::Permuted => {
                available.push(reserved(entropy)?);
                entropy.shuffle(&mut available)?;
            }
            QuicVersionGrease::First => available.insert(0, reserved(entropy)?),
            _ => {
                return Err(profile_error(
                    "version_information",
                    "provider does not support this version GREASE policy",
                ));
            }
        }

        let chosen = version.wire();
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

fn min_ack_delay_identifier(
    draft: QuicAckFrequencyDraft,
) -> Result<u64, QuicTransportProfileError> {
    match draft {
        QuicAckFrequencyDraft::Draft02 => Ok(0xff02_de1a),
        QuicAckFrequencyDraft::Draft07 => Ok(MIN_ACK_DELAY_DRAFT_07),
        _ => Err(profile_error(
            "min_ack_delay_us",
            "provider does not support this ACK frequency draft",
        )),
    }
}

/// Returns the shortest QUIC varint width that holds `value`.
fn minimal_width(value: u64) -> QuicVarIntWidth {
    [
        QuicVarIntWidth::One,
        QuicVarIntWidth::Two,
        QuicVarIntWidth::Four,
    ]
    .into_iter()
    .find(|width| width.can_encode(value))
    .unwrap_or(QuicVarIntWidth::Eight)
}

/// Reads `initial_max_streams_bidi` (RFC 9000, section 18.2) from a peer's
/// encoded transport parameters: the number of bidirectional streams the
/// peer lets this endpoint open before it sends `MAX_STREAMS`. An absent
/// parameter is 0; a malformed encoding returns `None`.
pub(crate) fn initial_max_streams_bidi(encoded: &[u8]) -> Option<u64> {
    let parsed = ParsedTransportParameters::from_encoded(encoded).ok()?;
    if !parsed.values.contains_key(&INITIAL_MAX_STREAMS_BIDI) {
        return Some(0);
    }
    parsed.scalar(INITIAL_MAX_STREAMS_BIDI).ok()
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
        0x0b => "max_ack_delay_ms",
        0x0e => "active_connection_id_limit",
        0x0f => "initial_source_connection_id",
        0x1d => "reset_stream_at",
        0xff02_de1a | MIN_ACK_DELAY_DRAFT_07 => "min_ack_delay_us",
        0x20 => "max_datagram_frame_size",
        0x3127 => "initial_rtt",
        _ => "wire_parameters",
    }
}

fn profile_error(field: &'static str, message: impl Into<Box<str>>) -> QuicTransportProfileError {
    QuicTransportProfileError {
        kind: QuicTransportProfileErrorKind::InvalidProfile,
        field,
        message: message.into(),
    }
}

fn entropy_error(message: impl Into<Box<str>>) -> QuicTransportProfileError {
    QuicTransportProfileError {
        kind: QuicTransportProfileErrorKind::EntropyFailure,
        field: "entropy",
        message: message.into(),
    }
}

/// Category of a QUIC transport profile failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicTransportProfileErrorKind {
    /// A setting is invalid or cannot be represented by the transport.
    InvalidProfile,
    /// Required randomness could not be generated or consumed.
    EntropyFailure,
}

/// Failure while applying or encoding a QUIC transport profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportProfileError {
    kind: QuicTransportProfileErrorKind,
    field: &'static str,
    message: Box<str>,
}

impl QuicTransportProfileError {
    /// Returns the broad failure category without matching a field name.
    #[must_use]
    pub const fn kind(&self) -> QuicTransportProfileErrorKind {
        self.kind
    }

    /// Returns the profile field responsible for the failure.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    pub(crate) fn is_entropy_failure(&self) -> bool {
        self.kind == QuicTransportProfileErrorKind::EntropyFailure
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
