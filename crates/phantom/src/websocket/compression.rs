use tokio_tungstenite::tungstenite::protocol::{
    PerMessageDeflateConfig as EngineNegotiated,
    PerMessageDeflateOfferParameter as EngineOfferParameter, Role, WebSocketConfig,
};

use super::WebSocketError;

/// One parameter in an ordered RFC 7692 client offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerMessageDeflateOfferParameter {
    /// Requires the server to reset its encoder between messages.
    ServerNoContextTakeover,
    /// Announces that the client resets its encoder between messages.
    ClientNoContextTakeover,
    /// Limits the server encoder to the supplied 8–15-bit window.
    ServerMaxWindowBits(u8),
    /// Offers client-window negotiation, optionally with an 8–15-bit hint.
    ClientMaxWindowBits(Option<u8>),
}

impl PerMessageDeflateOfferParameter {
    const fn kind(self) -> u8 {
        match self {
            Self::ServerNoContextTakeover => 0,
            Self::ClientNoContextTakeover => 1,
            Self::ServerMaxWindowBits(_) => 2,
            Self::ClientMaxWindowBits(_) => 3,
        }
    }

    const fn engine(self) -> EngineOfferParameter {
        match self {
            Self::ServerNoContextTakeover => EngineOfferParameter::ServerNoContextTakeover,
            Self::ClientNoContextTakeover => EngineOfferParameter::ClientNoContextTakeover,
            Self::ServerMaxWindowBits(bits) => EngineOfferParameter::ServerMaxWindowBits(bits),
            Self::ClientMaxWindowBits(bits) => EngineOfferParameter::ClientMaxWindowBits(bits),
        }
    }
}

/// Client policy for the RFC 7692 `permessage-deflate` extension.
///
/// The default offer is `permessage-deflate; client_max_window_bits`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerMessageDeflate {
    offer_parameters: Vec<PerMessageDeflateOfferParameter>,
    client_max_window_bits: u8,
    compression_level: u8,
}

impl PerMessageDeflate {
    /// Creates the default client policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            offer_parameters: vec![PerMessageDeflateOfferParameter::ClientMaxWindowBits(None)],
            client_max_window_bits: 15,
            compression_level: 6,
        }
    }

    /// Replaces the complete ordered parameter sequence in the offer.
    ///
    /// An empty sequence emits only `permessage-deflate`. Each parameter may
    /// occur once, and window widths must be between 8 and 15.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] for a duplicate parameter, too many
    /// parameters, or an invalid window width.
    pub fn offer_parameters(
        mut self,
        parameters: impl IntoIterator<Item = PerMessageDeflateOfferParameter>,
    ) -> Result<Self, WebSocketError> {
        let parameters = parameters.into_iter().collect::<Vec<_>>();
        validate_offer_parameters(&parameters)?;
        self.offer_parameters = parameters;
        Ok(self)
    }

    /// Returns the ordered parameters emitted after `permessage-deflate`.
    #[must_use]
    pub fn parameters(&self) -> &[PerMessageDeflateOfferParameter] {
        &self.offer_parameters
    }

    /// Requires the server to reset its compression context after each message.
    #[must_use]
    pub fn server_no_context_takeover(mut self, enabled: bool) -> Self {
        self.set_parameter(
            PerMessageDeflateOfferParameter::ServerNoContextTakeover,
            enabled,
        );
        self
    }

    /// Offers client-side context reset after each message.
    #[must_use]
    pub fn client_no_context_takeover(mut self, enabled: bool) -> Self {
        self.set_parameter(
            PerMessageDeflateOfferParameter::ClientNoContextTakeover,
            enabled,
        );
        self
    }

    /// Sets the maximum server encoder window, from 8 through 15 bits.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] when `bits` is outside the RFC 7692 range.
    pub fn server_max_window_bits(mut self, bits: u8) -> Result<Self, WebSocketError> {
        validate_window_bits(bits)?;
        self.set_parameter(
            PerMessageDeflateOfferParameter::ServerMaxWindowBits(bits),
            true,
        );
        Ok(self)
    }

    /// Sets the local client encoder cap, from 8 through 15 bits.
    ///
    /// The default bare offer parameter remains unchanged. Use
    /// [`Self::offer_parameters`] to attach a value to the wire offer.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] when `bits` is outside the RFC 7692 range.
    pub fn client_max_window_bits(mut self, bits: u8) -> Result<Self, WebSocketError> {
        validate_window_bits(bits)?;
        self.client_max_window_bits = bits;
        Ok(self)
    }

    /// Sets the DEFLATE compression level from 0 through 9.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] when `level` is outside the codec range.
    pub fn compression_level(mut self, level: u8) -> Result<Self, WebSocketError> {
        if level > 9 {
            return Err(WebSocketError::invalid_request(
                "WebSocket compression level must be between 0 and 9",
            ));
        }
        self.compression_level = level;
        Ok(self)
    }

    pub(super) fn apply(self, config: WebSocketConfig) -> Result<WebSocketConfig, WebSocketError> {
        let parameters = self
            .offer_parameters
            .iter()
            .copied()
            .map(PerMessageDeflateOfferParameter::engine)
            .collect::<Vec<_>>();
        config
            .enable_deflate()
            .deflate_max_window_bits(Role::Client, self.client_max_window_bits)
            .deflate_compression_level(u32::from(self.compression_level))
            .deflate_offer_parameters(&parameters)
            .map_err(|_| WebSocketError::invalid_request("invalid permessage-deflate offer"))
    }

    fn set_parameter(&mut self, parameter: PerMessageDeflateOfferParameter, enabled: bool) {
        let kind = parameter.kind();
        if let Some(index) = self
            .offer_parameters
            .iter()
            .position(|candidate| candidate.kind() == kind)
        {
            if enabled {
                self.offer_parameters[index] = parameter;
            } else {
                self.offer_parameters.remove(index);
            }
            return;
        }
        if enabled {
            let index = self
                .offer_parameters
                .iter()
                .position(|candidate| candidate.kind() > kind)
                .unwrap_or(self.offer_parameters.len());
            self.offer_parameters.insert(index, parameter);
        }
    }
}

impl Default for PerMessageDeflate {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_window_bits(bits: u8) -> Result<(), WebSocketError> {
    if !(8..=15).contains(&bits) {
        return Err(WebSocketError::invalid_request(
            "WebSocket compression window must be between 8 and 15 bits",
        ));
    }
    Ok(())
}

fn validate_offer_parameters(
    parameters: &[PerMessageDeflateOfferParameter],
) -> Result<(), WebSocketError> {
    if parameters.len() > 4 {
        return Err(WebSocketError::invalid_request(
            "permessage-deflate accepts at most four offer parameters",
        ));
    }
    let mut seen = 0_u8;
    for parameter in parameters {
        let bit = 1 << parameter.kind();
        if seen & bit != 0 {
            return Err(WebSocketError::invalid_request(
                "permessage-deflate offer parameters must be unique",
            ));
        }
        seen |= bit;
        match parameter {
            PerMessageDeflateOfferParameter::ServerMaxWindowBits(bits)
            | PerMessageDeflateOfferParameter::ClientMaxWindowBits(Some(bits)) => {
                validate_window_bits(*bits)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Effective `permessage-deflate` settings selected by the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedPerMessageDeflate {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

impl NegotiatedPerMessageDeflate {
    pub(super) fn from_engine(config: EngineNegotiated) -> Self {
        Self {
            server_no_context_takeover: config.server_no_context_takeover(),
            client_no_context_takeover: config.client_no_context_takeover(),
            server_max_window_bits: config.server_max_window_bits(),
            client_max_window_bits: config.client_max_window_bits(),
        }
    }

    /// Whether the server resets its compression context after each message.
    #[must_use]
    pub const fn server_no_context_takeover(self) -> bool {
        self.server_no_context_takeover
    }

    /// Whether the client resets its compression context after each message.
    #[must_use]
    pub const fn client_no_context_takeover(self) -> bool {
        self.client_no_context_takeover
    }

    /// Returns the server encoder's negotiated window width.
    #[must_use]
    pub const fn server_max_window_bits(self) -> u8 {
        self.server_max_window_bits
    }

    /// Returns the client encoder's negotiated window width.
    #[must_use]
    pub const fn client_max_window_bits(self) -> u8 {
        self.client_max_window_bits
    }
}

#[cfg(test)]
mod tests {
    use super::{PerMessageDeflate, PerMessageDeflateOfferParameter};
    use crate::WebSocketErrorKind;

    #[test]
    fn validates_public_codec_ranges_without_panicking() {
        for bits in [8, 15] {
            assert!(
                PerMessageDeflate::new()
                    .server_max_window_bits(bits)
                    .is_ok()
            );
            assert!(
                PerMessageDeflate::new()
                    .client_max_window_bits(bits)
                    .is_ok()
            );
        }
        for bits in [0, 7, 16, u8::MAX] {
            let result = PerMessageDeflate::new().client_max_window_bits(bits);
            assert_eq!(
                result.as_ref().err().map(crate::WebSocketError::kind),
                Some(WebSocketErrorKind::InvalidRequest)
            );
        }
        let result = PerMessageDeflate::new().compression_level(10);
        assert_eq!(
            result.as_ref().err().map(crate::WebSocketError::kind),
            Some(WebSocketErrorKind::InvalidRequest)
        );
    }

    #[test]
    fn validates_ordered_offer_parameters() -> Result<(), crate::WebSocketError> {
        use PerMessageDeflateOfferParameter::{
            ClientMaxWindowBits, ClientNoContextTakeover, ServerMaxWindowBits,
        };

        let policy = PerMessageDeflate::new().offer_parameters([
            ClientMaxWindowBits(Some(10)),
            ServerMaxWindowBits(12),
            ClientNoContextTakeover,
        ])?;
        assert_eq!(
            policy.parameters(),
            &[
                ClientMaxWindowBits(Some(10)),
                ServerMaxWindowBits(12),
                ClientNoContextTakeover,
            ]
        );

        let duplicate = PerMessageDeflate::new()
            .offer_parameters([ClientMaxWindowBits(None), ClientMaxWindowBits(Some(10))]);
        assert_eq!(
            duplicate.as_ref().err().map(crate::WebSocketError::kind),
            Some(WebSocketErrorKind::InvalidRequest)
        );
        Ok(())
    }
}
