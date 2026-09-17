use flate2::Compression;
use http::{HeaderMap, HeaderValue};

use crate::{
    error::{Error, ProtocolError, Result},
    protocol::{PerMessageDeflateOfferParameter, Role},
};

mod codec;
mod negotiate;
#[cfg(test)]
mod tests;

pub(crate) use self::{codec::Context, negotiate::headers_select_deflate};

const NAME: &str = "permessage-deflate";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Offer {
    parameters: [Option<PerMessageDeflateOfferParameter>; 4],
}

impl Default for Offer {
    fn default() -> Self {
        Self {
            parameters: [
                Some(PerMessageDeflateOfferParameter::ClientMaxWindowBits(None)),
                None,
                None,
                None,
            ],
        }
    }
}

impl Offer {
    fn new(parameters: &[PerMessageDeflateOfferParameter]) -> Result<Self> {
        if parameters.len() > 4 {
            return Err(invalid_offer());
        }
        let mut offer = Self {
            parameters: [None; 4],
        };
        let mut seen = 0_u8;
        for (slot, parameter) in offer.parameters.iter_mut().zip(parameters.iter().copied()) {
            let (bit, window) = match parameter {
                PerMessageDeflateOfferParameter::ServerNoContextTakeover => (1, None),
                PerMessageDeflateOfferParameter::ClientNoContextTakeover => (2, None),
                PerMessageDeflateOfferParameter::ServerMaxWindowBits(bits) => (4, Some(bits)),
                PerMessageDeflateOfferParameter::ClientMaxWindowBits(bits) => (8, bits),
            };
            if seen & bit != 0 || window.is_some_and(|bits| !(8..=15).contains(&bits)) {
                return Err(invalid_offer());
            }
            seen |= bit;
            *slot = Some(parameter);
        }
        Ok(offer)
    }

    pub(crate) fn parameters(self) -> impl Iterator<Item = PerMessageDeflateOfferParameter> {
        self.parameters.into_iter().flatten()
    }

    pub(crate) fn server_no_context_takeover(self) -> bool {
        self.parameters()
            .any(|parameter| parameter == PerMessageDeflateOfferParameter::ServerNoContextTakeover)
    }

    pub(crate) fn client_no_context_takeover(self) -> bool {
        self.parameters()
            .any(|parameter| parameter == PerMessageDeflateOfferParameter::ClientNoContextTakeover)
    }

    pub(crate) fn server_max_window_bits(self) -> Option<u8> {
        self.parameters().find_map(|parameter| match parameter {
            PerMessageDeflateOfferParameter::ServerMaxWindowBits(bits) => Some(bits),
            _ => None,
        })
    }

    pub(crate) fn client_max_window_bits(self) -> Option<Option<u8>> {
        self.parameters().find_map(|parameter| match parameter {
            PerMessageDeflateOfferParameter::ClientMaxWindowBits(bits) => Some(bits),
            _ => None,
        })
    }

    fn set(&mut self, parameter: PerMessageDeflateOfferParameter, enabled: bool) {
        let kind = parameter_kind(parameter);
        if let Some(index) = self
            .parameters
            .iter()
            .position(|candidate| candidate.is_some_and(|value| parameter_kind(value) == kind))
        {
            if enabled {
                self.parameters[index] = Some(parameter);
            } else {
                self.parameters.copy_within(index + 1.., index);
                self.parameters[3] = None;
            }
            return;
        }
        if !enabled {
            return;
        }
        let index = self
            .parameters()
            .position(|candidate| parameter_kind(candidate) > kind)
            .unwrap_or_else(|| self.parameters().count());
        self.parameters.copy_within(index..3, index + 1);
        self.parameters[index] = Some(parameter);
    }
}

fn parameter_kind(parameter: PerMessageDeflateOfferParameter) -> u8 {
    match parameter {
        PerMessageDeflateOfferParameter::ServerNoContextTakeover => 0,
        PerMessageDeflateOfferParameter::ClientNoContextTakeover => 1,
        PerMessageDeflateOfferParameter::ServerMaxWindowBits(_) => 2,
        PerMessageDeflateOfferParameter::ClientMaxWindowBits(_) => 3,
    }
}

fn invalid_offer() -> Error {
    ProtocolError::InvalidHeader(http::header::SEC_WEBSOCKET_EXTENSIONS.clone().into()).into()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Settings {
    pub(crate) compression: Compression,
    pub(crate) server_no_context_takeover: bool,
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_max_window_bits: u8,
    pub(crate) client_max_window_bits: u8,
    pub(crate) offer: Offer,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            compression: Compression::default(),
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
            offer: Offer::default(),
        }
    }
}

impl Settings {
    pub(crate) fn max_window_bits(mut self, role: Role, bits: u8) -> Self {
        assert!(
            (8..=15).contains(&bits),
            "deflate window bits must be in 8..=15"
        );
        *match role {
            Role::Server => &mut self.server_max_window_bits,
            Role::Client => &mut self.client_max_window_bits,
        } = bits;
        if role == Role::Server {
            self.offer.set(
                PerMessageDeflateOfferParameter::ServerMaxWindowBits(bits),
                bits < 15,
            );
        }
        self
    }

    pub(crate) fn no_context_takeover(mut self, role: Role, on: bool) -> Self {
        *match role {
            Role::Server => &mut self.server_no_context_takeover,
            Role::Client => &mut self.client_no_context_takeover,
        } = on;
        let parameter = match role {
            Role::Server => PerMessageDeflateOfferParameter::ServerNoContextTakeover,
            Role::Client => PerMessageDeflateOfferParameter::ClientNoContextTakeover,
        };
        self.offer.set(parameter, on);
        self
    }

    pub(crate) fn compression_level(mut self, level: u32) -> Self {
        assert!(level <= 9, "deflate compression level must be in 0..=9");
        self.compression = Compression::new(level);
        self
    }

    pub(crate) fn offer_parameters(
        mut self,
        parameters: &[PerMessageDeflateOfferParameter],
    ) -> Result<Self> {
        self.offer = Offer::new(parameters)?;
        self.server_no_context_takeover = self.offer.server_no_context_takeover();
        self.client_no_context_takeover = self.offer.client_no_context_takeover();
        self.server_max_window_bits = self.offer.server_max_window_bits().unwrap_or(15);
        if let Some(Some(bits)) = self.offer.client_max_window_bits() {
            self.client_max_window_bits = self.client_max_window_bits.min(bits);
        }
        Ok(self)
    }

    pub(crate) fn offer(self) -> HeaderValue {
        negotiate::offer(self)
    }

    pub(crate) fn accept_response(self, headers: &HeaderMap) -> Result<Option<Self>> {
        negotiate::accept_response(self, headers)
    }

    pub(crate) fn accept_offers(self, offers: &[HeaderValue]) -> Option<(Self, HeaderValue)> {
        negotiate::accept_offers(self, offers)
    }
}
