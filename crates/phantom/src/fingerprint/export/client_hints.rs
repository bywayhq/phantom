//! client hints settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for ClientHint {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "name" => self.name(), "value" => self.value(), "delivery" => &self.delivery())
    }
}
impl Encode for ClientHintSettings {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "hints" => self.hints())
    }
}

tokens!(ClientHintDelivery, Default, AcceptCh);
