//! cookie settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for CookiePlacement {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "before" => self.before())
    }
}
