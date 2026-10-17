//! http1 settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

record!(Http1Settings, max_connections_per_origin, idle_timeout);

impl Encode for Http1IdleTimeout {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Unlimited => object!(e, f, "kind" => "Unlimited"),
            Self::CheckedOnRequest(duration) => {
                object!(e, f, "kind" => "CheckedOnRequest", "duration" => duration)
            }
            Self::ClosedOnTimer(duration) => {
                object!(e, f, "kind" => "ClosedOnTimer", "duration" => duration)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
