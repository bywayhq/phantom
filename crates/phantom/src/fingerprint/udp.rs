//! Complete UDP description parsing.

use super::{Result, json::Value};
use phantom_profile::UdpSettings;

pub(super) fn parse(v: &Value) -> Result<UdpSettings> {
    v.record_with_optional(&["port_randomization"], &["option_policy"], "udp")?;
    let settings = UdpSettings {
        option_policy: super::tcp::option_policy(
            v.optional_member("option_policy", "udp.option_policy")?,
            "udp.option_policy",
        )?,
        port_randomization: v
            .member("port_randomization", "udp.port_randomization")?
            .boolean("udp.port_randomization")?,
    };
    Ok(settings)
}
