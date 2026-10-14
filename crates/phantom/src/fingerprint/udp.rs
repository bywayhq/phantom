//! Complete UDP description parsing.

use super::{Result, json::Value};
use phantom_profile::UdpSettings;

pub(super) fn parse(v: &Value) -> Result<UdpSettings> {
    v.record(&["port_randomization"], "udp")?;
    let settings = UdpSettings {
        port_randomization: v
            .member("port_randomization", "udp.port_randomization")?
            .boolean("udp.port_randomization")?,
    };
    Ok(settings)
}
