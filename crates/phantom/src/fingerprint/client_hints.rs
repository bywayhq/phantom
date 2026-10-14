//! Complete client hints description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

pub(super) fn parse(v: &Value) -> Result<ClientHintSettings> {
    v.record(&["hints"], "client_hints")?;
    let settings = ClientHintSettings::new(
        v.member("hints", "client_hints.hints")?
            .list("client_hints.hints", hint)?,
    );
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("client_hints", error))?;
    Ok(settings)
}
fn hint(v: &Value) -> Result<ClientHint> {
    v.record(&["name", "value", "delivery"], "client_hints.hints")?;
    let delivery = match v
        .member("delivery", "client_hints.hints.delivery")?
        .text("client_hints.hints.delivery")?
    {
        "Default" => ClientHintDelivery::Default,
        "AcceptCh" => ClientHintDelivery::AcceptCh,
        _ => return Err(json::unsupported("client_hints.hints.delivery")),
    };
    Ok(ClientHint::new(
        v.member("name", "client_hints.hints.name")?
            .text("client_hints.hints.name")?,
        v.member("value", "client_hints.hints.value")?
            .bytes("client_hints.hints.value")?,
        delivery,
    ))
}
