//! Synchronous parsed identities, independent of HTTP operations and buffers.

use crate::{error::Failure, operations::MAX_UPLOAD, prepared_body::Span};
use phantom::{ClientCertificate, ClientCertificateError, ClientCertificateErrorKind};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Format {
    Pem,
    Der,
}

#[derive(Default)]
struct Registry {
    last: u64,
    owners: HashMap<u64, ClientCertificate>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

pub(super) fn failure(error: &ClientCertificateError) -> Failure {
    Failure::new(match error.kind() {
        ClientCertificateErrorKind::Certificate => "client_certificate_certificate",
        ClientCertificateErrorKind::PrivateKey => "client_certificate_private_key",
        ClientCertificateErrorKind::KeyMismatch => "client_certificate_key_mismatch",
        ClientCertificateErrorKind::SignatureScheme => "client_certificate_signature_scheme",
        _ => "client_certificate_unsupported_error",
    })
}

pub(super) fn parse(
    format: Format,
    chain: Vec<Span>,
    key: Span,
    input: &[u8],
) -> Result<Value, Failure> {
    if input.len() > MAX_UPLOAD {
        return Err(Failure::new("input_limit"));
    }
    if chain.is_empty() || chain.len() > 256 || (matches!(format, Format::Pem) && chain.len() != 1)
    {
        return Err(Failure::new("client_certificate_invalid_chain_count"));
    }
    let bytes = |span: &Span| {
        span.bytes(input)
            .map_err(|_| Failure::new("client_certificate_invalid_span"))
    };
    // Also bound overlapping spans before the parsers allocate native objects.
    let mut total = bytes(&key)?.len();
    for item in &chain {
        total = total.saturating_add(bytes(item)?.len());
        if total > MAX_UPLOAD {
            return Err(Failure::new("input_limit"));
        }
    }
    let key = bytes(&key)?;
    let owner = match format {
        Format::Pem => ClientCertificate::from_pem(bytes(&chain[0])?, key),
        Format::Der => {
            let chain = chain
                .iter()
                .map(bytes)
                .collect::<Result<Vec<_>, Failure>>()?;
            ClientCertificate::from_der(chain, key)
        }
    }
    .map_err(|error| failure(&error))?;
    let mut state = registry().lock().map_err(|_| Failure::new("internal"))?;
    if state.owners.len() >= 64 {
        return Err(Failure::new("capacity"));
    }
    let id = state
        .last
        .checked_add(1)
        .ok_or_else(|| Failure::new("capacity"))?;
    state
        .owners
        .try_reserve(1)
        .map_err(|_| Failure::new("client_certificate_allocation"))?;
    state.owners.insert(id, owner);
    state.last = id;
    Ok(json!({"id":id}))
}

pub(super) fn get(id: u64) -> Result<ClientCertificate, Failure> {
    registry()
        .lock()
        .map_err(|_| Failure::new("internal"))?
        .owners
        .get(&id)
        .cloned()
        .ok_or_else(|| Failure::new("client_certificate_closed"))
}

pub(super) fn release(id: u64) -> Result<Value, Failure> {
    registry()
        .lock()
        .map_err(|_| Failure::new("internal"))?
        .owners
        .remove(&id);
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(lengths: &[usize]) -> Result<Vec<Span>, serde_json::Error> {
        let mut offset = 0;
        let value: Vec<_> = lengths
            .iter()
            .map(|length| {
                let value = json!({"offset":offset,"length":length});
                offset += length;
                value
            })
            .collect();
        serde_json::from_value(json!(value))
    }

    #[test]
    fn real_identity_outlives_release_and_direct_inputs_stay_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let pem = include_bytes!("../../../python/tests/fixtures/certificate.pem");
        let key_pem = include_bytes!("../../../python/tests/fixtures/key.pem");
        let input = [pem.as_slice(), key_pem.as_slice()].concat();
        let fields = spans(&[pem.len(), key_pem.len()])?;
        let mut fields = fields.into_iter();
        let cert = fields.next().ok_or("certificate span missing")?;
        let key = fields.next().ok_or("key span missing")?;
        let reply = parse(Format::Pem, vec![cert], key, &input).map_err(|_| "parse failed")?;
        let id = reply["id"].as_u64().ok_or("id missing")?;
        let owner = get(id).map_err(|_| "owner missing")?;
        release(id).map_err(|_| "release failed")?;
        assert!(get(id).is_err());
        assert!(owner.certificate_chain_sha256().is_ok());
        release(id).map_err(|_| "second release failed")?;
        let empty: Span = serde_json::from_value(json!({"offset":0,"length":0}))?;
        assert!(parse(Format::Der, vec![], empty, &[]).is_err());
        let invalid: Span = serde_json::from_value(json!({"offset":usize::MAX,"length":1}))?;
        let key: Span = serde_json::from_value(json!({"offset":0,"length":0}))?;
        assert_eq!(
            parse(Format::Pem, vec![invalid], key, &[])
                .err()
                .ok_or("missing error")?
                .kind,
            "client_certificate_invalid_span"
        );
        let key: Span = serde_json::from_value(json!({"offset":0,"length":0}))?;
        assert!(parse(Format::Der, spans(&[0; 257])?, key, &[]).is_err());
        for (chain, key, kind) in [
            (
                b"private input".as_slice(),
                key_pem.as_slice(),
                "client_certificate_certificate",
            ),
            (
                pem.as_slice(),
                b"private input".as_slice(),
                "client_certificate_private_key",
            ),
        ] {
            let cause = ClientCertificate::from_pem(chain, key)
                .err()
                .ok_or("expected parse failure")?;
            assert_eq!(failure(&cause).kind, kind);
            assert!(!format!("{:?}", failure(&cause)).contains("private input"));
        }
        Ok(())
    }
}
