//! Leaf pin restrictions through the public client and its pooled transports.

use std::{error::Error, time::Duration};

use phantom::{Client, ClientBuilder, RequestError, ServerSpkiPins, profile::ClientProfile};
use phantom_net::{TlsError, TlsErrorKind};

use crate::support::{
    h3 as h3_support,
    tls::{TestIdentity, TestResult, tls_settings},
};

mod masque;
mod proxy;
mod quic;
mod routes;
mod tcp;
mod tickets;

const DEADLINE: Duration = Duration::from_secs(10);

fn pins(identity: &TestIdentity) -> TestResult<ServerSpkiPins> {
    let key = btls::pkey::PKey::private_key_from_pkcs8(identity.private_key_der())?;
    Ok(ServerSpkiPins::new(vec![btls::sha::sha256(
        &key.public_key_to_der()?,
    )])?)
}

fn builder(identity: &TestIdentity) -> ClientBuilder {
    Client::builder(
        ClientProfile::new(tls_settings())
            .with_http2(phantom::profile::browser::chrome::v154_http2())
            .with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
}

fn tls_error(error: &RequestError) -> TestResult<TlsErrorKind> {
    let mut cause: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(error) = cause {
        if let Some(tls) = error.downcast_ref::<TlsError>() {
            return Ok(tls.kind());
        }
        cause = error.source();
    }
    Err(format!("missing typed TLS cause: {error:?}").into())
}
