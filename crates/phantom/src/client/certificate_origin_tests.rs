//! Client certificate origins: how a mapped origin is parsed, and which
//! connectors a request to it gets.

use std::sync::Arc;

use phantom_net::ClientCertificate;
use phantom_profile::{ClientProfile, Http3ClientSettings, browser::chrome};

use super::{Client, certificate_origin};
use crate::{
    BuildErrorKind,
    authority::{Endpoint, parse_absolute_uri},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn certificate() -> TestResult<ClientCertificate> {
    let certified = rcgen::generate_simple_self_signed(Vec::<String>::new())?;
    Ok(ClientCertificate::from_pem(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
    )?)
}

fn profile() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
}

/// The endpoint a request to `uri` has.
fn request_endpoint(uri: &str) -> TestResult<Endpoint> {
    let uri = parse_absolute_uri(uri)?;
    let authority = uri.authority().cloned().ok_or("no authority")?;
    Ok(Endpoint::new(authority, 443)?)
}

#[test]
fn origin_parses_to_the_host_and_port_a_request_has() -> TestResult {
    for (origin, host, port) in [
        ("https://api.example:8443", "api.example", 8443),
        ("https://api.example/", "api.example", 443),
        ("wss://A.Test", "a.test", 443),
        ("https://[::1]:8443", "::1", 8443),
        ("https://127.0.0.1", "127.0.0.1", 443),
        ("https://a.test.", "a.test.", 443),
        ("https://bücher.example", "xn--bcher-kva.example", 443),
    ] {
        let endpoint = certificate_origin(origin)?;
        assert_eq!((endpoint.host(), endpoint.port()), (host, port), "{origin}");
    }
    Ok(())
}

#[test]
fn origin_with_more_than_a_host_and_port_is_an_invalid_policy() {
    for origin in [
        "",
        "api.example",
        "https://",
        "http://api.example",
        "ftp://api.example",
        "https://api.example/path",
        "https://api.example?query",
        "https://api.example#fragment",
        "https://user@api.example",
        "https://api.example:",
        "https://api.example:65536",
        "https://[::1",
        "https://::1",
    ] {
        let kind = certificate_origin(origin).err().map(|error| error.kind());
        assert_eq!(kind, Some(BuildErrorKind::InvalidPolicy), "{origin:?}");
    }
}

#[test]
fn mapped_origin_gets_its_own_connectors_with_the_client_s_early_data_choice() -> TestResult {
    let client = Client::builder(profile())
        .http3_early_data(false)
        .client_certificate_for("https://API.example:8443", certificate()?)
        .build()?;
    let inner = &client.inner;
    let base = inner.http3.as_ref().ok_or("no HTTP/3 connector")?;

    let mapped = inner.connectors_for(&request_endpoint("https://api.EXAMPLE:8443/a")?);
    let mapped_http3 = mapped.http3.ok_or("no mapped HTTP/3 connector")?;
    assert!(!Arc::ptr_eq(mapped_http3, base));
    assert!(!mapped_http3.sends_early_data());
    assert!(mapped.http1.is_some() && mapped.http1_or_2.is_some() && mapped.http2.is_some());

    for unmapped in ["https://api.example/", "https://other.example:8443/"] {
        let connectors = inner.connectors_for(&request_endpoint(unmapped)?);
        let http3 = connectors.http3.ok_or("no HTTP/3 connector")?;
        assert!(Arc::ptr_eq(http3, base), "{unmapped}");
    }
    Ok(())
}

#[test]
fn mapped_connectors_follow_the_profile_s_early_data() -> TestResult {
    // The Chrome 154 QUIC recipe offers early data.
    let client = Client::builder(profile())
        .client_certificate_for("https://api.example", certificate()?)
        .build()?;

    let mapped = client
        .inner
        .connectors_for(&request_endpoint("https://api.example/")?);

    assert!(
        mapped
            .http3
            .is_some_and(|connector| connector.sends_early_data())
    );
    Ok(())
}

#[test]
fn later_mapping_for_a_host_and_port_replaces_the_earlier_one() -> TestResult {
    let client = Client::builder(profile())
        .client_certificate_for("https://api.example", certificate()?)
        .client_certificate_for("wss://API.example:443/", certificate()?)
        .client_certificate_for("https://api.example:8443", certificate()?)
        .build()?;

    assert_eq!(client.inner.certificate_origins.len(), 2);
    Ok(())
}
