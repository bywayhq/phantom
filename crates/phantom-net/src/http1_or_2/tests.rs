use phantom_profile::chromium::{v154_http2, v154_tls};

use super::{Http1Or2TlsErrorKind, validate_settings};

#[cfg(feature = "https-records")]
mod ech;

#[test]
fn negotiation_requires_both_alpn_protocols() {
    let http2 = v154_http2();

    let mut tls = v154_tls();
    tls.alpn_protocols
        .retain(|protocol| protocol.as_ref() != b"http/1.1");
    let error = match validate_settings(&tls, &http2) {
        Ok(()) => panic!("missing HTTP/1.1 was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http1Or2TlsErrorKind::InvalidConfiguration);

    let mut tls = v154_tls();
    tls.alpn_protocols
        .retain(|protocol| protocol.as_ref() != b"h2");
    let error = match validate_settings(&tls, &http2) {
        Ok(()) => panic!("missing h2 was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http1Or2TlsErrorKind::InvalidConfiguration);
}
