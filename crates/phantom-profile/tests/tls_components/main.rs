//! Independent TLS settings controls retained before component migration.

mod originals;

use phantom_profile::{TlsSettings, browser};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn tcp_and_quic_factories_preserve_every_original_tls_field() -> TestResult {
    for (actual, expected) in [
        (browser::chrome::v154_tcp_tls(), originals::chrome_tcp()?),
        (browser::chrome::v154_quic_tls(), originals::chrome_quic()?),
        (browser::firefox::v157_tcp_tls(), originals::firefox_tcp()?),
        (
            browser::firefox::v157_quic_tls(),
            originals::firefox_quic()?,
        ),
    ] {
        actual.validate()?;
        expected.validate()?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[test]
fn generated_tls_values_keep_runtime_policies_and_fresh_ownership() -> TestResult {
    for (factory, expected) in [
        (
            browser::chrome::v154_tcp_tls as fn() -> TlsSettings,
            originals::chrome_tcp()?,
        ),
        (browser::chrome::v154_quic_tls, originals::chrome_quic()?),
        (browser::firefox::v157_tcp_tls, originals::firefox_tcp()?),
        (browser::firefox::v157_quic_tls, originals::firefox_quic()?),
    ] {
        let mut custom = factory();
        custom.draw_per_client(|| -> Result<u64, Box<dyn std::error::Error>> {
            Err("a fixed core recipe unexpectedly drew a per-client value".into())
        })?;
        assert_eq!(custom, expected);
        custom.cipher_suites.reverse();
        custom.alpn_protocols.clear();
        custom.requested_trust_anchor_ids = None;
        assert_eq!(factory(), expected);
    }
    Ok(())
}
