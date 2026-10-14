use super::{branded_originals, originals};

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

#[test]
fn branded_and_android_factories_preserve_every_original_tls_field() -> TestResult {
    for (actual, expected) in [
        (
            browser::edge::v154_tcp_tls(),
            branded_originals::edge_tcp()?,
        ),
        (
            browser::edge::v154_quic_tls(),
            branded_originals::edge_quic()?,
        ),
        (
            browser::brave::v154_tcp_tls(),
            branded_originals::brave_tcp()?,
        ),
        (
            browser::brave::v154_quic_tls(),
            branded_originals::brave_quic()?,
        ),
        (
            browser::opera::v136_tcp_tls(),
            branded_originals::opera_tcp()?,
        ),
        (
            browser::opera::v136_quic_tls(),
            branded_originals::opera_quic()?,
        ),
        (
            browser::chrome::v154_android_tcp_tls(),
            branded_originals::chrome_android_tcp()?,
        ),
        (
            browser::chrome::v154_android_quic_tls(),
            branded_originals::chrome_android_quic()?,
        ),
        (
            browser::edge::v153_android_tcp_tls(),
            branded_originals::edge_android_tcp()?,
        ),
        (
            browser::edge::v153_android_quic_tls(),
            branded_originals::edge_android_quic()?,
        ),
        (
            browser::brave::v153_android_tcp_tls(),
            branded_originals::brave_android_tcp()?,
        ),
        (
            browser::brave::v153_android_quic_tls(),
            branded_originals::brave_android_quic()?,
        ),
        (
            browser::firefox::v156_android_tcp_tls(),
            branded_originals::firefox_android_tcp()?,
        ),
        (
            browser::opera::v102_android_tcp_tls(),
            branded_originals::opera_android_tcp()?,
        ),
    ] {
        actual.validate()?;
        expected.validate()?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[test]
fn opera_preserves_weighted_slots_and_the_time_of_each_draw() -> TestResult {
    use phantom_profile::TrustAnchorIds;

    let expected = branded_originals::opera_tcp()?;
    let Some(ids @ TrustAnchorIds::PerClient(orders)) = &expected.requested_trust_anchor_ids else {
        return Err("original Opera TCP policy is not per client".into());
    };
    assert_eq!(orders.as_slice().len(), 29);
    for index in 0..29_u64 {
        let random = u64::try_from((u128::from(index) << 64).div_ceil(29))?;
        let mut actual = browser::opera::v136_tcp_tls();
        let mut draws = 0;
        actual.draw_per_client(|| -> TestResultU64 {
            draws += 1;
            Ok(random)
        })?;
        assert_eq!(draws, 1);
        assert_eq!(
            actual.requested_trust_anchor_ids,
            ids.select(random).cloned().map(TrustAnchorIds::Fixed)
        );
        actual
            .draw_per_client(|| -> TestResultU64 { Err("a resolved client drew again".into()) })?;
        assert_eq!(browser::opera::v136_tcp_tls(), expected);
    }

    let expected = branded_originals::opera_quic()?;
    let Some(TrustAnchorIds::PerConnection(orders)) = &expected.requested_trust_anchor_ids else {
        return Err("original Opera QUIC policy is not per connection".into());
    };
    assert_eq!(orders.as_slice().len(), 20);
    let mut actual = browser::opera::v136_quic_tls();
    actual.draw_per_client(|| -> TestResultU64 { Err("QUIC drew before a connection".into()) })?;
    assert_eq!(actual, expected);
    actual.requested_trust_anchor_ids = None;
    assert_eq!(browser::opera::v136_quic_tls(), expected);
    Ok(())
}

type TestResultU64 = Result<u64, Box<dyn std::error::Error>>;
