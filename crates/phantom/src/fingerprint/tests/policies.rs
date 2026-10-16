//! Custom policies preserve order, weighted candidates and native ranges.
use super::super::import_profile_json;
use super::profiles::{PROFILES, TestResult, document, import};
use phantom_profile::{
    ClientHint, ClientHintDelivery, ClientHintSettings, CookiePlacement, TrustAnchorIds,
    TrustAnchorOrder, TrustAnchorOrders,
};
use serde_json::json;
use std::num::NonZeroUsize;

#[test]
fn drawn_anchor_candidates_preserve_duplicates_weights_and_order() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["tls"]["requested_trust_anchor_ids"] =
        json!({"kind":"PerClient","orders":[[[98],[97],[97]],[[97],[98],[97]],[[98],[97],[97]]]});
    let mut expected = phantom_profile::catalog::profile(PROFILES[0].0)?.instantiate(&[])?;
    let mut tls = expected.tls().clone();
    tls.requested_trust_anchor_ids =
        Some(TrustAnchorIds::PerClient(TrustAnchorOrders::new(vec![
            TrustAnchorOrder::new(vec![Box::from([98]), Box::from([97]), Box::from([97])])?,
            TrustAnchorOrder::new(vec![Box::from([97]), Box::from([98]), Box::from([97])])?,
            TrustAnchorOrder::new(vec![Box::from([98]), Box::from([97]), Box::from([97])])?,
        ])?));
    expected = with_tls(&expected, tls);
    let actual = import(&value)?;
    assert_eq!(actual, expected);
    assert_eq!(import(&value)?, actual);
    value["profile"]["tls"]["requested_trust_anchor_ids"]["kind"] = json!("PerConnection");
    let mut tls = expected.tls().clone();
    let Some(TrustAnchorIds::PerClient(orders)) = tls.requested_trust_anchor_ids.take() else {
        return Err("unexpected anchor policy".into());
    };
    tls.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(orders));
    assert_eq!(import(&value)?, with_tls(&expected, tls));
    Ok(())
}

#[test]
fn cookie_names_and_resolved_hint_bytes_are_kept_without_offline_normalization() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["cookie_placement"] = json!({"before":["","X","X","x"]});
    value["profile"]["client_hints"] = json!({"hints":[{"name":"sec-ch-custom","value":[34,34],"delivery":"AcceptCh"},{"name":"sec-ch-other","value":[],"delivery":"Default"}]});
    let expected = phantom_profile::catalog::profile(PROFILES[0].0)?
        .instantiate(&[])?
        .with_cookie_placement(CookiePlacement::before_fields(["", "X", "X", "x"]))
        .with_client_hints(ClientHintSettings::new(vec![
            ClientHint::new("sec-ch-custom", b"\"\"", ClientHintDelivery::AcceptCh),
            ClientHint::new("sec-ch-other", b"", ClientHintDelivery::Default),
        ]));
    assert_eq!(import(&value)?, expected);
    Ok(())
}

#[test]
fn host_sized_custom_limits_and_fractional_durations_are_not_offline_capped() -> TestResult {
    let mut value = document(0)?;
    let limit = usize::MAX;
    value["profile"]["dns_cache"] = json!({"address_failure_policy":{"kind":"Ignore","max_unusable_addresses":null},"system_ttl":"Ignore","max_entries":limit,"ttl":{"seconds":7,"nanoseconds":3},"min_record_ttl":{"seconds":0,"nanoseconds":1},"negative_ttl":null});
    let expected = phantom_profile::catalog::profile(PROFILES[0].0)?
        .instantiate(&[])?
        .with_dns_cache(phantom_profile::DnsCacheSettings {
            address_failure_policy: phantom_profile::DnsAddressFailurePolicy::Ignore,
            max_entries: NonZeroUsize::new(limit).ok_or("zero host size")?,
            ttl: std::time::Duration::new(7, 3),
            min_record_ttl: std::time::Duration::new(0, 1),
            negative_ttl: None,
            system_ttl: phantom_profile::SystemDnsTtlPolicy::Ignore,
        });
    assert_eq!(import(&value)?, expected);
    Ok(())
}

#[test]
fn importer_is_synchronous_owned_input_only_and_requires_no_runtime() -> TestResult {
    let parse: fn(
        &[u8],
    )
        -> Result<phantom_profile::ClientProfile, super::super::FingerprintImportError> =
        import_profile_json;
    let imported = parse(PROFILES[0].1.as_bytes())?;
    drop(imported);
    Ok(())
}

fn with_tls(
    original: &phantom_profile::ClientProfile,
    tls: phantom_profile::TlsSettings,
) -> phantom_profile::ClientProfile {
    let mut result = phantom_profile::ClientProfile::new(tls)
        .with_cookie_placement(original.cookie_placement().clone());
    macro_rules! layer {
        ($getter:ident,$setter:ident) => {
            if let Some(value) = original.$getter() {
                result = result.$setter(value.clone());
            }
        };
    }
    layer!(tcp, with_tcp);
    layer!(udp, with_udp);
    layer!(dns_cache, with_dns_cache);
    layer!(http1, with_http1);
    layer!(http2, with_http2);
    layer!(http3, with_http3);
    layer!(client_hints, with_client_hints);
    layer!(websocket, with_websocket);
    layer!(proxy_connect, with_proxy_connect);
    layer!(request_template, with_request_template);
    result
}
