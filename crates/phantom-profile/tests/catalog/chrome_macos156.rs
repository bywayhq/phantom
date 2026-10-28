//! Mac 156 declarations compared with headed hosted-browser captures.

use phantom_profile::{
    ClientHintDelivery, ClientProfile, Http2RequestPriority, browser,
    catalog::{
        CaptureEnvironment, CatalogError, LayerSupport, ProfileLayer, RequestTemplateKind, profile,
    },
    client_hello::ClientHelloSummary,
};

use super::{
    chrome_windows156::{
        field,
        startup::{compare_http_startup, compare_quic_parameters, compare_tls},
        unhex,
    },
    resource_templates::{captured_fields, declared_fields},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) mod navigation;

struct MacCapture {
    selector: &'static str,
    platform: &'static str,
    architecture: &'static str,
    settings: fn() -> ClientProfile,
    snapshot: &'static str,
    resources: [&'static str; 3],
}

const CAPTURES: [MacCapture; 2] = [
    MacCapture {
        selector: "chrome-156-macos",
        platform: "macos-26.6.2-arm64",
        architecture: "arm64",
        settings: browser::chrome::v156_macos,
        snapshot: include_str!(
            "../../../../fixtures/client-hints/chrome/156.0.8078.48/macos-26.6.2-arm64/snapshot-1.txt"
        ),
        resources: [
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-26.6.2-arm64/resources-h1.txt"
            ),
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-26.6.2-arm64/resources-h2.txt"
            ),
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-26.6.2-arm64/resources-h3.txt"
            ),
        ],
    },
    MacCapture {
        selector: "chrome-156-macos-intel",
        platform: "macos-15.7.9-x86-64",
        architecture: "x86_64",
        settings: browser::chrome::v156_macos_intel,
        snapshot: include_str!(
            "../../../../fixtures/client-hints/chrome/156.0.8078.48/macos-15.7.9-x86-64/snapshot-1.txt"
        ),
        resources: [
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-15.7.9-x86-64/resources-h1.txt"
            ),
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-15.7.9-x86-64/resources-h2.txt"
            ),
            include_str!(
                "../../../../fixtures/lifecycle/chrome/156.0.8078.48/macos-15.7.9-x86-64/resources-h3.txt"
            ),
        ],
    },
];

const CONTEXTS: [(RequestTemplateKind, &str); 4] = [
    (RequestTemplateKind::Script, "script"),
    (RequestTemplateKind::Stylesheet, "stylesheet"),
    (RequestTemplateKind::Image, "image"),
    (RequestTemplateKind::Font, "font"),
];

#[test]
fn macos156_no_store_fetch_matches_both_platforms_and_all_three_protocols() -> TestResult {
    for capture in &CAPTURES {
        super::resource_templates::fetch_no_store::compare(capture.selector, capture.resources)?;
    }
    Ok(())
}

#[test]
fn macos156_selects_exact_platforms_and_seven_observed_layers() -> TestResult {
    for capture in &CAPTURES {
        let definition = profile(capture.selector)?;
        assert_eq!(
            definition.id().as_str(),
            format!("chrome/156.0.8078.48/{}/r1", capture.platform)
        );
        assert_eq!(
            definition.metadata().build(),
            Some(field(capture.snapshot, "client_version")?)
        );
        assert_eq!(
            definition.metadata().platform_release(),
            Some(capture.platform)
        );
        assert_eq!(
            definition.metadata().architecture(),
            Some(capture.architecture)
        );
        assert_eq!(
            definition.metadata().environment(),
            Some(CaptureEnvironment::Desktop)
        );
        assert!(field(capture.snapshot, "operating_system")?.contains(capture.architecture));
        let mut configured_count = 0;
        for layer in definition.layers() {
            let configured = matches!(
                layer.layer(),
                ProfileLayer::TcpTls
                    | ProfileLayer::Http2
                    | ProfileLayer::QuicTls
                    | ProfileLayer::QuicTransport
                    | ProfileLayer::Http3
                    | ProfileLayer::Http3Request
                    | ProfileLayer::ClientHints
            );
            assert_eq!(layer.support() == LayerSupport::Configured, configured);
            if configured {
                configured_count += 1;
            } else {
                assert_eq!(
                    definition.instantiate(&[layer.layer()]),
                    Err(CatalogError::UnavailableLayer {
                        profile: definition.id(),
                        layer: layer.layer(),
                    })
                );
            }
        }
        assert_eq!(configured_count, 7);
        let selected = definition.instantiate(&[])?;
        assert_eq!(selected, (capture.settings)());
        assert!(selected.tcp().is_none());
        assert!(selected.udp().is_none());
        assert!(selected.dns_cache().is_none());
        assert!(selected.http1().is_none());
        assert!(selected.websocket().is_none());
        assert!(selected.proxy_connect().is_none());
        assert!(selected.request_template().is_none());
        for kind in [RequestTemplateKind::Fetch, RequestTemplateKind::FetchUpload] {
            if capture.selector == "chrome-156-macos" && kind == RequestTemplateKind::Fetch {
                assert_eq!(
                    definition.request_template(kind)?,
                    browser::chrome::v154_macos_fetch_template()
                );
                continue;
            }
            assert_eq!(
                definition.request_template(kind),
                Err(CatalogError::UnavailableTemplate {
                    profile: definition.id(),
                    kind
                })
            );
        }
    }
    assert_ne!((CAPTURES[0].settings)(), (CAPTURES[1].settings)());
    Ok(())
}

#[test]
fn macos156_hint_values_delivery_and_order_match_each_snapshot() -> TestResult {
    for capture in &CAPTURES {
        let selected = (capture.settings)();
        let hints = selected.client_hints().ok_or("missing client hints")?;
        hints.validate()?;
        assert_eq!(
            hints.hints().len(),
            field(capture.snapshot, "hint_count")?.parse::<usize>()?
        );
        for (index, hint) in hints.hints().iter().enumerate() {
            let entry = field(capture.snapshot, &format!("hint_{index}"))?;
            let mut parts = entry.splitn(3, '|');
            let delivery = match parts.next().ok_or("missing hint delivery")? {
                "default" => ClientHintDelivery::Default,
                "accept-ch" => ClientHintDelivery::AcceptCh,
                _ => return Err("unknown captured delivery".into()),
            };
            assert_eq!(hint.delivery(), delivery);
            assert_eq!(Some(hint.name()), parts.next());
            assert_eq!(Some(hint.value()), parts.next().map(str::as_bytes));
        }
    }
    Ok(())
}

#[test]
fn macos156_tls_matches_fresh_tcp_and_quic_hellos() -> TestResult {
    for capture in &CAPTURES {
        let selected = (capture.settings)();
        let record = unhex(field(capture.snapshot, "tls.record_0_hex")?)?;
        let hello =
            ClientHelloSummary::from_handshake_bytes(record.get(5..).ok_or("short TLS record")?)?;
        compare_tls(selected.tls(), &hello)?;
        let handshake = unhex(field(capture.snapshot, "quic_client_hello.handshake_hex")?)?;
        let hello = ClientHelloSummary::from_handshake_bytes(&handshake)?;
        compare_tls(selected.http3().ok_or("missing HTTP/3")?.tls(), &hello)?;
    }
    Ok(())
}

#[test]
fn macos156_http_startup_and_quic_limits_match_retained_bytes() -> TestResult {
    for capture in &CAPTURES {
        let selected = (capture.settings)();
        compare_http_startup(&selected, capture.snapshot)?;
        compare_quic_parameters(&selected, capture.snapshot)?;
    }
    Ok(())
}

#[test]
fn macos156_resources_match_ordered_protocol_fields_and_captured_weight_bands() -> TestResult {
    for capture in &CAPTURES {
        let definition = profile(capture.selector)?;
        let selected = definition.instantiate(&[])?;
        let hints = selected
            .client_hints()
            .ok_or("missing client hints")?
            .hints();
        for (kind, context) in CONTEXTS {
            let template = definition.request_template(kind)?;
            template.validate()?;
            assert!(!template.requested_client_hint_placement);
            assert!(!template.restarts_for_connection_accept_ch);
            for (wire, fields) in capture.resources.into_iter().zip([
                template.http1_fields.as_slice(),
                template.http2_fields.as_slice(),
                template
                    .http3_fields
                    .as_deref()
                    .ok_or("missing HTTP/3 fields")?,
            ]) {
                assert_eq!(field(wire, "page_result")?, "resources:ok");
                assert_eq!(field(wire, "request_count")?, "6");
                let captured = captured_fields(wire, context)?;
                let caller = captured
                    .iter()
                    .filter(|(name, _)| {
                        name.eq_ignore_ascii_case("referer") || name.eq_ignore_ascii_case("origin")
                    })
                    .cloned()
                    .collect();
                assert_eq!(
                    declared_fields(fields, hints, &caller)?,
                    captured,
                    "{} {context}",
                    capture.selector
                );
                assert!(declared_fields(fields, hints, &Vec::new()).is_err());
            }
            let priority = field(
                capture.resources[1],
                &format!("resource_{context}_initial_priority"),
            )?;
            let parts: Vec<_> = priority.split(',').collect();
            assert_eq!(parts.first(), Some(&"exclusive:true"));
            let weight = parts
                .iter()
                .find_map(|part| part.strip_prefix("weight:"))
                .ok_or("missing captured weight")?
                .parse::<u16>()?;
            assert_eq!(
                template.http2_priority,
                Some(Http2RequestPriority::WeightBand {
                    weight,
                    exclusive: true
                })
            );
        }
    }
    Ok(())
}
