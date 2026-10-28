//! Linux 156 declarations compared with headed WSL2 browser captures.

use phantom_profile::{
    ClientHintDelivery, Http2RequestPriority, browser,
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

const SNAPSHOT: &str = include_str!(
    "../../../../fixtures/client-hints/chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/snapshot-1.txt"
);
const RESOURCES: [&str; 3] = [
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/resources-h1.txt"
    ),
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/resources-h2.txt"
    ),
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/resources-h3.txt"
    ),
];
const CONTEXTS: [(RequestTemplateKind, &str); 4] = [
    (RequestTemplateKind::Script, "script"),
    (RequestTemplateKind::Stylesheet, "stylesheet"),
    (RequestTemplateKind::Image, "image"),
    (RequestTemplateKind::Font, "font"),
];

#[test]
fn linux156_no_store_fetch_matches_all_three_protocol_captures() -> TestResult {
    super::resource_templates::fetch_no_store::compare("chrome-156-linux", RESOURCES)
}

#[test]
fn linux156_selects_its_seven_observed_layers() -> TestResult {
    let definition = profile("chrome-156-linux")?;
    assert_eq!(
        definition.id().as_str(),
        "chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/r1"
    );
    assert_eq!(
        definition.metadata().build(),
        Some(field(SNAPSHOT, "client_version")?)
    );
    assert_eq!(
        definition.metadata().platform_release(),
        Some("ubuntu-24.04.4-wsl2")
    );
    assert_eq!(definition.metadata().architecture(), Some("x86_64"));
    assert_eq!(
        definition.metadata().environment(),
        Some(CaptureEnvironment::Desktop)
    );
    let host = field(SNAPSHOT, "operating_system")?;
    assert!(host.contains("Ubuntu24.04.4 WSL2 x86_64"));
    assert!(host.contains("WSLg1.0.73"));
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
    assert_eq!(selected, browser::chrome::v156_linux());
    assert!(selected.tcp().is_none());
    assert!(selected.udp().is_none());
    assert!(selected.dns_cache().is_none());
    assert!(selected.http1().is_none());
    assert!(selected.websocket().is_none());
    assert!(selected.proxy_connect().is_none());
    assert!(selected.request_template().is_none());
    for kind in [RequestTemplateKind::Fetch, RequestTemplateKind::FetchUpload] {
        assert_eq!(
            definition.request_template(kind),
            Err(CatalogError::UnavailableTemplate {
                profile: definition.id(),
                kind,
            })
        );
    }
    Ok(())
}

#[test]
fn linux156_hint_values_delivery_and_order_match_the_snapshot() -> TestResult {
    let selected = browser::chrome::v156_linux();
    let hints = selected.client_hints().ok_or("missing client hints")?;
    hints.validate()?;
    assert_eq!(
        hints.hints().len(),
        field(SNAPSHOT, "hint_count")?.parse::<usize>()?
    );
    for (index, hint) in hints.hints().iter().enumerate() {
        let entry = field(SNAPSHOT, &format!("hint_{index}"))?;
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
    Ok(())
}

#[test]
fn linux156_tls_matches_fresh_tcp_and_quic_hellos() -> TestResult {
    let selected = browser::chrome::v156_linux();
    let record = unhex(field(SNAPSHOT, "tls.record_0_hex")?)?;
    let hello =
        ClientHelloSummary::from_handshake_bytes(record.get(5..).ok_or("short TLS record")?)?;
    compare_tls(selected.tls(), &hello)?;
    let handshake = unhex(field(SNAPSHOT, "quic_client_hello.handshake_hex")?)?;
    let hello = ClientHelloSummary::from_handshake_bytes(&handshake)?;
    compare_tls(selected.http3().ok_or("missing HTTP/3")?.tls(), &hello)
}

#[test]
fn linux156_http_startup_and_quic_limits_match_retained_bytes() -> TestResult {
    let selected = browser::chrome::v156_linux();
    compare_http_startup(&selected, SNAPSHOT)?;
    compare_quic_parameters(&selected, SNAPSHOT)
}

#[test]
fn linux156_resources_match_ordered_protocol_fields_and_captured_weight_bands() -> TestResult {
    let definition = profile("chrome-156-linux")?;
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
        for (capture, fields) in RESOURCES.into_iter().zip([
            template.http1_fields.as_slice(),
            template.http2_fields.as_slice(),
            template
                .http3_fields
                .as_deref()
                .ok_or("missing HTTP/3 resource fields")?,
        ]) {
            let captured = captured_fields(capture, context)?;
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
                "{context}"
            );
            assert!(declared_fields(fields, hints, &Vec::new()).is_err());
        }
        let priority = field(
            RESOURCES[1],
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
    assert_eq!(
        definition
            .request_template(RequestTemplateKind::Navigation)?
            .http2_priority,
        Some(Http2RequestPriority::WeightBand {
            weight: 256,
            exclusive: true
        })
    );
    Ok(())
}
