//! Windows 156 declarations compared with retained browser observations.

use phantom_profile::{
    ClientHintDelivery, RequestField, RequestTemplate, browser,
    catalog::{
        CaptureEnvironment, CatalogError, LayerSupport, ProfileLayer, RequestTemplateKind, profile,
    },
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

mod startup;

const SNAPSHOTS: [&str; 3] = [
    include_str!(
        "../../../../fixtures/client-hints/chrome/156.0.8078.48/windows-11-26200/snapshot-1.txt"
    ),
    include_str!(
        "../../../../fixtures/client-hints/chrome/156.0.8078.48/windows-11-26200/snapshot-2.txt"
    ),
    include_str!(
        "../../../../fixtures/client-hints/chrome/156.0.8078.48/windows-11-26200/snapshot-3.txt"
    ),
];
const RESOURCES: [&str; 3] = [
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources-h1.txt"
    ),
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources.txt"
    ),
    include_str!(
        "../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/resources-h3.txt"
    ),
];

fn field<'a>(capture: &'a str, key: &str) -> TestResult<&'a str> {
    capture
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
        .ok_or_else(|| format!("missing capture field {key}").into())
}

fn unhex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err("invalid capture hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

pub(super) fn expected_navigation() -> RequestTemplate {
    let mut template = browser::chrome::v154_windows_navigation_template();
    template.http2_priority = Some(phantom_profile::Http2RequestPriority::WeightBand {
        weight: 256,
        exclusive: true,
    });
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
    let accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    for fields in [&mut template.http1_fields, &mut template.http2_fields]
        .into_iter()
        .chain(template.http3_fields.iter_mut())
    {
        for field in fields {
            if let RequestField::Literal { name, value } = field {
                if name.eq_ignore_ascii_case("user-agent") {
                    *value = ua.into();
                }
                if name.eq_ignore_ascii_case("accept") {
                    *value = accept.into();
                }
            }
        }
    }
    template
}

#[test]
fn windows156_selects_its_captured_layers() -> TestResult {
    let definition = profile("chrome-156-windows")?;
    assert_eq!(
        definition.id().as_str(),
        "chrome/156.0.8078.48/windows-11-26200/r1"
    );
    assert_eq!(definition.metadata().build(), Some("156.0.8078.48"));
    assert_eq!(definition.metadata().architecture(), Some("x86_64"));
    assert_eq!(
        definition.metadata().environment(),
        Some(CaptureEnvironment::Desktop)
    );
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
        if !configured {
            assert_eq!(
                definition.instantiate(&[layer.layer()]),
                Err(CatalogError::UnavailableLayer {
                    profile: definition.id(),
                    layer: layer.layer(),
                })
            );
        }
    }
    let selected = definition.instantiate(&[])?;
    assert_eq!(selected, browser::chrome::v156_windows());
    assert!(selected.tcp().is_none());
    assert!(selected.udp().is_none());
    assert!(selected.dns_cache().is_none());
    assert!(selected.http1().is_none());
    assert!(selected.websocket().is_none());
    assert!(selected.proxy_connect().is_none());
    assert!(selected.request_template().is_none());
    for kind in [
        RequestTemplateKind::Fetch,
        RequestTemplateKind::FetchNoStore,
        RequestTemplateKind::FetchUpload,
    ] {
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
fn windows156_hint_values_delivery_and_order_match_all_headful_snapshots() -> TestResult {
    let selected = browser::chrome::v156_windows();
    let hints = selected.client_hints().ok_or("missing client hints")?;
    hints.validate()?;
    for capture in SNAPSHOTS {
        assert_eq!(
            hints.hints().len(),
            field(capture, "hint_count")?.parse::<usize>()?
        );
        for (index, hint) in hints.hints().iter().enumerate() {
            let entry = field(capture, &format!("hint_{index}"))?;
            let mut parts = entry.splitn(3, '|');
            let delivery = parts.next().ok_or("missing hint delivery")?;
            assert_eq!(
                hint.delivery(),
                match delivery {
                    "default" => ClientHintDelivery::Default,
                    "accept-ch" => ClientHintDelivery::AcceptCh,
                    _ => return Err("unknown captured hint delivery".into()),
                }
            );
            assert_eq!(Some(hint.name()), parts.next());
            assert_eq!(Some(hint.value()), parts.next().map(str::as_bytes));
        }
    }
    Ok(())
}

// Project the declaration's initial-navigation and restarted-hint slots.
fn declared_names(fields: &[RequestField], hints: &[String], restart: bool) -> Vec<String> {
    let mut names = Vec::new();
    for field in fields {
        match field {
            RequestField::ClientHints if !restart => names.extend_from_slice(hints),
            RequestField::RestartClientHints if restart => names.extend_from_slice(hints),
            RequestField::Literal { name, .. } => names.push(name.to_ascii_lowercase()),
            RequestField::ByTrust {
                name,
                trustworthy: Some(_),
                ..
            }
            | RequestField::ByForwarding {
                name,
                unforwarded: Some(_),
                ..
            } => {
                names.push(name.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    names
}

#[test]
fn windows156_navigation_values_and_slot_order_match_initial_and_restarted_requests() -> TestResult
{
    let selected = browser::chrome::v156_windows();
    let hints = selected.client_hints().ok_or("missing hints")?;
    let template =
        profile("chrome-156-windows")?.request_template(RequestTemplateKind::Navigation)?;
    template.validate()?;
    assert_eq!(template, expected_navigation());
    assert!(template.requested_client_hint_placement);
    assert!(template.restarts_for_connection_accept_ch);
    let defaults: Vec<_> = hints
        .hints()
        .iter()
        .filter(|hint| hint.delivery() == ClientHintDelivery::Default)
        .map(|hint| hint.name().to_owned())
        .collect();
    let all: Vec<_> = hints
        .hints()
        .iter()
        .map(|hint| hint.name().to_owned())
        .collect();
    for capture in SNAPSHOTS {
        for (index, hint_names, restart) in [(0, &defaults, false), (1, &all, true)] {
            let captured: Vec<_> = field(capture, &format!("request_{index}_field_order"))?
                .split(',')
                .filter(|name| !name.starts_with(':'))
                .map(str::to_owned)
                .collect();
            assert_eq!(
                declared_names(&template.http2_fields, hint_names, restart),
                captured
            );
        }
        for item in &template.http2_fields {
            if let RequestField::Literal { name, value } = item {
                let mut found = false;
                for index in 0..field(capture, "request_0_field_count")?.parse::<usize>()? {
                    let row = field(capture, &format!("request_0_field_{index}"))?;
                    let (_, encoded_name) =
                        row.split_once("name_hex:").ok_or("missing captured name")?;
                    let (encoded_name, encoded_value) = encoded_name
                        .split_once(",value_hex:")
                        .ok_or("missing captured value")?;
                    if unhex(encoded_name)? == name.as_bytes() {
                        assert_eq!(unhex(encoded_value)?, value.as_bytes());
                        found = true;
                    }
                }
                assert!(found, "missing captured literal {name}");
            }
        }
    }
    for (capture, fields) in RESOURCES.into_iter().zip([
        template.http1_fields.as_slice(),
        template.http2_fields.as_slice(),
        template
            .http3_fields
            .as_deref()
            .ok_or("missing HTTP/3 fields")?,
    ]) {
        let request = field(capture, "request_0")?;
        let (_, fields_text) = request
            .split_once("fields:")
            .ok_or("missing resource fields")?;
        let captured: Vec<_> = fields_text
            .split('|')
            .filter(|name| !name.starts_with(':'))
            .map(str::to_ascii_lowercase)
            .collect();
        let mut expected = declared_names(fields, &defaults, false);
        if expected.first().is_none_or(|name| name != "host")
            && captured.first().is_some_and(|name| name == "host")
        {
            expected.insert(0, "host".to_owned());
        }
        assert_eq!(expected, captured);
    }
    Ok(())
}
