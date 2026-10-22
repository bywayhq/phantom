//! Resource declarations compared with Chrome's ordered request captures.

use phantom_profile::{
    ClientHint, ClientHintDelivery, Http2RequestPriority, RequestField,
    catalog::{CatalogError, RequestTemplateKind, profile, profiles},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Fields = Vec<(String, Vec<u8>)>;

const CAPTURES: [&str; 3] = [
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
const CONTEXTS: [(RequestTemplateKind, &str); 4] = [
    (RequestTemplateKind::Script, "script"),
    (RequestTemplateKind::Stylesheet, "stylesheet"),
    (RequestTemplateKind::Image, "image"),
    (RequestTemplateKind::Font, "font"),
];

fn field<'a>(capture: &'a str, key: &str) -> TestResult<&'a str> {
    capture
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
        .ok_or_else(|| format!("missing capture field {key}").into())
}

fn unhex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid capture hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

fn captured_fields(capture: &str, context: &str) -> TestResult<Fields> {
    let prefix = format!("resource_{context}");
    let count = field(capture, &format!("{prefix}_field_count"))?.parse::<usize>()?;
    let mut fields = Vec::with_capacity(count);
    for index in 0..count {
        let value = field(capture, &format!("{prefix}_field_{index}"))?;
        let (name, value) = value
            .split_once(",value_hex:")
            .ok_or("missing capture value")?;
        let name = String::from_utf8(unhex(
            name.strip_prefix("name_hex:").ok_or("missing name hex")?,
        )?)?;
        if !name.starts_with(':') && !name.eq_ignore_ascii_case("host") {
            fields.push((name, unhex(value)?));
        }
    }
    Ok(fields)
}

// Supply only the captured caller values; every automatic value comes from the declaration.
fn declared_fields(
    fields: &[RequestField],
    hints: &[ClientHint],
    caller: &Fields,
) -> TestResult<Fields> {
    let named_hints: Vec<_> = fields
        .iter()
        .filter_map(|field| match field {
            RequestField::ClientHint { name } => Some(name.as_ref()),
            _ => None,
        })
        .collect();
    let mut result = Vec::new();
    for field in fields {
        let entry = match field {
            RequestField::Literal { name, value } => Some((name.as_ref(), value.as_bytes())),
            RequestField::ByTrust {
                name, trustworthy, ..
            } => trustworthy
                .as_ref()
                .map(|value| (name.as_ref(), value.as_bytes())),
            RequestField::ByForwarding {
                name, unforwarded, ..
            } => unforwarded
                .as_ref()
                .map(|value| (name.as_ref(), value.as_bytes())),
            RequestField::Caller { name, required } => {
                let value = caller
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name));
                if *required && value.is_none() {
                    return Err(format!("missing required caller field {name}").into());
                }
                value.map(|(_, value)| (name.as_ref(), value.as_slice()))
            }
            RequestField::ClientHint { name } => hints
                .iter()
                .find(|hint| {
                    hint.name() == name.as_ref() && hint.delivery() == ClientHintDelivery::Default
                })
                .map(|hint| (hint.name(), hint.value())),
            RequestField::ClientHints => {
                result.extend(
                    hints
                        .iter()
                        .filter(|hint| {
                            hint.delivery() == ClientHintDelivery::Default
                                && !named_hints.contains(&hint.name())
                        })
                        .map(|hint| (hint.name().to_owned(), hint.value().to_vec())),
                );
                None
            }
            RequestField::ProxyAuthorization { .. } => None,
            _ => return Err("unexpected resource template field".into()),
        };
        if let Some((name, value)) = entry {
            result.push((name.to_owned(), value.to_vec()));
        }
    }
    Ok(result)
}

#[test]
fn resource_fields_match_all_three_ordered_protocol_captures() -> TestResult {
    let definition = profile("chrome-156-windows")?;
    let selected = definition.instantiate(&[])?;
    let hints = selected
        .client_hints()
        .ok_or("missing client hints")?
        .hints();
    for (kind, context) in CONTEXTS {
        let template = definition.request_template(kind)?;
        template.validate()?;
        let fields = [
            template.http1_fields.as_slice(),
            template.http2_fields.as_slice(),
            template
                .http3_fields
                .as_deref()
                .ok_or("missing HTTP/3 resource fields")?,
        ];
        for (capture, fields) in CAPTURES.into_iter().zip(fields) {
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
        }
    }
    Ok(())
}

#[test]
fn resources_require_page_fields_and_keep_trust_dependent_metadata() -> TestResult {
    let definition = profile("chrome-156-windows")?;
    for (kind, context) in CONTEXTS {
        let template = definition.request_template(kind)?;
        assert!(!template.requested_client_hint_placement);
        assert!(!template.restarts_for_connection_accept_ch);
        for fields in [&template.http1_fields, &template.http2_fields]
            .into_iter()
            .chain(template.http3_fields.iter())
        {
            let callers: Vec<_> = fields
                .iter()
                .filter_map(|field| match field {
                    RequestField::Caller { name, required } => {
                        Some((name.to_ascii_lowercase(), *required))
                    }
                    _ => None,
                })
                .collect();
            let expected = if context == "font" {
                vec![("origin".to_owned(), true), ("referer".to_owned(), true)]
            } else {
                vec![("referer".to_owned(), true)]
            };
            assert_eq!(callers, expected);
            let mut metadata = 0;
            for field in fields {
                if let RequestField::ByTrust {
                    name,
                    trustworthy,
                    untrustworthy,
                } = field
                {
                    if name.to_ascii_lowercase().starts_with("sec-fetch-") {
                        assert!(trustworthy.is_some());
                        assert!(untrustworthy.is_none());
                        metadata += 1;
                    }
                    if name.eq_ignore_ascii_case("accept-encoding") {
                        assert_eq!(trustworthy.as_deref(), Some("gzip, deflate, br, zstd"));
                        assert_eq!(untrustworthy.as_deref(), Some("gzip, deflate"));
                    }
                }
            }
            assert_eq!(metadata, 3);
        }
    }
    Ok(())
}

#[test]
fn resource_weight_bands_match_captured_initial_priorities() -> TestResult {
    let definition = profile("chrome-156-windows")?;
    for (kind, context) in CONTEXTS {
        let captured = field(CAPTURES[1], &format!("resource_{context}_initial_priority"))?;
        let components: Vec<_> = captured.split(',').collect();
        assert_eq!(components.first(), Some(&"exclusive:true"));
        let weight = components
            .iter()
            .find_map(|part| part.strip_prefix("weight:"))
            .ok_or("missing captured weight")?
            .parse::<u16>()?;
        assert_eq!(
            definition.request_template(kind)?.http2_priority,
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

#[test]
fn resource_contexts_are_available_only_on_the_observed_windows_recipe() -> TestResult {
    let observed = profile("chrome-156-windows")?;
    for definition in profiles()
        .iter()
        .filter(|definition| definition.id() != observed.id())
    {
        for (kind, _) in CONTEXTS {
            assert_eq!(
                definition.request_template(kind),
                Err(CatalogError::UnavailableTemplate {
                    profile: definition.id(),
                    kind,
                })
            );
        }
    }
    Ok(())
}
