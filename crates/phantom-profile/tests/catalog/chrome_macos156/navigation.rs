use phantom_profile::{
    ClientHintDelivery, RequestField, RequestTemplate,
    catalog::{RequestTemplateKind, profile},
};

use super::{CAPTURES, TestResult, field, unhex};
use crate::chrome_windows156::declared_names;

pub(crate) fn expected_navigation() -> RequestTemplate {
    let mut template = crate::chrome_windows156::expected_navigation();
    for fields in [&mut template.http1_fields, &mut template.http2_fields]
        .into_iter()
        .chain(template.http3_fields.iter_mut())
    {
        for field in fields {
            if let RequestField::Literal { name, value } = field
                && name.eq_ignore_ascii_case("user-agent")
            {
                *value = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36".into();
            }
        }
    }
    template
}

#[test]
fn macos156_navigation_matches_captured_literals_and_initial_and_restart_order() -> TestResult {
    for capture in &CAPTURES {
        let selected = (capture.settings)();
        let hints = selected.client_hints().ok_or("missing hints")?;
        let template =
            profile(capture.selector)?.request_template(RequestTemplateKind::Navigation)?;
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
        for (index, hint_names, restart) in [(0, &defaults, false), (1, &all, true)] {
            let captured: Vec<_> =
                field(capture.snapshot, &format!("request_{index}_field_order"))?
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
                for index in
                    0..field(capture.snapshot, "request_0_field_count")?.parse::<usize>()?
                {
                    let row = field(capture.snapshot, &format!("request_0_field_{index}"))?;
                    let (_, encoded) =
                        row.split_once("name_hex:").ok_or("missing captured name")?;
                    let (encoded_name, encoded_value) = encoded
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
        for (capture, fields) in capture.resources.into_iter().zip([
            template.http1_fields.as_slice(),
            template.http2_fields.as_slice(),
            template
                .http3_fields
                .as_deref()
                .ok_or("missing HTTP/3 fields")?,
        ]) {
            assert_eq!(field(capture, "page_result")?, "resources:ok");
            let request = field(capture, "request_0")?;
            let captured: Vec<_> = request
                .split_once("fields:")
                .ok_or("missing resource fields")?
                .1
                .split('|')
                .filter(|name| !name.starts_with(':') && !name.eq_ignore_ascii_case("host"))
                .map(str::to_ascii_lowercase)
                .collect();
            assert_eq!(declared_names(fields, &defaults, false), captured);
        }
    }
    Ok(())
}
