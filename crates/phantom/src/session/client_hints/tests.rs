use std::num::NonZeroUsize;

use http::{HeaderMap, HeaderValue};
use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

use super::{
    ClientHintContext, ClientHintStore, OriginKey, parse_token_list, prepare_default_fields,
};
use crate::{RequestError, authority::Endpoint};

fn settings() -> ClientHintSettings {
    ClientHintSettings::new(vec![
        ClientHint::new("sec-ch-ua", "baseline", ClientHintDelivery::Default),
        ClientHint::new("sec-ch-ua-arch", "arm", ClientHintDelivery::AcceptCh),
        ClientHint::new(
            "sec-ch-ua-platform-version",
            "15.5.0",
            ClientHintDelivery::AcceptCh,
        ),
    ])
}

fn endpoint(authority: &str) -> Endpoint {
    match authority.parse() {
        Ok(authority) => match Endpoint::new(authority, 443) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("test authority is invalid: {error}"),
        },
        Err(error) => panic!("test authority failed to parse: {error}"),
    }
}

fn value<'a>(headers: &'a [RequestHeader], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .map(RequestHeader::value)
}

#[test]
fn defaults_precede_caller_fields_and_caller_values_win() {
    let prepared = prepare_default_fields(
        &settings(),
        vec![
            RequestHeader::new("x-caller", "one"),
            RequestHeader::new("Sec-CH-UA", "override"),
        ],
    );
    let names = prepared.iter().map(RequestHeader::name).collect::<Vec<_>>();

    assert_eq!(names, ["x-caller", "Sec-CH-UA"]);
    assert_eq!(value(&prepared, "sec-ch-ua"), Some(b"override".as_slice()));
}

#[test]
fn valid_replacement_empty_clearing_and_malformed_preservation_are_distinct() {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());

    let mut learned = HeaderMap::new();
    learned.insert(
        "accept-ch",
        HeaderValue::from_static("Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch"),
    );
    assert!(!store.learn_and_should_retry(&endpoint, &settings, &learned, &sent));
    let prepared = store.prepare(&endpoint, &settings, Vec::new());
    assert_eq!(
        prepared.iter().map(RequestHeader::name).collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-platform-version"]
    );

    let mut malformed = HeaderMap::new();
    malformed.insert("accept-ch", HeaderValue::from_static("\"not-a-token\""));
    assert!(!store.learn_and_should_retry(&endpoint, &settings, &malformed, &prepared));
    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 3);

    let mut empty = HeaderMap::new();
    empty.insert("accept-ch", HeaderValue::from_static(""));
    assert!(!store.learn_and_should_retry(&endpoint, &settings, &empty, &prepared));
    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 1);
}

#[test]
fn critical_retry_requires_a_supported_missing_requested_hint() {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut response = HeaderMap::new();
    response.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    response.insert("critical-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));

    assert!(store.learn_and_should_retry(&endpoint, &settings, &response, &sent));
    let retry = store.prepare(&endpoint, &settings, Vec::new());
    assert!(!store.learn_and_should_retry(&endpoint, &settings, &response, &retry));
}

#[test]
fn origin_capacity_is_lru_and_ports_are_distinct() {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut response = HeaderMap::new();
    response.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    let first = endpoint("example.test:443");
    let second = endpoint("example.test:8443");

    store.learn_and_should_retry(&first, &settings, &response, &sent);
    store.learn_and_should_retry(&second, &settings, &response, &sent);

    assert_eq!(store.prepare(&first, &settings, Vec::new()).len(), 1);
    assert_eq!(store.prepare(&second, &settings, Vec::new()).len(), 2);
    assert_ne!(OriginKey::new(&first), OriginKey::new(&second));
}

#[test]
fn structured_field_parser_accepts_token_parameters_and_rejects_other_members() {
    assert!(parse_token_list("").is_ok());
    assert!(parse_token_list("Sec-CH-UA-Arch, Sec-CH-UA-Bitness").is_ok());
    assert!(parse_token_list("\"sec-ch-ua-arch\"").is_err());
    assert!(parse_token_list("sec-ch-ua-arch;flag").is_ok());
    assert!(parse_token_list("(sec-ch-ua-arch)").is_err());
}

#[test]
fn repeated_fields_are_combined_and_malformed_critical_ch_does_not_retry() {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut response = HeaderMap::new();
    response.append("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    response.append(
        "accept-ch",
        HeaderValue::from_static("Sec-CH-UA-Platform-Version"),
    );
    response.insert("critical-ch", HeaderValue::from_static("\"not-a-token\""));

    assert!(!store.learn_and_should_retry(&endpoint, &settings, &response, &sent));
    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 3);
}

#[test]
fn unknown_only_replacement_clears_previous_preferences() {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut learned = HeaderMap::new();
    learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    store.learn_and_should_retry(&endpoint, &settings, &learned, &sent);

    let mut unknown = HeaderMap::new();
    unknown.insert("accept-ch", HeaderValue::from_static("Sec-CH-Unknown"));
    store.learn_and_should_retry(&endpoint, &settings, &unknown, &sent);

    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 1);
}

#[test]
fn connection_preferences_augment_session_state_without_persisting() -> Result<(), RequestError> {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut learned = HeaderMap::new();
    learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    store.learn_and_should_retry(&endpoint, &settings, &learned, &sent);
    let context =
        ClientHintContext::new(&endpoint, "https://example.test", &settings, Some(&store));

    let prepared = context.prepare(
        vec![RequestHeader::new("Sec-CH-UA-Platform-Version", "caller")],
        Some(b"Sec-CH-UA-Platform-Version, Sec-CH-Unknown"),
    )?;
    assert_eq!(
        prepared.iter().map(RequestHeader::name).collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch", "Sec-CH-UA-Platform-Version"]
    );
    assert_eq!(
        value(&prepared, "sec-ch-ua-platform-version"),
        Some(b"caller".as_slice())
    );

    let without_connection = context.prepare(Vec::new(), None)?;
    assert_eq!(
        without_connection
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch"]
    );
    Ok(())
}

#[test]
fn empty_or_malformed_connection_value_does_not_clear_session_state() -> Result<(), RequestError> {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut learned = HeaderMap::new();
    learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    store.learn_and_should_retry(&endpoint, &settings, &learned, &sent);
    let context =
        ClientHintContext::new(&endpoint, "https://example.test", &settings, Some(&store));

    for value in [&b""[..], &b"\xff"[..], &b"\"not-a-token\""[..]] {
        let prepared = context.prepare(Vec::new(), Some(value))?;
        assert_eq!(
            prepared.iter().map(RequestHeader::name).collect::<Vec<_>>(),
            ["sec-ch-ua", "sec-ch-ua-arch"]
        );
    }
    Ok(())
}

mod template_slots {
    use phantom_net::request::RequestHeader;
    use phantom_profile::{ClientHintSettings, RequestTemplate, chromium, edge};

    use super::super::prepare_fields;
    use crate::request::template::expand;

    const ALL_REQUESTED: &[usize] = &[2, 3, 5, 6, 7, 8, 9, 10];

    fn prepared(
        template: &RequestTemplate,
        http1: bool,
        hints: &ClientHintSettings,
        caller: &[RequestHeader],
        stored: Option<&[usize]>,
    ) -> Vec<String> {
        let fields = if http1 {
            &template.http1_fields
        } else {
            &template.http2_fields
        };
        let expanded = expand(fields, caller, Some(hints));
        prepare_fields(hints, stored, None, expanded, Some(template))
            .iter()
            .map(|header| header.name().to_owned())
            .collect()
    }

    #[test]
    fn navigation_hints_follow_connection_as_one_block_in_profile_order() {
        let template = chromium::v153_windows_navigation_template();
        let hints = chromium::v153_windows_client_hints();
        let first = prepared(&template, true, &hints, &[], None);
        assert_eq!(
            first[..5],
            [
                "Connection",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "Upgrade-Insecure-Requests"
            ]
        );

        let requested = prepared(&template, true, &hints, &[], Some(ALL_REQUESTED));
        let block: Vec<&str> = hints.hints().iter().map(|hint| hint.name()).collect();
        assert_eq!(requested[1..12], block[..]);
        assert_eq!(requested[12], "Upgrade-Insecure-Requests");
    }

    #[test]
    fn fetch_hints_surround_user_agent_as_captured() {
        let template = chromium::v153_windows_fetch_no_store_template();
        let hints = chromium::v153_windows_client_hints();
        assert_eq!(
            prepared(&template, false, &hints, &[], None)[..7],
            [
                "pragma",
                "cache-control",
                "sec-ch-ua-platform",
                "user-agent",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "accept"
            ]
        );
        // Slot placement puts requested hints after `sec-ch-ua-mobile`; no
        // capture backs that, so the client refuses to send them with this
        // template (see `requested_hints_fail_without_a_captured_position`).
        let requested = prepared(&template, false, &hints, &[], Some(ALL_REQUESTED));
        assert_eq!(requested[6], "sec-ch-ua-full-version");
        assert_eq!(requested[14], "accept");
    }

    #[test]
    fn an_empty_user_agent_slot_keeps_the_platform_hint_before_accept() {
        let template = edge::v153_windows_fetch_no_store_template();
        let hints = edge::v153_windows_client_hints();
        assert_eq!(
            prepared(&template, true, &hints, &[], None)[..7],
            [
                "Connection",
                "Pragma",
                "Cache-Control",
                "sec-ch-ua-platform",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "Accept"
            ]
        );
    }

    #[test]
    fn requested_hints_fail_without_a_captured_position() {
        use std::num::NonZeroUsize;

        use http::{HeaderMap, HeaderValue};

        use super::super::{ClientHintContext, ClientHintStore};
        use crate::RequestErrorKind;

        let hints = chromium::v153_windows_client_hints();
        let fetch = chromium::v153_windows_fetch_no_store_template();
        let navigation = chromium::v153_windows_navigation_template();
        let endpoint = super::endpoint("example.test");
        let origin = "https://example.test";
        let store = ClientHintStore::new(NonZeroUsize::MIN);
        let context = |template| {
            ClientHintContext::new(&endpoint, origin, &hints, Some(&store))
                .with_template(Some(template))
        };
        let kind = |result: Result<Vec<RequestHeader>, crate::RequestError>| {
            result.err().map(|error| error.kind())
        };
        let fields = expand(&fetch.http2_fields, &[], Some(&hints));

        // Default hints alone are the captured fetch shape.
        assert_eq!(kind(context(&fetch).prepare(fields.clone(), None)), None);

        // A hint requested through ALPS ACCEPT_CH, or supplied by the caller.
        assert_eq!(
            kind(context(&fetch).prepare(fields.clone(), Some(b"Sec-CH-UA-Arch"))),
            Some(RequestErrorKind::RequestTemplate)
        );
        let caller = [RequestHeader::new("sec-ch-ua-arch", "\"x86\"")];
        let with_caller = expand(&fetch.http2_fields, &caller, Some(&hints));
        assert_eq!(
            kind(context(&fetch).prepare(with_caller, None)),
            Some(RequestErrorKind::RequestTemplate)
        );

        // A hint the origin requested through a response `Accept-CH`.
        let mut learned = HeaderMap::new();
        learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
        store.learn_and_should_retry(&endpoint, &hints, &learned, &[]);
        assert_eq!(
            kind(context(&fetch).prepare(fields, None)),
            Some(RequestErrorKind::RequestTemplate)
        );

        // The navigation capture shows where requested hints go.
        let navigation_fields = expand(&navigation.http2_fields, &[], Some(&hints));
        assert_eq!(
            kind(context(&navigation).prepare(navigation_fields, Some(b"Sec-CH-UA-Model"))),
            None
        );

        // A template without client-hint slots places no hint, whatever its
        // requested-hint flag claims.
        let mut slotless = crate::profile::firefox::v156_windows_navigation_template();
        slotless.requested_client_hint_placement = true;
        let slotless_fields = expand(&slotless.http2_fields, &[], None);
        assert_eq!(
            kind(context(&slotless).prepare(slotless_fields, Some(b"Sec-CH-UA-Arch"))),
            Some(RequestErrorKind::RequestTemplate)
        );
    }

    #[test]
    fn caller_hint_values_keep_the_slot_position() {
        let template = chromium::v153_windows_fetch_no_store_template();
        let hints = chromium::v153_windows_client_hints();
        let caller = [
            RequestHeader::new("x-first", "1"),
            RequestHeader::new("SEC-CH-UA-MOBILE", "?1"),
        ];
        let expanded = expand(&template.http2_fields, &caller, Some(&hints));
        let prepared = prepare_fields(&hints, None, None, expanded, Some(&template));
        let mobile = prepared
            .iter()
            .position(|header| header.name() == "sec-ch-ua-mobile");
        assert_eq!(mobile, Some(5));
        assert_eq!(prepared[5].value(), b"?1");
        assert_eq!(
            prepared
                .iter()
                .filter(|header| header.name().eq_ignore_ascii_case("sec-ch-ua-mobile"))
                .count(),
            1
        );
        assert_eq!(prepared.last().map(RequestHeader::name), Some("x-first"));
    }
}
