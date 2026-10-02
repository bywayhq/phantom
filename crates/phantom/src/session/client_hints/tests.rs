use std::num::NonZeroUsize;

use http::{HeaderMap, HeaderValue};
use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

use super::{
    ClientHintContext, ClientHintStore, OriginKey, RestartHints, parse_token_list,
    prepare_default_fields,
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
    assert!(!store.learn_and_should_retry(&endpoint, true, &settings, &learned, &sent));
    let prepared = store.prepare(&endpoint, &settings, Vec::new());
    assert_eq!(
        prepared.iter().map(RequestHeader::name).collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-platform-version"]
    );

    let mut malformed = HeaderMap::new();
    malformed.insert("accept-ch", HeaderValue::from_static("\"not-a-token\""));
    assert!(!store.learn_and_should_retry(&endpoint, true, &settings, &malformed, &prepared));
    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 3);

    let mut empty = HeaderMap::new();
    empty.insert("accept-ch", HeaderValue::from_static(""));
    assert!(!store.learn_and_should_retry(&endpoint, true, &settings, &empty, &prepared));
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

    assert!(store.learn_and_should_retry(&endpoint, true, &settings, &response, &sent));
    let retry = store.prepare(&endpoint, &settings, Vec::new());
    assert!(!store.learn_and_should_retry(&endpoint, true, &settings, &response, &retry));
}

#[test]
fn http_and_https_origins_on_one_host_and_port_are_distinct() {
    let store = ClientHintStore::new(NonZeroUsize::new(2).unwrap_or(NonZeroUsize::MIN));
    let endpoint = endpoint("127.0.0.1:8443");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut response = HeaderMap::new();
    response.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));

    store.learn_and_should_retry(&endpoint, false, &settings, &response, &sent);
    let https =
        ClientHintContext::new(&endpoint, "https://127.0.0.1:8443", &settings, Some(&store));
    let http = ClientHintContext::new(&endpoint, "http://127.0.0.1:8443", &settings, Some(&store));
    let names = |context: ClientHintContext<'_>| -> Vec<String> {
        context
            .prepare(Vec::new())
            .unwrap_or_default()
            .iter()
            .map(|field| field.name().to_owned())
            .collect()
    };
    assert_eq!(names(https), ["sec-ch-ua"]);
    assert_eq!(names(http), ["sec-ch-ua", "sec-ch-ua-arch"]);
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

    store.learn_and_should_retry(&first, true, &settings, &response, &sent);
    store.learn_and_should_retry(&second, true, &settings, &response, &sent);

    assert_eq!(store.prepare(&first, &settings, Vec::new()).len(), 1);
    assert_eq!(store.prepare(&second, &settings, Vec::new()).len(), 2);
    assert_ne!(OriginKey::new(&first, true), OriginKey::new(&second, true));
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

    assert!(!store.learn_and_should_retry(&endpoint, true, &settings, &response, &sent));
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
    store.learn_and_should_retry(&endpoint, true, &settings, &learned, &sent);

    let mut unknown = HeaderMap::new();
    unknown.insert("accept-ch", HeaderValue::from_static("Sec-CH-Unknown"));
    store.learn_and_should_retry(&endpoint, true, &settings, &unknown, &sent);

    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 1);
}

#[test]
fn connection_accept_ch_naming_a_missing_hint_asks_for_a_restart() -> Result<(), RequestError> {
    let store = ClientHintStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint("example.test");
    let settings = settings();
    let sent = prepare_default_fields(&settings, Vec::new());
    let mut learned = HeaderMap::new();
    learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
    store.learn_and_should_retry(&endpoint, true, &settings, &learned, &sent);
    let context =
        ClientHintContext::new(&endpoint, "https://example.test", &settings, Some(&store));

    // The list carries the stored hint and nothing the connection asks for.
    let built = context.prepare(Vec::new())?;
    assert_eq!(
        built.iter().map(RequestHeader::name).collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch"]
    );
    // A stored hint, a default hint, and an unknown token ask for nothing.
    assert_eq!(
        context.connection_restart(&built, Some(b"Sec-CH-UA-Arch, Sec-CH-UA, Sec-CH-Unknown")),
        None
    );
    // A requested hint the list lacks restarts the request.
    let missing =
        context.connection_restart(&built, Some(b"Sec-CH-UA-Platform-Version, Sec-CH-Unknown"));
    assert_eq!(missing.as_deref(), Some(&[2][..]));

    // The restarted list carries it, and the connection asks for nothing more.
    let mut restart = RestartHints::default();
    restart.add(&missing.unwrap_or_default());
    let restarted = context.with_restart_hints(&restart);
    let rebuilt = restarted.prepare(Vec::new())?;
    assert_eq!(
        rebuilt.iter().map(RequestHeader::name).collect::<Vec<_>>(),
        ["sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-platform-version"]
    );
    assert_eq!(
        restarted.connection_restart(&rebuilt, Some(b"Sec-CH-UA-Platform-Version")),
        None
    );
    // The restart taught the store nothing.
    assert_eq!(store.prepare(&endpoint, &settings, Vec::new()).len(), 2);
    Ok(())
}

#[test]
fn caller_supplied_hint_satisfies_the_connection() -> Result<(), RequestError> {
    let endpoint = endpoint("example.test");
    let settings = settings();
    let context = ClientHintContext::new(&endpoint, "https://example.test", &settings, None);
    let built = context.prepare(vec![RequestHeader::new("Sec-CH-UA-Arch", "caller")])?;
    assert_eq!(
        context.connection_restart(&built, Some(b"Sec-CH-UA-Arch")),
        None
    );
    Ok(())
}

#[test]
fn hint_already_restarted_for_is_not_asked_again() -> Result<(), RequestError> {
    let endpoint = endpoint("example.test");
    let settings = settings();
    let mut restart = RestartHints::default();
    restart.add(&[1]);
    let context = ClientHintContext::new(&endpoint, "https://example.test", &settings, None)
        .with_restart_hints(&restart);
    // Even a list that lost the hint asks for no second restart for it.
    let sent = [RequestHeader::new("sec-ch-ua", "baseline")];
    assert_eq!(
        context.connection_restart(&sent, Some(b"Sec-CH-UA-Arch")),
        None
    );
    Ok(())
}

#[test]
fn empty_absent_or_malformed_connection_value_asks_for_nothing() -> Result<(), RequestError> {
    let endpoint = endpoint("example.test");
    let settings = settings();
    let context = ClientHintContext::new(&endpoint, "https://example.test", &settings, None);
    let built = context.prepare(Vec::new())?;

    assert_eq!(context.connection_restart(&built, None), None);
    for value in [&b""[..], &b"\xff"[..], &b"\"not-a-token\""[..]] {
        assert_eq!(context.connection_restart(&built, Some(value)), None);
    }
    Ok(())
}

#[test]
fn restart_hints_accumulate_in_ascending_order() {
    let mut restart = RestartHints::default();
    restart.add(&[2]);
    restart.add(&[1, 2]);
    assert_eq!(restart.indices, [1, 2]);
}

mod template_slots {
    use phantom_net::request::RequestHeader;
    use phantom_profile::{ClientHintSettings, RequestTemplate, chromium, edge};

    use super::super::prepare_fields;
    use crate::{PreparedRequestTemplate, request::template::expand};

    fn prepare(template: &RequestTemplate) -> PreparedRequestTemplate {
        PreparedRequestTemplate::new(template.clone())
            .unwrap_or_else(|error| panic!("built-in template is invalid: {error}"))
    }

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
        let expanded = expand(fields, caller, Some(hints), true);
        prepare_fields(hints, stored, None, expanded, Some(&prepare(template)))
            .iter()
            .map(|header| header.name().to_owned())
            .collect()
    }

    #[test]
    fn navigation_hints_follow_connection_as_one_block_in_profile_order() {
        let template = chromium::v154_windows_navigation_template();
        let hints = chromium::v154_windows_client_hints();
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
        let template = chromium::v154_windows_fetch_no_store_template();
        let hints = chromium::v154_windows_client_hints();
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
        let template = edge::v154_windows_fetch_no_store_template();
        let hints = edge::v154_windows_client_hints();
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

        let hints = chromium::v154_windows_client_hints();
        let fetch = chromium::v154_windows_fetch_no_store_template();
        let navigation = chromium::v154_windows_navigation_template();
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
        let prepared_fetch = prepare(&fetch);
        let prepared_navigation = prepare(&navigation);
        let fields = expand(&fetch.http2_fields, &[], Some(&hints), true);

        // Default hints alone are the captured fetch shape.
        assert_eq!(kind(context(&prepared_fetch).prepare(fields.clone())), None);

        // A hint a connection's ALPS ACCEPT_CH restarted the request for, or
        // supplied by the caller.
        // `sec-ch-ua-arch` is index 3 of the Chromium hints.
        let mut restart = super::super::RestartHints::default();
        restart.add(&[3]);
        assert_eq!(
            kind(
                context(&prepared_fetch)
                    .with_restart_hints(&restart)
                    .prepare(fields.clone())
            ),
            Some(RequestErrorKind::RequestTemplate)
        );
        let caller = [RequestHeader::new("sec-ch-ua-arch", "\"x86\"")];
        let with_caller = expand(&fetch.http2_fields, &caller, Some(&hints), true);
        assert_eq!(
            kind(context(&prepared_fetch).prepare(with_caller)),
            Some(RequestErrorKind::RequestTemplate)
        );

        // A hint the origin requested through a response `Accept-CH`.
        let mut learned = HeaderMap::new();
        learned.insert("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
        store.learn_and_should_retry(&endpoint, true, &hints, &learned, &[]);
        assert_eq!(
            kind(context(&prepared_fetch).prepare(fields)),
            Some(RequestErrorKind::RequestTemplate)
        );

        // The navigation capture shows where requested hints go.
        let navigation_fields = expand(&navigation.http2_fields, &[], Some(&hints), true);
        assert_eq!(
            kind(
                context(&prepared_navigation)
                    .with_restart_hints(&restart)
                    .prepare(navigation_fields)
            ),
            None
        );

        // A template without client-hint slots places no hint, whatever its
        // requested-hint flag claims.
        let mut slotless = crate::profile::firefox::v157_windows_navigation_template();
        slotless.requested_client_hint_placement = true;
        let slotless_fields = expand(&slotless.http2_fields, &[], None, true);
        assert_eq!(
            kind(
                context(&prepare(&slotless))
                    .with_restart_hints(&restart)
                    .prepare(slotless_fields)
            ),
            Some(RequestErrorKind::RequestTemplate)
        );
    }

    #[test]
    fn caller_hint_values_keep_the_slot_position() {
        let template = chromium::v154_windows_fetch_no_store_template();
        let hints = chromium::v154_windows_client_hints();
        let caller = [
            RequestHeader::new("x-first", "1"),
            RequestHeader::new("SEC-CH-UA-MOBILE", "?1"),
        ];
        let expanded = expand(&template.http2_fields, &caller, Some(&hints), true);
        let prepared = prepare_fields(&hints, None, None, expanded, Some(&prepare(&template)));
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
