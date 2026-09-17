use std::num::NonZeroUsize;

use http::{HeaderMap, HeaderValue};
use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

use super::{ClientHintStore, OriginKey, parse_token_list, prepare_default_fields};
use crate::authority::Endpoint;

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
