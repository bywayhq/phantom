use std::time::Duration;

use phantom_net::request::RequestHeader;
use phantom_profile::{
    ClientProfile, Http3ClientSettings, RequestField, RequestTemplate, browser::chrome,
};

use crate::{Client, HttpProtocol, RetryPolicy, SseErrorKind};

use super::{
    SseHeader, default_headers, effective_retry, resolve_template, validate_client_fields,
    validate_template,
};

#[test]
fn default_headers_preserve_protocol_spelling_and_order() {
    for (protocol, expected_names) in [
        (HttpProtocol::Http1, ["Accept", "Cache-Control"]),
        (HttpProtocol::Http2, ["accept", "cache-control"]),
        (HttpProtocol::Http3, ["accept", "cache-control"]),
    ] {
        let headers = resolve_template(&default_headers(protocol), protocol, "");
        assert_eq!(names(&headers), expected_names);
        assert_eq!(headers[0].value(), b"text/event-stream");
        assert_eq!(headers[1].value(), b"no-cache");
    }
}

#[test]
fn placeholder_emits_the_committed_id_at_its_position_with_caller_spelling() {
    let template = vec![
        field("Accept", "text/event-stream"),
        SseHeader::last_event_id("last-EVENT-id"),
        field("Referer", "http://origin.test/"),
    ];

    let headers = resolve_template(&template, HttpProtocol::Http1, "é-☃");

    assert_eq!(names(&headers), ["Accept", "last-EVENT-id", "Referer"]);
    assert_eq!(headers[1].value(), "é-☃".as_bytes());
}

#[test]
fn empty_committed_id_omits_the_placeholder_field() {
    let template = vec![
        field("Accept", "text/event-stream"),
        SseHeader::last_event_id("Last-Event-ID"),
        field("Referer", "http://origin.test/"),
    ];

    let headers = resolve_template(&template, HttpProtocol::Http1, "");

    assert_eq!(names(&headers), ["Accept", "Referer"]);
}

#[test]
fn template_without_placeholder_appends_a_nonempty_id_last() {
    for (protocol, expected) in [
        (HttpProtocol::Http1, "Last-Event-ID"),
        (HttpProtocol::Http2, "last-event-id"),
        (HttpProtocol::Http3, "last-event-id"),
    ] {
        let headers = resolve_template(&default_headers(protocol), protocol, "7");
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[2].name(), expected);
        assert_eq!(headers[2].value(), b"7");
        assert_eq!(
            resolve_template(&default_headers(protocol), protocol, "").len(),
            2
        );
    }
}

#[test]
fn template_validation_rejects_literal_repeated_and_misspelled_last_event_id() {
    let rejected = [
        (HttpProtocol::Http1, vec![field("last-event-id", "caller")]),
        (
            HttpProtocol::Http1,
            vec![
                SseHeader::last_event_id("Last-Event-ID"),
                SseHeader::last_event_id("Last-Event-ID"),
            ],
        ),
        (
            HttpProtocol::Http1,
            vec![SseHeader::last_event_id("Last-Event")],
        ),
        (
            HttpProtocol::Http1,
            vec![SseHeader::last_event_id("Last-Event-ID ")],
        ),
        (
            HttpProtocol::Http2,
            vec![SseHeader::last_event_id("Last-Event-ID")],
        ),
        (
            HttpProtocol::Http3,
            vec![SseHeader::last_event_id("Last-Event-ID")],
        ),
    ];
    for (protocol, template) in rejected {
        let error = validate_template(&template, protocol)
            .err()
            .unwrap_or_else(|| panic!("{protocol:?} accepted {template:?}"));
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    }

    for (protocol, name) in [
        (HttpProtocol::Http1, "Last-Event-ID"),
        (HttpProtocol::Http1, "LAST-EVENT-ID"),
        (HttpProtocol::Http2, "last-event-id"),
        (HttpProtocol::Http3, "last-event-id"),
    ] {
        let template = vec![SseHeader::last_event_id(name)];
        assert!(
            validate_template(&template, protocol).is_ok(),
            "{name} rejected"
        );
    }
}

#[test]
fn minimum_retry_raises_only_shorter_delays() {
    let minimum = Some(Duration::from_millis(500));
    assert_eq!(effective_retry(Duration::ZERO, None), Duration::ZERO);
    assert_eq!(
        effective_retry(Duration::from_millis(100), minimum),
        Duration::from_millis(500)
    );
    assert_eq!(
        effective_retry(Duration::from_millis(750), minimum),
        Duration::from_millis(750)
    );
}

#[test]
fn inherited_defaults_cannot_replace_an_empty_or_reset_managed_id() {
    for (field, conditions) in [
        (
            RequestField::literal("LaSt-EvEnT-ID", "unmanaged"),
            (true, false),
        ),
        (
            RequestField::trustworthy_only("last-event-id", "unmanaged"),
            (true, false),
        ),
        (
            RequestField::ByTrust {
                name: "last-event-id".into(),
                trustworthy: None,
                untrustworthy: Some("unmanaged".into()),
            },
            (false, false),
        ),
        (
            RequestField::unless_forwarded("last-event-id", "unmanaged"),
            (true, false),
        ),
        (
            RequestField::when_forwarded("last-event-id", "unmanaged"),
            (false, true),
        ),
    ] {
        let error = validate_client_fields(&[field], conditions)
            .err()
            .unwrap_or_else(|| panic!("an inherited Last-Event-ID default was accepted"));
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    }

    for field in [
        RequestField::caller("Last-Event-ID"),
        RequestField::ByTrust {
            name: "last-event-id".into(),
            trustworthy: None,
            untrustworthy: None,
        },
        RequestField::ByForwarding {
            name: "last-event-id".into(),
            unforwarded: None,
            forwarded: None,
        },
        RequestField::literal("x-other", "value"),
    ] {
        assert!(validate_client_fields(&[field], (true, false)).is_ok());
    }
}

#[test]
fn inherited_id_validation_checks_only_selected_protocols_and_enabled_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let mut template = empty_client_template();
    template
        .http1_fields
        .push(RequestField::literal("Last-Event-ID", "unmanaged"));
    let client = client_with_template(template.clone(), RetryPolicy::none())?;
    let uri = "https://example.test/events";

    let error = client
        .event_source(HttpProtocol::Http1, uri)?
        .request
        .validate_headers()
        .err()
        .ok_or("selected HTTP/1.1 default was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    for protocol in [HttpProtocol::Http2, HttpProtocol::Http3] {
        client
            .event_source(protocol, uri)?
            .request
            .validate_headers()?;
    }

    template.http1_fields.clear();
    template
        .http2_fields
        .push(RequestField::literal("last-event-id", "unmanaged"));
    let retry = RetryPolicy::none().with_http2_fallback(true);
    let client = client_with_template(template.clone(), retry)?;
    let error = client
        .event_source(HttpProtocol::Http3, uri)?
        .request
        .validate_headers()
        .err()
        .ok_or("enabled fallback default was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);

    for retry in [RetryPolicy::none(), retry.with_max_retries(Some(0))] {
        let client = client_with_template(template.clone(), retry)?;
        client
            .event_source(HttpProtocol::Http3, uri)?
            .request
            .validate_headers()?;
    }
    Ok(())
}

#[test]
fn inherited_conditional_defaults_use_the_resolved_url_and_effective_route()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{EnvironmentProxies, HttpProxy, Route};

    let proxy = Route::HttpProxy(HttpProxy::new("http://proxy.test:8080")?);
    for (field, uri, route, rejected) in [
        (
            RequestField::ByTrust {
                name: "Last-Event-ID".into(),
                trustworthy: None,
                untrustworthy: Some("unmanaged".into()),
            },
            "events",
            Route::Direct,
            false,
        ),
        (
            RequestField::ByTrust {
                name: "Last-Event-ID".into(),
                trustworthy: None,
                untrustworthy: Some("unmanaged".into()),
            },
            "http://example.test/events",
            Route::Direct,
            true,
        ),
        (
            RequestField::trustworthy_only("Last-Event-ID", "unmanaged"),
            "http://example.test/events",
            Route::Direct,
            false,
        ),
        (
            RequestField::trustworthy_only("Last-Event-ID", "unmanaged"),
            "events",
            Route::Direct,
            true,
        ),
        (
            RequestField::when_forwarded("Last-Event-ID", "unmanaged"),
            "http://example.test/events",
            Route::Direct,
            false,
        ),
        (
            RequestField::when_forwarded("Last-Event-ID", "unmanaged"),
            "http://example.test/events",
            proxy.clone(),
            true,
        ),
        (
            RequestField::when_forwarded("Last-Event-ID", "unmanaged"),
            "events",
            proxy.clone(),
            false,
        ),
        (
            RequestField::unless_forwarded("Last-Event-ID", "unmanaged"),
            "http://example.test/events",
            proxy.clone(),
            false,
        ),
    ] {
        let mut template = empty_client_template();
        template.http1_fields.push(field);
        let client = Client::builder(
            ClientProfile::new(chrome::v154_tcp_tls()).with_request_template(template),
        )
        .base_url("https://example.test/")?
        .redirect_policy(crate::RedirectPolicy::limited(std::num::NonZeroUsize::MIN))
        .environment_proxies(EnvironmentProxies::from_values([(
            "http_proxy",
            "http://environment.test:8080",
        )])?)
        .build()?;
        let result = client
            .event_source(HttpProtocol::Http1, uri)?
            .route(route)
            .request
            .validate_headers();
        assert_eq!(
            result.err().map(|error| error.kind()),
            rejected.then_some(SseErrorKind::InvalidRequestHeader),
            "{uri}"
        );
    }
    Ok(())
}

#[test]
fn automatic_managed_id_hints_are_rejected_only_where_hints_can_be_emitted()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    for delivery in [ClientHintDelivery::Default, ClientHintDelivery::AcceptCh] {
        let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_client_hints(
            ClientHintSettings::new(vec![ClientHint::new(
                "last-event-id",
                "unmanaged-canary",
                delivery,
            )]),
        );
        let client = Client::builder(profile.clone())
            .base_url("https://example.test/")?
            .build()?;
        let error = client
            .event_source(HttpProtocol::Http1, "https://example.test/events")?
            .request
            .validate_headers()
            .err()
            .ok_or("managed-ID automatic hint was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);

        let error = client
            .event_source(HttpProtocol::Http1, "events")?
            .request
            .validate_headers()
            .err()
            .ok_or("resolved base URL enabled a managed-ID hint")?;
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);

        client
            .event_source(HttpProtocol::Http1, "http://example.test/events")?
            .request
            .validate_headers()?;
        let client = Client::builder(profile)
            .redirect_policy(crate::RedirectPolicy::limited(std::num::NonZeroUsize::MIN))
            .build()?;
        client
            .event_source(HttpProtocol::Http1, "http://example.test/events")?
            .request
            .validate_headers()?;
    }

    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_client_hints(ClientHintSettings::new(vec![ClientHint::new(
            "last-event-id",
            "unmanaged-canary",
            ClientHintDelivery::AcceptCh,
        )]))
        .with_request_template(empty_client_template());
    let client = Client::builder(profile).build()?;
    client
        .event_source(HttpProtocol::Http1, "https://example.test/events")?
        .request
        .validate_headers()?;
    Ok(())
}

#[test]
fn managed_hint_exclusions_preserve_indices_and_ordinary_hint_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{RequestErrorKind, authority::Endpoint, session::client_hints::RestartHints};
    use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    let hints = ClientHintSettings::new(vec![
        ClientHint::new(
            "last-event-id",
            "unmanaged-canary",
            ClientHintDelivery::AcceptCh,
        ),
        ClientHint::new(
            "sec-ch-ua-arch",
            "normal-canary",
            ClientHintDelivery::AcceptCh,
        ),
    ]);
    let client = Client::builder(
        ClientProfile::new(chrome::v154_tcp_tls()).with_client_hints(hints.clone()),
    )
    .build()?;
    let endpoint = Endpoint::new("example.test".parse()?, 443)?;
    let context = client.client_hint_context(&endpoint, "https://example.test", &hints);
    let managed = context.with_managed_headers(&["last-event-id"]);
    assert_eq!(
        managed.connection_restart(&[], Some(b"last-event-id")),
        None
    );
    assert_eq!(
        managed
            .connection_restart(&[], Some(b"last-event-id, sec-ch-ua-arch"))
            .as_deref(),
        Some(&[1][..])
    );
    let mut restart = RestartHints::default();
    restart.add(&[0, 1]);
    let fields = managed
        .with_restart_hints(&restart)
        .prepare(vec![RequestHeader::new("Last-Event-ID", "committed")])?;
    assert_eq!(names(&fields), ["Last-Event-ID", "sec-ch-ua-arch"]);
    assert_eq!(fields[0].value(), b"committed");
    assert_eq!(fields[1].value(), b"normal-canary");

    let template = crate::PreparedRequestTemplate::new(empty_client_template())?;
    let caller = vec![RequestHeader::new("Last-Event-ID", "committed")];
    assert_eq!(
        context
            .with_template(Some(&template))
            .prepare(caller.clone())
            .err()
            .map(|error| error.kind()),
        Some(RequestErrorKind::RequestTemplate)
    );
    let fields = managed.with_template(Some(&template)).prepare(caller)?;
    assert_eq!(names(&fields), ["Last-Event-ID"]);
    assert_eq!(fields[0].value(), b"committed");
    Ok(())
}

#[test]
fn protected_critical_hint_does_not_retry_but_ordinary_hints_still_do()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::authority::Endpoint;
    use http::{HeaderMap, HeaderValue};
    use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    let hints = ClientHintSettings::new(vec![
        ClientHint::new(
            "last-event-id",
            "unmanaged-canary",
            ClientHintDelivery::AcceptCh,
        ),
        ClientHint::new(
            "sec-ch-ua-arch",
            "normal-canary",
            ClientHintDelivery::AcceptCh,
        ),
    ]);
    let client = Client::builder(
        ClientProfile::new(chrome::v154_tcp_tls()).with_client_hints(hints.clone()),
    )
    .build()?;
    let endpoint = Endpoint::new("example.test".parse()?, 443)?;
    let mut response = HeaderMap::new();
    response.insert("accept-ch", HeaderValue::from_static("last-event-id"));
    response.insert("critical-ch", HeaderValue::from_static("last-event-id"));
    assert!(!client.learn_client_hints_and_should_retry(
        &endpoint,
        true,
        &hints,
        &response,
        &[],
        &["last-event-id"]
    ));
    let context = client.client_hint_context(&endpoint, "https://example.test", &hints);
    assert!(
        context
            .with_managed_headers(&["last-event-id"])
            .prepare(vec![])?
            .is_empty()
    );
    let ordinary = context.prepare(vec![])?;
    assert_eq!(names(&ordinary), ["last-event-id"]);
    assert_eq!(ordinary[0].value(), b"unmanaged-canary");
    assert!(client.learn_client_hints_and_should_retry(
        &endpoint,
        true,
        &hints,
        &response,
        &[],
        &[]
    ));
    response.insert(
        "accept-ch",
        HeaderValue::from_static("last-event-id, sec-ch-ua-arch"),
    );
    response.insert("critical-ch", HeaderValue::from_static("sec-ch-ua-arch"));
    assert!(client.learn_client_hints_and_should_retry(
        &endpoint,
        true,
        &hints,
        &response,
        &[],
        &["last-event-id"]
    ));
    Ok(())
}

fn empty_client_template() -> RequestTemplate {
    RequestTemplate {
        http1_fields: Vec::new(),
        http2_fields: Vec::new(),
        http3_fields: Some(Vec::new()),
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}

fn client_with_template(
    template: RequestTemplate,
    retry: RetryPolicy,
) -> Result<Client, crate::BuildError> {
    Client::builder(
        ClientProfile::new(chrome::v154_tcp_tls())
            .with_http2(chrome::v154_http2())
            .with_http3(Http3ClientSettings::new(
                chrome::v154_quic_tls(),
                chrome::v154_quic(),
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            ))
            .with_request_template(template),
    )
    .retry_policy(retry)
    .build()
}

fn field(name: &str, value: &str) -> SseHeader {
    SseHeader::field(RequestHeader::new(name, value))
}

fn names(headers: &[RequestHeader]) -> Vec<&str> {
    headers.iter().map(RequestHeader::name).collect()
}
