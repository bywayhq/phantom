use bytes::Bytes;
use phantom_net::request::{RequestBody, RequestHeader, RequestTrailerName};

use super::{
    ProtocolSelection, RequestBodySource, ResolvedRequest, contains_caller_alt_used,
    declares_alt_used_trailer, ensure_request_supported,
};
use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route, Socks5Proxy};

#[test]
fn new_requests_share_the_prepared_profile_default() -> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{ClientProfile, browser::chrome};

    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_request_template(chrome::v154_windows_navigation_template());
    let client = crate::Client::builder(profile).build()?;
    let prepared = client
        .inner
        .request_template
        .as_ref()
        .ok_or("default was not prepared")?;
    for request in [
        client.get(HttpProtocol::Http1, "https://example.com/")?,
        client.request(
            HttpProtocol::Http2,
            http::Method::POST,
            "https://example.com/",
        )?,
        client.get_negotiated("https://example.com/")?,
        client.request_negotiated(http::Method::POST, "https://example.com/")?,
    ] {
        let inherited = request
            .request
            .template
            .as_ref()
            .ok_or("default was not inherited")?;
        assert!(std::ptr::eq(
            prepared
                .fields_for(HttpProtocol::Http1)
                .ok_or("missing H1 fields")?,
            inherited
                .fields_for(HttpProtocol::Http1)
                .ok_or("missing H1 fields")?,
        ));
    }
    Ok(())
}

#[test]
fn template_override_and_opt_out_apply_only_to_the_current_request()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{ClientProfile, browser::chrome};

    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_request_template(chrome::v154_windows_navigation_template());
    let client = crate::Client::builder(profile).build()?;
    let explicit =
        crate::PreparedRequestTemplate::new(chrome::v154_windows_fetch_no_store_template())?;
    let request = client
        .get(HttpProtocol::Http1, "https://example.com/")?
        .without_template()
        .template(&explicit);
    let applied = request
        .request
        .template
        .as_ref()
        .ok_or("explicit template was not restored")?;
    assert!(std::ptr::eq(
        explicit
            .fields_for(HttpProtocol::Http1)
            .ok_or("missing H1 fields")?,
        applied
            .fields_for(HttpProtocol::Http1)
            .ok_or("missing H1 fields")?,
    ));
    assert!(request.without_template().request.template.is_none());
    assert!(
        client
            .get(HttpProtocol::Http1, "https://example.com/")?
            .request
            .template
            .is_some()
    );
    let no_default = crate::Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?;
    assert!(
        no_default
            .get(HttpProtocol::Http1, "https://example.com/")?
            .request
            .template
            .is_none()
    );
    Ok(())
}

#[test]
fn appending_queries_keeps_raw_targets_and_normalized_redirect_state()
-> Result<(), Box<dyn std::error::Error>> {
    let original = "https://example.test/a/%2e%2e/final?x=%2f+old&bare&x=second&&";
    let mut request = ResolvedRequest::new(&original.parse()?)?;
    let endpoint = request.endpoint.clone();
    request.append_query("x=new&empty=&=value")?;
    let expected = format!("{original}&x=new&empty=&=value");
    assert_eq!(request.uri.to_string(), expected);
    assert_eq!(request.endpoint, endpoint);
    assert_eq!(
        request.target,
        phantom_net::request::OriginForm::parse(
            "/a/%2e%2e/final?x=%2f+old&bare&x=second&&&x=new&empty=&=value"
        )?
    );
    assert_eq!(
        request.absolute_target,
        phantom_net::request::AbsoluteForm::parse(&expected)?
    );
    assert_eq!(
        request.url.query(),
        Some("x=%2f+old&bare&x=second&&&x=new&empty=&=value")
    );
    assert_eq!(
        request.url.join("?follow=next")?.as_str(),
        "https://example.test/final?follow=next"
    );
    Ok(())
}

#[test]
fn failed_query_updates_leave_all_resolved_fields_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = ResolvedRequest::new(&"https://example.test/old?q=original".parse()?)?;
    let original_uri = request.uri.clone();
    let original_url = request.url.clone();
    let original_target = request.target.clone();
    let original_absolute_target = request.absolute_target.clone();
    request.expect_continue = Some(std::time::Duration::from_millis(37));
    request.alternative = super::PinnedAlternative::parse("alternative.test", 443);
    let original_alternative = request.alternative.clone();
    let error = request
        .append_query("invalid\r\nquery")
        .err()
        .ok_or("invalid URI accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidUri);
    assert_eq!(request.uri, original_uri);
    assert_eq!(request.url, original_url);
    assert_eq!(request.target, original_target);
    assert_eq!(request.absolute_target, original_absolute_target);
    assert_eq!(
        request.expect_continue,
        Some(std::time::Duration::from_millis(37))
    );
    assert_eq!(request.alternative, original_alternative);
    Ok(())
}

#[test]
fn query_pairs_keep_template_choices_body_waits_and_pinned_alternatives()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{ClientProfile, browser::chrome};

    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_request_template(chrome::v154_windows_navigation_template());
    let client = crate::Client::builder(profile).build()?;
    let explicit =
        crate::PreparedRequestTemplate::new(chrome::v154_windows_fetch_no_store_template())?;
    let default = client
        .inner
        .request_template
        .as_ref()
        .ok_or("missing default")?;
    let wait = std::time::Duration::from_millis(37);
    let mut initial = client
        .get(HttpProtocol::Http1, "https://example.test/path?old=%2f")?
        .body("payload")
        .expect_continue(wait)
        .alt_svc_alternative("alternative.test", 8443);
    initial.request.alternative = super::PinnedAlternative::parse("resolved.test", 9443);
    let original_alternative = initial.request.alternative.clone();
    for (request, expected_template) in [
        (initial, Some(default)),
        (
            client
                .get(HttpProtocol::Http1, "https://example.test/path")?
                .template(&explicit),
            Some(&explicit),
        ),
        (
            client
                .get(HttpProtocol::Http1, "https://example.test/path")?
                .without_template(),
            None,
        ),
    ] {
        let old_wait = request.request.expect_continue;
        let old_body_len = request.body.exact_length();
        let old_builder_alternative = request.alternative.clone();
        let old_resolved_alternative = request.request.alternative.clone();
        let request = request.query_pairs([("q", "one"), ("q", "two")])?;
        assert_eq!(request.request.expect_continue, old_wait);
        assert_eq!(request.body.exact_length(), old_body_len);
        assert_eq!(request.alternative, old_builder_alternative);
        assert_eq!(request.request.alternative, old_resolved_alternative);
        if old_wait.is_some() {
            assert_eq!(request.request.alternative, original_alternative);
            assert_eq!(request.alternative, Some(("alternative.test".into(), 8443)));
        }
        match expected_template {
            Some(expected) => assert!(std::ptr::eq(
                expected
                    .fields_for(HttpProtocol::Http1)
                    .ok_or("missing H1 fields")?,
                request
                    .request
                    .template
                    .as_ref()
                    .ok_or("template lost")?
                    .fields_for(HttpProtocol::Http1)
                    .ok_or("missing H1 fields")?,
            )),
            None => assert!(request.request.template.is_none()),
        }
    }
    Ok(())
}

#[test]
fn empty_query_inputs_preserve_the_existing_empty_query_marker()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{ClientProfile, browser::chrome};
    let client = crate::Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?;
    for original in ["https://example.test/path", "https://example.test/path?"] {
        let request = client
            .get(HttpProtocol::Http1, original)?
            .query_pairs(std::iter::empty::<(&str, &str)>())?;
        assert_eq!(request.request.uri.to_string(), original);
        assert_eq!(
            request.query_pairs([("", "")])?.request.uri.to_string(),
            "https://example.test/path?="
        );
    }
    Ok(())
}

#[test]
fn streaming_body_cannot_be_replayed_for_a_second_attempt() {
    let mut body = RequestBodySource::Streaming(Some(RequestBody::from_bytes(Bytes::from_static(
        b"payload",
    ))));

    assert!(matches!(body.next_attempt(), Ok(Some(_))));
    let error = match body.next_attempt() {
        Ok(_) => panic!("second attempt accepted a consumed stream"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RequestBody);
}

/// Reads one attempt's body to its end or first error.
fn drain(body: &mut RequestBody) -> Result<Vec<u8>, ()> {
    use http_body::Body as _;
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut sent = Vec::new();
    loop {
        match std::pin::Pin::new(&mut *body).poll_frame(&mut context) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    sent.extend_from_slice(&data);
                }
            }
            std::task::Poll::Ready(Some(Err(_))) => return Err(()),
            std::task::Poll::Ready(None) => return Ok(sent),
            std::task::Poll::Pending => return Err(()),
        }
    }
}

#[test]
fn a_buffered_body_is_replayable_within_its_limit_and_not_past_it() {
    let full = |bytes: &'static [u8]| http_body_util::Full::new(Bytes::from_static(bytes));
    let mut within =
        RequestBodySource::Buffered(super::ReplayBuffer::new(full(b"payload"), Vec::new(), 7));
    for _ in 0..2 {
        let Ok(Some(mut attempt)) = within.next_attempt() else {
            panic!("a buffered body within its limit was refused");
        };
        assert_eq!(drain(&mut attempt), Ok(b"payload".to_vec()));
        assert!(within.can_replay());
    }

    let mut past =
        RequestBodySource::Buffered(super::ReplayBuffer::new(full(b"payload"), Vec::new(), 6));
    let Ok(Some(mut attempt)) = past.next_attempt() else {
        panic!("the first attempt was refused");
    };
    assert_eq!(drain(&mut attempt), Ok(b"payload".to_vec()));
    assert!(!past.can_replay());
    let error = match past.next_attempt() {
        Ok(_) => panic!("a body past its limit was sent again"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RequestBody);
    assert!(error.to_string().contains("replay limit"));
}

/// A body whose first poll fails.
struct Failing;

impl http_body::Body for Failing {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        std::task::Poll::Ready(Some(Err(std::io::Error::other("source failed"))))
    }
}

#[test]
fn a_buffered_body_whose_source_failed_is_not_sent_again() {
    let mut body = RequestBodySource::Buffered(super::ReplayBuffer::new(Failing, Vec::new(), 64));
    let Ok(Some(mut attempt)) = body.next_attempt() else {
        panic!("the first attempt was refused");
    };
    assert_eq!(drain(&mut attempt), Err(()));
    assert!(!body.can_replay());
    let error = match body.next_attempt() {
        Ok(_) => panic!("a failed body was sent again"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::RequestBody);
    assert!(error.to_string().contains("one-shot"));
}

#[test]
fn recognizes_alt_used_in_each_caller_controlled_field_source() {
    assert!(contains_caller_alt_used(
        &[RequestHeader::new("ALT-USED", "alt.example:443")],
        &[],
        false,
    ));
    assert!(contains_caller_alt_used(
        &[],
        &[RequestHeader::new("Alt-Used", "alt.example:443")],
        false,
    ));
    assert!(declares_alt_used_trailer(&[RequestTrailerName::new(
        "alt-used",
    )]));
    assert!(contains_caller_alt_used(&[], &[], true));
    assert!(!contains_caller_alt_used(
        &[RequestHeader::new("x-field", "value")],
        &[RequestHeader::new("x-trailer", "value")],
        false,
    ));
}

#[test]
fn http_proxy_routes_reject_http3_without_network_io() -> Result<(), Box<dyn std::error::Error>> {
    let routes = [Route::http_proxy(HttpProxy::new("http://127.0.0.1:9")?)];
    let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

    for route in routes {
        let error = match ensure_request_supported(
            ProtocolSelection::Exact(HttpProtocol::Http3),
            &route,
            &request,
        ) {
            Ok(()) => panic!("HTTP proxy route accepted HTTP/3"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    }
    Ok(())
}

#[test]
fn local_dns_socks5_route_accepts_http3() -> Result<(), Box<dyn std::error::Error>> {
    let route = Route::socks5(Socks5Proxy::new("socks5://127.0.0.1:9")?);
    let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

    assert!(
        ensure_request_supported(
            ProtocolSelection::Exact(HttpProtocol::Http3),
            &route,
            &request,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn remote_dns_socks5_route_accepts_http3() -> Result<(), Box<dyn std::error::Error>> {
    let route = Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?);
    let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

    assert!(
        ensure_request_supported(
            ProtocolSelection::Exact(HttpProtocol::Http3),
            &route,
            &request,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn connect_udp_route_accepts_only_exact_http3() -> Result<(), Box<dyn std::error::Error>> {
    let route = Route::connect_udp(crate::ConnectUdpProxy::new(
        "https://127.0.0.1:9/masque/{target_host}/{target_port}/",
    )?);
    let secure = ResolvedRequest::new(&"https://example.test/".parse()?)?;
    let plaintext = ResolvedRequest::new(&"http://example.test/".parse()?)?;

    assert!(
        ensure_request_supported(
            ProtocolSelection::Exact(HttpProtocol::Http3),
            &route,
            &secure,
        )
        .is_ok()
    );
    for (selection, request, protocol) in [
        (
            ProtocolSelection::Exact(HttpProtocol::Http1),
            &secure,
            Some(HttpProtocol::Http1),
        ),
        (
            ProtocolSelection::Exact(HttpProtocol::Http2),
            &secure,
            Some(HttpProtocol::Http2),
        ),
        (ProtocolSelection::Http1Or2, &secure, None),
        (
            ProtocolSelection::Exact(HttpProtocol::Http1),
            &plaintext,
            Some(HttpProtocol::Http1),
        ),
    ] {
        let error = match ensure_request_supported(selection, &route, request) {
            Ok(()) => panic!("CONNECT-UDP route accepted {selection:?}"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), protocol);
    }
    Ok(())
}

#[test]
fn direct_route_accepts_each_supported_protocol() -> Result<(), Box<dyn std::error::Error>> {
    let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;
    for protocol in [
        HttpProtocol::Http1,
        HttpProtocol::Http2,
        HttpProtocol::Http3,
    ] {
        assert!(
            ensure_request_supported(ProtocolSelection::Exact(protocol), &Route::Direct, &request,)
                .is_ok()
        );
    }
    Ok(())
}

#[test]
fn initial_uri_is_not_reserialized_through_whatwg_rules() -> Result<(), Box<dyn std::error::Error>>
{
    let uri = "https://example.test/a/%2e%2e/final?value=%2f".parse()?;
    let request = ResolvedRequest::new(&uri)?;

    assert_eq!(request.uri, uri);
    Ok(())
}

#[test]
fn initial_uri_uses_one_canonical_host_for_wire_and_url_state()
-> Result<(), Box<dyn std::error::Error>> {
    let uri = super::parse_absolute_uri("https://BÜCHER.Example:443/a/%2e%2e/final?value=%2f")?;
    let request = ResolvedRequest::new(&uri)?;

    assert_eq!(request.endpoint.host(), "xn--bcher-kva.example");
    assert_eq!(
        request.endpoint.authority().as_str(),
        "xn--bcher-kva.example:443"
    );
    assert_eq!(
        request.uri,
        "https://xn--bcher-kva.example:443/a/%2e%2e/final?value=%2f".parse::<http::Uri>()?
    );
    assert_eq!(
        request.url.origin().ascii_serialization(),
        "https://xn--bcher-kva.example"
    );
    Ok(())
}

#[test]
fn redirect_fragments_are_not_sent() -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse("https://example.test/final?value=yes#section")?;
    let request = ResolvedRequest::from_redirect_url(&url)?;

    assert_eq!(
        request.uri,
        "https://example.test/final?value=yes".parse::<http::Uri>()?
    );
    Ok(())
}

#[test]
fn redirect_url_retains_the_same_canonical_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse("https://BÜCHER.Example:8443/next")?;
    let request = ResolvedRequest::from_redirect_url(&url)?;

    assert_eq!(request.endpoint.host(), "xn--bcher-kva.example");
    assert_eq!(
        request.endpoint.authority().as_str(),
        "xn--bcher-kva.example:8443"
    );
    assert_eq!(request.url, url);
    Ok(())
}

/// A request's future holds every future on its path inline, and a debug
/// build's poll frames grow with them; see `phantom_testkit::future_size`.
///
/// With all features, the largest, `RequestBuilder::send_inner`, is
/// 15,264 bytes as measured on Windows (x86-64, Rust 1.99.0); other
/// platforms may differ. When this fails, for example after a toolchain
/// upgrade, run it with `--nocapture` to see every size, then box the
/// largest cold branch with `Box::pin`. Raise `FUTURE_BUDGET` only with the measurements
/// that justify it, and never box the path of an ordinary request.
#[cfg(debug_assertions)]
#[test]
fn request_futures_stay_within_the_stack_budget() {
    use phantom_testkit::future_size::{assert_within_budget, future_size};

    use super::{RequestBuilder, alt_svc_attempt, attempt};
    use crate::session::{
        http1_or_2_pool::Http1Or2Pool, http1_pool::Http1Pool, http2_pool::Http2Pool,
        http3_pool::Http3Pool,
    };

    assert_within_budget(&[
        ("RequestBuilder::send", future_size(&RequestBuilder::send)),
        (
            "RequestBuilder::send_inner",
            future_size(&RequestBuilder::send_inner),
        ),
        ("send_once", future_size(&attempt::send_once)),
        ("send_once_origin", future_size(&attempt::send_once_origin)),
        (
            "send_once_alt_svc",
            future_size(&alt_svc_attempt::send_once_alt_svc),
        ),
        (
            "send_once_raced",
            future_size(&alt_svc_attempt::send_once_raced),
        ),
        (
            "Http1Pool::send_request",
            future_size(&Http1Pool::send_request),
        ),
        (
            "Http2Pool::send_request",
            future_size(&Http2Pool::send_request),
        ),
        (
            "Http1Or2Pool::send_request",
            future_size(&Http1Or2Pool::send_request),
        ),
        (
            "Http3Pool::send_request",
            future_size(&Http3Pool::send_request),
        ),
        (
            "Http3Pool::send_request_on_lease",
            future_size(&Http3Pool::send_request_on_lease),
        ),
    ]);
}
