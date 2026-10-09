//! Compile consumer workflows using only dependencies declared by the consumer.

use std::{error::Error, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, EnvironmentProxies, HttpProtocol, Method, MultipartPart, PreparedRequestBody,
    PreparedRequestTemplate, RequestBuilder, RequestError, RequestHeader, RequestReplayObservation,
    RequestTimeoutOverrides, RequestTimeouts, RetryPolicy, Route, TimeoutOverride,
    profile::browser::chrome,
};

type ConsumerResult<T> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn reusable_client_prepares_a_bounded_upload_with_explicit_route_and_deadlines()
-> ConsumerResult<()> {
    let profile = chrome::v154_windows();
    let snapshot = EnvironmentProxies::from_values([
        ("https_proxy", "http://127.0.0.1:8080"),
        ("no_proxy", "example.test,.internal.example,127.0.0.0/8"),
    ])?;
    let client = Client::builder(profile)
        .environment_proxies(snapshot)
        .request_timeouts(RequestTimeouts::new().connect(Duration::from_secs(5)))
        .build()?;
    let cloned = client.clone();
    let template = PreparedRequestTemplate::new(chrome::v154_windows_fetch_upload_template())?;
    let body = PreparedRequestBody::form([("tag", "first"), ("tag", "second")], 1024)?;
    let _request = cloned
        .request(
            HttpProtocol::Http2,
            Method::POST,
            "https://example.test/upload",
        )?
        .route(Route::Direct)
        .template(&template)
        .fill_slots(|slots| {
            slots.fill(RequestHeader::new("origin", "https://example.test"))?;
            slots.fill(RequestHeader::new("referer", "https://example.test/page"))
        })?
        .prepared_body(body)
        .timeouts(
            RequestTimeoutOverrides::new()
                .read_idle(TimeoutOverride::Disabled)
                .total(TimeoutOverride::Limit(Duration::from_secs(30))),
        )
        .retry_policy(
            RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO)
                .with_max_retries(Some(1)),
        );
    Ok(())
}

#[test]
fn body_link_and_checked_settings_types_are_available_without_transitive_imports()
-> ConsumerResult<()> {
    let file = MultipartPart::bytes("file", b"contents")?
        .with_filename("report.txt")?
        .with_content_type("text/plain")?;
    let body = PreparedRequestBody::multipart("consumer-boundary", [file], 1024)?;
    assert_eq!(
        body.content_type(),
        "multipart/form-data; boundary=consumer-boundary"
    );
    let links = phantom::parse_link_headers([&b"</next>; rel=next"[..]], 1024)?;
    assert_eq!(links.len(), 1);
    let range = phantom::profile::TlsVersionRange::new(
        phantom::profile::TlsVersion::Tls12,
        phantom::profile::TlsVersion::Tls13,
    )?;
    let mut tls = chrome::v154_tcp_tls();
    tls.versions = range;
    tls.validate()?;
    Ok(())
}

#[cfg(feature = "json")]
#[test]
fn typed_json_body_uses_the_optional_public_helper() -> ConsumerResult<()> {
    let body = PreparedRequestBody::json(&["first", "second"], 1024)?;
    assert_eq!(body.bytes().as_ref(), br#"["first","second"]"#);
    Ok(())
}

#[allow(dead_code)]
fn inspect_error(error: &RequestError) -> bool {
    let _category = error.kind();
    let _origin = error
        .origin()
        .map(|origin| (origin.scheme(), origin.host(), origin.port()));
    let _cause: Option<&(dyn Error + 'static)> = error.source();
    matches!(
        error.replay_observation(),
        RequestReplayObservation::RequestUnprocessed
    )
}

#[allow(dead_code)]
async fn cancel_upload_after_one_poll(builder: RequestBuilder) {
    let mut pending = Box::pin(builder.send());
    std::future::poll_fn(|context| {
        let _first_poll = pending.as_mut().poll(context);
        std::task::Poll::Ready(())
    })
    .await;
    drop(pending);
}

#[cfg(feature = "sse")]
#[allow(dead_code)]
fn sse_sources_implement_the_reexported_stream_trait(
    stream: phantom::SseStream,
    source: phantom::SseEventSource,
) {
    fn assert_stream<T: phantom::Stream<Item = Result<phantom::SseEvent, phantom::SseError>>>(
        _value: T,
    ) {
    }
    assert_stream(stream);
    assert_stream(source);
}
