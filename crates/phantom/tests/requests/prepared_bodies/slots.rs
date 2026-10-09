//! Public preparation hooks, body metadata, and placement across redirects.

use super::{BUDGET, TestResult, uploads::read_upload};
use crate::support::tls::tls_settings;
use phantom::{
    Client, HttpProtocol, HttpProxy, Method, PreparedRequestBody, PreparedRequestTemplate,
    RedirectPolicy, RequestErrorKind, RequestHeader, RequestSlotErrorKind, RetryPolicy, Route,
    profile::{ClientProfile, RequestField, RequestTemplate, browser::chrome},
};
use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};

fn slots_template(
    h2_slot: bool,
    h3_slot: bool,
) -> Result<PreparedRequestTemplate, phantom::profile::InvalidRequestTemplate> {
    let fields = |slot: bool| {
        let mut fields = vec![RequestField::literal("x-first", "first")];
        if slot {
            fields.push(RequestField::caller("x-token"));
        }
        fields.extend([
            RequestField::caller("content-type"),
            RequestField::caller("content-length"),
            RequestField::caller("authorization"),
            RequestField::literal("x-last", "last"),
        ]);
        fields
    };
    PreparedRequestTemplate::new(RequestTemplate {
        http1_fields: vec![
            RequestField::literal("X-First", "first"),
            RequestField::caller("X-Token"),
            RequestField::caller("Content-Type"),
            RequestField::caller("Content-Length"),
            RequestField::caller("Authorization"),
            RequestField::literal("X-Last", "last"),
        ],
        http2_fields: fields(h2_slot),
        http3_fields: Some(fields(h3_slot)),
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    })
}

async fn quiet(listener: &TcpListener) {
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "rejected request opened a connection"
    );
}

#[tokio::test]
async fn slot_hook_preserves_literal_order_and_redacts_sensitive_input() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/upload", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });
        let prepared = slots_template(true, true)?;
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        let secret = "PRIVATE_SLOT_VALUE";
        let request = client
            .request(HttpProtocol::Http1, Method::POST, &url)?
            .template(&prepared)
            .fill_slots(|slots| {
                for name in ["X-First", "x-arbitrary", "sec-ch-ua", "Proxy-Authorization"] {
                    assert_eq!(
                        slots
                            .fill(RequestHeader::new(name, secret))
                            .map_err(|error| error.kind()),
                        Err(RequestSlotErrorKind::Undeclared)
                    );
                }
                let invalid = slots.fill(RequestHeader::new(
                    "x-ToKeN",
                    b"PRIVATE_BAD_VALUE\r\nInjected: true",
                ));
                assert!(!format!("{invalid:?}").contains("PRIVATE_BAD_VALUE"));
                assert_eq!(
                    invalid.map_err(|error| error.kind()),
                    Err(RequestSlotErrorKind::InvalidValue)
                );
                assert!(!slots.is_filled("X-TOKEN"));
                slots.fill(RequestHeader::new("x-ToKeN", secret).sensitive())?;
                assert!(slots.is_filled("X-TOKEN"));
                assert_eq!(
                    slots
                        .fill(RequestHeader::new("X-TOKEN", "duplicate"))
                        .map_err(|error| error.kind()),
                    Err(RequestSlotErrorKind::AlreadyFilled)
                );
                assert!(!format!("{slots:?}").contains(secret));
                Ok(())
            })?
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?);
        assert!(!format!("{request:?}").contains(secret));
        assert_eq!(
            request.send().await?.status(),
            phantom::StatusCode::NO_CONTENT
        );
        let observed = server.await??;
        let names: Vec<_> = observed
            .fields
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "X-First",
                "X-Token",
                "Content-Type",
                "Content-Length",
                "X-Last"
            ]
        );
        assert_eq!(observed.value("x-token"), Some(secret.as_bytes()));
        assert_eq!(observed.body, b"a=b");
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cross_origin_307_strips_slot_credentials_without_rerunning_hook() -> TestResult<()> {
    timeout(BUDGET, async {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let first_url = format!("http://{}/first", first.local_addr()?);
        let second_url = format!("http://{}/second", second.local_addr()?);
        let first_peer = tokio::spawn(async move {
            let (stream, _) = first.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;
            stream.get_mut().write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {second_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });
        let second_peer = tokio::spawn(async move {
            let (stream, _) = second.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;
            stream.get_mut().write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN)).build()?;
        let count = Arc::new(AtomicUsize::new(0));
        let marker = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let token = format!("{marker:032x}");
        let authorization = format!("Bearer {token}");
        let body = PreparedRequestBody::form([("tag", "first"), ("tag", "last")], 128)?;
        let request = client.request(HttpProtocol::Http1, Method::POST, &first_url)?
            .template(&slots_template(true, true)?)
            .fill_slots(|slots| {
                count.fetch_add(1, Ordering::SeqCst);
                slots.fill(RequestHeader::new("Authorization", authorization.clone()).sensitive())?;
                slots.fill(RequestHeader::new("X-Token", "ordinary-value").sensitive())?;
                Ok(())
            })?.prepared_body(body.clone());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!format!("{request:?}").contains(&token));
        assert_eq!(request.send().await?.status(), phantom::StatusCode::NO_CONTENT);
        let initial = first_peer.await??;
        let redirected = second_peer.await??;
        assert_eq!(initial.value("authorization"), Some(authorization.as_bytes()));
        assert_eq!(redirected.value("authorization"), None);
        assert_eq!(redirected.value("x-token"), Some(&b"ordinary-value"[..]));
        for observed in [initial, redirected] {
            assert_eq!(observed.method, b"POST");
            assert_eq!(observed.body, body.bytes().as_ref());
            assert_eq!(observed.value("content-type"), Some(body.content_type().as_bytes()));
            assert_eq!(observed.value("content-length"), Some(body.bytes().len().to_string().as_bytes()));
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        Ok(())
    }).await?
}

#[tokio::test]
async fn prepared_body_rejects_literal_conflicting_and_duplicate_content_types_before_io()
-> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/upload", listener.local_addr()?);
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        for case in 0..3 {
            let body = PreparedRequestBody::form([("a", "b")], 128)?;
            let mut template = RequestTemplate {
                http1_fields: vec![RequestField::caller("Content-Type")],
                http2_fields: vec![],
                http3_fields: None,
                http2_priority: None,
                requested_client_hint_placement: false,
                restarts_for_connection_accept_ch: false,
            };
            if case == 0 {
                template.http1_fields[0] =
                    RequestField::literal("Content-Type", body.content_type());
            }
            let prepared = PreparedRequestTemplate::new(template)?;
            let mut request = client
                .request(HttpProtocol::Http1, Method::POST, &url)?
                .template(&prepared);
            if case == 1 {
                request = request.header(RequestHeader::new("Content-Type", "application/wrong"));
            }
            if case == 2 {
                request = request
                    .header(RequestHeader::new("Content-Type", body.content_type()))
                    .header(RequestHeader::new("content-TYPE", body.content_type()));
            }
            let error = request
                .prepared_body(body)
                .send()
                .await
                .err()
                .ok_or("invalid content type succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::InvalidHeader, "case {case}");
        }
        quiet(&listener).await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn filled_slots_reject_later_template_removal_or_changed_protocol_scope_before_io()
-> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/upload", listener.local_addr()?);
        let client = Client::builder(super::profile())
            .alt_svc(NonZeroUsize::MIN)
            .build()?;
        let all = slots_template(true, true)?;
        let h3_only = slots_template(false, true)?;
        let no_h3_slot = slots_template(true, false)?;
        let request = client
            .request(HttpProtocol::Http1, Method::GET, &url)?
            .template(&all)
            .fill_slots(|slots| slots.fill(RequestHeader::new("X-Token", "value")))?
            .without_template();
        assert_eq!(
            request
                .send()
                .await
                .err()
                .ok_or("removed template sent hook field")?
                .kind(),
            RequestErrorKind::RequestTemplate
        );
        let request = client
            .request(HttpProtocol::Http3, Method::GET, &url)?
            .template(&h3_only)
            .fill_slots(|slots| slots.fill(RequestHeader::new("X-Token", "value")))?
            .retry_policy(RetryPolicy::none().with_http2_fallback(true));
        assert_eq!(
            request
                .send()
                .await
                .err()
                .ok_or("changed fallback scope sent hook field")?
                .kind(),
            RequestErrorKind::RequestTemplate
        );
        let request = client
            .request(HttpProtocol::Http3, Method::GET, &url)?
            .template(&all)
            .retry_policy(RetryPolicy::none().with_http2_fallback(true))
            .fill_slots(|slots| slots.fill(RequestHeader::new("X-Token", "value")))?
            .template(&h3_only);
        assert_eq!(
            request
                .send()
                .await
                .err()
                .ok_or("changed template sent unplaced field")?
                .kind(),
            RequestErrorKind::RequestTemplate
        );
        let proxy = Route::http_proxy(HttpProxy::new(&format!(
            "http://{}",
            listener.local_addr()?
        ))?);
        let request = client
            .request_negotiated(Method::GET, &url)?
            .route(proxy)
            .template(&no_h3_slot)
            .fill_slots(|slots| slots.fill(RequestHeader::new("X-Token", "value")))?
            .route(Route::direct());
        assert_eq!(
            request
                .send()
                .await
                .err()
                .ok_or("changed route sent unplaced field")?
                .kind(),
            RequestErrorKind::RequestTemplate
        );
        // With fallback enabled up front, an H3-only slot is never exposed.
        let error = client
            .request(HttpProtocol::Http3, Method::GET, &url)?
            .template(&h3_only)
            .retry_policy(RetryPolicy::none().with_http2_fallback(true))
            .fill_slots(|slots| slots.fill(RequestHeader::new("X-Token", "value")))
            .err()
            .ok_or("hook accepted slot missing from reachable H2")?;
        assert_eq!(error.kind(), RequestSlotErrorKind::Undeclared);
        quiet(&listener).await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn named_upload_template_rejects_uncaptured_http3_before_io() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/upload", listener.local_addr()?);
        let client = Client::builder(super::profile()).build()?;
        let body = PreparedRequestBody::form([("a", "b")], 128)?;
        let prepared = PreparedRequestTemplate::new(chrome::v154_windows_fetch_upload_template())?;
        let error = client
            .request(HttpProtocol::Http3, Method::POST, &url)?
            .template(&prepared)
            .header(RequestHeader::new("Origin", "https://127.0.0.1"))
            .header(RequestHeader::new("Referer", "https://127.0.0.1/start"))
            .header(RequestHeader::new("Content-Type", body.content_type()))
            .prepared_body(body)
            .send()
            .await
            .err()
            .ok_or("uncaptured H3 upload succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
        quiet(&listener).await;
        Ok(())
    })
    .await?
}
