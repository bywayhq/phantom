use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom::{
    Client, HeaderHookError, HttpProtocol, PreparedRequestBody, RedirectPolicy, RequestErrorKind,
    RequestHeader,
    profile::{ClientProfile, RequestField, RequestTemplate},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::tls::{TestResult, read_head, tls_settings};

#[tokio::test]
async fn base_urls_and_hooks_preserve_template_order_and_request_overrides() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut heads = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });
        let template = RequestTemplate {
            http1_fields: vec![
                RequestField::literal("X-First", "literal"),
                RequestField::caller("X-Token"),
                RequestField::literal("X-Last", "literal"),
            ],
            http2_fields: Vec::new(),
            http3_fields: None,
            http2_priority: None,
            requested_client_hint_placement: false,
            restarts_for_connection_accept_ch: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        let client =
            Client::builder(ClientProfile::new(tls_settings()).with_request_template(template))
                .base_url(&format!("http://{address}/api/"))?
                .header_hook(move |context| {
                    hook_calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(context.uri().path(), "/api/users");
                    assert_eq!(context.uri().query(), Some("page=2"));
                    context.set(RequestHeader::new("x-token", "first"))
                })
                .header_hook(|context| {
                    assert_eq!(context.headers()[0].value(), b"first");
                    context.set(RequestHeader::new("x-token", "second"))
                })
                .build()?;
        client
            .get(HttpProtocol::Http1, "users")?
            .query_pairs([("page", "2")])?
            .header_hook(|context| context.set(RequestHeader::new("x-token", "request")))
            .send()
            .await?
            .into_body()
            .collect_with_limit(0)
            .await?;
        client
            .clone()
            .get_negotiated("users")?
            .without_header_hooks()
            .header(RequestHeader::new("X-Token", "manual"))
            .send()
            .await?
            .into_body()
            .collect_with_limit(0)
            .await?;
        let heads = server.await??;
        assert!(heads[0].starts_with("GET /api/users?page=2 HTTP/1.1\r\n"));
        assert!(heads[0].contains("X-First: literal\r\nX-Token: request\r\nX-Last: literal\r\n"));
        assert!(heads[1].contains("X-First: literal\r\nX-Token: manual\r\nX-Last: literal\r\n"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn redirects_strip_hook_credentials_without_running_hooks_again() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let source = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let source_address = source.local_addr()?;
        let target_address = target.local_addr()?;
        let first = tokio::spawn(async move {
            let (mut stream, _) = source.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{target_address}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let second = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .base_url(&format!("http://{source_address}/api/"))?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .header_hook(move |context| {
                hook_calls.fetch_add(1, Ordering::Relaxed);
                context.append(RequestHeader::new("Authorization", "Bearer private").sensitive())?;
                context.append(RequestHeader::new("Cookie", "private=value").sensitive())
            }).build()?;
        client.get(HttpProtocol::Http1, "start")?.send().await?.into_body().collect_with_limit(0).await?;
        let first = first.await??;
        let second = second.await??;
        assert!(first.contains("Authorization: Bearer private\r\n"));
        assert!(!second.to_ascii_lowercase().contains("authorization:"));
        assert!(!second.to_ascii_lowercase().contains("cookie:"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn invalid_hooks_and_changed_prepared_metadata_fail_before_connecting() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let uri = format!("http://{}/", listener.local_addr()?);
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    let error = client
        .get(HttpProtocol::Http1, &uri)?
        .header_hook(|_| {
            Err(HeaderHookError::new(std::io::Error::other(
                "private-canary",
            )))
        })
        .send()
        .await
        .err()
        .ok_or("hook unexpectedly succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::HeaderHook);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert!(std::error::Error::source(&error).is_some());
    for remove in [false, true] {
        let error = client
            .request(HttpProtocol::Http1, phantom::Method::POST, &uri)?
            .prepared_body(PreparedRequestBody::form([("key", "value")], 100)?)
            .header(RequestHeader::new(
                "Content-Type",
                "application/x-www-form-urlencoded",
            ))
            .header_hook(move |context| {
                if remove {
                    context.remove("content-type")
                } else {
                    context.set(RequestHeader::new("Content-Type", "text/plain"))
                }
            })
            .send()
            .await
            .err()
            .ok_or("invalid metadata unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
