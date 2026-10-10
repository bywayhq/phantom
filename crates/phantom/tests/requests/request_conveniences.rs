use std::{
    future::Future,
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

mod peer_contract;

#[tokio::test]
async fn base_urls_and_hooks_preserve_template_order_and_request_overrides() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = async move {
            let mut heads = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        };

        let (heads, calls) = exchange_peer(peer, async {
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
            let client = Client::builder(
                ClientProfile::new(tls_settings())
                    .with_http2(phantom::profile::browser::chrome::v154_http2())
                    .with_request_template(template),
            )
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
            Ok(calls)
        })
        .await?;

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
        let canary = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let authorization = format!("Bearer {canary:x}");
        let hook_authorization = authorization.clone();
        let cookie = format!("private={canary:x}");
        let hook_cookie = cookie.clone();
        let first = async move {
            let (mut stream, _) = source.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{target_address}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        };
        let second = async move {
            let (mut stream, _) = target.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        };
        let peer = async move { tokio::try_join!(first, second) };

        let ((first, second), calls) = exchange_peer(peer, async {
            let calls = Arc::new(AtomicUsize::new(0));
            let hook_calls = calls.clone();
            let client = Client::builder(ClientProfile::new(tls_settings()))
                .base_url(&format!("http://{source_address}/api/"))?
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .header_hook(move |context| {
                    hook_calls.fetch_add(1, Ordering::Relaxed);
                    context.append(RequestHeader::new("Authorization", hook_authorization.clone()).sensitive())?;
                    context.append(RequestHeader::new("Cookie", hook_cookie.clone()).sensitive())
                }).build()?;

            client.get(HttpProtocol::Http1, "start")?.send().await?.into_body().collect_with_limit(0).await?;
            Ok(calls)
        })
        .await?;

        assert!(first.contains(&format!("Authorization: {authorization}\r\n")));
        assert!(!second.to_ascii_lowercase().contains("authorization:"));
        assert!(!second.to_ascii_lowercase().contains("cookie:"));
        assert!(cookie_transition(&first, &second, &cookie));
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

#[tokio::test]
async fn status_retries_reuse_the_hook_result() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = async move {
            let mut heads = Vec::new();
            for status in ["503 Service Unavailable", "204 No Content"] {
                let (mut stream, _) = listener.accept().await?;
                heads.push(read_head(&mut stream).await?);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        };

        let (heads, calls) = exchange_peer(peer, async {
            let calls = Arc::new(AtomicUsize::new(0));
            let hook_calls = calls.clone();
            let retry = phantom::StatusRetry::new(
                &[phantom::StatusCode::SERVICE_UNAVAILABLE],
                NonZeroUsize::MIN,
                Duration::ZERO,
            )?;
            let client = Client::builder(ClientProfile::new(tls_settings()))
                .retry_policy(phantom::RetryPolicy::none().with_status_retry(retry))
                .header_hook(move |context| {
                    let count = hook_calls.fetch_add(1, Ordering::Relaxed);
                    context.set(RequestHeader::new("X-Sequence", count.to_string()))
                })
                .build()?;

            client
                .get(HttpProtocol::Http1, &format!("http://{address}/retry"))?
                .send()
                .await?
                .into_body()
                .collect_with_limit(0)
                .await?;
            Ok(calls)
        })
        .await?;

        assert_eq!(heads[0], heads[1]);
        assert!(retry_heads_reuse_hook_result(&heads));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[cfg(feature = "sse")]
#[tokio::test]
async fn event_source_hooks_cannot_change_the_managed_event_id() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .header_hook(move |context| {
                hook_calls.fetch_add(1, Ordering::Relaxed);
                context.append(RequestHeader::new("Last-Event-ID", "injected"))
            })
            .build()?;
        let error = client
            .event_source(
                HttpProtocol::Http1,
                &format!("http://{}/events", listener.local_addr()?),
            )?
            .connect()
            .await
            .err()
            .ok_or("managed field changed")?;
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<phantom::RequestError>())
            .ok_or("missing request error source")?;
        assert_eq!(source.kind(), RequestErrorKind::HeaderHook);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

async fn exchange_peer<T, R>(
    peer: impl Future<Output = TestResult<T>>,
    request: impl Future<Output = TestResult<R>>,
) -> TestResult<(T, R)> {
    tokio::try_join!(peer, request)
}

fn retry_heads_reuse_hook_result(heads: &[Vec<u8>]) -> bool {
    const HOOK_FIELD: &[u8] = b"\r\nX-Sequence: 0\r\n";
    heads.len() == 2
        && heads[0] == heads[1]
        && heads.iter().all(|head| {
            head.windows(HOOK_FIELD.len())
                .any(|field| field == HOOK_FIELD)
        })
}

fn cookie_transition(first: &str, second: &str, cookie: &str) -> bool {
    first.contains(&format!("\r\nCookie: {cookie}\r\n"))
        && !second.to_ascii_lowercase().contains("cookie:")
}
