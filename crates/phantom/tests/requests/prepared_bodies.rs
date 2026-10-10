//! Prepared-body placement, reachability, and redirect provenance.

use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, EnvironmentProxies, HttpProtocol, Method, PreparedRequestBody, PreparedRequestTemplate,
    RedirectPolicy, RequestErrorKind, RetryPolicy,
    profile::{ClientProfile, Http3ClientSettings, RequestField, RequestTemplate, browser::chrome},
};
use phantom_testkit::http1::{CaptureLimits, capture_request_head};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::{Instant, timeout},
};

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

mod slots;
mod trailers;
mod uploads;

const BUDGET: Duration = Duration::from_secs(10);
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn finish_prepared_peer<T: Send + 'static>(
    operation: TestResult,
    mut peer: ConnectionPeer<TestResult<T>>,
) -> TestResult<T> {
    match operation {
        Ok(()) => match timeout(BUDGET, &mut peer).await {
            Ok(joined) => joined?,
            Err(error) => finish_with_cleanup(Err(error.into()), peer.stop().await),
        },
        Err(primary) => finish_with_cleanup(Err(primary), peer.stop().await),
    }
}

fn profile() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
}

fn template(
    http2_slot: bool,
    http3_slot: bool,
) -> Result<PreparedRequestTemplate, phantom::profile::InvalidRequestTemplate> {
    let slot = |enabled: bool| {
        if enabled {
            vec![RequestField::caller("content-type")]
        } else {
            Vec::new()
        }
    };
    PreparedRequestTemplate::new(RequestTemplate {
        http1_fields: slot(true),
        http2_fields: slot(http2_slot),
        http3_fields: Some(slot(http3_slot)),
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    })
}

#[tokio::test]
async fn prepared_body_requires_placement_before_any_connection() -> TestResult {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let client = Client::builder(profile()).build()?;
        let error = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{}/upload", listener.local_addr()?),
            )?
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?)
            .send()
            .await
            .err()
            .ok_or("body without declared placement succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        assert!(
            timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn prepared_body_checks_enabled_http2_fallback_before_connecting() -> TestResult {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let client = Client::builder(profile()).build()?;
        let error = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{}/upload", listener.local_addr()?),
            )?
            .template(&template(false, true)?)
            .retry_policy(RetryPolicy::none().with_http2_fallback(true))
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?)
            .send()
            .await
            .err()
            .ok_or("missing fallback slot was accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        assert!(
            timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn preserved_body_redirect_checks_new_route_without_refilling_dropped_fields() -> TestResult {
    for status in [307, 303] {
        timeout(BUDGET, async {
            let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy_address = proxy.local_addr()?;
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let origin_address = origin.local_addr()?;
            let deadline = Instant::now() + BUDGET;

            let env = EnvironmentProxies::from_values([
                ("http_proxy", format!("http://{proxy_address}")), ("no_proxy", "127.0.0.1".to_owned()),
            ])?;
            let client = Client::builder(profile()).environment_proxies(env)
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .alt_svc(NonZeroUsize::MIN).build()?;
            let prepared = template(true, false)?;
            let body = PreparedRequestBody::form([("a", "b")], 128)?;

            let peer = ConnectionPeer::spawn(async move {
                let (stream, _) = proxy.accept().await?;
                let mut stream = BufReader::new(stream);
                let head = capture_request_head(&mut stream, deadline, CaptureLimits::new(8192, 4096, 64)).await?;
                assert!(head.headers().iter().any(|field| field.name() == b"content-type"));

                let length = head.headers().iter().find(|field| field.name().eq_ignore_ascii_case(b"content-length"))
                    .ok_or("body length missing")?;
                let length: usize = std::str::from_utf8(length.value_bytes())?.trim().parse()?;
                if length != b"a=b".len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "redirect upload must have Content-Length 3",
                    ).into());
                }

                let mut body = vec![0; length];
                stream.read_exact(&mut body).await?;
                assert_eq!(body, b"a=b");

                stream.get_mut().write_all(format!("HTTP/1.1 {status} Redirect\r\nLocation: http://{origin_address}/upload\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });

            let mut origin_peer = None;
            let operation = async {
                let request = client
                    .request_negotiated(Method::POST, "http://origin.invalid/upload")?
                    .template(&prepared)
                    .prepared_body(body);

                if status == 307 {
                    let error = request.send().await.err().ok_or("undeclared redirected slot succeeded")?;
                    assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
                    assert_eq!(error.origin().map(phantom::RequestOrigin::port), Some(origin_address.port()));
                    assert!(timeout(Duration::from_millis(30), origin.accept()).await.is_err());
                } else {
                    origin_peer = Some(ConnectionPeer::spawn(async move {
                        let (stream, _) = origin.accept().await?;
                        let mut stream = BufReader::new(stream);
                        let head = capture_request_head(&mut stream, deadline, CaptureLimits::new(8192, 4096, 64)).await?;
                        assert_eq!(head.method(), b"GET");
                        assert!(!head.headers().iter().any(|field| field.name().eq_ignore_ascii_case(b"content-type")));

                        stream.get_mut().write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    }));
                    assert_eq!(request.send().await?.status(), phantom::StatusCode::NO_CONTENT);
                }
                Ok(())
            }.await;

            let result = finish_prepared_peer(operation, peer).await;
            if let Some(origin_peer) = origin_peer {
                finish_prepared_peer(result, origin_peer).await?;
            } else {
                result?;
            }

            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }).await??;
    }
    Ok(())
}

#[tokio::test]
async fn pinned_http3_alternative_keeps_h3_only_placement() -> TestResult {
    let client = Client::builder(profile()).build()?;
    for hook in [false, true] {
        let body = PreparedRequestBody::form([("a", "b")], 128)?;
        let content_type = body.content_type().to_owned();
        let request = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                "https://example.invalid/upload",
            )?
            .template(&template(false, true)?)
            .alt_svc_alternative("127.0.0.1", 443)
            .retry_policy(RetryPolicy::none().with_http2_fallback(true));
        let request = if hook {
            request.fill_slots(|slots| {
                slots.fill(phantom::RequestHeader::new("content-type", content_type))
            })?
        } else {
            request
        };
        let error = request
            .prepared_body(body)
            .timeouts(
                phantom::RequestTimeoutOverrides::new()
                    .total(phantom::TimeoutOverride::Limit(Duration::MAX)),
            )
            .send()
            .await
            .err()
            .ok_or("unrepresentable timeout succeeded")?;
        // Placement passes; the independently invalid timeout stops before I/O.
        assert_eq!(error.kind(), RequestErrorKind::InvalidTimeout);
    }
    Ok(())
}
