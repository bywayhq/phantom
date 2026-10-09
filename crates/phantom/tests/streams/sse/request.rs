use std::{net::Ipv4Addr, time::Duration};

use http::StatusCode;
use phantom::{
    Client, HttpProtocol, RequestHeader, SseErrorKind, SseHeader,
    profile::{ClientProfile, RequestField, RequestTemplate},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::{
    TestResult,
    tls_support::{H1_ALPN, accept_tls, read_head, test_client},
};

#[tokio::test]
async fn replacing_headers_removes_event_source_defaults() -> TestResult<()> {
    let identity = super::tls_support::TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
    });

    let response = test_client(&identity, false)?
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .headers(vec![SseHeader::field(RequestHeader::new(
            "X-Custom", "only",
        ))])
        .connect()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let head = String::from_utf8(server.await??)?;
    assert!(head.lines().any(|line| line == "X-Custom: only"));
    assert!(!head.lines().any(|line| line.starts_with("Accept:")));
    assert!(!head.lines().any(|line| line.starts_with("Cache-Control:")));
    Ok(())
}

#[tokio::test]
async fn inherited_last_event_id_defaults_fail_before_connecting() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut template = id_slot_template();
    template.http1_fields[1] = RequestField::literal("Last-Event-ID", "unmanaged");
    let client = Client::builder(
        ClientProfile::new(super::tls_support::tls_settings()).with_request_template(template),
    )
    .build()?;

    let connecting = client
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .connect();
    let error = timeout(super::TEST_TIMEOUT, connecting)
        .await
        .map_err(|_| "inherited ID rejection stalled during network setup")?
        .err()
        .ok_or("inherited Last-Event-ID default reached the network")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    assert!(
        timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn automatic_last_event_id_hints_fail_before_connecting() -> TestResult<()> {
    use phantom::profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    for delivery in [ClientHintDelivery::Default, ClientHintDelivery::AcceptCh] {
        let client = Client::builder(
            ClientProfile::new(super::tls_support::tls_settings()).with_client_hints(
                ClientHintSettings::new(vec![ClientHint::new(
                    "last-event-id",
                    "unmanaged-canary",
                    delivery,
                )]),
            ),
        )
        .build()?;

        let connecting = client
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .connect();
        let error = timeout(super::TEST_TIMEOUT, connecting)
            .await
            .map_err(|_| "automatic ID rejection stalled during network setup")?
            .err()
            .ok_or("automatic Last-Event-ID reached the network")?;
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    }
    assert!(
        timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn inherited_optional_id_slot_preserves_order_and_omits_initial_and_reset_ids()
-> TestResult<()> {
    super::bounded(async {
        let identity = super::tls_support::TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let mut heads = Vec::new();
            for body in ["id: first\ndata: one\n\n", "id:\ndata: two\n\n"] {
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                     Content-Length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(body.as_bytes()).await?;
                stream.flush().await?;
            }
            heads.push(String::from_utf8(read_head(&mut stream).await?)?);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });
        let profile = ClientProfile::new(super::tls_support::tls_settings())
            .with_request_template(id_slot_template());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let mut events = client
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .initial_retry(Duration::ZERO)
            .max_reconnects(2)
            .connect()
            .await?
            .into_body();

        let first = events.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.id(), "first");
        let second = events.next_event().await?.ok_or("reset event missing")?;
        assert_eq!(second.id(), "");
        assert_eq!(events.last_event_id(), "");
        assert_eq!(events.next_event().await?, None);

        let heads = server.await??;
        for (index, head) in heads.iter().enumerate() {
            let fields = head
                .lines()
                .skip(1)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            let expected = if index == 1 {
                vec![
                    "X-Before: first",
                    "Last-Event-ID: first",
                    "X-After: last",
                    "Accept: text/event-stream",
                    "Cache-Control: no-cache",
                ]
            } else {
                vec![
                    "X-Before: first",
                    "X-After: last",
                    "Accept: text/event-stream",
                    "Cache-Control: no-cache",
                ]
            };
            assert_eq!(&fields[1..], expected, "request {index}");
        }
        Ok(())
    })
    .await
}

fn id_slot_template() -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("X-Before", "first"),
            RequestField::caller("Last-Event-ID"),
            RequestField::literal("X-After", "last"),
        ],
        http2_fields: Vec::new(),
        http3_fields: None,
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}
