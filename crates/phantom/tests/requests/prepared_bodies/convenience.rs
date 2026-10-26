use std::net::Ipv4Addr;

use phantom::{
    Client, Method, PreparedRequestTemplate, RequestErrorKind, RequestHeader,
    profile::{RequestField, RequestTemplate},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};

use super::{BUDGET, TestResult, finish_prepared_peer, profile, uploads::read_upload};
use crate::support::tunnel_proxy::ConnectionPeer;

#[tokio::test]
async fn form_supplies_content_type_and_preserves_duplicate_pairs() -> TestResult {
    for with_template in [false, true] {
        timeout(BUDGET, async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let url = format!("http://{}/submit", listener.local_addr()?);
            let server = ConnectionPeer::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut stream = BufReader::new(stream);
                let observed = read_upload(&mut stream).await?;
                assert_eq!(observed.method, b"POST");
                assert_eq!(observed.body, b"tag=first&tag=last&space=a+b");
                assert_eq!(
                    observed.value("content-type"),
                    Some(b"application/x-www-form-urlencoded;charset=UTF-8".as_slice())
                );
                assert_eq!(
                    observed
                        .fields
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                        .count(),
                    1
                );
                if with_template {
                    let names = observed
                        .fields
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>();
                    let first = names
                        .iter()
                        .position(|name| *name == "x-first")
                        .ok_or("first field missing")?;
                    let content_type = names
                        .iter()
                        .position(|name| *name == "content-type")
                        .ok_or("content type missing")?;
                    let last = names
                        .iter()
                        .position(|name| *name == "x-last")
                        .ok_or("last field missing")?;
                    assert!(first < content_type && content_type < last);
                }
                stream
                    .get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
            let client = Client::builder(profile()).build()?;
            let operation = async {
                let mut request = client.request(Method::POST, &url)?;
                if with_template {
                    let fields = vec![
                        RequestField::literal("x-first", "one"),
                        RequestField::caller("content-type"),
                        RequestField::literal("x-last", "two"),
                    ];
                    request = request.template(&PreparedRequestTemplate::new(RequestTemplate {
                        http1_fields: fields.clone(),
                        http2_fields: fields,
                        http3_fields: None,
                        http2_priority: None,
                        requested_client_hint_placement: false,
                        restarts_for_connection_accept_ch: false,
                    })?);
                }
                let response = request
                    .form([("tag", "first"), ("tag", "last"), ("space", "a b")], 128)?
                    .send()
                    .await?;
                assert_eq!(response.version(), http::Version::HTTP_11);
                assert_eq!(response.into_body().collect_with_limit(2).await?, "ok");
                Ok(())
            }
            .await;
            finish_prepared_peer(operation, server).await
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn form_rejects_conflicting_headers_and_encoding_limits_before_connecting() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = Client::builder(profile()).build()?;
    let url = format!("http://{}/submit", listener.local_addr()?);
    assert!(
        client
            .request(Method::POST, &url)?
            .form([("name", "value")], 1)
            .is_err()
    );

    for fields in [
        vec![RequestHeader::new("content-type", "text/plain")],
        vec![
            RequestHeader::new(
                "content-type",
                "application/x-www-form-urlencoded;charset=UTF-8",
            ),
            RequestHeader::new(
                "Content-Type",
                "application/x-www-form-urlencoded;charset=UTF-8",
            ),
        ],
    ] {
        let error = client
            .request(Method::POST, &url)?
            .headers(fields)
            .form([("a", "b")], 128)?
            .send()
            .await
            .err()
            .ok_or("invalid content type was accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
    }
    assert!(
        timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "json")]
#[tokio::test]
async fn json_supplies_content_type_and_sends_bounded_bytes() -> TestResult {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/submit", listener.local_addr()?);
        let server = ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;
            assert_eq!(observed.body, br#"{"message":"hello"}"#);
            assert_eq!(
                observed.value("content-type"),
                Some(b"application/json".as_slice())
            );
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let client = Client::builder(profile()).build()?;
        let operation = async {
            let value = serde_json::json!({"message": "hello"});
            assert!(client.request(Method::POST, &url)?.json(&value, 1).is_err());
            let response = client
                .request(Method::POST, &url)?
                .json(&value, 128)?
                .send()
                .await?;
            assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
            response.into_body().collect_with_limit(0).await?;
            Ok(())
        }
        .await;
        finish_prepared_peer(operation, server).await
    })
    .await?
}
