//! Ordered query appends and explicitly placed authorization fields.

use std::{future::Future, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, RedirectPolicy, RequestHeader,
    ResponseInfo, Route,
    profile::{ClientProfile, RequestField, RequestTemplate},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::support::tls::{TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

async fn bounded<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    timeout(TEST_TIMEOUT, future).await?
}

fn template(value: &str) -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![RequestField::literal("X-Template", value)],
        http2_fields: vec![RequestField::literal("x-template", value)],
        http3_fields: None,
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}

#[tokio::test]
async fn query_appends_keep_origin_bytes_duplicates_and_template_choices() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut heads = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await?;
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });
        let client = Client::builder(
            ClientProfile::new(tls_settings()).with_request_template(template("default")),
        )
        .build()?;
        let explicit = PreparedRequestTemplate::new(template("override"))?;
        let url = format!("http://{address}/a/%2e%2e/final?x=%2f+old&bare&x=second&&");
        for request in [
            client.get(HttpProtocol::Http1, &url)?,
            client.get(HttpProtocol::Http1, &url)?.template(&explicit),
            client.get(HttpProtocol::Http1, &url)?.without_template(),
        ] {
            let response = request
                .query_pairs([
                    ("x", "café"),
                    ("k ey+", "two words+"),
                    ("", ""),
                    ("x", "last"),
                ])?
                .query_pairs([("tail", "next")])?
                .header(RequestHeader::new("X-Caller", "kept"))
                .send()
                .await?;
            response.into_body().collect_with_limit(0).await?;
        }
        let heads = server.await??;
        let target = "/a/%2e%2e/final?x=%2f+old&bare&x=second&&&x=caf%C3%A9&k+ey%2B=two+words%2B&=&x=last&tail=next";
        for head in &heads {
            assert!(head.starts_with(&format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n")));
            assert!(head.contains("X-Caller: kept\r\n"));
        }
        assert!(heads[0].contains("X-Template: default\r\nX-Caller: kept\r\n"));
        assert!(heads[1].contains("X-Template: override\r\nX-Caller: kept\r\n"));
        assert!(!heads[2].contains("X-Template"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forwarding_keeps_absolute_bytes_and_explicit_authorization_positions() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{address}"
            ))?))
            .build()?;
        let canary = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let basic = RequestHeader::basic_authorization("runtime-user", &canary)?;
        let basic_value = String::from_utf8(basic.value().to_vec())?;
        let bearer = RequestHeader::bearer_authorization(&canary)?;
        let response = client
            .get(
                HttpProtocol::Http1,
                "http://BÜCHER.Example:8080/a/%2e%2e/final?x=%2f&bare&&",
            )?
            .header(RequestHeader::new("X-First", "one"))
            .header(basic)
            .header(RequestHeader::new("X-Middle", "two"))
            .header(bearer)
            .header(RequestHeader::new("X-Last", "three"))
            .query_pairs([("x", "new"), ("x", "again")])?
            .send()
            .await?;
        response.into_body().collect_with_limit(0).await?;
        let head = server.await??;
        let expected = format!(
            "GET http://xn--bcher-kva.example:8080/a/%2e%2e/final?x=%2f&bare&&&x=new&x=again HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\nX-First: one\r\nauthorization: {basic_value}\r\nX-Middle: two\r\nauthorization: Bearer {canary}\r\nX-Last: three\r\n\r\n"
        );
        assert_eq!(head, expected);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn empty_inputs_preserve_query_markers_and_empty_pairs_get_equals() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut heads = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await?;
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        for (path, add_pair) in [
            ("/empty", false),
            ("/empty?", false),
            ("/empty?", true),
            ("/empty?old&&", true),
        ] {
            let request = client
                .get(HttpProtocol::Http1, &format!("http://{address}{path}"))?
                .query_pairs(std::iter::empty::<(&str, &str)>())?;
            let request = if add_pair {
                request.query_pairs([("", "")])?
            } else {
                request
            };
            request
                .send()
                .await?
                .into_body()
                .collect_with_limit(0)
                .await?;
        }
        let heads = server.await??;
        for (head, target) in heads
            .iter()
            .zip(["/empty", "/empty?", "/empty?=", "/empty?old&&&="])
        {
            assert!(head.starts_with(&format!("GET {target} HTTP/1.1\r\n")));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn relative_redirects_use_the_appended_query_in_the_current_url() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            let first_head = String::from_utf8(read_head(&mut first).await?)?;
            first
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: #section\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            drop(first);
            let (mut second, _) = listener.accept().await?;
            let second_head = String::from_utf8(read_head(&mut second).await?)?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first_head, second_head))
        });
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("http://{address}/redirect?old=%2f"),
            )?
            .query_pairs([("q", "first"), ("q", "second")])?
            .send()
            .await?;
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("missing response info")?;
        assert_eq!(info.redirects_followed(), 1);
        assert_eq!(info.effective_uri().query(), Some("old=%2f&q=first&q=second"));
        response.into_body().collect_with_limit(0).await?;
        let (first, second) = server.await??;
        let request_line = "GET /redirect?old=%2f&q=first&q=second HTTP/1.1\r\n";
        assert!(first.starts_with(request_line));
        assert!(second.starts_with(request_line));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn query_appending_preserves_the_body_and_continue_wait() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            let mut body = [0_u8; 4];
            assert!(
                timeout(Duration::from_millis(100), stream.read_exact(&mut body))
                    .await
                    .is_err()
            );
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, body))
        });
        let client = Client::builder(
            ClientProfile::new(tls_settings()).with_request_template(template("default")),
        )
        .build()?;
        client
            .request(
                HttpProtocol::Http1,
                http::Method::POST,
                &format!("http://{address}/body"),
            )?
            .body("data")
            .expect_continue(Duration::from_secs(2))
            .query_pairs([("q", "value")])?
            .send()
            .await?
            .into_body()
            .collect_with_limit(0)
            .await?;
        let (head, body) = server.await??;
        assert!(head.starts_with("POST /body?q=value HTTP/1.1\r\n"));
        assert!(head.contains("X-Template: default\r\n"));
        assert!(
            head.to_ascii_lowercase()
                .contains("expect: 100-continue\r\n")
        );
        assert_eq!(&body, b"data");
        Ok(())
    })
    .await
}
