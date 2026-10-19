//! Public raw-request imports use normal validation and independent wire peers.

use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom::{
    Client, HttpAttemptBudget, HttpProxy, RawRequestErrorKind, RedirectPolicy, RequestErrorKind,
    ResponseInfo, Route,
    profile::{ClientProfile, RequestField, RequestTemplate, browser::chrome},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn profile() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
}

#[tokio::test]
async fn import_preserves_escaped_target_duplicate_bytes_and_owned_body() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = Client::builder(profile()).build()?;
        let mut raw = format!(
            "POST /a/%2e%2e/end?q=%2f&q=two HTTP/1.1\r\nX-First: one\r\nHost: {address}\r\nContent-Length: 4\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nX-Bytes: "
        )
        .into_bytes();
        raw.extend_from_slice(b"\x80\xff\r\nAuthorization: Bearer raw-secret\r\n\r\n\0\r\n\xff");
        let request = client
            .request_from_http1(
                &format!("http://{address}/a/%2e%2e/end?q=%2f&q=two"),
                &raw,
                raw.len(),
            )?
            .header_hook(|context| {
                assert_eq!(context.headers().len(), 6);
                assert!(context.headers().iter().all(|header| header.is_sensitive()));
                assert!(!format!("{:?}", context.headers()).contains("raw-secret"));
                Ok(())
            });
        raw.fill(0);
        drop(raw);

        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await?);
                assert!(head.len() <= 32 * 1024);
            }
            let mut body = [0; 4];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, TestError>((head, body))
        };
        let caller = async {
            let response = request.send().await?;
            assert_eq!(response.status(), 204);
            assert_eq!(
                response.extensions().get::<ResponseInfo>().map(ResponseInfo::protocol),
                Some(phantom::HttpProtocol::Http1)
            );
            response.into_body().collect_with_limit(0).await?;
            Ok::<_, TestError>(())
        };
        let ((), (head, body)) = tokio::try_join!(caller, peer)?;
        let mut expected = format!(
            "POST /a/%2e%2e/end?q=%2f&q=two HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nContent-Length: 4\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nX-Bytes: "
        )
        .into_bytes();
        expected.extend_from_slice(b"\x80\xff\r\nAuthorization: Bearer raw-secret\r\n\r\n");
        assert_eq!(head, expected);
        assert_eq!(body, [0, b'\r', b'\n', 255]);
        Ok::<_, TestError>(())
    })
    .await?
}

#[tokio::test]
async fn framing_rejection_never_opens_a_connection() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = Client::builder(profile()).build()?;
        for fields in [
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Upgrade: websocket\r\n",
            "Proxy-Authorization: secret\r\n",
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {address}\r\n{fields}\r\n");
            assert!(client.request_from_http1(&format!("http://{address}/"), raw.as_bytes(), raw.len()).is_err());
        }
        let raw = format!("GET / HTTP/1.1\r\nHost: {address}\r\n\r\nGET /second HTTP/1.1\r\nHost: {address}\r\n\r\n");
        assert_eq!(client.request_from_http1(&format!("http://{address}/"), raw.as_bytes(), raw.len()).err().ok_or("pipelined request accepted")?.kind(), RawRequestErrorKind::BodyLengthMismatch);
        assert!(timeout(Duration::from_millis(100), listener.accept()).await.is_err());
        Ok::<_, TestError>(())
    })
    .await?
}

#[tokio::test]
async fn imported_requests_keep_default_template_requirements_and_order() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let template = RequestTemplate {
            http1_fields: vec![RequestField::required_caller("X-Required")],
            http2_fields: vec![RequestField::required_caller("x-required")],
            http3_fields: None,
            http2_priority: None,
            requested_client_hint_placement: false,
            restarts_for_connection_accept_ch: false,
        };
        let client = Client::builder(profile().with_request_template(template)).build()?;
        let uri = format!("http://{address}/");
        let missing = format!("GET / HTTP/1.1\r\nHost: {address}\r\nX-Last: last\r\n\r\n");
        let error = client.request_from_http1(&uri, missing.as_bytes(), missing.len())?.send().await.err().ok_or("missing required template slot accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
        assert!(timeout(Duration::from_millis(100), listener.accept()).await.is_err());

        let raw = format!("GET / HTTP/1.1\r\nHost: {address}\r\nX-Last: last\r\nx-required: supplied\r\n\r\n");
        let request = client.request_from_http1(&uri, raw.as_bytes(), raw.len())?;
        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await?);
                assert!(head.len() <= 32 * 1024);
            }
            assert_eq!(head, format!("GET / HTTP/1.1\r\nHost: {address}\r\nX-Required: supplied\r\nX-Last: last\r\n\r\n").as_bytes());
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, TestError>(())
        };
        let caller = async {
            request.send().await?.into_body().collect_with_limit(0).await?;
            Ok::<_, TestError>(())
        };
        tokio::try_join!(caller, peer)?;
        Ok::<_, TestError>(())
    })
    .await?
}

#[tokio::test]
async fn imported_requests_keep_the_callers_shared_attempt_budget() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = Client::builder(profile()).build()?;
        let raw = format!("GET / HTTP/1.1\r\nHost: {address}\r\n\r\n");
        let budget = HttpAttemptBudget::new(0);
        let error = client
            .request_from_http1(&format!("http://{address}/"), raw.as_bytes(), raw.len())?
            .attempt_budget(budget.clone())
            .send()
            .await
            .err()
            .ok_or("exhausted budget accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(budget.remaining(), 0);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        Ok::<_, TestError>(())
    })
    .await?
}

#[tokio::test]
async fn imported_body_replays_through_the_selected_proxy_and_strips_origin_credentials()
-> TestResult {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
        let client = Client::builder(profile()).route(Route::http_proxy(proxy)).build()?;
        let raw = b"POST /first?x=%2f HTTP/1.1\r\nHost: first.example\r\nAuthorization: Bearer origin-secret\r\nContent-Length: 4\r\n\r\nbody";
        let budget = HttpAttemptBudget::new(2);
        let request = client
            .request_from_http1("http://first.example/first?x=%2f", raw, raw.len())?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .attempt_budget(budget.clone());
        let peer = async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await?);
                    assert!(head.len() <= 32 * 1024);
                }
                let mut body = [0; 4];
                stream.read_exact(&mut body).await?;
                assert_eq!(&body, b"body");
                if attempt == 0 {
                    assert_eq!(head, b"POST http://first.example/first?x=%2f HTTP/1.1\r\nHost: first.example\r\nAuthorization: Bearer origin-secret\r\nContent-Length: 4\r\n\r\n");
                    stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://second.example/second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                } else {
                    assert_eq!(head, b"POST http://second.example/second HTTP/1.1\r\nHost: second.example\r\nContent-Length: 4\r\n\r\n");
                    stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
                }
            }
            Ok::<_, TestError>(())
        };
        let caller = async {
            request.send().await?.into_body().collect_with_limit(0).await?;
            Ok::<_, TestError>(())
        };
        tokio::try_join!(caller, peer)?;
        assert_eq!(budget.remaining(), 0);
        Ok::<_, TestError>(())
    })
    .await?
}
