use std::{io, net::Ipv4Addr, panic::catch_unwind, time::Duration};

use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestHeader,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, browser::chrome},
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{
    ACCEPT_CH_VALUE, H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_http2, accept_tls,
    assert_hints, assert_http1_hints, client, drive_http2_until_client_done, read_head,
    tls_settings, write_http1_response,
};

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn actual_configured_hint_values_pass_after_accept_ch() -> TestResult<()> {
    let headers = learned_values("\"arm\"", "\"15.5.0\"").await?;
    assert_hints(&headers, true)
}

#[tokio::test]
async fn the_actual_hint_assertion_rejects_a_wrong_configured_architecture() -> TestResult<()> {
    let headers = learned_values("\"x86\"", "\"15.5.0\"").await?;
    require_rejection(
        catch_unwind(|| assert_hints(&headers, true)),
        "actual hint assertion accepted the wrong configured architecture",
    )
}

#[tokio::test]
async fn the_actual_hint_assertion_rejects_a_wrong_configured_platform_version() -> TestResult<()> {
    let headers = learned_values("\"arm\"", "\"99.0.0\"").await?;
    require_rejection(
        catch_unwind(|| assert_hints(&headers, true)),
        "actual hint assertion accepted the wrong configured platform version",
    )
}

#[tokio::test]
async fn actual_http1_without_unsolicited_high_entropy_fields_passes() -> TestResult<()> {
    let head = unsolicited_field(None).await?;
    assert_http1_hints(&head, false)
}

#[tokio::test]
async fn the_actual_http1_assertion_rejects_unsolicited_wrong_valued_architecture() -> TestResult<()>
{
    let head = unsolicited_field(Some(("sec-ch-ua-arch", "\"x86\""))).await?;
    require_rejection(
        catch_unwind(|| assert_http1_hints(&head, false)),
        "actual HTTP/1 hint assertion accepted an unsolicited wrong-valued architecture",
    )
}

#[tokio::test]
async fn the_actual_http1_assertion_rejects_unsolicited_wrong_valued_platform_version()
-> TestResult<()> {
    let head = unsolicited_field(Some(("sec-ch-ua-platform-version", "\"99.0.0\""))).await?;
    require_rejection(
        catch_unwind(|| assert_http1_hints(&head, false)),
        "actual HTTP/1 hint assertion accepted an unsolicited wrong-valued platform version",
    )
}

fn require_rejection(
    result: std::thread::Result<TestResult<()>>,
    accepted: &'static str,
) -> TestResult<()> {
    match result {
        Ok(Ok(())) => Err(accepted.into()),
        Ok(Err(_)) | Err(_) => Ok(()),
    }
}

async fn learned_values(architecture: &str, platform_version: &str) -> TestResult<HeaderMap> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let hints = ClientHintSettings::new(vec![
        ClientHint::new("sec-ch-ua", "baseline", ClientHintDelivery::Default),
        ClientHint::new("sec-ch-ua-arch", architecture, ClientHintDelivery::AcceptCh),
        ClientHint::new(
            "sec-ch-ua-platform-version",
            platform_version,
            ClientHintDelivery::AcceptCh,
        ),
    ]);
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_client_hints(hints);
    let session = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
    let url = format!("https://{address}/hint-values");
    let (done, completed) = oneshot::channel();
    let (captured, observed) = oneshot::channel();
    let server = ConnectionPeer::spawn(async move {
        let stream = accept_tls(&listener, &acceptor).await?;
        let mut connection = ::http2::server::handshake(stream).await?;
        let mut requests = Vec::new();
        for index in 0..2 {
            let (request, mut respond) = accept_http2(&mut connection).await?;
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri().path(), "/hint-values");
            assert_eq!(request.version(), Version::HTTP_2);
            assert!(request.body().is_end_stream());
            requests.push(request.into_parts().0.headers);
            let response = if index == 0 {
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", ACCEPT_CH_VALUE)
                    .body(())?
            } else {
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?
            };
            respond.send_response(response, true)?;
        }
        drive_http2_until_client_done(&mut connection, completed).await?;
        captured
            .send(requests)
            .map_err(|_| "hint-value capture receiver disappeared")?;
        std::future::pending::<()>().await;
        drop(connection);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let operation = async {
        collect_no_content(&session, &url).await?;
        collect_no_content(&session, &url).await?;
        done.send(())
            .map_err(|_| "hint-value peer ended before response collection")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed.await?)
    };
    let result = match timeout(DEADLINE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    // The real client remains alive while the accepted TLS/H2 peer is joined.
    let requests = finish_with_cleanup(result, server.stop().await)?;
    drop(session);
    assert_eq!(requests.len(), 2);
    assert_one_value(&requests[0], "sec-ch-ua", "baseline")?;
    assert!(!requests[0].contains_key("sec-ch-ua-arch"));
    assert!(!requests[0].contains_key("sec-ch-ua-platform-version"));

    assert_one_value(&requests[1], "sec-ch-ua", "baseline")?;
    assert_one_value(&requests[1], "sec-ch-ua-arch", architecture)?;
    assert_one_value(&requests[1], "sec-ch-ua-platform-version", platform_version)?;
    requests
        .into_iter()
        .nth(1)
        .ok_or_else(|| "actual learned request missing".into())
}

async fn unsolicited_field(field: Option<(&str, &str)>) -> TestResult<Vec<u8>> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let session = client(&identity)?;
    let url = format!("https://{address}/hint-values");
    let (done, completed) = oneshot::channel();
    let (captured, observed) = oneshot::channel();
    let server = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(&listener, &acceptor).await?;
        let head = read_head(&mut stream).await?;
        write_http1_response(&mut stream, None).await?;
        completed.await.map_err(io::Error::other)?;
        captured
            .send(head)
            .map_err(|_| "HTTP/1 hint capture receiver disappeared")?;
        std::future::pending::<()>().await;
        drop(stream);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let operation = async {
        let mut request = session.get(HttpProtocol::Http1, &url)?;
        if let Some((name, value)) = field {
            request = request.header(RequestHeader::new(name, value));
        }
        let response = request.send().await?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err("actual HTTP/1 control received a non-204 response".into());
        }
        let body = response.into_body().collect().await?;
        if !body.to_bytes().is_empty() {
            return Err("actual HTTP/1 control response was not empty".into());
        }
        done.send(())
            .map_err(|_| "HTTP/1 hint peer ended before response collection")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed.await?)
    };
    let result = match timeout(DEADLINE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let head = finish_with_cleanup(result, server.stop().await)?;
    drop(session);
    let headers = captured_http1_fields(&head)?;
    assert_one_value(&headers, "sec-ch-ua", "baseline")?;
    for name in ["sec-ch-ua-arch", "sec-ch-ua-platform-version"] {
        if let Some((expected_name, value)) =
            field.filter(|(expected_name, _)| *expected_name == name)
        {
            assert_one_value(&headers, expected_name, value)?;
        } else {
            assert!(!headers.contains_key(name));
        }
    }
    Ok(head)
}

fn captured_http1_fields(head: &[u8]) -> TestResult<HeaderMap> {
    let text = std::str::from_utf8(head)?;
    assert!(text.ends_with("\r\n\r\n"));
    let mut lines = text.split("\r\n");
    assert_eq!(lines.next(), Some("GET /hint-values HTTP/1.1"));
    let mut fields = HeaderMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or("actual HTTP/1 field has no separator")?;
        let name: HeaderName = name.parse()?;
        let value: HeaderValue = value.trim_matches([' ', '\t']).parse()?;
        fields.append(name, value);
    }
    assert!(!fields.is_empty());
    Ok(fields)
}

fn assert_one_value(headers: &HeaderMap, name: &str, value: &str) -> TestResult<()> {
    assert_eq!(headers.get_all(name).iter().count(), 1);
    assert_eq!(headers.get(name), Some(&value.parse()?));
    Ok(())
}

async fn collect_no_content(session: &Client, url: &str) -> TestResult<()> {
    let response = session.get(HttpProtocol::Http2, url)?.send().await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err("actual HTTP/2 control received a non-204 response".into());
    }

    let body = response.into_body().collect().await?;
    if !body.to_bytes().is_empty() {
        return Err("actual HTTP/2 control response was not empty".into());
    }

    Ok(())
}
