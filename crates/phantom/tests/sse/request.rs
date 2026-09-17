use std::net::Ipv4Addr;

use http::StatusCode;
use phantom::{HttpProtocol, RequestHeader};
use tokio::{io::AsyncWriteExt, net::TcpListener};

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
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .headers(vec![RequestHeader::new("X-Custom", "only")])
        .connect()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let head = String::from_utf8(server.await??)?;
    assert!(head.lines().any(|line| line == "X-Custom: only"));
    assert!(!head.lines().any(|line| line.starts_with("Accept:")));
    assert!(!head.lines().any(|line| line.starts_with("Cache-Control:")));
    Ok(())
}
