use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};
use tracing::instrument::WithSubscriber;

use super::{HttpConnectError, HttpConnectErrorKind, HttpConnectHeader, connect_http_tunnel};
use crate::{
    request::RequestHeader,
    tls::test_support::TouchCountingStream,
    tracing_test::{OutcomeSubscriber, poll_once_then_drop},
};

mod authentication;
mod https_connect;
mod socks5;
mod socks5_udp;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn preserves_order_and_surplus_after_fragmented_informational_and_success_heads() -> TestResult
{
    let (client, mut proxy) = duplex(16 * 1024);
    let subscriber = OutcomeSubscriber::default();
    let proxy_task = tokio::spawn(async move {
        let request = read_head(&mut proxy).await?;
        proxy.write_all(b"HTTP/1.1 103 Ear").await?;
        proxy
            .write_all(
                b"ly Hints\r\nLink: </hint>\r\n\r\nHTTP/1.1 204 No Content\r\nProxy-Agent: fixture\r\n\r\nprefix",
            )
            .await?;
        proxy.flush().await?;

        let mut tunneled = [0_u8; 5];
        proxy.read_exact(&mut tunneled).await?;
        Ok::<_, std::io::Error>((request, tunneled))
    });

    let mut tunnel = connect_http_tunnel(
        client,
        "origin.example:443",
        &[
            HttpConnectHeader::field(RequestHeader::new("User-Agent", "fixture")),
            HttpConnectHeader::authority("host"),
            HttpConnectHeader::field(RequestHeader::new("X-Repeat", "first")),
            HttpConnectHeader::field(RequestHeader::new("x-repeat", "second")),
        ],
    )
    .with_subscriber(subscriber.dispatch())
    .await?;

    let mut prefix = [0_u8; 6];
    tunnel.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"prefix");
    tunnel.write_all(b"hello").await?;

    let (request, tunneled) = proxy_task.await??;
    assert_eq!(
        request,
        b"CONNECT origin.example:443 HTTP/1.1\r\n\
          User-Agent: fixture\r\n\
          host: origin.example:443\r\n\
          X-Repeat: first\r\n\
          x-repeat: second\r\n\r\n"
    );
    assert_eq!(&tunneled, b"hello");
    assert_eq!(subscriber.outcomes_for("proxy.http_connect"), ["ok"]);
    Ok(())
}

#[tokio::test]
async fn invalid_fields_are_rejected_before_stream_io() -> TestResult {
    let (client, _proxy) = duplex(1024);
    let touches = Arc::new(AtomicUsize::new(0));
    let stream = TouchCountingStream::new(client, touches.clone());

    let error = match connect_http_tunnel(
        stream,
        "origin.example:443",
        &[
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::field(RequestHeader::new("Host", "elsewhere.example")),
        ],
    )
    .await
    {
        Ok(_) => return Err("caller-supplied Host was accepted".into()),
        Err(error) => error,
    };

    assert!(matches!(error, HttpConnectError::AuthorityHeader));
    assert_eq!(error.kind(), HttpConnectErrorKind::InvalidRequest);
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn missing_and_duplicate_authority_placeholders_fail_before_io() -> TestResult {
    for headers in [
        Vec::new(),
        vec![
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::authority("host"),
        ],
    ] {
        let (client, _proxy) = duplex(1024);
        let touches = Arc::new(AtomicUsize::new(0));
        let stream = TouchCountingStream::new(client, touches.clone());

        let error = match connect_http_tunnel(stream, "origin.example:443", &headers).await {
            Ok(_) => return Err("invalid authority placeholders were accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), HttpConnectErrorKind::InvalidRequest);
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn connect_target_rejects_userinfo_before_io() -> TestResult {
    let (client, _proxy) = duplex(1024);
    let touches = Arc::new(AtomicUsize::new(0));
    let stream = TouchCountingStream::new(client, touches.clone());

    let error = match connect_http_tunnel(
        stream,
        "user@origin.example:443",
        &[HttpConnectHeader::authority("Host")],
    )
    .await
    {
        Ok(_) => return Err("CONNECT authority userinfo was accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(error, HttpConnectError::InvalidAuthority));
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn reports_rejection_without_exposing_response_fields() -> TestResult {
    let (client, mut proxy) = duplex(4096);
    let subscriber = OutcomeSubscriber::default();
    let proxy_task = tokio::spawn(async move {
        let _request = read_head(&mut proxy).await?;
        proxy
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nX-Secret: value\r\n\r\n")
            .await?;
        Ok::<_, std::io::Error>(())
    });

    let error = match connect_http_tunnel(
        client,
        "origin.example:443",
        &[HttpConnectHeader::authority("Host")],
    )
    .with_subscriber(subscriber.dispatch())
    .await
    {
        Ok(_) => return Err("407 response established a tunnel".into()),
        Err(error) => error,
    };
    assert!(matches!(error, HttpConnectError::Rejected { status: 407 }));
    assert_eq!(error.kind(), HttpConnectErrorKind::Rejected);
    assert!(!error.to_string().contains("X-Secret"));
    assert_eq!(subscriber.outcomes_for("proxy.http_connect"), ["error"]);
    proxy_task.await??;
    Ok(())
}

#[tokio::test]
async fn switching_protocols_is_terminal_and_header_debug_redacts_values() -> TestResult {
    let (client, mut proxy) = duplex(4096);
    let proxy_task = tokio::spawn(async move {
        let _request = read_head(&mut proxy).await?;
        proxy
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\ncoalesced-upgraded-bytes")
            .await?;
        Ok::<_, std::io::Error>(())
    });
    let headers = [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::field(RequestHeader::new("Proxy-Authorization", "secret")),
    ];

    let error = match connect_http_tunnel(client, "origin.example:443", &headers).await {
        Ok(_) => return Err("101 response established a tunnel".into()),
        Err(error) => error,
    };
    assert!(matches!(error, HttpConnectError::Rejected { status: 101 }));
    let debug = format!("{:?}", headers[1]);
    assert!(debug.contains("Proxy-Authorization"));
    assert!(!debug.contains("secret"));
    proxy_task.await??;
    Ok(())
}

#[tokio::test]
async fn oversized_response_head_is_bounded() -> TestResult {
    let (client, mut proxy) = duplex(64 * 1024);
    let proxy_task = tokio::spawn(async move {
        proxy.write_all(&vec![b'a'; 32 * 1024]).await?;
        Ok::<_, std::io::Error>(())
    });

    let error = match connect_http_tunnel(
        client,
        "origin.example:443",
        &[HttpConnectHeader::authority("Host")],
    )
    .await
    {
        Ok(_) => return Err("oversized proxy response was accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        HttpConnectError::ResponseHeadTooLarge { maximum: 32_768 }
    ));
    proxy_task.await??;
    Ok(())
}

#[tokio::test]
async fn informational_response_count_is_bounded() -> TestResult {
    let (client, mut proxy) = duplex(16 * 1024);
    let proxy_task = tokio::spawn(async move {
        let _request = read_head(&mut proxy).await?;
        for _ in 0..9 {
            proxy.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        proxy.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
        Ok::<_, std::io::Error>(())
    });

    let error = match connect_http_tunnel(
        client,
        "origin.example:443",
        &[HttpConnectHeader::authority("Host")],
    )
    .await
    {
        Ok(_) => return Err("unbounded informational responses were accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        HttpConnectError::TooManyInformationalResponses { maximum: 8 }
    ));
    proxy_task.await??;
    Ok(())
}

#[tokio::test]
async fn dropping_negotiation_records_cancellation() -> TestResult {
    let (client, _proxy) = duplex(4096);
    let subscriber = OutcomeSubscriber::default();

    assert!(
        poll_once_then_drop(
            connect_http_tunnel(
                client,
                "origin.example:443",
                &[HttpConnectHeader::authority("Host")],
            ),
            subscriber.clone(),
        )
        .await,
        "CONNECT negotiation completed before cancellation"
    );
    assert_eq!(subscriber.outcomes_for("proxy.http_connect"), ["cancelled"]);
    Ok(())
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 32 * 1024 {
            return Err(std::io::Error::other("request head exceeded test bound"));
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}
