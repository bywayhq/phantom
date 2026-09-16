use std::{
    future::Future,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex},
    net::TcpListener,
};
use tracing::instrument::WithSubscriber;

use super::super::socks5::connect_socks5_tunnel;
use super::super::{Socks5ErrorKind, connect_socks5_tunnel_direct};
use crate::{
    tls::test_support::TouchCountingStream,
    tracing_test::{OutcomeSubscriber, poll_once_then_drop},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TARGET_HOST: &str = "origin.example";
const TARGET_PORT: u16 = 8443;

#[tokio::test]
async fn direct_remote_dns_emits_exact_domain_request_and_returns_raw_stream() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        expect_greeting(&mut stream).await?;
        stream.write_all(&[0x05, 0x00]).await?;
        let request = read_domain_request(&mut stream).await?;
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0xfb])
            .await?;
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await?;
        stream.write_all(b"pong").await?;
        Ok::<_, std::io::Error>((request, payload))
    });
    let subscriber = OutcomeSubscriber::default();

    let mut tunnel =
        connect_socks5_tunnel_direct("127.0.0.1", address.port(), TARGET_HOST, TARGET_PORT)
            .with_subscriber(subscriber.dispatch())
            .await?;
    tunnel.write_all(b"ping").await?;
    let mut response = [0_u8; 4];
    tunnel.read_exact(&mut response).await?;

    let (request, payload) = server.await??;
    assert_eq!(
        request,
        [
            &[0x05, 0x01, 0x00, 0x03, TARGET_HOST.len() as u8][..],
            TARGET_HOST.as_bytes(),
            &TARGET_PORT.to_be_bytes(),
        ]
        .concat()
    );
    assert_eq!(&payload, b"ping");
    assert_eq!(&response, b"pong");
    assert_eq!(subscriber.outcomes_for("proxy.socks5"), ["ok"]);
    Ok(())
}

#[tokio::test]
async fn accepts_fragmented_ipv4_ipv6_and_domain_success_replies() -> TestResult {
    for reply in [
        vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb],
        vec![
            0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
        ],
        vec![
            0x05, 0x00, 0x00, 0x03, 5, b'p', b'r', b'o', b'x', b'y', 0x01, 0xbb,
        ],
    ] {
        let (client, proxy) = duplex(4096);
        let server = tokio::spawn(serve_fragmented_success(proxy, reply));

        let tunnel = connect_socks5_tunnel(client, TARGET_HOST, TARGET_PORT).await?;
        drop(tunnel);
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn malformed_method_and_connect_responses_are_negotiation_errors() -> TestResult {
    let (client, mut proxy) = duplex(1024);
    let server = tokio::spawn(async move {
        expect_greeting(&mut proxy).await?;
        proxy.write_all(&[0x04, 0x00]).await
    });
    let error = match connect_socks5_tunnel(client, TARGET_HOST, TARGET_PORT).await {
        Ok(_) => return Err("invalid method response version was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
    server.await??;

    for reply in [
        vec![0x05, 0x00, 0x01, 0x01],
        vec![0x05, 0x00, 0x00, 0x09],
        vec![0x05, 0x00, 0x00, 0x01, 127],
        vec![0x05, 0x00, 0x00, 0x03, 1, 0xff, 0x01, 0xbb],
    ] {
        let (client, proxy) = duplex(1024);
        let server = tokio::spawn(serve_reply_and_close(proxy, reply));
        let error = match connect_socks5_tunnel(client, TARGET_HOST, TARGET_PORT).await {
            Ok(_) => return Err("malformed CONNECT response was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_connect_is_typed_and_traced_without_peer_payload() -> TestResult {
    let (client, proxy) = duplex(1024);
    let server = tokio::spawn(serve_reply_and_close(proxy, vec![0x05, 0x05, 0x00, 0x01]));
    let subscriber = OutcomeSubscriber::default();

    let error = match connect_socks5_tunnel(client, TARGET_HOST, TARGET_PORT)
        .with_subscriber(subscriber.dispatch())
        .await
    {
        Ok(_) => return Err("rejected SOCKS5 CONNECT succeeded".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), Socks5ErrorKind::Rejected);
    assert_eq!(error.to_string(), "SOCKS5 proxy rejected CONNECT");
    assert_eq!(subscriber.outcomes_for("proxy.socks5"), ["error"]);
    assert_eq!(subscriber.error_kinds_for("proxy.socks5"), ["rejected"]);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn invalid_target_fails_before_stream_io() -> TestResult {
    let (client, _proxy) = duplex(1024);
    let touches = Arc::new(AtomicUsize::new(0));
    let stream = TouchCountingStream::new(client, touches.clone());
    let host = "a".repeat(256);

    let error = match connect_socks5_tunnel(stream, &host, TARGET_PORT).await {
        Ok(_) => return Err("overlong target was accepted".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), Socks5ErrorKind::InvalidTarget);
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn proxy_tcp_failure_has_connect_kind() -> TestResult {
    let error = match connect_socks5_tunnel_direct("127.0.0.1", 0, TARGET_HOST, TARGET_PORT).await {
        Ok(_) => return Err("TCP port zero unexpectedly accepted a proxy connection".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), Socks5ErrorKind::Connect);
    Ok(())
}

#[tokio::test]
async fn dropping_negotiation_records_cancellation() -> TestResult {
    let (client, _proxy) = duplex(1024);
    let subscriber = OutcomeSubscriber::default();

    assert!(
        poll_once_then_drop(
            connect_socks5_tunnel(client, TARGET_HOST, TARGET_PORT),
            subscriber.clone(),
        )
        .await,
        "SOCKS5 negotiation completed before cancellation"
    );
    assert_eq!(subscriber.outcomes_for("proxy.socks5"), ["cancelled"]);
    Ok(())
}

#[test]
fn polling_direct_tunnel_without_tokio_returns_runtime_error() -> TestResult {
    let mut future = Box::pin(connect_socks5_tunnel_direct(
        "127.0.0.1",
        9,
        TARGET_HOST,
        TARGET_PORT,
    ));
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("SOCKS5 request waited without a runtime".into()),
    };
    let error = match result {
        Ok(_) => return Err("SOCKS5 request completed outside a runtime".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Socks5ErrorKind::RuntimeUnavailable);
    Ok(())
}

async fn serve_fragmented_success(
    mut proxy: tokio::io::DuplexStream,
    reply: Vec<u8>,
) -> std::io::Result<()> {
    expect_greeting(&mut proxy).await?;
    for byte in [0x05, 0x00] {
        proxy.write_all(&[byte]).await?;
        tokio::task::yield_now().await;
    }
    let _request = read_domain_request(&mut proxy).await?;
    for byte in reply {
        proxy.write_all(&[byte]).await?;
        tokio::task::yield_now().await;
    }
    Ok(())
}

async fn serve_reply_and_close(
    mut proxy: tokio::io::DuplexStream,
    reply: Vec<u8>,
) -> std::io::Result<()> {
    expect_greeting(&mut proxy).await?;
    proxy.write_all(&[0x05, 0x00]).await?;
    let _request = read_domain_request(&mut proxy).await?;
    proxy.write_all(&reply).await
}

async fn expect_greeting(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<()> {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await?;
    if greeting == [0x05, 0x01, 0x00] {
        Ok(())
    } else {
        Err(std::io::Error::other("unexpected SOCKS5 greeting"))
    }
}

async fn read_domain_request(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 5];
    stream.read_exact(&mut prefix).await?;
    if prefix[..4] != [0x05, 0x01, 0x00, 0x03] {
        return Err(std::io::Error::other("unexpected SOCKS5 CONNECT prefix"));
    }
    let mut suffix = vec![0_u8; usize::from(prefix[4]) + 2];
    stream.read_exact(&mut suffix).await?;
    Ok([prefix.as_slice(), suffix.as_slice()].concat())
}
