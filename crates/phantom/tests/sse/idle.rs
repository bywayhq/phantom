use std::{error::Error, net::Ipv4Addr, pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use phantom::{HttpProtocol, SseErrorKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, sleep, timeout},
};
use tokio_btls::SslStream;

use super::{
    TestResult,
    tls_support::{H1_ALPN, TestIdentity, read_head, test_client},
};

#[tokio::test(flavor = "current_thread")]
async fn activity_resets_a_cancellation_safe_deadline() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (response_ready, response_ready_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut first = accept_tls_reusable(&listener, &acceptor).await?;
        let _first_head = read_head(&mut first).await?;
        first
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await?;
        first.flush().await?;
        response_ready
            .send(())
            .map_err(|_| "client stopped before the idle response was ready")?;

        sleep(Duration::from_millis(250)).await;
        first.write_all(b"d\r\n: keepalive\n\n\r\n").await?;
        first.flush().await?;
        sleep(Duration::from_millis(250)).await;
        first.write_all(b"d\r\ndata: alive\n\n\r\n").await?;
        first.flush().await?;
        await_peer_close(&mut first).await?;

        let mut second = accept_tls_reusable(&listener, &acceptor).await?;
        let _second_head = read_head(&mut second).await?;
        second
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Content-Length: 15\r\n\
                  Connection: close\r\n\r\n\
                  data: resumed\n\n",
            )
            .await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let response = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .idle_timeout(Duration::from_secs(1))
        .initial_retry(Duration::ZERO)
        .max_reconnects(1)
        .connect()
        .await?;
    let mut source = response.into_body();
    assert_eq!(source.idle_timeout(), Some(Duration::from_secs(1)));
    response_ready_rx
        .await
        .map_err(|_| "server stopped before the idle response was ready")?;

    let active = source
        .next_event()
        .await?
        .ok_or("event after keepalive comment was missing")?;
    assert_eq!(active.data(), "alive");
    assert!(
        timeout(Duration::from_millis(900), source.next_event())
            .await
            .is_err(),
        "idle deadline elapsed too early"
    );
    let resumed_at = Instant::now();
    let event = source
        .next_event()
        .await?
        .ok_or("reconnected event was missing")?;
    assert_eq!(event.data(), "resumed");
    assert_eq!(
        source.reconnects(),
        1,
        "the idle deadline did not trigger exactly one reconnect"
    );
    let remaining = Instant::now().duration_since(resumed_at);
    assert!(
        (Duration::from_millis(20)..Duration::from_millis(750)).contains(&remaining),
        "cancelling the read restarted or discarded the idle deadline: {remaining:?}"
    );
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn timeout_without_a_reconnect_budget_is_terminal() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls_reusable(&listener, &acceptor).await?;
        let _head = read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        await_peer_close(&mut stream).await
    });

    let response = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .idle_timeout(Duration::from_secs(1))
        .max_reconnects(0)
        .connect()
        .await?;
    let mut source = response.into_body();
    let started_at = Instant::now();
    let error = source
        .next_event()
        .await
        .err()
        .ok_or("idle response remained open without a reconnect budget")?;
    assert_eq!(error.kind(), SseErrorKind::IdleTimeout);
    assert_eq!(
        Instant::now().duration_since(started_at),
        Duration::from_secs(1)
    );
    assert!(source.is_closed());
    assert_eq!(source.next_event().await?, None);
    server.await??;
    Ok(())
}

#[tokio::test]
async fn invalid_timeout_fails_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;

    let error = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .idle_timeout(Duration::MAX)
        .connect()
        .await
        .err()
        .ok_or("unrepresentable idle timeout was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidIdleTimeout);

    let listener = listener.into_std()?;
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "invalid idle configuration touched the network"
    );
    Ok(())
}

async fn accept_tls_reusable(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn await_peer_close(stream: &mut SslStream<TcpStream>) -> TestResult<()> {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte).await {
        Ok(0) | Err(_) => Ok(()),
        Ok(_) => Err("idle response received unexpected client bytes".into()),
    }
}
