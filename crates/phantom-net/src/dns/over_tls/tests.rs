use std::{future::Future, io, net::SocketAddr, num::NonZeroUsize, time::Duration};

use btls::ssl::{AlpnError, SslAcceptor, select_next_proto};
use phantom_profile::browser::chrome;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};

use super::{DnsOverTlsTransport, authentication_name};
use crate::{
    dns::wire::{DnsWireQuery, DnsWireQueryKind, DnsWireResult},
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestResult, accept_tls},
};

fn query(name: &str) -> TestResult<DnsWireQuery> {
    Ok(DnsWireQuery::new(name, DnsWireQueryKind::A, 0, None)?)
}

async fn peer() -> TestResult<(SocketAddr, TcpListener, TestIdentity, SslAcceptor)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let identity = TestIdentity::generate()?;
    let mut acceptor = identity.acceptor_builder()?;
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x03dot", offered).ok_or(AlpnError::NOACK)
    });
    Ok((listener.local_addr()?, listener, identity, acceptor.build()))
}

fn transport(
    address: SocketAddr,
    identity: &TestIdentity,
    maximum: NonZeroUsize,
) -> TestResult<DnsOverTlsTransport> {
    Ok(DnsOverTlsTransport::new_with_additional_roots(
        &chrome::v154_tcp_tls(),
        TEST_SERVER_NAME,
        [address],
        Duration::from_secs(3),
        maximum,
        [identity.root_der()],
    )?)
}

async fn read_query(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let length = usize::from(stream.read_u16().await?);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn answer(mut bytes: Vec<u8>, last: u8) -> Vec<u8> {
    bytes[2..4].copy_from_slice(&[0x81, 0x80]);
    bytes[6..8].copy_from_slice(&[0, 1]);
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, last]);
    bytes
}

async fn write_answer(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<()> {
    let prefix = u16::try_from(bytes.len())
        .map_err(io::Error::other)?
        .to_be_bytes();
    // Independent framing deliberately splits the prefix and payload.
    stream.write_all(&prefix[..1]).await?;
    stream.flush().await?;
    tokio::task::yield_now().await;
    stream.write_all(&prefix[1..]).await?;
    for chunk in bytes.chunks(7) {
        stream.write_all(chunk).await?;
    }
    stream.flush().await
}

fn last_address(result: DnsWireResult) -> TestResult<std::net::IpAddr> {
    let DnsWireResult::Addresses(records) = result else {
        return Err("expected address answer".into());
    };
    records
        .addresses()
        .first()
        .copied()
        .ok_or_else(|| "missing address".into())
}

#[tokio::test]
async fn pipelined_replies_can_arrive_out_of_order_on_one_verified_connection() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::new(2).ok_or("bound")?)?;
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (mut stream, sni) = accept_tls(listener, acceptor).await?;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(stream.ssl().selected_alpn_protocol(), Some(&b"dot"[..]));
        let first = read_query(&mut stream).await?;
        let second = read_query(&mut stream).await?;
        assert_ne!(first[..2], second[..2]);
        write_answer(&mut stream, &answer(second, 2)).await?;
        write_answer(&mut stream, &answer(first, 1)).await?;
        let third = read_query(&mut stream).await?;
        write_answer(&mut stream, &answer(third, 3)).await?;
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte)).await??,
            0
        );
        TestResult::Ok(())
    });
    let first = query("first.example")?;
    let second = query("second.example")?;
    let (a, b) = tokio::join!(transport.exchange(&first), transport.exchange(&second));
    assert_eq!(
        last_address(a?)?,
        "203.0.113.1".parse::<std::net::IpAddr>()?
    );
    assert_eq!(
        last_address(b?)?,
        "203.0.113.2".parse::<std::net::IpAddr>()?
    );
    assert_eq!(
        last_address(transport.exchange(&query("third.example")?).await?)?,
        "203.0.113.3".parse::<std::net::IpAddr>()?
    );
    drop(transport);
    joined(&mut peers).await??;
    Ok(())
}

#[tokio::test]
async fn cancelling_one_query_preserves_its_sibling_and_reuses_the_connection() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::new(2).ok_or("bound")?)?;
    let (received, pending) = tokio::sync::oneshot::channel();
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let cancelled = read_query(&mut stream).await?;
        received.send(()).map_err(|_| "receiver gone")?;
        let sibling = read_query(&mut stream).await?;
        write_answer(&mut stream, &answer(sibling, 2)).await?;
        // A late reply for the cancelled request must not satisfy another.
        write_answer(&mut stream, &answer(cancelled, 1)).await?;
        let next = read_query(&mut stream).await?;
        write_answer(&mut stream, &answer(next, 3)).await?;
        TestResult::Ok(())
    });
    let clone = transport.clone();
    let mut queries = JoinSet::new();
    let cancelled = queries.spawn(async move {
        clone
            .exchange(&query("cancel.example").map_err(io::Error::other)?)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), pending).await??;
    let sibling_query = query("sibling.example")?;
    let sibling = transport.exchange(&sibling_query);
    tokio::pin!(sibling);
    // Poll the second exchange before cancelling the first.
    assert!(matches!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(sibling.as_mut().poll(cx))).await,
        std::task::Poll::Pending
    ));
    cancelled.abort();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), queries.join_next())
            .await?
            .ok_or("cancelled task disappeared")?
            .is_err_and(|error| error.is_cancelled())
    );
    assert_eq!(
        last_address(sibling.await?)?,
        "203.0.113.2".parse::<std::net::IpAddr>()?
    );
    assert_eq!(
        last_address(transport.exchange(&query("next.example")?).await?)?,
        "203.0.113.3".parse::<std::net::IpAddr>()?
    );
    joined(&mut peers).await??;
    Ok(())
}

#[tokio::test]
async fn admission_is_shared_and_exhaustion_sends_no_additional_query() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::MIN)?;
    let clone = transport.clone();
    let (received, pending) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let bytes = read_query(&mut stream).await?;
        received.send(()).map_err(|_| "receiver gone")?;
        tokio::time::timeout(Duration::from_secs(5), wait).await??;
        write_answer(&mut stream, &answer(bytes, 1)).await?;
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .is_err()
        );
        TestResult::Ok(())
    });
    let mut queries = JoinSet::new();
    queries.spawn(async move {
        clone
            .exchange(&query("held.example").map_err(io::Error::other)?)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), pending).await??;
    assert_eq!(
        transport
            .exchange(&query("blocked.example")?)
            .await
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    release.send(()).map_err(|_| "receiver gone")?;
    joined(&mut queries).await??;
    joined(&mut peers).await??;
    Ok(())
}

#[tokio::test]
async fn certificate_trust_and_endpoint_name_remain_mandatory() -> TestResult<()> {
    for wrong_name in [false, true] {
        let (address, listener, identity, acceptor) = peer().await?;
        let name = if wrong_name {
            "wrong.phantom.test"
        } else {
            TEST_SERVER_NAME
        };
        let roots = if wrong_name {
            vec![identity.root_der()]
        } else {
            vec![]
        };
        let transport = DnsOverTlsTransport::new_with_additional_roots(
            &chrome::v154_tcp_tls(),
            name,
            [address],
            Duration::from_secs(3),
            NonZeroUsize::MIN,
            roots,
        )?;
        let mut peers = JoinSet::new();
        peers.spawn(accept_tls(listener, acceptor));
        assert!(transport.exchange(&query("example.com")?).await.is_err());
        assert!(joined(&mut peers).await?.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn deadline_covers_a_peer_that_never_completes_tls_setup() -> TestResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let transport = DnsOverTlsTransport::new(
        &chrome::v154_tcp_tls(),
        TEST_SERVER_NAME,
        [listener.local_addr()?],
        Duration::from_millis(100),
        NonZeroUsize::MIN,
    )?;
    let question = query("example.com")?;
    let exchange = transport.exchange(&question);
    let server = async {
        let (stream, _) = listener.accept().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(stream);
        io::Result::Ok(())
    };
    let (result, peer) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exchange, server)
    })
    .await?;
    peer?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[tokio::test]
async fn a_matching_id_with_the_wrong_question_is_rejected() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::MIN)?;
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let mut bytes = read_query(&mut stream).await?;
        bytes[13] ^= 1;
        write_answer(&mut stream, &answer(bytes, 1)).await?;
        TestResult::Ok(())
    });
    assert_eq!(
        transport
            .exchange(&query("example.com")?)
            .await
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    joined(&mut peers).await??;
    Ok(())
}

#[test]
fn invalid_configuration_fails_without_network_work() -> TestResult<()> {
    for name in [
        "",
        "https://dns.example",
        "name..example",
        "-dns.example",
        "dns-.example",
        "é.example",
        "dns.example.",
    ] {
        assert!(authentication_name(name).is_err(), "{name}");
    }
    assert_eq!(authentication_name("::1")?, "::1");
    for addresses in [
        vec![],
        vec!["0.0.0.0:853".parse()?],
        vec!["224.0.0.1:853".parse()?],
        vec!["127.0.0.1:0".parse()?],
        vec!["[fe80::1]:853".parse()?],
    ] {
        assert!(
            DnsOverTlsTransport::new(
                &chrome::v154_tcp_tls(),
                TEST_SERVER_NAME,
                addresses,
                Duration::from_secs(1),
                NonZeroUsize::MIN
            )
            .is_err()
        );
    }
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert!(
            DnsOverTlsTransport::new(
                &chrome::v154_tcp_tls(),
                TEST_SERVER_NAME,
                ["127.0.0.1:853".parse()?],
                timeout,
                NonZeroUsize::MIN
            )
            .is_err()
        );
    }
    assert!(
        DnsOverTlsTransport::new(
            &chrome::v154_tcp_tls(),
            "127.0.0.1",
            ["127.0.0.2:853".parse()?],
            Duration::from_secs(1),
            NonZeroUsize::MIN
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_reply_id_cannot_complete_a_query() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::MIN)?;
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let bytes = read_query(&mut stream).await?;
        let mut wrong = answer(bytes.clone(), 99);
        wrong[0] ^= 1;
        write_answer(&mut stream, &wrong).await?;
        write_answer(&mut stream, &answer(bytes, 1)).await?;
        TestResult::Ok(())
    });
    assert_eq!(
        last_address(transport.exchange(&query("example.com")?).await?)?,
        "203.0.113.1".parse::<std::net::IpAddr>()?
    );
    joined(&mut peers).await??;
    Ok(())
}

#[tokio::test]
async fn a_query_after_connection_failure_opens_a_new_verified_connection() -> TestResult<()> {
    let (address, listener, identity, acceptor) = peer().await?;
    let transport = transport(address, &identity, NonZeroUsize::MIN)?;
    let mut peers = JoinSet::new();
    peers.spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let ssl = btls::ssl::Ssl::new(acceptor.context())?;
        let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
        std::pin::Pin::new(&mut stream).accept().await?;
        read_query(&mut stream).await?;
        drop(stream);
        let (mut stream, _) = accept_tls(listener, acceptor).await?;
        let bytes = read_query(&mut stream).await?;
        write_answer(&mut stream, &answer(bytes, 2)).await?;
        TestResult::Ok(())
    });
    assert!(transport.exchange(&query("failed.example")?).await.is_err());
    assert_eq!(
        last_address(transport.exchange(&query("next.example")?).await?)?,
        "203.0.113.2".parse::<std::net::IpAddr>()?
    );
    joined(&mut peers).await??;
    Ok(())
}

#[test]
fn missing_runtime_drivers_return_recoverable_errors() -> TestResult<()> {
    for enable_time in [false, true] {
        let mut builder = tokio::runtime::Builder::new_current_thread();
        if enable_time {
            builder.enable_time();
        }
        let runtime = builder.build()?;
        let transport = DnsOverTlsTransport::new(
            &chrome::v154_tcp_tls(),
            TEST_SERVER_NAME,
            ["127.0.0.1:853".parse()?],
            Duration::from_secs(1),
            NonZeroUsize::MIN,
        )?;
        let question = query("example.com")?;
        assert_eq!(
            runtime
                .block_on(transport.exchange(&question))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

// Dropping a JoinSet aborts every still-owned peer, including on assertion and
// error exits. Normal completion is observed through a bounded join.
async fn joined<T: Send + 'static>(tasks: &mut JoinSet<T>) -> TestResult<T> {
    Ok(
        tokio::time::timeout(Duration::from_secs(5), tasks.join_next())
            .await?
            .ok_or("fixture task disappeared")??,
    )
}
