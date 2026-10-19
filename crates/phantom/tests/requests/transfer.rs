//! Public body-byte caps, pacing and multiplexed cancellation.

use crate::support::tls::{self, H2_ALPN, TestIdentity, TestResult};
use bytes::{Buf, Bytes};
use http::Response;
use phantom::{
    Client, ContentDecoding, HttpProtocol, Method, RedirectPolicy, RequestErrorKind, RequestHeader,
    TransferControl, TransferLimits,
};
use std::{
    future::{Future, poll_fn},
    io::Write,
    net::Ipv4Addr,
    num::{NonZeroU64, NonZeroUsize},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};

const BUDGET: Duration = Duration::from_secs(10);

#[tokio::test]
async fn http3_upload_counts_and_download_caps_use_body_bytes() -> TestResult<()> {
    timeout(BUDGET, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = crate::support::h3::server_endpoint(&identity)?;
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
            let mut connection =
                h3::server::Connection::new(h3_quinn::Connection::new(incoming)).await?;
            let request = connection.accept().await?.ok_or("request absent")?;
            let (_, mut stream) = request.resolve_request().await?;
            let mut received = Vec::new();
            while let Some(mut data) = stream.recv_data().await? {
                received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(received, b"data");
            stream.send_response(Response::new(())).await?;
            stream.send_data(Bytes::from_static(b"abcd")).await?;
            stream.finish().await?;
            drop(stream);
            match connection.accept().await {
                Ok(None) => Ok(()),
                Err(error) if error.is_h3_no_error() => Ok(()),
                Ok(Some(_)) => Err("unexpected request".into()),
                Err(error) => Err(Box::<dyn std::error::Error + Send + Sync>::from(error)),
            }
        });
        let client = Client::builder(
            phantom::profile::ClientProfile::new(tls::tls_settings())
                .with_http3(crate::support::h3::client_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
        let control = TransferControl::new(TransferLimits::new().upload_bytes(4).download_bytes(3));
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/"),
            )?
            .body("data")
            .transfer_control(control.clone())
            .send()
            .await?;
        let error = response
            .into_body()
            .collect_with_limit(4)
            .await
            .err()
            .ok_or("download cap ignored")?;
        assert_eq!(error.kind(), RequestErrorKind::Transfer);
        assert_eq!(control.snapshot().upload_body_bytes, 4);
        assert_eq!(control.snapshot().download_encoded_bytes, 0);
        client.shutdown().await;
        peers.join_next().await.ok_or("peer absent")???;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn deliberate_pacing_does_not_consume_network_read_idle() -> TestResult<()> {
    let (body, control) = paced_body(false).await?;
    assert_eq!(timeout(BUDGET, body.collect_with_limit(4)).await??, "abcd");
    assert_eq!(control.snapshot().download_encoded_bytes, 4);
    Ok(())
}

#[tokio::test]
async fn total_deadline_expires_while_a_download_chunk_is_paced() -> TestResult<()> {
    let (body, control) = paced_body(true).await?;
    let error = timeout(BUDGET, body.collect_with_limit(4))
        .await?
        .err()
        .ok_or("total deadline ignored during pacing")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(phantom::TimeoutPhase::Total));
    assert_eq!(control.snapshot().download_encoded_bytes, 0);
    Ok(())
}

async fn paced_body(total_limit: bool) -> TestResult<(phantom::ResponseBody, TransferControl)> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            tls::read_head(&mut socket).await?;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd")
                .await?;
            Ok::<_, std::io::Error>(())
        });
        let client =
            Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings())).build()?;
        let rate = if total_limit {
            NonZeroU64::MIN
        } else {
            NonZeroU64::new(20).ok_or("rate absent")?
        };
        let control = TransferControl::new(TransferLimits::new().download_rate(rate));
        let mut limits = phantom::RequestTimeoutOverrides::new()
            .read_idle(phantom::TimeoutOverride::Limit(Duration::from_millis(10)));
        if total_limit {
            limits = limits.total(phantom::TimeoutOverride::Limit(Duration::from_secs(1)));
        }
        let response = client
            .get(HttpProtocol::Http1, &url)?
            .timeouts(limits)
            .transfer_control(control.clone())
            .send()
            .await?;
        peers.join_next().await.ok_or("peer absent")???;
        Ok((response.into_body(), control))
    })
    .await?
}

#[tokio::test]
async fn encoded_and_decoded_download_counts_have_distinct_boundaries() -> TestResult<()> {
    timeout(BUDGET, async {
        let payload = vec![b'x'; 20_000];
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&payload)?;
        let encoded = gzip.finish()?;
        let length = encoded.len();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            tls::read_head(&mut socket).await?;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            socket.write_all(&encoded).await?;
            Ok::<_, std::io::Error>(())
        });
        let client = Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings())).build()?;
        let control = TransferControl::new(TransferLimits::new().download_bytes(length as u64));
        let response = client.get(HttpProtocol::Http1, &url)?
            .header(RequestHeader::new("accept-encoding", "gzip"))
            .content_decoding(ContentDecoding::advertised(25_000))
            .transfer_control(control.clone()).send().await?;
        assert_eq!(response.into_body().collect_with_limit(25_000).await?, payload);
        let counts = control.snapshot();
        assert_eq!(counts.download_encoded_bytes, length as u64);
        assert_eq!(counts.download_decoded_bytes, 20_000);
        peers.join_next().await.ok_or("peer absent")???;
        Ok(())
    }).await?
}

#[tokio::test]
async fn redirect_resends_share_upload_allowance_and_return_typed_exhaustion() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/first", listener.local_addr()?);
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            tls::read_head(&mut socket).await?;
            let mut body = [0; 4];
            socket.read_exact(&mut body).await?;
            assert_eq!(&body, b"data");
            socket.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            drop(socket);
            let (mut socket, _) = listener.accept().await?;
            // The second request may fail before or after its head is written.
            let mut bytes = Vec::new();
            let _ = socket.read_to_end(&mut bytes).await;
            assert!(!bytes.windows(4).any(|bytes| bytes == b"data"));
            Ok::<_, std::io::Error>(())
        });
        let client = Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN)).build()?;
        let control = TransferControl::new(TransferLimits::new().upload_bytes(4));
        let error = client.request(HttpProtocol::Http1, Method::POST, &url)?
            .body("data").transfer_control(control.clone()).send().await.err().ok_or("resend exceeded upload cap")?;
        assert_eq!(error.kind(), RequestErrorKind::Transfer);
        assert_eq!(control.snapshot().upload_body_bytes, 4);
        assert_eq!(control.snapshot().upload_reserved_bytes, 4);
        peers.join_next().await.ok_or("peer absent")???;
        Ok(())
    }).await?
}

#[tokio::test]
async fn cancelling_a_paced_http2_body_preserves_sibling_streams() -> TestResult<()> {
    timeout(BUDGET, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(H2_ALPN)?;
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let stream = tls::accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            for _ in 0..2 {
                let (_, mut respond) = connection.accept().await.ok_or("request absent")??;
                let mut body = respond.send_response(Response::new(()), false)?;
                body.send_data(Bytes::from_static(b"abcd"), true)?;
            }
            // Keep driving the same connection until client shutdown.
            poll_fn(|cx| connection.poll_closed(cx)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let client = tls::client_builder(&identity, true).build()?;
        let control = TransferControl::new(TransferLimits::new().download_rate(NonZeroU64::MIN));
        let first = client.get(HttpProtocol::Http2, &url)?.transfer_control(control.clone()).send().await?;
        let mut read = Box::pin(first.into_body().collect_with_limit(4));
        assert!(matches!(poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await, Poll::Pending));
        // Ensure pacing has actually reserved data rather than waiting on I/O.
        while control.snapshot().download_reserved_bytes == 0 {
            tokio::select! {
                result = &mut read => return Err(format!("paced body completed: {result:?}").into()),
                () = tokio::task::yield_now() => {},
            }
        }
        let second = client.get(HttpProtocol::Http2, &url)?.send().await?;
        assert_eq!(second.into_body().collect_with_limit(4).await?, "abcd");
        drop(read);
        assert_eq!(control.snapshot().download_reserved_bytes, 4);
        assert_eq!(control.snapshot().download_encoded_bytes, 0);
        client.shutdown().await;
        peers.join_next().await.ok_or("peer absent")???;
        Ok(())
    }).await?
}
