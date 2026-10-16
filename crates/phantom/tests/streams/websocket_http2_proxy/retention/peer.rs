use crate::support::{tls, tunnel_proxy};
use btls::ssl::SslAcceptor;
use bytes::Bytes;
use std::{future::poll_fn, io, net::SocketAddr, time::Duration};
use tls::TestResult;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const QUIET: Duration = Duration::from_millis(100);

pub(super) async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: SocketAddr,
    mut done: oneshot::Receiver<()>,
) -> TestResult<()> {
    // IPv4 wins the real race while the primary's IPv6 refusal is pending.
    // Holding winner TLS lets that primary advance to this IPv4 endpoint.
    let (winner, address) = listener.accept().await?;
    assert!(address.is_ipv4());
    let (mut backup, address) = listener.accept().await?;
    assert!(address.is_ipv4());
    assert!(
        matches!(backup.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(timeout(QUIET, backup.read(&mut [0])).await.is_err());

    let stream = tls::accept_tls_stream(winner, acceptor).await?;
    assert_eq!(
        stream.ssl().selected_alpn_protocol(),
        Some(b"h2".as_slice())
    );
    let mut byte = [0];
    match backup.read(&mut byte).await {
        Ok(0) => {}
        Err(error) if tls::is_peer_gone(&error) => {}
        other => {
            return Err(format!(
                "raw backup was not retired without TLS or application bytes: {other:?}"
            )
            .into());
        }
    }
    drop(backup);

    // The peer cannot send SETTINGS or accept authenticated CONNECT until
    // verified outer TLS selected h2 and the real raw backup reached EOF.
    let mut connection = ::http2::server::handshake(stream).await?;
    let (anonymous, mut challenge) = connection
        .accept()
        .await
        .ok_or("no CONNECT after backup retirement")??;
    check_connect(&anonymous, origin, false);
    challenge.send_response(
        http::Response::builder()
            .status(407)
            .header("proxy-authenticate", "Basic realm=\"proxy\"")
            .body(())?,
        true,
    )?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("no authenticated CONNECT after challenge")??;
    check_connect(&request, origin, true);
    let send = respond.send_response(http::Response::new(()), false)?;
    let upstream = TcpStream::connect(origin).await?;
    let relay = relay(request.into_body(), send, upstream);
    tokio::pin!(relay);
    tokio::select! {
        biased;
        completed = &mut done => completed?,
        result = &mut relay => {
            result?;
            tokio::select! {
                biased;
                completed = &mut done => completed?,
                next = connection.accept() => return unexpected_connect(next),
            }
        }
        next = connection.accept() => return unexpected_connect(next),
    }
    // Only the challenge and its authenticated retry are permitted. Neither
    // another CONNECT nor a third physical proxy connection is needed.
    assert!(tunnel_proxy::no_connection_arrives(&listener).await);
    Ok(())
}

fn check_connect(
    request: &http::Request<::http2::RecvStream>,
    origin: SocketAddr,
    authenticated: bool,
) {
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(
        request.uri().authority().map(|a| a.as_str()),
        Some(origin.to_string().as_str())
    );
    assert!(request.uri().scheme().is_none());
    assert!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .is_none()
    );
    if authenticated {
        assert_eq!(
            request.headers()["proxy-authorization"],
            "Basic YWxpY2U6c2VjcmV0"
        );
    } else {
        assert!(!request.headers().contains_key("proxy-authorization"));
    }
    assert_eq!(request.headers()["user-agent"], "current");
}

fn unexpected_connect<T>(accepted: Option<Result<T, ::http2::Error>>) -> TestResult<()> {
    match accepted {
        Some(Err(error)) => Err(error.into()),
        Some(Ok(_)) => Err("more than one proxy CONNECT was sent".into()),
        None => Err("proxy connection ended before WebSocket completion".into()),
    }
}

async fn relay(
    mut receive: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
) -> TestResult<()> {
    let (mut read, mut write) = upstream.into_split();
    let incoming = async {
        let result = async {
            while let Some(chunk) = receive.data().await {
                let chunk = chunk?;
                receive.flow_control().release_capacity(chunk.len())?;
                write.write_all(&chunk).await?;
            }
            write.shutdown().await?;
            TestResult::Ok(())
        }
        .await;
        tunnel_proxy::relay_result(result)
    };
    let outgoing = async {
        let result = async {
            let mut buffer = [0; 16 * 1024];
            loop {
                let count = read.read(&mut buffer).await?;
                if count == 0 {
                    send.send_data(Bytes::new(), true)?;
                    return TestResult::Ok(());
                }
                let mut data = Bytes::copy_from_slice(&buffer[..count]);
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let capacity = poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or("proxy response capacity closed")??;
                    if capacity != 0 {
                        let part = data.split_to(capacity.min(data.len()));
                        send.send_data(part, false)?;
                    }
                }
            }
        }
        .await;
        tunnel_proxy::relay_result(result)
    };
    tokio::try_join!(incoming, outgoing)?;
    Ok(())
}
