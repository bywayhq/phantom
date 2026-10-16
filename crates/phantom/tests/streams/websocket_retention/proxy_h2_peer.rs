use crate::support::{
    tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, is_peer_gone, read_head},
    websocket::append_server_frame,
};
use btls::ssl::Ssl;
use bytes::Bytes;
use http::{Method, Response};
use phantom_net::route::ConnectedStream;
use std::{pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

const QUIET: Duration = Duration::from_millis(100);
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Mode {
    Accept,
    Cancel,
    Reject,
    Reuse,
}

async fn outer(
    tcp: TcpStream,
    identity: &TestIdentity,
    https: bool,
) -> TestResult<ConnectedStream> {
    if !https {
        return Ok(ConnectedStream::new(tcp));
    }
    let acceptor = identity.acceptor(H1_ALPN)?;
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
    Pin::new(&mut tls).accept().await?;
    assert_eq!(
        tls.ssl().selected_alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    Ok(ConnectedStream::new(tls))
}
async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if is_peer_gone(&error) => Ok(()),
        other => {
            Err(format!("quiet raw proxy backup sent bytes instead of closing: {other:?}").into())
        }
    }
}
fn check_connect(head: &[u8], claimant: &str, authenticated: bool) -> TestResult<()> {
    let head = std::str::from_utf8(head)?;
    assert!(head.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\n"));
    assert!(head.contains("\r\nHost: 127.0.0.1:443\r\n"));
    if authenticated {
        assert!(head.contains("\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
    } else {
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("\r\nproxy-authorization:")
        );
    }
    if !claimant.is_empty() {
        assert!(head.contains(&format!("\r\nUser-Agent: {claimant}\r\n")));
    }
    Ok(())
}

pub(super) async fn serve(
    listener: TcpListener,
    origin: &TestIdentity,
    proxy: &TestIdentity,
    https: bool,
    mode: Mode,
    ready: oneshot::Sender<()>,
    done: oneshot::Receiver<()>,
) -> TestResult<()> {
    let (winner, _) = listener.accept().await?;
    // Hold winning proxy TLS/CONNECT until the physical backup has arrived.
    let (spare, _) = listener.accept().await?;
    let (mut winner, spare) =
        tokio::try_join!(outer(winner, proxy, https), outer(spare, proxy, https))?;
    let mut spare = Some(spare);
    let head = read_head(&mut winner).await?;
    let claimant = if mode == Mode::Reuse { "" } else { "current" };
    check_connect(
        &head,
        if mode == Mode::Cancel {
            "first"
        } else {
            claimant
        },
        false,
    )?;
    assert!(
        timeout(QUIET, spare.as_mut().ok_or("missing raw backup")?.read_u8())
            .await
            .is_err(),
        "backup sent speculative CONNECT/origin TLS"
    );
    let mut ready = Some(ready);
    let mut stream = if mode == Mode::Cancel {
        ready
            .take()
            .ok_or("missing cancellation barrier")?
            .send(())
            .map_err(|_| "caller ended before cancellation")?;
        closed(&mut winner).await?;
        drop(winner);
        let mut spare = spare.take().ok_or("missing claimant backup")?;
        let head = read_head(&mut spare).await?;
        check_connect(&head, claimant, false)?;
        spare
    } else {
        winner
    };
    // This fresh client has no accepted credential record. A challenge must
    // precede the single authenticated retry on the same physical stream.
    stream
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
        .await?;
    check_connect(&read_head(&mut stream).await?, claimant, true)?;
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let acceptor = origin.acceptor(H2_ALPN)?;
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut tls).accept().await?;
    assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(tls).await?;
    if mode != Mode::Cancel {
        closed(spare.as_mut().ok_or("missing retired backup")?).await?;
    }
    if mode == Mode::Reuse {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("missing ordinary request")??;
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/page");
        respond.send_response(Response::new(()), true)?;
        ready
            .take()
            .ok_or("missing reuse barrier")?
            .send(())
            .map_err(|_| "caller ended before ordinary response")?;
    }
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("missing WebSocket extended CONNECT")??;
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.uri().path(), "/events");
    assert_eq!(
        request.uri().authority().map(|a| a.as_str()),
        Some("127.0.0.1:443")
    );
    assert_eq!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .map(|p| p.as_str()),
        Some("websocket")
    );
    assert_eq!(
        request
            .headers()
            .get("user-agent")
            .ok_or("missing current user-agent")?,
        "current"
    );
    assert_eq!(
        request
            .headers()
            .get("x-claim")
            .ok_or("missing current opening field")?,
        "current"
    );
    #[cfg(feature = "cookies")]
    assert_eq!(
        request
            .headers()
            .get("cookie")
            .ok_or("missing current cookies")?,
        "claim=current"
    );
    let response = Response::builder()
        .status(if mode == Mode::Reject { 403 } else { 200 })
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    let data = if mode == Mode::Reject {
        b"denied".to_vec()
    } else {
        let mut wire = Vec::new();
        append_server_frame(&mut wire, true, 2, b"peer");
        wire
    };
    send.send_data(Bytes::from(data), mode == Mode::Reject)?;
    let finish = async {
        done.await.map_err(|_| "caller ended before completion")?;
        TestResult::Ok(())
    };
    tokio::pin!(finish);
    tokio::select! {
        biased;
        result = &mut finish => result?,
        next = connection.accept() => match next {
            Some(Ok(_)) => return Err("unexpected extra CONNECT/GET/application HEADERS".into()),
            Some(Err(error)) if error.get_io().is_some_and(is_peer_gone) => finish.await?,
            Some(Err(error)) => return Err(error.into()),
            None => finish.await?,
        }
    }
    assert!(
        timeout(QUIET, listener.accept()).await.is_err(),
        "opening or reuse dialed an extra proxy TCP"
    );
    drop((send, respond, request));
    Ok(())
}
