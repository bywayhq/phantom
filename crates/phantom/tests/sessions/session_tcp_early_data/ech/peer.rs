use std::{future::poll_fn, pin::Pin};

use btls::{
    hpke::HpkeKey,
    ssl::{Ssl, SslEchKeys},
};
use phantom_testkit::tls::EchTestKey;
use tokio_btls::SslStream;

use super::*;
use crate::early_data_server::Server;

pub(super) mod lifecycle;

pub(super) fn set_key(acceptor: &SslAcceptor, id: u8, key: &EchTestKey) -> TestResult<()> {
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &ech_config(id, key, PUBLIC_NAME),
        HpkeKey::dhkem_p256_sha256(&key.private_key)?,
    )?;
    acceptor.context().set_ech_keys(&keys.build())?;
    Ok(())
}

pub(super) async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    plain: SslAcceptor,
    transport: Transport,
    method: Method,
    recovery: Recovery,
    closed: oneshot::Sender<()>,
) -> TestResult<()> {
    let seed = accept(&listener, &acceptor, Duration::ZERO).await?;
    assert!(seed.stream.ssl().ech_accepted());
    answer(seed, transport, Method::GET, "/seed").await?;
    closed.send(()).map_err(|_| "seed close observer stopped")?;

    if matches!(recovery, Recovery::RemoveEch) {
        reject(&listener, &plain).await?;
    } else if matches!(recovery, Recovery::AuthenticationTimeout) {
        let (mut tcp, _) = listener.accept().await?;
        tokio::time::sleep(Duration::from_millis(400)).await;
        // Drain only handshake records until cancellation closes the socket.
        let mut bytes = [0; 4096];
        loop {
            match tcp.read(&mut bytes).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if tls_support::is_peer_gone(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        return Ok(());
    } else {
        set_key(&acceptor, 2, &TEST_ECH_KEYS[1])?;
        reject(&listener, &acceptor).await?;
    }

    if matches!(recovery, Recovery::ExhaustedBudget) {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "an exhausted HTTP budget opened a recovery connection"
        );
        return Ok(());
    }
    if matches!(recovery, Recovery::SecondRejection) {
        set_key(&acceptor, 3, &TEST_ECH_KEYS[0])?;
        reject(&listener, &acceptor).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a second authenticated rejection opened another connection"
        );
        return Ok(());
    }

    let acceptor = if matches!(recovery, Recovery::RemoveEch) {
        &plain
    } else {
        &acceptor
    };
    let recovered = accept(&listener, acceptor, Duration::ZERO).await?;
    assert!(!recovered.stream.ssl().session_reused());
    assert!(!recovered.stream.ssl().early_data_accepted());
    assert_eq!(
        recovered.stream.ssl().ech_accepted(),
        !matches!(recovery, Recovery::RemoveEch)
    );
    answer(recovered, transport, method, "/recovered").await
}

pub(super) async fn serve_shared(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
) -> TestResult<()> {
    let seed = accept(&listener, &acceptor, Duration::ZERO).await?;
    answer(seed, transport, Method::GET, "/seed").await?;
    closed.send(()).map_err(|_| "seed close observer stopped")?;
    set_key(&acceptor, 2, &TEST_ECH_KEYS[1])?;
    reject(&listener, &acceptor).await?;

    let fresh = accept(&listener, &acceptor, Duration::ZERO).await?;
    assert!(fresh.stream.ssl().ech_accepted());
    assert!(!fresh.stream.ssl().session_reused());
    assert!(!fresh.stream.ssl().early_data_accepted());
    let mut connection = ::http2::server::handshake(fresh).await?;
    let mut paths = Vec::new();
    for _ in 0..2 {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("shared H2 request missing")??;
        assert_eq!(request.method(), Method::GET);
        paths.push(request.uri().path().to_owned());
        respond.send_response(
            http::Response::builder().status(StatusCode::OK).body(())?,
            true,
        )?;
    }
    paths.sort();
    assert_eq!(paths, ["/first", "/second"]);
    connection.graceful_shutdown();
    match poll_fn(|context| connection.poll_closed(context)).await {
        Ok(()) => {}
        Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => {}
        Err(error) => return Err(error.into()),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "concurrent failed streams opened more than one fresh ECH connection"
    );
    Ok(())
}

pub(super) async fn serve_cancelled_post(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
    waiting: oneshot::Sender<()>,
) -> TestResult<()> {
    let seed = accept(&listener, &acceptor, Duration::ZERO).await?;
    answer(seed, transport, Method::GET, "/seed").await?;
    closed.send(()).map_err(|_| "seed close observer stopped")?;
    let (mut tcp, _) = listener.accept().await?;
    let mut bytes = [0; 4096];
    let received = tcp.read(&mut bytes).await?;
    if received == 0 {
        return Err("POST closed before sending its ClientHello".into());
    }
    waiting
        .send(())
        .map_err(|_| "POST cancellation observer stopped")?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match tcp.read(&mut bytes).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if tls_support::is_peer_gone(&error) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    if tokio::time::timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_ok()
    {
        return Err("cancelled POST opened another connection".into());
    }
    Ok(())
}

async fn reject(listener: &TcpListener, acceptor: &SslAcceptor) -> TestResult<()> {
    let (tcp, _) = listener.accept().await?;
    reject_stream(tcp, acceptor).await
}

pub(super) async fn serve_contended_admission(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
    arrived: oneshot::Sender<()>,
    allow_rejection: oneshot::Receiver<()>,
    blocked: oneshot::Sender<()>,
) -> TestResult<()> {
    let seed = accept(&listener, &acceptor, Duration::ZERO).await?;
    answer(seed, transport, Method::GET, "/seed").await?;
    closed.send(()).map_err(|_| "seed close observer stopped")?;
    set_key(&acceptor, 2, &TEST_ECH_KEYS[1])?;
    let (failed, _) = listener.accept().await?;
    arrived
        .send(())
        .map_err(|_| "failed connection observer stopped")?;
    allow_rejection.await?;
    reject_stream(failed, &acceptor).await?;
    let (mut competing, _) = listener.accept().await?;
    let mut bytes = [0; 4096];
    if competing.read(&mut bytes).await? == 0 {
        return Err("competing POST omitted its ClientHello".into());
    }
    blocked
        .send(())
        .map_err(|_| "competing connection observer stopped")?;
    loop {
        match competing.read(&mut bytes).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if tls_support::is_peer_gone(&error) => break,
            Err(error) => return Err(error.into()),
        }
    }
    if tokio::time::timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_ok()
    {
        return Err("expired recovery opened a fresh ECH connection".into());
    }
    Ok(())
}

async fn reject_stream(tcp: tokio::net::TcpStream, acceptor: &SslAcceptor) -> TestResult<()> {
    // The TLS answer is withheld so the client returns its real deferred
    // early-data connection before learning that the old ECH key is gone.
    tokio::time::sleep(SERVER_DELAY).await;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(true);
    let mut stream = SslStream::new(ssl, tcp)?;
    let handshake = Pin::new(&mut stream).accept().await;
    assert!(!stream.ssl().ech_accepted());
    assert!(!stream.ssl().early_data_accepted());
    if let Err(error) = handshake {
        // BoringSSL represents the peer's ech_required alert (121) as 1121.
        // Retain unrelated backend/I/O failures instead of treating them as a
        // successful observation of the authenticated rejection.
        if !is_ech_required(&error) {
            return Err(error.into());
        }
    } else {
        // The server can finish first; the client's authenticated ECH rejection
        // then arrives as an alert on this read instead of accept().
        let mut byte = [0; 1];
        match stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error)
                if tls_support::is_peer_gone(&error)
                    || error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<btls::ssl::Error>())
                        .is_some_and(is_ech_required) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err("rejected public-name connection received origin HTTP bytes".into());
            }
        }
    }
    Ok(())
}

fn is_ech_required(error: &btls::ssl::Error) -> bool {
    error.ssl_error().is_some_and(|stack| {
        !stack.errors().is_empty()
            && stack
                .errors()
                .iter()
                .all(|error| error.library_code() == 16 && error.reason_code() == 1121)
    })
}

async fn answer(
    mut stream: Server,
    transport: Transport,
    method: Method,
    path: &str,
) -> TestResult<()> {
    if transport.alpn() == H1_ALPN {
        let head = tls_support::read_head(&mut stream).await?;
        assert!(head.starts_with(format!("{method} {path} HTTP/1.1\r\n").as_bytes()));
        if path == "/recovered" {
            assert!(
                head.windows(b"x-frozen: original\r\n".len())
                    .any(|field| field.eq_ignore_ascii_case(b"x-frozen: original\r\n"))
            );
        }
        if method == Method::POST {
            let mut body = [0; 7];
            stream.read_exact(&mut body).await?;
            assert_eq!(&body, b"payload");
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        let mut byte = [0; 1];
        match stream.read(&mut byte).await {
            Ok(0) => Ok(()),
            Err(error) if tls_support::is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err("unexpected bytes after the recovered request".into()),
        }
    } else {
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection.accept().await.ok_or("H2 request missing")??;
        assert_eq!(request.method(), method);
        assert_eq!(request.uri().path(), path);
        if path == "/recovered" {
            assert_eq!(
                request
                    .headers()
                    .get("x-frozen")
                    .map(http::HeaderValue::as_bytes),
                Some(b"original".as_slice())
            );
        }
        let respond = async {
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(data) = body.data().await {
                let data = data?;
                if bytes.len() + data.len() > 7 {
                    return Err("recovered body exceeded its bound".into());
                }
                bytes.extend_from_slice(&data);
                body.flow_control().release_capacity(data.len())?;
            }
            assert_eq!(
                bytes.as_slice(),
                if method == Method::POST {
                    b"payload".as_slice()
                } else {
                    b""
                }
            );
            respond.send_response(
                http::Response::builder().status(StatusCode::OK).body(())?,
                true,
            )?;
            TestResult::<()>::Ok(())
        };
        tokio::pin!(respond);
        tokio::select! {
            biased;
            result = &mut respond => result?,
            closed = poll_fn(|context| connection.poll_closed(context)) => {
                closed?;
                return Err("H2 connection closed before its body and response completed".into());
            }
        }
        connection.graceful_shutdown();
        match poll_fn(|context| connection.poll_closed(context)).await {
            Ok(()) => Ok(()),
            Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
