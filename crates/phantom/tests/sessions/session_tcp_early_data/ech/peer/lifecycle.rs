use super::*;

pub(in super::super) struct RecoveryGate {
    pub(in super::super) arrived: oneshot::Sender<()>,
    pub(in super::super) released: oneshot::Receiver<()>,
}

async fn rejected_then_fresh(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
) -> TestResult<tokio::net::TcpStream> {
    let seed = accept(listener, acceptor, Duration::ZERO).await?;
    answer(seed, transport, Method::GET, "/seed").await?;
    closed.send(()).map_err(|_| "seed observer stopped")?;
    set_key(acceptor, 2, &TEST_ECH_KEYS[1])?;
    reject(listener, acceptor).await?;
    let (tcp, _) = listener.accept().await?;
    let mut byte = [0; 1];
    if tcp.peek(&mut byte).await? != 1 {
        return Err("fresh ECH handshake omitted its ClientHello".into());
    }
    Ok(tcp)
}

pub(in super::super) async fn serve_cancelled_owner(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
    arrived: oneshot::Sender<()>,
) -> TestResult<()> {
    let mut tcp = rejected_then_fresh(&listener, &acceptor, transport, closed).await?;
    arrived.send(()).map_err(|_| "recovery observer stopped")?;
    let mut bytes = [0; 4096];
    loop {
        match tcp.read(&mut bytes).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if tls_support::is_peer_gone(&error) => break,
            Err(error) => return Err(error.into()),
        }
    }
    no_extra_connection(&listener).await
}

pub(in super::super) async fn serve_siblings(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
    gate: RecoveryGate,
    reset_observed: oneshot::Sender<()>,
) -> TestResult<()> {
    let tcp = rejected_then_fresh(&listener, &acceptor, transport, closed).await?;
    gate.arrived
        .send(())
        .map_err(|_| "recovery observer stopped")?;
    gate.released.await?;
    let stream = fresh_tls(tcp, &acceptor).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut owner) = connection
        .accept()
        .await
        .ok_or("recovery owner missing")??;
    assert_eq!(request.uri().path(), "/owner");
    let mut held = owner.send_response(http::Response::builder().status(200).body(())?, false)?;
    held.send_data(bytes::Bytes::from_static(b"held"), false)?;

    let (request, mut cancelled) = connection
        .accept()
        .await
        .ok_or("cancellation stream missing")??;
    assert_eq!(request.uri().path(), "/cancel-stream");
    let mut cancelled =
        cancelled.send_response(http::Response::builder().status(200).body(())?, false)?;
    let reason = poll_fn(|context| {
        if let Poll::Ready(result) = connection.poll_closed(context) {
            return Poll::Ready(match result {
                Ok(()) => {
                    Err(io::Error::other("H2 closed before its cancelled stream reset").into())
                }
                Err(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
            });
        }
        cancelled.poll_reset(context).map_err(Into::into)
    })
    .await?;
    assert_eq!(reason, ::http2::Reason::CANCEL);
    reset_observed
        .send(())
        .map_err(|_| "stream reset observer stopped")?;

    let (request, mut sibling) = connection
        .accept()
        .await
        .ok_or("healthy sibling missing")??;
    assert_eq!(request.uri().path(), "/sibling");
    sibling.send_response(http::Response::builder().status(204).body(())?, true)?;
    held.send_data(bytes::Bytes::from_static(b"-done"), true)?;
    connection.graceful_shutdown();
    close_h2(&mut connection).await?;
    no_extra_connection(&listener).await
}

pub(in super::super) async fn serve_refreshed(
    listener: TcpListener,
    acceptor: SslAcceptor,
    transport: Transport,
    closed: oneshot::Sender<()>,
    gate: RecoveryGate,
) -> TestResult<()> {
    let old_tcp = rejected_then_fresh(&listener, &acceptor, transport, closed).await?;
    gate.arrived
        .send(())
        .map_err(|_| "recovery observer stopped")?;
    let old = async {
        gate.released.await?;
        let stream = fresh_tls(old_tcp, &acceptor).await?;
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("old recovery request missing")??;
        assert_eq!(request.uri().path(), "/before-refresh");
        respond.send_response(http::Response::builder().status(200).body(())?, true)?;
        // Keep this generation reusable until the client chooses where the
        // post-refresh request belongs. Any new request here is a defect.
        match connection.accept().await {
            None => {}
            Some(Err(error)) if error.get_io().is_some_and(tls_support::is_peer_gone) => {}
            Some(Err(error)) => return Err(error.into()),
            Some(Ok(_)) => {
                return Err("refreshed request reused the retired recovery connection".into());
            }
        }
        TestResult::<()>::Ok(())
    };
    let fresh = async {
        // Discovery still has the old key. Refresh gets its own rejection
        // and retry, rather than joining an old entry's stalled recovery.
        reject(&listener, &acceptor).await?;
        let stream = accept(&listener, &acceptor, Duration::ZERO).await?;
        assert!(stream.stream.ssl().ech_accepted());
        assert!(!stream.stream.ssl().session_reused());
        assert!(!stream.stream.ssl().early_data_accepted());
        let mut connection = ::http2::server::handshake(stream).await?;
        for path in ["/after-refresh", "/new-reuse"] {
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("refreshed request missing")??;
            assert_eq!(request.uri().path(), path);
            respond.send_response(http::Response::builder().status(200).body(())?, true)?;
        }
        connection.graceful_shutdown();
        close_h2(&mut connection).await
    };
    tokio::try_join!(old, fresh)?;
    no_extra_connection(&listener).await
}

async fn fresh_tls(
    tcp: tokio::net::TcpStream,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<tokio::net::TcpStream>> {
    let stream = tls_support::accept_tls_stream(tcp, acceptor.clone()).await?;
    assert!(stream.ssl().ech_accepted());
    assert!(!stream.ssl().session_reused());
    assert!(!stream.ssl().early_data_accepted());
    Ok(stream)
}

async fn close_h2<T>(
    connection: &mut ::http2::server::Connection<T, bytes::Bytes>,
) -> TestResult<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match poll_fn(|context| connection.poll_closed(context)).await {
        Ok(()) => Ok(()),
        Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn no_extra_connection(listener: &TcpListener) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
        Err(_) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Ok(Ok(_)) => Err("H2 lifecycle opened an unexpected ECH connection".into()),
    }
}
