use btls::ssl::SslAcceptor;
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::ownership::{Control, ObservedStream};
use super::{
    EXTRA_CONNECTION_WINDOW, PRIMING_RESPONSE, REPLAY_RESPONSE, ReceivedRequest, TestResult,
    accept_tls_stream, read_request, serve_stale_connection,
};
use crate::support::tunnel_proxy::connection_peer::ConnectionPeer;

pub(super) fn spawn_replay_with_quiet(
    listener: TcpListener,
) -> ConnectionPeer<TestResult<(ReceivedRequest, ReceivedRequest, bool)>> {
    ConnectionPeer::spawn(async move {
        let stale = serve_stale_connection(&listener, None).await?;

        let (mut replacement, _) = listener.accept().await?;
        let replayed = read_request(&mut replacement).await?;

        replacement.write_all(REPLAY_RESPONSE).await?;
        replacement.flush().await?;

        let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
        Ok((stale, replayed, extra.is_err()))
    })
}

pub(super) fn spawn_fresh(listener: TcpListener) -> ConnectionPeer<TestResult<bool>> {
    ConnectionPeer::spawn(async move {
        let (mut fresh, _) = listener.accept().await?;
        read_request(&mut fresh).await?;
        drop(fresh);

        let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
        Ok(extra.is_err())
    })
}

pub(super) fn spawn_replay(
    listener: TcpListener,
    control: Option<Control>,
) -> ConnectionPeer<TestResult<(ReceivedRequest, ReceivedRequest)>> {
    let register = control.as_ref().map(Control::abort_registration);
    let server = ConnectionPeer::spawn(async move {
        let _lifetime = control.as_ref().map(Control::lifetime);

        let stale = serve_stale_connection(&listener, control).await?;

        let (mut replacement, _) = listener.accept().await?;
        let replayed = read_request(&mut replacement).await?;

        replacement.write_all(REPLAY_RESPONSE).await?;
        replacement.flush().await?;

        Ok((stale, replayed))
    });

    if let Some(register) = register {
        register(server.abort_handle());
    }

    server
}

pub(super) fn spawn_closed_replacement(
    listener: TcpListener,
) -> ConnectionPeer<TestResult<(ReceivedRequest, bool)>> {
    ConnectionPeer::spawn(async move {
        serve_stale_connection(&listener, None).await?;

        let (mut replacement, _) = listener.accept().await?;
        let replayed = read_request(&mut replacement).await?;
        drop(replacement);

        let extra = timeout(EXTRA_CONNECTION_WINDOW, listener.accept()).await;
        Ok((replayed, extra.is_err()))
    })
}

pub(super) fn spawn_observable(listener: TcpListener) -> ConnectionPeer<TestResult> {
    ConnectionPeer::spawn(async move {
        serve_stale_connection(&listener, None).await?;

        let (mut replacement, _) = listener.accept().await?;
        read_request(&mut replacement).await?;

        replacement.write_all(REPLAY_RESPONSE).await?;
        replacement.flush().await?;

        Ok(())
    })
}

pub(super) fn spawn_negotiated(
    listener: TcpListener,
    stale_acceptor: SslAcceptor,
    replacement_acceptor: SslAcceptor,
    control: Option<Control>,
) -> ConnectionPeer<TestResult<(ReceivedRequest, ReceivedRequest)>> {
    let register = control.as_ref().map(Control::abort_registration);
    let server = ConnectionPeer::spawn(async move {
        let _lifetime = control.as_ref().map(Control::lifetime);

        let (tcp, _) = listener.accept().await?;
        let stale = accept_tls_stream(tcp, stale_acceptor).await?;
        let mut stale = ObservedStream::new(stale, control);
        read_request(&mut stale).await?;

        stale.write_all(PRIMING_RESPONSE).await?;
        stale.flush().await?;

        let stale_request = read_request(&mut stale).await?;
        drop(stale);

        let (tcp, _) = listener.accept().await?;
        let mut replacement = accept_tls_stream(tcp, replacement_acceptor).await?;
        let replayed = read_request(&mut replacement).await?;

        replacement.write_all(REPLAY_RESPONSE).await?;
        replacement.flush().await?;

        Ok((stale_request, replayed))
    });

    if let Some(register) = register {
        register(server.abort_handle());
    }

    server
}
