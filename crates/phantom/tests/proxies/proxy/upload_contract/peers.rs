use std::{io, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};

use super::super::{
    ConnectUpload, H1_ALPN, OriginUpload, TestIdentity, TestResult, accept_tls,
    forward_one_connect_observed, prepare_connect_upload, read_head,
};

pub(super) const DEADLINE: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(150);

#[derive(Clone, Copy)]
pub(super) enum Reply {
    Held,
    Complete,
    Truncated,
    BothFail,
}

struct Destroyed(Option<oneshot::Sender<()>>);

impl Drop for Destroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

pub(super) struct Observations {
    origin_ready: oneshot::Receiver<OriginUpload>,
    proxy_ready: oneshot::Receiver<Vec<u8>>,
    origin_gone: oneshot::Receiver<()>,
    proxy_gone: oneshot::Receiver<()>,
    pub(super) origin_failure: oneshot::Receiver<(io::ErrorKind, String)>,
    pub(super) proxy_failure: oneshot::Receiver<(io::ErrorKind, String)>,
    release: Option<oneshot::Sender<()>>,
    origin_abort: AbortHandle,
    proxy_abort: AbortHandle,
    origin_observed: bool,
    proxy_observed: bool,
}

impl Drop for Observations {
    fn drop(&mut self) {
        self.origin_abort.abort();
        self.proxy_abort.abort();
    }
}

impl Observations {
    pub(super) async fn ready(&mut self, origin_address: SocketAddr) -> TestResult<()> {
        let connect = timeout(DEADLINE, &mut self.proxy_ready).await??;
        let expected = format!(
            "CONNECT {origin_address} HTTP/1.1\r\n\
             User-Agent: phantom-test\r\n\
             host: {origin_address}\r\n\
             X-Proxy-Order: last\r\n\r\n"
        );
        assert_eq!(connect, expected.as_bytes());

        let (request, body) = timeout(DEADLINE, &mut self.origin_ready).await??;
        let expected = format!(
            "POST /proxied HTTP/1.1\r\nHost: {origin_address}\r\nX-Origin: only\r\nContent-Length: 7\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        assert_eq!(&body, b"payload");
        Ok(())
    }

    pub(super) async fn destroyed_before_backup(&mut self) -> TestResult<(bool, bool)> {
        match timeout(QUIET, &mut self.origin_gone).await {
            Ok(result) => {
                self.origin_observed = true;
                result?;
            }
            Err(_) => self.origin_observed = false,
        }
        match timeout(QUIET, &mut self.proxy_gone).await {
            Ok(result) => {
                self.proxy_observed = true;
                result?;
            }
            Err(_) => self.proxy_observed = false,
        }
        Ok((self.origin_observed, self.proxy_observed))
    }

    pub(super) async fn cleanup(&mut self) -> TestResult<()> {
        if let Some(release) = self.release.take() {
            // The task may already have been destroyed by the owner under test.
            let _ = release.send(());
        }
        self.origin_abort.abort();
        self.proxy_abort.abort();

        let origin = if self.origin_observed {
            Ok(())
        } else {
            async {
                timeout(DEADLINE, &mut self.origin_gone).await??;
                Ok(())
            }
            .await
        };
        let proxy = if self.proxy_observed {
            Ok(())
        } else {
            async {
                timeout(DEADLINE, &mut self.proxy_gone).await??;
                Ok(())
            }
            .await
        };
        crate::support::tunnel_proxy::finish_with_cleanup(origin, proxy)
    }
}

pub(super) async fn ready_upload(
    reply: Reply,
) -> TestResult<(
    ConnectUpload,
    Observations,
    TestIdentity,
    SocketAddr,
    SocketAddr,
)> {
    let identity = TestIdentity::generate()?;
    let origin_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let origin_acceptor = identity.acceptor(H1_ALPN)?;
    let proxy_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;

    let (origin_ready, origin_received) = oneshot::channel();
    let (proxy_ready, proxy_received) = oneshot::channel();
    let (origin_gone, origin_destroyed) = oneshot::channel();
    let (proxy_gone, proxy_destroyed) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (origin_failure, origin_failed) = oneshot::channel();
    let (proxy_failure, proxy_failed) = oneshot::channel();
    let origin_guard = Destroyed(Some(origin_gone));
    let proxy_guard = Destroyed(Some(proxy_gone));

    let origin = tokio::spawn(async move {
        let _destroyed = origin_guard;
        let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
        let request = read_head(&mut stream).await?;
        let mut body = [0_u8; 7];
        stream.read_exact(&mut body).await?;
        origin_ready
            .send((request.clone(), body))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "origin observer stopped"))?;

        let response = if matches!(reply, Reply::Truncated) {
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nth".as_slice()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough".as_slice()
        };
        stream.write_all(response).await?;
        if matches!(reply, Reply::Held) {
            released.await?;
        }
        stream.shutdown().await?;

        if matches!(reply, Reply::BothFail) {
            let error = io::Error::new(io::ErrorKind::Unsupported, "completed CONNECT origin 912");
            origin_failure
                .send((error.kind(), error.to_string()))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "origin cause observer stopped")
                })?;
            return Err(error.into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((request, body))
    });
    let origin_abort = origin.abort_handle();

    let proxy = tokio::spawn(async move {
        let _destroyed = proxy_guard;
        let request =
            forward_one_connect_observed(proxy_listener, origin_address, Some(proxy_ready)).await?;
        if matches!(reply, Reply::Truncated | Reply::BothFail) {
            let error = io::Error::new(
                io::ErrorKind::PermissionDenied,
                "completed CONNECT proxy 911",
            );
            proxy_failure
                .send((error.kind(), error.to_string()))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "proxy cause observer stopped")
                })?;
            return Err(error.into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
    });
    let proxy_abort = proxy.abort_handle();

    let mut observations = Observations {
        origin_ready: origin_received,
        proxy_ready: proxy_received,
        origin_gone: origin_destroyed,
        proxy_gone: proxy_destroyed,
        origin_failure: origin_failed,
        proxy_failure: proxy_failed,
        release: Some(release),
        origin_abort,
        proxy_abort,
        origin_observed: false,
        proxy_observed: false,
    };
    let prepared = match prepare_connect_upload(origin, proxy, &identity, proxy_address) {
        Ok(prepared) => prepared,
        Err(primary) => {
            let cleanup = observations.cleanup().await;
            return crate::support::tunnel_proxy::finish_with_cleanup(Err(primary), cleanup);
        }
    };
    Ok((
        prepared,
        observations,
        identity,
        origin_address,
        proxy_address,
    ))
}
