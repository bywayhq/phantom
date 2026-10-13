use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, PoisonError},
    time::Duration,
};

use tokio::{net::UdpSocket, sync::watch, task::JoinSet, time::timeout};

use super::{TestResult, ZeroRttLog, carries_zero_rtt};
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const MAX_CLIENTS: usize = 64;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct ZeroRttRelay {
    pub(super) address: SocketAddr,
    pub(super) log: ZeroRttLog,
    task: Option<ConnectionPeer<TestResult<()>>>,
    stop: watch::Sender<bool>,
    failure: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ZeroRttRelay {
    pub(super) async fn spawn(server: SocketAddr) -> TestResult<Self> {
        if !server.ip().is_loopback() {
            return Err("0-RTT relay requires a loopback origin".into());
        }
        let front = Arc::new(phantom_testkit::udp::bind_tokio(
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?);
        let address = front.local_addr()?;
        let log: ZeroRttLog = Arc::default();
        let task_log = Arc::clone(&log);
        let (stop, stopped) = watch::channel(false);
        let task = ConnectionPeer::spawn(serve(front, server, task_log, stop.clone(), stopped));
        Ok(Self {
            address,
            log,
            task: Some(task),
            stop,
            failure: None,
        })
    }

    pub(super) async fn finish(&mut self, caller: TestResult<()>) -> TestResult<()> {
        if let Err(error) = caller {
            self.retain(error);
        }
        self.stop.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            match timeout(CLEANUP_TIMEOUT, task.join()).await {
                Ok(joined) => {
                    drop(self.task.take());
                    if let Err(error) = joined.map_err(Into::into).and_then(|result| result) {
                        self.retain(error);
                    }
                }
                Err(elapsed) => self.retain(
                    FixtureDeadline::new("0-RTT relay cleanup exceeded its deadline", elapsed)
                        .into(),
                ),
            }
        }
        self.failure.take().map_or(Ok(()), Err)
    }

    fn retain(&mut self, error: Box<dyn std::error::Error + Send + Sync>) {
        self.failure =
            finish_with_cleanup::<()>(self.failure.take().map_or(Ok(()), Err), Err(error)).err();
    }
}

impl Drop for ZeroRttRelay {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(
    front: Arc<UdpSocket>,
    server: SocketAddr,
    log: ZeroRttLog,
    stop: watch::Sender<bool>,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut upstreams: HashMap<SocketAddr, (usize, Arc<UdpSocket>)> = HashMap::new();
    let mut replies = JoinSet::new();
    let result: TestResult<()> = async {
        let mut datagram = vec![0; 65_535];
        loop {
            let (len, client) = tokio::select! {
                biased;
                joined = replies.join_next(), if !replies.is_empty() => {
                    joined.ok_or("0-RTT reply outcome disappeared")???;
                    continue;
                }
                result = stopping(&mut stopped) => { result?; break; }
                received = front.recv_from(&mut datagram) => received?,
            };
            let (index, upstream) = match upstreams.get(&client) {
                Some((index, upstream)) => (*index, Arc::clone(upstream)),
                None => {
                    if upstreams.len() >= MAX_CLIENTS {
                        return Err("0-RTT relay client bound exceeded".into());
                    }
                    let upstream =
                        phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
                    upstream.connect(server).await?;
                    let upstream = Arc::new(upstream);
                    let index = {
                        let mut log = log.lock().unwrap_or_else(PoisonError::into_inner);
                        log.push(false);
                        log.len() - 1
                    };
                    upstreams.insert(client, (index, Arc::clone(&upstream)));
                    replies.spawn(forward_replies(
                        Arc::clone(&upstream),
                        Arc::clone(&front),
                        client,
                        stopped.clone(),
                    ));
                    (index, upstream)
                }
            };
            if carries_zero_rtt(&datagram[..len]) {
                log.lock().unwrap_or_else(PoisonError::into_inner)[index] = true;
            }
            upstream.send(&datagram[..len]).await?;
        }
        Ok(())
    }
    .await;
    stop.send_replace(true);
    let mut result = result;
    while let Some(joined) = replies.join_next().await {
        result = finish_with_cleanup(result, joined.map_err(Into::into).and_then(|result| result));
    }
    result
}

async fn stopping(stopped: &mut watch::Receiver<bool>) -> TestResult<()> {
    stopped.wait_for(|value| *value).await?;
    Ok(())
}

async fn forward_replies(
    upstream: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    client: SocketAddr,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let operation = async {
        let mut datagram = vec![0; 65_535];
        loop {
            let len = upstream.recv(&mut datagram).await?;
            front.send_to(&datagram[..len], client).await?;
        }
    };
    tokio::select! {
        biased;
        result = operation => result,
        result = stopping(&mut stopped) => result,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::time::error::Elapsed;

    use super::*;

    async fn exchanged() -> TestResult<(ZeroRttRelay, UdpSocket, SocketAddr)> {
        let origin = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let relay = ZeroRttRelay::spawn(origin.local_addr()?).await?;
        let client = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        client.send_to(b"ready", relay.address).await?;
        let mut buffer = [0; 16];
        let (len, upstream) = timeout(CLEANUP_TIMEOUT, origin.recv_from(&mut buffer)).await??;
        assert_eq!(&buffer[..len], b"ready");
        origin.send_to(b"reply", upstream).await?;
        let (len, source) = timeout(CLEANUP_TIMEOUT, client.recv_from(&mut buffer)).await??;
        assert_eq!(&buffer[..len], b"reply");
        assert_eq!(source, relay.address);
        Ok((relay, origin, upstream))
    }

    #[tokio::test]
    async fn caller_failure_collects_original_reply_workers_and_releases_both_sockets()
    -> TestResult<()> {
        let (mut relay, _origin, upstream) = exchanged().await?;
        let address = relay.address;
        let primary = Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller failed",
        ));
        let original = (&*primary) as *const io::Error;
        let error = relay.finish(Err(primary)).await.unwrap_err();
        assert!(std::ptr::eq(
            error.downcast_ref::<io::Error>().unwrap(),
            original
        ));
        assert!(relay.task.is_none());
        assert_eq!(phantom_testkit::udp::bind(address)?.local_addr()?, address);
        assert_eq!(
            phantom_testkit::udp::bind(upstream)?.local_addr()?,
            upstream
        );
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_cleanup_keeps_deadline_and_original_parent_for_retry() -> TestResult<()> {
        let (mut relay, _origin, upstream) = exchanged().await?;
        let address = relay.address;
        tokio::time::pause();
        let caller = super::super::bounded(std::future::pending()).await;
        {
            let finishing = relay.finish(caller);
            tokio::pin!(finishing);
            assert!(futures_util::poll!(&mut finishing).is_pending());
        }
        assert!(relay.task.is_some());
        let error = relay.finish(Ok(())).await.unwrap_err();
        assert!(error.source().unwrap().downcast_ref::<Elapsed>().is_some());
        assert!(relay.task.is_none());
        assert_eq!(phantom_testkit::udp::bind(address)?.local_addr()?, address);
        assert_eq!(
            phantom_testkit::udp::bind(upstream)?.local_addr()?,
            upstream
        );
        Ok(())
    }
}
