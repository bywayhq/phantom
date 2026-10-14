use std::collections::HashMap;

use tokio::net::UdpSocket;

use super::*;

/// Owns every upstream socket and queued server datagram.
pub(super) struct Gate {
    pub address: SocketAddr,
    pub open: watch::Sender<bool>,
    pub queued: watch::Receiver<usize>,
    pub sockets: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    stop: watch::Sender<bool>,
    task: ConnectionPeer<TestResult<()>>,
}

impl Gate {
    pub(super) async fn spawn(server: SocketAddr, open: watch::Sender<bool>) -> TestResult<Self> {
        let front = Arc::new(phantom_testkit::udp::bind_tokio(
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?);
        let address = front.local_addr()?;
        let opened = open.subscribe();
        let sockets_owned = Arc::new(std::sync::Mutex::new(vec![address]));
        let socket_observer = Arc::clone(&sockets_owned);
        let (stop, mut stopped) = watch::channel(false);
        let coordinator_stop = stop.clone();
        let (queued_tx, queued) = watch::channel(0);
        let task = ConnectionPeer::spawn(async move {
            let mut sockets = HashMap::new();
            let mut workers = JoinSet::new();
            let mut packet = vec![0; 65_535];
            let outcome: TestResult<()> = async {
                loop {
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => break,
                        result = workers.join_next(), if !workers.is_empty() => {
                            result.ok_or("relay worker disappeared")???;
                            return Err("relay worker ended before stop".into());
                        }
                        result = front.recv_from(&mut packet) => {
                            let (len, client) = result?;
                            let upstream = match sockets.get(&client) {
                                Some(socket) => Arc::clone(socket),
                                None => {
                                    if sockets.len() == 4 { return Err("relay client bound exceeded".into()); }
                                    let socket = Arc::new(phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?);
                                    socket_observer.lock().map_err(|_| "relay socket observer poisoned")?.push(socket.local_addr()?);
                                    socket.connect(server).await?;
                                    workers.spawn(replies(Arc::clone(&front), Arc::clone(&socket), client, opened.clone(), stopped.clone(), queued_tx.clone()));
                                    sockets.insert(client, Arc::clone(&socket));
                                    socket
                                }
                            };
                            upstream.send(&packet[..len]).await?;
                        }
                    }
                }
                Ok(())
            }.await;
            // Wake all receivers, including those holding queued sends.
            coordinator_stop.send_replace(true);
            drop(sockets);
            let cleanup: TestResult<()> = async {
                let mut cleanup = Ok(());
                while let Some(result) = workers.join_next().await {
                    cleanup = finish_with_cleanup(
                        cleanup,
                        result.map_err(Into::into).and_then(|result| result),
                    );
                }
                cleanup
            }
            .await;
            finish_with_cleanup(outcome, cleanup)
        });
        Ok(Self {
            address,
            open,
            queued,
            sockets: sockets_owned,
            stop,
            task,
        })
    }

    pub(super) async fn held_reply(&mut self) -> TestResult<()> {
        while *self.queued.borrow() == 0 {
            self.queued.changed().await?;
        }
        Ok(())
    }

    pub(super) async fn finish(self) -> TestResult<()> {
        self.stop.send_replace(true);
        timeout(TEST_TIMEOUT, self.task).await??
    }
}

async fn replies(
    front: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    mut open: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
    queued: watch::Sender<usize>,
) -> TestResult<()> {
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut packet = vec![0; 65_535];
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        if *open.borrow() {
            while let Some(bytes) = pending.pop_front() {
                front.send_to(&bytes, client).await?;
            }
        }
        tokio::select! {
            biased;
            _ = stop.changed() => return Ok(()),
            result = open.changed() => { result?; }
            result = upstream.recv(&mut packet) => {
                let len = result?;
                if *open.borrow() { front.send_to(&packet[..len], client).await?; }
                else {
                    if pending.len() == 128 { return Err("gated datagram bound exceeded".into()); }
                    pending.push_back(packet[..len].to_vec());
                    queued.send_modify(|count| *count += 1);
                }
            }
        }
    }
}
