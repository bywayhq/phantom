//! CONNECT listener and relay ownership for the negotiated route script.
use tokio::io::copy_bidirectional;

use super::*;

pub(super) struct Proxy {
    pub(super) address: SocketAddr,
    pub(super) connects: mpsc::Receiver<Vec<u8>>,
    stop: watch::Sender<bool>,
}
impl Proxy {
    pub(super) async fn start(origin: SocketAddr, connections: Spawner) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (connects_tx, connects) = mpsc::channel(MAX_CONNECTIONS);
        let (stop, mut stopped) = watch::channel(false);
        let children = connections.clone();
        connections.spawn(async move {
            for _ in 0..MAX_CONNECTIONS {
                let (mut downstream, _) = tokio::select! {
                    biased;
                    () = stopping(&mut stopped) => return Ok(()),
                    accepted = listener.accept() => accepted?,
                };
                let connects_tx = connects_tx.clone();
                let mut stopped = stopped.clone();
                children.spawn(async move {
                    let relay = async {
                        let head = request_head(&mut downstream, false)
                            .await?
                            .ok_or("CONNECT peer omitted its request")?;
                        connects_tx.try_send(head)?;
                        let mut upstream = TcpStream::connect(origin).await?;
                        downstream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                        match copy_bidirectional(&mut downstream, &mut upstream).await {
                            Ok(_) => Ok(()),
                            // The CONNECT response has been written. Endpoint
                            // teardown may now finish this already-open relay.
                            Err(error) if tls_support::is_peer_gone(&error) => Ok(()),
                            Err(error) => {
                                Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
                            }
                        }
                    };
                    tokio::select! {
                        biased;
                        result = relay => result,
                        () = stopping(&mut stopped) => Ok(()),
                    }
                })?;
            }
            Err("CONNECT listener exceeded its connection script".into())
        })?;
        Ok(Self {
            address,
            connects,
            stop,
        })
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
