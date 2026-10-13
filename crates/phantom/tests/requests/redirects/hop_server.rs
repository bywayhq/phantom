use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc::UnboundedSender,
    time::timeout,
};

use super::{
    ConnectionPeer, FixtureDeadline, TEST_TIMEOUT, TestResult, finish_with_cleanup, tls_support,
};

// The longest script makes four hops. Eight accepted connections leave room
// for each hop to use a replacement connection without an unbounded task tree.
const MAX_CONNECTIONS: usize = 8;

pub(super) struct HopServer {
    listener: ConnectionPeer<TestResult<()>>,
    connections: Arc<Mutex<Connections>>,
}

#[derive(Default)]
struct Connections {
    peers: Vec<AcceptedPeer>,
    failure: Option<Box<dyn std::error::Error + Send + Sync>>,
}

struct AcceptedPeer {
    task: Option<ConnectionPeer<TestResult<()>>>,
    stopping: bool,
}

impl HopServer {
    pub(super) fn spawn(
        listener: TcpListener,
        heads: UnboundedSender<Vec<u8>>,
        routes: impl Fn(&str) -> Option<String> + Clone + Send + 'static,
    ) -> Self {
        let connections = Arc::new(Mutex::new(Connections::default()));
        let accepted = Arc::clone(&connections);
        let listener = ConnectionPeer::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await?;
                let mut connections = accepted.lock().unwrap_or_else(|error| error.into_inner());
                if connections.peers.len() == MAX_CONNECTIONS {
                    return Err("redirect fixture exceeded its connection limit".into());
                }
                connections.peers.push(AcceptedPeer {
                    task: Some(ConnectionPeer::spawn(serve_connection(
                        stream,
                        heads.clone(),
                        routes.clone(),
                    ))),
                    stopping: false,
                });
            }
        });
        Self {
            listener,
            connections,
        }
    }

    pub(super) async fn shutdown(&mut self) -> TestResult<()> {
        // Stop admission before inspecting children. Completed failures remain
        // in the registry if a deadline interrupts the collection below.
        let listener_result = self.listener.shutdown().await;
        {
            let mut connections = self
                .connections
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            connections.record(listener_result);
            for peer in &mut connections.peers {
                if let Some(task) = &peer.task
                    && !task.is_finished()
                {
                    peer.stopping = true;
                    task.abort();
                }
            }
        }
        let collected = timeout(
            TEST_TIMEOUT,
            poll_fn(|context| {
                let mut connections = self
                    .connections
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let mut pending = false;
                for index in 0..connections.peers.len() {
                    let peer = &mut connections.peers[index];
                    let Some(task) = peer.task.as_mut() else {
                        continue;
                    };
                    let result = match Pin::new(task).poll(context) {
                        Poll::Pending => {
                            pending = true;
                            continue;
                        }
                        Poll::Ready(Ok(result)) => result,
                        Poll::Ready(Err(error)) if error.is_cancelled() && peer.stopping => Ok(()),
                        Poll::Ready(Err(error)) => Err(error.into()),
                    };
                    peer.task.take();
                    connections.record(result);
                }
                if pending {
                    Poll::Pending
                } else {
                    Poll::Ready(connections.failure.take().map_or(Ok(()), Err))
                }
            }),
        )
        .await;
        match collected {
            Ok(result) => result,
            Err(elapsed) => {
                let observed = self
                    .connections
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .failure
                    .take()
                    .map_or(Ok(()), Err);
                finish_with_cleanup(
                    Err(FixtureDeadline::new("redirect peers did not stop", elapsed).into()),
                    observed,
                )
            }
        }
    }
}

impl Drop for HopServer {
    fn drop(&mut self) {
        self.listener.abort();
        let connections = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for peer in &connections.peers {
            if let Some(task) = &peer.task {
                task.abort();
            }
        }
    }
}

impl Connections {
    fn record(&mut self, result: TestResult<()>) {
        let previous = self.failure.take().map_or(Ok(()), Err);
        self.failure = finish_with_cleanup(previous, result).err();
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    heads: UnboundedSender<Vec<u8>>,
    routes: impl Fn(&str) -> Option<String>,
) -> TestResult<()> {
    let mut served = false;
    loop {
        let mut first = [0_u8; 1];
        match stream.peek(&mut first).await {
            Ok(0) => return Ok(()),
            // Reset between completed requests is a normal client retirement.
            Err(error)
                if served
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        // Once a request starts, a truncated head is an actual child failure.
        let head = tls_support::read_head(&mut stream).await?;
        let path = std::str::from_utf8(
            head.split(|byte| *byte == b' ')
                .nth(1)
                .ok_or("redirect request omitted its path")?,
        )?;
        let response = match routes(path) {
            Some(location) => {
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
            }
            None => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_owned(),
        };
        heads.send(head)?;
        stream.write_all(response.as_bytes()).await?;
        served = true;
    }
}

#[cfg(test)]
mod tests;
