use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{net::UdpSocket, sync::Notify, task::AbortHandle};

#[derive(Default)]
pub(crate) struct RelayObservation {
    pub(crate) front: ReadObservation,
    pub(crate) reply: ReadObservation,
    pub(crate) worker: Mutex<Option<AbortHandle>>,
}

#[derive(Default)]
pub(crate) struct ReadObservation {
    pub(crate) pending_after_packet: AtomicBool,
    pub(crate) destroyed: AtomicBool,
    received: AtomicBool,
    fault: Mutex<Option<io::Error>>,
    wake: Notify,
    pub(crate) invoked: AtomicBool,
}

impl ReadObservation {
    pub(crate) fn fail_next_read(&self, error: io::Error) {
        *self.fault.lock().expect("read fault lock poisoned") = Some(error);
        self.wake.notify_one();
    }

    fn fault(&self) -> Option<io::Error> {
        let error = self.fault.lock().expect("read fault lock poisoned").take();
        if error.is_some() {
            self.invoked.store(true, Ordering::SeqCst);
        }

        error
    }

    pub(crate) async fn recv_from(
        &self,
        socket: &UdpSocket,
        bytes: &mut [u8],
    ) -> io::Result<(usize, SocketAddr)> {
        let read = socket.recv_from(bytes);
        tokio::pin!(read);
        let result = std::future::poll_fn(|context| {
            let result = std::future::Future::poll(read.as_mut(), context);
            if result.is_pending() && self.received.load(Ordering::SeqCst) {
                self.pending_after_packet.store(true, Ordering::SeqCst);
            }

            result
        })
        .await;

        if result.is_ok() {
            self.received.store(true, Ordering::SeqCst);
        }

        result
    }

    pub(crate) async fn recv(&self, socket: &UdpSocket, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.fault() {
            return Err(error);
        }

        let read = socket.recv(bytes);
        tokio::pin!(read);
        loop {
            tokio::select! {
                result = std::future::poll_fn(|context| {
                    let result = std::future::Future::poll(read.as_mut(), context);
                    if result.is_pending() && self.received.load(Ordering::SeqCst) {
                        self.pending_after_packet.store(true, Ordering::SeqCst);
                    }

                    result
                }) => {
                    if result.is_ok() {
                        self.received.store(true, Ordering::SeqCst);
                    }
                    return result;
                }
                () = self.wake.notified() => {
                    if let Some(error) = self.fault() {
                        return Err(error);
                    }
                }
            }
        }
    }
}

pub(crate) struct ReadLifetime {
    observation: Arc<RelayObservation>,
    reply: bool,
}

impl ReadLifetime {
    pub(crate) fn front(observation: Arc<RelayObservation>) -> Self {
        Self {
            observation,
            reply: false,
        }
    }

    pub(crate) fn reply(observation: Arc<RelayObservation>) -> Self {
        Self {
            observation,
            reply: true,
        }
    }
}

impl Drop for ReadLifetime {
    fn drop(&mut self) {
        let read = if self.reply {
            &self.observation.reply
        } else {
            &self.observation.front
        };
        read.destroyed.store(true, Ordering::SeqCst);
    }
}
