use std::{
    collections::HashMap,
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
    worker: Mutex<Option<AbortHandle>>,
    receivers: Mutex<HashMap<SocketAddr, Arc<ReceiverObservation>>>,
    pub(crate) observe_receivers: AtomicBool,
}

#[derive(Default)]
pub(crate) struct ReceiverObservation {
    pub(crate) read: ReadObservation,
    worker: Mutex<Option<AbortHandle>>,
}

impl RelayObservation {
    pub(crate) fn receiver(&self, client: SocketAddr) -> io::Result<Arc<ReceiverObservation>> {
        let mut receivers = self
            .receivers
            .lock()
            .map_err(|_| io::Error::other("relay receiver registry lock poisoned"))?;

        Ok(Arc::clone(receivers.entry(client).or_default()))
    }

    pub(crate) fn receivers(&self) -> (Vec<Arc<ReceiverObservation>>, io::Result<()>) {
        match self.receivers.lock() {
            Ok(receivers) => (receivers.values().cloned().collect(), Ok(())),
            Err(poisoned) => (
                poisoned.into_inner().values().cloned().collect(),
                Err(io::Error::other(
                    "relay receiver registry cleanup lock poisoned",
                )),
            ),
        }
    }

    pub(crate) fn publish_worker(&self, worker: AbortHandle) -> io::Result<()> {
        match self.worker.lock() {
            Ok(mut slot) => {
                *slot = Some(worker);

                Ok(())
            }
            Err(poisoned) => {
                // Retain the acquired handle even when observation fails.
                *poisoned.into_inner() = Some(worker);
                Err(io::Error::other("relay worker publication lock poisoned"))
            }
        }
    }

    pub(crate) fn worker(&self) -> io::Result<Option<AbortHandle>> {
        self.worker
            .lock()
            .map(|slot| slot.clone())
            .map_err(|_| io::Error::other("relay worker observation lock poisoned"))
    }

    pub(crate) fn cleanup_worker(&self) -> (Option<AbortHandle>, io::Result<()>) {
        match self.worker.lock() {
            Ok(slot) => (slot.clone(), Ok(())),
            Err(poisoned) => (
                poisoned.into_inner().clone(),
                Err(io::Error::other("relay worker cleanup lock poisoned")),
            ),
        }
    }
}

impl ReceiverObservation {
    pub(crate) fn publish(&self, worker: AbortHandle) -> io::Result<()> {
        match self.worker.lock() {
            Ok(mut slot) => {
                *slot = Some(worker);

                Ok(())
            }
            Err(poisoned) => {
                *poisoned.into_inner() = Some(worker);
                Err(io::Error::other("relay receiver publication lock poisoned"))
            }
        }
    }

    pub(crate) fn worker(&self) -> (Option<AbortHandle>, io::Result<()>) {
        match self.worker.lock() {
            Ok(slot) => (slot.clone(), Ok(())),
            Err(poisoned) => (
                poisoned.into_inner().clone(),
                Err(io::Error::other("relay receiver handle lock poisoned")),
            ),
        }
    }
}

pub(crate) struct ReceiverLifetime(pub(crate) Arc<ReceiverObservation>);

impl Drop for ReceiverLifetime {
    fn drop(&mut self) {
        self.0.read.destroyed.store(true, Ordering::SeqCst);
    }
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
    pub(crate) fn fail_next_read(&self, error: io::Error) -> io::Result<()> {
        *self
            .fault
            .lock()
            .map_err(|_| io::Error::other("relay read fault installation lock poisoned"))? =
            Some(error);
        self.wake.notify_one();

        Ok(())
    }

    fn fault(&self) -> io::Result<Option<io::Error>> {
        let error = self
            .fault
            .lock()
            .map_err(|_| io::Error::other("relay read fault consumption lock poisoned"))?
            .take();

        if error.is_some() {
            self.invoked.store(true, Ordering::SeqCst);
        }

        Ok(error)
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
        if let Some(error) = self.fault()? {
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
                    if let Some(error) = self.fault()? {
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
