use crate::error::Failure;
use http_body::{Body, Frame, SizeHint};
use phantom::Bytes;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::sync::{Notify, mpsc, oneshot};

const OPEN: u8 = 0;
const CLOSED: u8 = 1;
const EXPIRED: u8 = 2;

enum Payload {
    Data(Bytes),
    End,
    Failed,
}
struct Chunk {
    payload: Payload,
    consumed: oneshot::Sender<()>,
}

pub(super) struct Upload {
    pub(super) client: u64,
    pub(super) multipart: Option<crate::multipart::Multipart>,
    _buffer: Option<crate::operations::UploadPermit>,
    length: Option<u64>,
    sender: mpsc::Sender<Chunk>,
    receiver: Mutex<Option<mpsc::Receiver<Chunk>>>,
    state: AtomicU8,
    changed: Notify,
    reader: Mutex<Option<Waker>>,
}
impl Upload {
    pub(super) fn new(client: u64, length: Option<u64>) -> Arc<Self> {
        Self::with_multipart(client, length, None, None)
    }

    pub(super) fn with_multipart(
        client: u64,
        length: Option<u64>,
        multipart: Option<crate::multipart::Multipart>,
        buffer: Option<crate::operations::UploadPermit>,
    ) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(1);
        Arc::new(Self {
            client,
            multipart,
            _buffer: buffer,
            length,
            sender,
            receiver: Mutex::new(Some(receiver)),
            state: AtomicU8::new(OPEN),
            changed: Notify::new(),
            reader: Mutex::new(None),
        })
    }

    pub(super) fn body(self: &Arc<Self>) -> Result<UploadBody, Failure> {
        if self.multipart.is_some() {
            return Err(Failure::new("invalid_upload"));
        }
        if self.state.load(Ordering::SeqCst) != OPEN {
            return Err(Failure::new("upload_closed"));
        }
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take()
            .ok_or_else(|| Failure::new("upload_used"))?;
        Ok(UploadBody {
            owner: Arc::clone(self),
            receiver,
            emitted: 0,
            done: false,
        })
    }

    pub(super) fn close(&self) {
        let _ = self
            .state
            .compare_exchange(OPEN, CLOSED, Ordering::SeqCst, Ordering::SeqCst);
        self.changed.notify_waiters();
        if let Some(multipart) = &self.multipart {
            multipart.close();
        }
        if let Ok(mut reader) = self.reader.lock()
            && let Some(waker) = reader.take()
        {
            waker.wake();
        }
    }

    pub(super) async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state.load(Ordering::SeqCst) != OPEN {
                return;
            }
            changed.await;
        }
    }

    pub(super) fn deadline(
        self: &Arc<Self>,
        runtime: &tokio::runtime::Handle,
        total: Option<std::time::Duration>,
    ) -> Result<(), Failure> {
        let Some(total) = total else {
            return Ok(());
        };
        // Fix the producer deadline at dispatch, just before core send starts.
        // It also closes a reader when an early response is left unread.
        let deadline = tokio::time::Instant::now()
            .checked_add(total)
            .ok_or_else(|| Failure::new("invalid_timeout"))?;
        let owner = Arc::clone(self);
        runtime.spawn(async move {
            tokio::select! {
                biased;
                () = owner.closed() => {}
                () = tokio::time::sleep_until(deadline) => {
                    if owner.state.compare_exchange(OPEN, EXPIRED, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        owner.close();
                    }
                }
            }
        });
        Ok(())
    }

    pub(super) fn failure(&self, original: Failure) -> Failure {
        if self.state.load(Ordering::SeqCst) == EXPIRED {
            Failure {
                kind: "timeout",
                protocol: original.protocol,
                timeout_phase: Some("total"),
            }
        } else {
            original
        }
    }

    // A write completes only when the transport polls its frame. The Go reader
    // cannot fill an unbounded queue while a peer stops consuming its upload.
    pub(super) async fn write(&self, bytes: Bytes, end: Option<bool>) -> Result<(), Failure> {
        match &self.multipart {
            Some(multipart) => {
                if self.state.load(Ordering::SeqCst) != OPEN {
                    return Err(Failure::new("upload_closed"));
                }
                multipart.active()?.write_single(bytes, end).await
            }
            None => self.write_single(bytes, end).await,
        }
    }

    pub(super) async fn next_part(&self) -> Result<usize, Failure> {
        let multipart = self
            .multipart
            .as_ref()
            .ok_or_else(|| Failure::new("invalid_multipart"))?;
        tokio::select! {
            biased;
            () = self.closed() => Err(Failure::new("upload_closed")),
            result = multipart.next() => result,
        }
    }

    async fn write_single(&self, bytes: Bytes, end: Option<bool>) -> Result<(), Failure> {
        let payload = match end {
            Some(true) => Payload::Failed,
            Some(false) => Payload::End,
            None => Payload::Data(bytes),
        };
        let (consumed, received) = oneshot::channel();
        let sending = async {
            self.sender
                .send(Chunk { payload, consumed })
                .await
                .map_err(|_| Failure::new("upload_closed"))?;
            received.await.map_err(|_| Failure::new("upload_closed"))
        };
        tokio::select! {
            biased;
            result = sending => result,
            () = self.closed() => Err(Failure::new("upload_closed")),
        }
    }
}

pub(super) struct UploadBody {
    owner: Arc<Upload>,
    receiver: mpsc::Receiver<Chunk>,
    emitted: u64,
    done: bool,
}
impl Drop for UploadBody {
    fn drop(&mut self) {
        self.owner.close();
    }
}
impl Body for UploadBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let owner = Arc::clone(&self.owner);
        let Ok(mut reader) = owner.reader.lock() else {
            return Poll::Ready(Some(Err(io::Error::other("upload unavailable"))));
        };
        *reader = Some(cx.waker().clone());
        drop(reader);
        if owner.state.load(Ordering::SeqCst) != OPEN {
            self.done = true;
            return Poll::Ready(Some(Err(io::Error::other("upload closed"))));
        }
        let chunk = match self.receiver.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                self.done = true;
                return Poll::Ready(Some(Err(io::Error::other("upload closed"))));
            }
            Poll::Ready(Some(chunk)) => chunk,
        };
        let _ = chunk.consumed.send(());
        match chunk.payload {
            Payload::Data(bytes) => {
                self.emitted = self.emitted.saturating_add(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Payload::End => {
                self.done = true;
                owner.close();
                Poll::Ready(None)
            }
            Payload::Failed => {
                self.done = true;
                owner.close();
                Poll::Ready(Some(Err(io::Error::other("upload reader failed"))))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn size_hint(&self) -> SizeHint {
        self.owner.length.map_or_else(SizeHint::new, |length| {
            SizeHint::with_exact(length.saturating_sub(self.emitted))
        })
    }
}

#[cfg(test)]
mod tests;
