//! A single native-owned frame, requested only by transport body polling.

use crate::error::failure;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use napi::Result;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::{Semaphore, mpsc, watch};

pub(crate) const MAXIMUM_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct Upload {
    credit: Semaphore,
    sender: Mutex<Option<mpsc::Sender<Bytes>>>,
    receiver: Mutex<Option<mpsc::Receiver<Bytes>>>,
    stopped: watch::Sender<bool>,
    length: Option<u64>,
    written: Mutex<u64>,
    failed: AtomicBool,
    allowed: AtomicBool,
    exchange: Mutex<Weak<crate::response::Exchange>>,
}

impl Upload {
    pub(crate) fn new(length: Option<u64>) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(1);
        Arc::new(Self {
            credit: Semaphore::new(0),
            sender: Mutex::new(Some(sender)),
            receiver: Mutex::new(Some(receiver)),
            stopped: watch::channel(false).0,
            length,
            written: Mutex::new(0),
            failed: AtomicBool::new(false),
            allowed: AtomicBool::new(false),
            exchange: Mutex::new(Weak::new()),
        })
    }

    pub(crate) fn bind(&self, exchange: &Arc<crate::response::Exchange>) {
        *self.exchange.lock().unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(exchange);
    }
    pub(crate) fn settled(&self) {
        if let Some(exchange) = self
            .exchange
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade()
        {
            exchange.upload_settled();
        }
    }

    pub(crate) fn body(self: &Arc<Self>) -> Result<UploadBody> {
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| failure("InvalidOperation", "an upload belongs to one request"))?;
        Ok(UploadBody {
            state: Arc::clone(self),
            receiver,
            remaining: self.length,
            requested: false,
        })
    }

    pub(crate) async fn ready(&self) -> bool {
        match self.credit.acquire().await {
            Ok(permit) => {
                permit.forget();
                self.allowed.store(true, Ordering::Release);
                true
            }
            Err(_) => false,
        }
    }

    pub(crate) fn write(&self, bytes: Vec<u8>) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CHUNK {
            return Err(failure(
                "InvalidUpload",
                "upload frames must contain 1..65536 bytes",
            ));
        }
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        let sender = self.sender.lock().unwrap_or_else(PoisonError::into_inner);
        let sender = sender
            .as_ref()
            .ok_or_else(|| failure("UploadClosed", "upload is closed"))?;
        if !self.allowed.swap(false, Ordering::AcqRel) {
            return Err(failure("InvalidUpload", "upload has no outstanding credit"));
        }
        let next = written
            .checked_add(bytes.len() as u64)
            .filter(|next| self.length.is_none_or(|length| *next <= length))
            .ok_or_else(|| failure("UploadLength", "upload exceeds bodyLength"))?;
        sender
            .try_send(Bytes::from(bytes))
            .map_err(|_| failure("UploadClosed", "upload has no outstanding credit"))?;
        *written = next;
        Ok(())
    }

    pub(crate) fn end(&self) -> Result<()> {
        let written = *self.written.lock().unwrap_or_else(PoisonError::into_inner);
        let mut sender = self.sender.lock().unwrap_or_else(PoisonError::into_inner);
        if sender.is_none() {
            return Err(failure("UploadClosed", "upload is closed"));
        }
        if self.length.is_some_and(|length| length != written) {
            drop(sender);
            self.fail();
            return Err(failure("UploadLength", "upload ended before bodyLength"));
        }
        sender.take();
        Ok(())
    }

    pub(crate) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.stop();
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub(crate) fn stop(&self) {
        self.stopped.send_replace(true);
        self.credit.close();
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
    pub(crate) async fn stopped(&self) {
        let mut stopped = self.stopped.subscribe();
        if !*stopped.borrow_and_update() {
            let _ = stopped.wait_for(|value| *value).await;
        }
    }
}

#[derive(Debug)]
pub(crate) struct UploadBody {
    state: Arc<Upload>,
    receiver: mpsc::Receiver<Bytes>,
    remaining: Option<u64>,
    requested: bool,
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if self.state.failed() {
            return Poll::Ready(Some(Err(io::Error::other("upload source failed"))));
        }
        if !self.requested {
            self.requested = true;
            self.state.credit.add_permits(1);
        }
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(bytes)) => {
                self.requested = false;
                if let Some(remaining) = &mut self.remaining {
                    *remaining -= bytes.len() as u64;
                }
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None)
                if self.state.failed()
                    || self.remaining.is_some_and(|remaining| remaining != 0) =>
            {
                Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upload source ended early",
                ))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::new, SizeHint::with_exact)
    }
}
impl Drop for UploadBody {
    fn drop(&mut self) {
        self.state.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::future::poll_fn;

    async fn poll_demand(body: &mut UploadBody) {
        poll_fn(|context| {
            assert!(Pin::new(&mut *body).poll_frame(context).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn transport_poll_grants_one_credit_and_retains_only_one_frame() -> Result<()> {
        let state = Upload::new(Some(3));
        let mut body = state.body()?;
        assert!(state.write(b"abc".to_vec()).is_err());
        assert_eq!(state.credit.available_permits(), 0);
        poll_demand(&mut body).await;
        poll_demand(&mut body).await;
        assert_eq!(state.credit.available_permits(), 1);
        assert!(state.ready().await);
        state.write(b"abc".to_vec())?;
        assert!(state.write(b"x".to_vec()).is_err());
        let frame = body
            .frame()
            .await
            .ok_or_else(|| failure("Test", "missing frame"))?
            .map_err(|_| failure("Test", "body failed"))?;
        assert_eq!(
            frame
                .into_data()
                .map_err(|_| failure("Test", "missing data"))?,
            Bytes::from_static(b"abc")
        );
        assert_eq!(state.credit.available_permits(), 0);
        assert_eq!(body.size_hint().exact(), Some(0));
        state.end()?;
        assert!(body.frame().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn source_eof_checks_exact_length_and_unknown_length_remains_unknown() -> Result<()> {
        let exact = Upload::new(Some(2));
        let mut body = exact.body()?;
        assert!(exact.end().is_err());
        assert!(body.frame().await.is_some_and(|frame| frame.is_err()));
        let unknown = Upload::new(None);
        let mut body = unknown.body()?;
        assert_eq!(body.size_hint().exact(), None);
        unknown.end()?;
        assert!(body.frame().await.is_none());
        let empty = Upload::new(Some(0));
        let mut body = empty.body()?;
        empty.end()?;
        assert!(body.frame().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn early_body_drop_notifies_the_producer_without_source_failure() -> Result<()> {
        let state = Upload::new(None);
        let body = state.body()?;
        assert!(state.body().is_err());
        drop(body);
        state.stopped().await;
        assert!(!state.ready().await);
        assert!(!state.failed());
        Ok(())
    }
}
