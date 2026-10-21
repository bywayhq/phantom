use crate::error;
use http_body::{Body, Frame, SizeHint};
use phantom::Bytes;
use pyo3::{prelude::*, types::PyBytes};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::sync::Notify;

pub(super) const CHUNK: usize = 65536;
enum Payload {
    Data(Bytes),
    End,
    Failed,
}
struct State {
    payload: Option<Payload>,
    credit: bool,
    claimed: bool,
    leased: bool,
    closed: bool,
    waker: Option<Waker>,
}
pub(crate) struct Producer {
    state: Mutex<State>,
    changed: Notify,
    length: Option<u64>,
}
impl Producer {
    pub(crate) fn new(length: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                payload: None,
                credit: false,
                claimed: false,
                leased: false,
                closed: false,
                waker: None,
            }),
            changed: Notify::new(),
            length,
        })
    }
    pub(crate) fn body(self: &Arc<Self>) -> PyResult<ProducerBody> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error::input("upload_state"))?;
        if state.claimed || state.closed {
            return Err(error::input("upload_used"));
        }
        state.claimed = true;
        Ok(ProducerBody {
            owner: Arc::clone(self),
            emitted: 0,
            done: false,
        })
    }
    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.payload = None;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
        self.changed.notify_waiters();
    }
    pub(crate) async fn wait(&self, terminal: bool) -> PyResult<bool> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| error::input("upload_state"))?;
                if state.closed {
                    return Ok(false);
                }
                if !terminal && state.credit {
                    state.credit = false;
                    state.leased = true;
                    return Ok(true);
                }
            }
            changed.await;
        }
    }
    fn submit(&self, payload: Payload) -> PyResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error::input("upload_state"))?;
        if state.closed {
            return Err(error::input("upload_closed"));
        }
        if state.payload.is_some() || !state.leased {
            return Err(error::input("upload_without_credit"));
        }
        state.leased = false;
        state.payload = Some(payload);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

#[pyclass]
pub(crate) struct NativeUpload {
    pub(crate) inner: Arc<Producer>,
}
#[pymethods]
impl NativeUpload {
    #[new]
    #[pyo3(signature = (length=None))]
    fn new(length: Option<u64>) -> Self {
        Self {
            inner: Producer::new(length),
        }
    }
    fn credit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move { owner.wait(false).await })
    }
    fn terminal<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(
            py,
            async move { owner.wait(true).await.map(|_| ()) },
        )
    }
    pub(crate) fn write(
        &self,
        bytes: &Bound<'_, PyBytes>,
        offset: usize,
        length: usize,
    ) -> PyResult<()> {
        if length == 0 || length > CHUNK {
            return Err(error::input("upload_chunk_size"));
        }
        let bytes = bytes
            .as_bytes()
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| error::input("upload_chunk_range"))?,
            )
            .ok_or_else(|| error::input("upload_chunk_range"))?;
        self.inner
            .submit(Payload::Data(Bytes::copy_from_slice(bytes)))
    }
    pub(crate) fn finish(&self) -> PyResult<()> {
        self.inner.submit(Payload::End)
    }
    pub(crate) fn fail(&self) -> PyResult<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| error::input("upload_state"))?;
        if state.closed {
            return Err(error::input("upload_closed"));
        }
        state.payload = Some(Payload::Failed);
        state.credit = false;
        state.leased = false;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        Ok(())
    }
    fn abort(&self) {
        self.inner.close();
    }
}

pub(crate) struct ProducerBody {
    owner: Arc<Producer>,
    emitted: u64,
    done: bool,
}
impl Drop for ProducerBody {
    fn drop(&mut self) {
        self.owner.close();
    }
}
impl Body for ProducerBody {
    type Data = Bytes;
    type Error = io::Error;
    fn size_hint(&self) -> SizeHint {
        self.owner.length.map_or_else(SizeHint::new, |length| {
            SizeHint::with_exact(length.saturating_sub(self.emitted))
        })
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let owner = Arc::clone(&self.owner);
        let Ok(mut state) = owner.state.lock() else {
            return Poll::Ready(Some(Err(io::Error::other("upload state unavailable"))));
        };
        if self.done {
            return Poll::Ready(None);
        }
        if state.closed {
            self.done = true;
            return Poll::Ready(Some(Err(io::Error::other("upload closed"))));
        }
        state.waker = Some(cx.waker().clone());
        match state.payload.take() {
            Some(Payload::Data(bytes)) => {
                if owner
                    .length
                    .is_some_and(|length| bytes.len() as u64 > length.saturating_sub(self.emitted))
                {
                    self.done = true;
                    drop(state);
                    owner.close();
                    return Poll::Ready(Some(Err(io::Error::other(
                        "upload exceeds declared length",
                    ))));
                }
                self.emitted = self.emitted.saturating_add(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Some(Payload::End) => {
                self.done = true;
                drop(state);
                owner.close();
                if owner.length.is_some_and(|length| self.emitted != length) {
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upload ended before declared length",
                    ))))
                } else {
                    Poll::Ready(None)
                }
            }
            Some(Payload::Failed) => {
                self.done = true;
                drop(state);
                owner.close();
                Poll::Ready(Some(Err(io::Error::other("upload producer failed"))))
            }
            None => {
                if !state.leased {
                    state.credit = true;
                }
                drop(state);
                owner.changed.notify_waiters();
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn poll(body: &mut ProducerBody) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        Pin::new(body).poll_frame(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn demand_has_one_payload_and_body_cannot_be_reused() -> PyResult<()> {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(error::io)?;
        runtime.block_on(async {
            let owner = Producer::new(Some(3));
            let mut body = owner.body()?;
            assert!(owner.body().is_err());
            assert!(
                owner
                    .submit(Payload::Data(Bytes::from_static(b"abc")))
                    .is_err()
            );
            assert!(poll(&mut body).is_pending());
            assert!(owner.wait(false).await?);
            assert!(poll(&mut body).is_pending());
            owner.submit(Payload::Data(Bytes::from_static(b"abc")))?;
            assert!(owner.submit(Payload::End).is_err());
            let frame = body
                .frame()
                .await
                .transpose()
                .map_err(error::io)?
                .ok_or_else(|| error::input("missing_frame"))?;
            assert_eq!(
                frame
                    .into_data()
                    .map_err(|_| error::input("unexpected_trailer"))?,
                b"abc"[..]
            );
            assert!(poll(&mut body).is_pending());
            assert!(owner.wait(false).await?);
            owner.submit(Payload::End)?;
            assert!(body.frame().await.is_none());
            assert!(!owner.wait(true).await?);
            Ok(())
        })
    }

    #[test]
    fn declared_lengths_reject_short_long_and_zero_overflow() -> PyResult<()> {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(error::io)?;
        runtime.block_on(async {
            for (length, bytes) in [(0, b"x".as_slice()), (1, b"xx".as_slice())] {
                let owner = Producer::new(Some(length));
                let mut body = owner.body()?;
                assert!(poll(&mut body).is_pending());
                owner.wait(false).await?;
                owner.submit(Payload::Data(Bytes::copy_from_slice(bytes)))?;
                assert!(body.frame().await.transpose().is_err());
                assert!(!owner.wait(true).await?);
            }
            let owner = Producer::new(Some(1));
            let mut body = owner.body()?;
            assert!(poll(&mut body).is_pending());
            owner.wait(false).await?;
            owner.submit(Payload::End)?;
            assert!(body.frame().await.transpose().is_err());
            Ok(())
        })
    }

    #[test]
    fn body_drop_terminates_credit_and_releases_queued_payload() -> PyResult<()> {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(error::io)?;
        runtime.block_on(async {
            let owner = Producer::new(None);
            let mut body = owner.body()?;
            assert!(poll(&mut body).is_pending());
            owner.wait(false).await?;
            owner.submit(Payload::Data(Bytes::from(vec![1; CHUNK])))?;
            drop(body);
            assert!(!owner.wait(false).await?);
            assert!(
                owner
                    .state
                    .lock()
                    .map_err(|_| error::input("upload_state"))?
                    .payload
                    .is_none()
            );
            Ok(())
        })
    }
}
