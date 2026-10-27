//! Exclusively owned WebSocket halves and client-scoped shutdown.

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use napi::Result;
use phantom::{WebSocket, WebSocketMessage};
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::{client::ClientState, error::failure};

type Writer = SplitSink<WebSocket, WebSocketMessage>;
type Reader = SplitStream<WebSocket>;

#[derive(Clone, Copy, Debug)]
enum End {
    Closed,
    Aborted,
}

#[derive(Debug)]
pub(crate) struct Socket {
    claimed: AtomicBool,
    ended: watch::Sender<Option<End>>,
    reader: Mutex<Option<Reader>>,
    writer: Mutex<Option<Writer>>,
    permit: Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    owner: Mutex<Option<Arc<ClientState>>>,
}

impl Socket {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            claimed: AtomicBool::new(false),
            ended: watch::channel(None).0,
            reader: Mutex::new(None),
            writer: Mutex::new(None),
            permit: Mutex::new(None),
            owner: Mutex::new(None),
        })
    }

    pub(crate) fn claim(
        &self,
        permit: OwnedSemaphorePermit,
        owner: Arc<ClientState>,
    ) -> Result<Arc<OwnedSemaphorePermit>> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(failure("InvalidOperation", "WebSocket was already opened"));
        }
        let mut retained = self.permit.lock().unwrap_or_else(PoisonError::into_inner);
        self.check()?;
        let permit = Arc::new(permit);
        *retained = Some(Arc::clone(&permit));
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner);
        Ok(permit)
    }

    pub(crate) fn attach(&self, socket: WebSocket) -> Result<()> {
        let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        self.check()?;
        let (outgoing, incoming) = socket.split();
        *reader = Some(incoming);
        *writer = Some(outgoing);
        Ok(())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.ended.borrow().is_none()
    }

    fn check(&self) -> Result<()> {
        match *self.ended.borrow() {
            None => Ok(()),
            Some(End::Closed) => Err(failure("WebSocketClosed", "WebSocket is closed")),
            Some(End::Aborted) => Err(failure("Cancelled", "WebSocket was aborted")),
        }
    }

    pub(crate) async fn interrupted(&self) -> napi::Error {
        let mut ended = self.ended.subscribe();
        // This sender is retained by self throughout the wait.
        let _ = ended.wait_for(Option::is_some).await;
        match *ended.borrow() {
            Some(End::Closed) => failure("WebSocketClosed", "WebSocket is closed"),
            _ => failure("Cancelled", "WebSocket was aborted"),
        }
    }

    pub(crate) fn abort(&self) {
        self.finish(End::Aborted);
    }

    fn finish(&self, end: End) {
        self.ended.send_if_modified(|value| {
            if value.is_some() {
                false
            } else {
                *value = Some(end);
                true
            }
        });
        self.reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let owner = {
            self.owner
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        };
        // The last client drop closes registered sockets and can re-enter here.
        drop(owner);
    }

    pub(crate) async fn receive(self: &Arc<Self>) -> Result<Option<WebSocketMessage>> {
        if matches!(*self.ended.borrow(), Some(End::Closed)) {
            return Ok(None);
        }
        self.check()?;
        let mut incoming = ReadHalf::take(self)?;
        let result = tokio::select! {
            biased;
            error = self.interrupted() => Err(error),
            message = incoming.reader.as_mut().ok_or_else(|| failure("Internal", "WebSocket reader is absent"))?.next() => {
                message.transpose().map_err(error)
            }
        };
        if !matches!(&result, Ok(Some(message)) if !matches!(message, WebSocketMessage::Close(_))) {
            self.finish(End::Closed);
        }
        result
    }

    pub(crate) async fn send(self: &Arc<Self>, message: WebSocketMessage) -> Result<()> {
        self.check()?;
        let mut outgoing = WriteHalf::take(self)?;
        let result = tokio::select! {
            biased;
            error = self.interrupted() => return Err(error),
            sent = outgoing.writer.as_mut().ok_or_else(|| failure("Internal", "WebSocket writer is absent"))?.send(message) => sent,
        };
        if result
            .as_ref()
            .is_err_and(|error| error.kind() != phantom::WebSocketErrorKind::Capacity)
        {
            self.finish(End::Closed);
        }
        result.map_err(error)
    }
}

// An admitted operation retains its permit until its owned half has been dropped,
// including when environment shutdown drops an unfinished async operation.
struct ReadHalf {
    reader: Option<Reader>,
    owner: Arc<Socket>,
    _permit: Arc<OwnedSemaphorePermit>,
}

impl ReadHalf {
    fn take(owner: &Arc<Socket>) -> Result<Self> {
        let mut reader = owner.reader.lock().unwrap_or_else(PoisonError::into_inner);
        owner.check()?;
        let permit = owner
            .permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .cloned()
            .ok_or_else(|| failure("WebSocketClosed", "WebSocket is closed"))?;
        Ok(Self {
            reader: Some(reader.take().ok_or_else(|| {
                failure("InvalidOperation", "a WebSocket receive is already pending")
            })?),
            owner: Arc::clone(owner),
            _permit: permit,
        })
    }
}

impl Drop for ReadHalf {
    fn drop(&mut self) {
        let mut reader = self
            .owner
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.owner.is_active() {
            *reader = self.reader.take();
        }
    }
}

struct WriteHalf {
    writer: Option<Writer>,
    owner: Arc<Socket>,
    _permit: Arc<OwnedSemaphorePermit>,
}

impl WriteHalf {
    fn take(owner: &Arc<Socket>) -> Result<Self> {
        let mut writer = owner.writer.lock().unwrap_or_else(PoisonError::into_inner);
        owner.check()?;
        let permit = owner
            .permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .cloned()
            .ok_or_else(|| failure("WebSocketClosed", "WebSocket is closed"))?;
        Ok(Self {
            writer: Some(writer.take().ok_or_else(|| {
                failure("InvalidOperation", "a WebSocket send is already pending")
            })?),
            owner: Arc::clone(owner),
            _permit: permit,
        })
    }
}

impl Drop for WriteHalf {
    fn drop(&mut self) {
        let mut writer = self
            .owner
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.owner.is_active() {
            *writer = self.writer.take();
        }
    }
}

pub(crate) fn error(error: phantom::WebSocketError) -> napi::Error {
    error_details(&error)
}

pub(crate) fn error_details(error: &phantom::WebSocketError) -> napi::Error {
    let phase = if error.timeout_phase().is_some() {
        "webSocketHandshake"
    } else {
        ""
    };
    let status = error
        .response()
        .map(|response| response.status().as_u16().to_string())
        .unwrap_or_default();
    napi::Error::new(
        napi::Status::GenericFailure,
        format!(
            "PHANTOM_WEBSOCKET:{:?}:{phase}:{status}:{error}",
            error.kind()
        ),
    )
}
