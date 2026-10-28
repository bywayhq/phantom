//! Pull-driven reconnecting SSE ownership and client-scoped cancellation.

use std::{
    error::Error as StdError,
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use napi::Result;
use phantom::{SseEvent, SseEventSource};
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::{client::ClientState, error::failure};

#[derive(Default)]
struct Snapshot {
    last_event_id: String,
    retry: Duration,
    reconnects: usize,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("retry", &self.retry)
            .field("reconnects", &self.reconnects)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Source {
    ended: watch::Sender<bool>,
    source: Mutex<Option<SseEventSource>>,
    snapshot: Mutex<Snapshot>,
    permit: Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    owner: Mutex<Option<Arc<ClientState>>>,
}

impl fmt::Debug for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Source")
            .field("closed", &!self.is_active())
            .finish_non_exhaustive()
    }
}

impl Source {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            ended: watch::channel(false).0,
            source: Mutex::new(None),
            snapshot: Mutex::new(Snapshot::default()),
            permit: Mutex::new(None),
            owner: Mutex::new(None),
        })
    }

    pub(crate) fn claim(
        &self,
        permit: OwnedSemaphorePermit,
        owner: Arc<ClientState>,
    ) -> Result<Arc<OwnedSemaphorePermit>> {
        let mut retained = self.permit.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.is_active() || retained.is_some() {
            return Err(failure(
                "InvalidOperation",
                "event source is closed or already opened",
            ));
        }
        let permit = Arc::new(permit);
        *retained = Some(Arc::clone(&permit));
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner);
        Ok(permit)
    }

    pub(crate) fn attach(&self, source: SseEventSource) -> Result<()> {
        let mut retained = self.source.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.is_active() {
            return Err(failure("Cancelled", "event source was closed"));
        }
        self.update(&source);
        let closed = source.is_closed();
        *retained = Some(source);
        drop(retained);
        if closed {
            self.close();
        }
        Ok(())
    }

    pub(crate) fn is_active(&self) -> bool {
        !*self.ended.borrow()
    }

    pub(crate) fn last_event_id(&self) -> String {
        self.snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_event_id
            .clone()
    }

    pub(crate) fn retry_delay(&self) -> Duration {
        self.snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retry
    }

    pub(crate) fn reconnects(&self) -> usize {
        self.snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconnects
    }

    fn update(&self, source: &SseEventSource) {
        let mut snapshot = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
        source
            .last_event_id()
            .clone_into(&mut snapshot.last_event_id);
        snapshot.retry = source.retry_delay();
        snapshot.reconnects = source.reconnects();
    }

    pub(crate) async fn interrupted(&self) -> napi::Error {
        let mut ended = self.ended.subscribe();
        // Self retains the sender for the lifetime of this wait.
        let _ = ended.wait_for(|value| *value).await;
        failure("Cancelled", "event source was closed")
    }

    pub(crate) fn close(&self) {
        self.ended.send_replace(true);
        let source = self
            .source
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(source) = source.as_ref() {
            self.update(source);
        }
        drop(source);
        self.permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let owner = self
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // The last client can re-enter registered-source cleanup on drop.
        drop(owner);
    }

    pub(crate) async fn read(self: &Arc<Self>) -> Result<Option<SseEvent>> {
        if !self.is_active() {
            return Err(failure("Cancelled", "event source was closed"));
        }
        let mut lease = Read::take(self)?;
        let source = lease
            .source
            .as_mut()
            .ok_or_else(|| failure("Internal", "event source reader is unavailable"))?;
        let result = tokio::select! {
            biased;
            error = self.interrupted() => Err(error),
            event = source.next_event() => event.map_err(error),
        };
        self.update(source);
        if !matches!(result, Ok(Some(_))) {
            self.close();
        }
        result
    }
}

struct Read {
    source: Option<SseEventSource>,
    owner: Arc<Source>,
    _permit: Arc<OwnedSemaphorePermit>,
}

impl Read {
    fn take(owner: &Arc<Source>) -> Result<Self> {
        let mut source = owner.source.lock().unwrap_or_else(PoisonError::into_inner);
        let permit = owner
            .permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .cloned()
            .ok_or_else(|| failure("Cancelled", "event source was closed"))?;
        Ok(Self {
            source: Some(
                source.take().ok_or_else(|| {
                    failure("ConcurrentRead", "only one event read may be pending")
                })?,
            ),
            owner: Arc::clone(owner),
            _permit: permit,
        })
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        let mut source = self
            .owner
            .source
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.owner.is_active() {
            *source = self.source.take();
        }
    }
}

pub(crate) fn error(error: phantom::SseError) -> napi::Error {
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<phantom::RequestError>())
        .map(crate::error::request_ref);
    let suffix = cause.map_or_else(String::new, |cause| format!("\n{}", cause.reason));
    napi::Error::new(
        napi::Status::GenericFailure,
        format!("PHANTOM_EVENT_SOURCE:{:?}:{error}{suffix}", error.kind()),
    )
}
