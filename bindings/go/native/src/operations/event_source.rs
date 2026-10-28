//! Reconnecting SSE ownership, with cancellation-safe exclusive read leases.

use std::{
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use phantom::{HttpProtocol, RequestError, Route, SseEventSource, SseHeader};
use tokio::sync::Notify;

use super::{Completed, CompletedHead, Execution, Outcome, Target, global, response, sse};
use crate::{error::Failure, timeouts::Timeouts};

pub(crate) struct Opening {
    pub(crate) client: u64,
    pub(crate) url: String,
    pub(crate) protocol: HttpProtocol,
    pub(crate) headers: Option<Vec<SseHeader>>,
    pub(crate) limits: sse::Limits,
    pub(crate) idle: Option<Duration>,
    pub(crate) initial_retry: Option<Duration>,
    pub(crate) min_retry: Option<Duration>,
    pub(crate) maximum: Option<usize>,
    pub(crate) timeouts: Timeouts,
    pub(crate) route: Option<Route>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Snapshot {
    pub(crate) retry_milliseconds: u64,
    pub(crate) reconnects: u64,
    pub(crate) closed: bool,
}

pub(super) struct Owner {
    pub(super) client: u64,
    source: Mutex<Option<Box<SseEventSource>>>,
    closed: AtomicBool,
    busy: AtomicBool,
    changed: Notify,
}

impl Owner {
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
        // A leased source observes changed; an idle source is dropped here.
        self.source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Ok(global) = global() {
            global.settled.notify_waiters();
        }
    }

    fn take(self: &Arc<Self>) -> Result<Lease, Failure> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(Failure::new("concurrent_event_source_read"));
        }
        let source = self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if self.is_closed() || source.is_none() {
            self.busy.store(false, Ordering::SeqCst);
            return Err(Failure::new("sse_closed"));
        }
        Ok(Lease {
            owner: self.clone(),
            source,
        })
    }
}

struct Lease {
    owner: Arc<Owner>,
    source: Option<Box<SseEventSource>>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut slot = self
            .owner
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.owner.is_closed() {
            *slot = self.source.take();
        }
        self.owner.busy.store(false, Ordering::SeqCst);
    }
}

impl Lease {
    async fn read(mut self) -> Result<ResultData, Failure> {
        let changed = self.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.owner.is_closed() {
            return Err(Failure::new("sse_closed"));
        }
        let source = self
            .source
            .as_mut()
            .ok_or_else(|| Failure::new("internal"))?;
        let event = tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("sse_closed")),
            result = source.next_event() => result,
        };
        let state = snapshot(source)?;
        let last_event_id = if matches!(&event, Ok(Some(_))) {
            String::new()
        } else {
            source.last_event_id().to_owned()
        };
        let (event, error, cause) = match event {
            Ok(event) => (event, None, None),
            Err(error) => {
                let cause = request_cause(&error);
                (None, Some(sse::failure(&error)), cause)
            }
        };
        if state.closed {
            self.owner.close();
        }
        Ok(ResultData {
            read: sse::Read {
                event,
                last_event_id,
                retry: Some(source.retry_delay()),
                error,
                cause,
                trailers: None,
            },
            state,
        })
    }
}

pub(crate) struct ResultData {
    pub(crate) read: sse::Read,
    pub(crate) state: Snapshot,
}

pub(super) enum Finished {
    Open {
        owner: Arc<Owner>,
        head: CompletedHead,
        result: ResultData,
    },
    Read(ResultData),
}

fn snapshot(source: &SseEventSource) -> Result<Snapshot, Failure> {
    Ok(Snapshot {
        retry_milliseconds: u64::try_from(source.retry_delay().as_millis())
            .map_err(|_| Failure::new("sse_retry_range"))?,
        reconnects: source.reconnects() as u64,
        closed: source.is_closed(),
    })
}

fn request_cause(error: &phantom::SseError) -> Option<Failure> {
    error
        .source()
        .and_then(|source| source.downcast_ref::<RequestError>())
        .map(Failure::from)
}

fn opening_failure(error: phantom::SseError) -> ResultData {
    ResultData {
        read: sse::Read {
            event: None,
            last_event_id: String::new(),
            retry: None,
            cause: request_cause(&error),
            error: Some(sse::failure(&error)),
            trailers: None,
        },
        state: Snapshot {
            closed: true,
            ..Snapshot::default()
        },
    }
}

pub(crate) fn open(opening: Opening) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let client = state
        .clients
        .get(&opening.client)
        .ok_or_else(|| Failure::new("client_closed"))?;
    if client.closing {
        return Err(Failure::new("client_closed"));
    }
    let mut request = client
        .client
        .event_source(opening.protocol, &opening.url)
        .map_err(Failure::from)?;
    request = request
        .limits(opening.limits.core()?)
        .request_timeouts(opening.timeouts.overrides());
    if let Some(headers) = opening.headers {
        request = request.headers(headers);
    }
    if let Some(value) = opening.idle {
        request = request.idle_timeout(value);
    }
    if let Some(value) = opening.initial_retry {
        request = request.initial_retry(value);
    }
    if let Some(value) = opening.min_retry {
        request = request.min_retry(value);
    }
    if let Some(value) = opening.maximum {
        request = request.max_reconnects(value);
    }
    if let Some(value) = opening.route {
        request = request.route(value);
    }
    let (id, cancel) = state.reserve(Target::EventSourceOpen(opening.client))?;
    drop(state);
    global.spawn(id, cancel, async move {
        match request.connect().await {
            Err(error) => Ok(Outcome::EventSource(Finished::Read(opening_failure(error)))),
            Ok(response) => {
                let head = response::metadata(&response)?;
                let source = response.into_body();
                let state = snapshot(&source)?;
                let result = ResultData {
                    read: sse::Read {
                        event: None,
                        last_event_id: source.last_event_id().to_owned(),
                        retry: Some(source.retry_delay()),
                        error: None,
                        cause: None,
                        trailers: None,
                    },
                    state,
                };
                let owner = Arc::new(Owner {
                    client: opening.client,
                    source: Mutex::new((!state.closed).then(|| Box::new(source))),
                    closed: AtomicBool::new(state.closed),
                    busy: AtomicBool::new(false),
                    changed: Notify::new(),
                });
                Ok(Outcome::EventSource(Finished::Open {
                    owner,
                    head,
                    result,
                }))
            }
        }
    });
    Ok(Execution::Operation(id))
}

pub(crate) fn next(source: u64) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let owner = state
        .sources
        .get(&source)
        .cloned()
        .ok_or_else(|| Failure::new("sse_closed"))?;
    let lease = owner.take()?;
    let (id, cancel) = state.reserve(Target::EventSourceRead(source))?;
    drop(state);
    global.spawn(id, cancel, async move {
        lease
            .read()
            .await
            .map(Finished::Read)
            .map(Outcome::EventSource)
    });
    Ok(Execution::Operation(id))
}

pub(crate) fn close(source: u64) -> Result<Execution, Failure> {
    global()?.lock().close_source(source);
    Ok(Execution::Complete)
}

// Unlike abandonment, this cancellation keeps the completion registered. The
// read future drops its lease before finish delivers the acknowledgement.
pub(crate) fn cancel_next(id: u64) -> Result<Execution, Failure> {
    let mut state = global()?.lock();
    let operation = state
        .operations
        .get_mut(&id)
        .ok_or_else(|| Failure::new("invalid_handle"))?;
    if !matches!(operation.target, Target::EventSourceRead(_)) {
        return Err(Failure::new("invalid_handle"));
    }
    if let Some(cancel) = operation.cancel.take() {
        let _ = cancel.send(());
    }
    Ok(Execution::Complete)
}

pub(crate) fn result(id: u64) -> Result<Arc<ResultData>, Failure> {
    global()?
        .lock()
        .operations
        .get(&id)
        .filter(|operation| operation.delivered && !operation.abandoned)
        .and_then(|operation| operation.source_result.clone())
        .ok_or_else(|| Failure::new("sse_result_unavailable"))
}

pub(super) fn finish(
    state: &mut super::State,
    id: u64,
    reserved: Option<u64>,
    finished: Finished,
) -> Result<Completed, Failure> {
    let (completed, result) = match finished {
        Finished::Open {
            owner,
            mut head,
            result,
        } => {
            let handle = reserved.ok_or_else(|| Failure::new("internal"))?;
            head.body = handle;
            if !owner.is_closed() {
                state.sources.insert(handle, owner);
                if let Some(operation) = state.operations.get_mut(&id) {
                    operation.source = Some(handle);
                }
            }
            (Completed::Head(head), result)
        }
        Finished::Read(result) => {
            if result.state.closed
                && let Some(super::Operation {
                    target: Target::EventSourceRead(source),
                    ..
                }) = state.operations.get(&id)
            {
                let source = *source;
                state.close_source(source);
            }
            (Completed::Complete, result)
        }
    };
    if let Some(operation) = state.operations.get_mut(&id) {
        operation.source_result = Some(Arc::new(result));
    }
    Ok(completed)
}
