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

pub(crate) mod header_hooks;

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
    hooks: Option<Arc<header_hooks::Owner>>,
}

impl Owner {
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(super) fn close(self: &Arc<Self>) -> Option<ClosedSource> {
        let source = {
            let mut slot = self
                .source
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let source = slot.take();
            // Publish closing only after an idle source has acquired cleanup
            // custody. A hook waiter can already be waiting for this close.
            if source.is_some() {
                self.busy.store(true, Ordering::SeqCst);
            }
            self.closed.store(true, Ordering::SeqCst);
            source
        };
        if let Some(hooks) = &self.hooks {
            hooks.close();
        }
        self.changed.notify_waiters();
        if let Ok(global) = global() {
            global.settled.notify_waiters();
        }
        source.map(|source| ClosedSource {
            owner: Arc::clone(self),
            source: Some(source),
        })
    }

    fn take(self: &Arc<Self>) -> Result<Lease, Failure> {
        let mut slot = self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_closed() {
            return Err(Failure::new("sse_closed"));
        }
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(Failure::new("concurrent_event_source_read"));
        }
        let source = slot.take();
        if source.is_none() {
            self.busy.store(false, Ordering::SeqCst);
            self.changed.notify_waiters();
            return Err(Failure::new("sse_closed"));
        }
        Ok(Lease {
            owner: Arc::clone(self),
            source,
        })
    }
}

struct Lease {
    owner: Arc<Owner>,
    source: Option<Box<SseEventSource>>,
}

/// Retain idle-source cleanup until the caller has released the registry lock.
/// Destruction can drop a reconnect callback which re-enters that registry.
pub(super) struct ClosedSource {
    owner: Arc<Owner>,
    source: Option<Box<SseEventSource>>,
}
impl Drop for ClosedSource {
    fn drop(&mut self) {
        drop(self.source.take());
        self.owner.busy.store(false, Ordering::SeqCst);
        self.owner.changed.notify_waiters();
        if let Ok(global) = global() {
            global.settled.notify_waiters();
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        {
            let mut slot = self
                .owner
                .source
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !self.owner.is_closed() {
                *slot = self.source.take();
                self.owner.busy.store(false, Ordering::SeqCst);
                self.owner.changed.notify_waiters();
                return;
            }
        }
        // A closed source owns its stream and pending reconnect. Drop those
        // outside both locks before publishing read handback.
        drop(self.source.take());
        self.owner.busy.store(false, Ordering::SeqCst);
        self.owner.changed.notify_waiters();
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
        let hook_operation = event
            .as_ref()
            .err()
            .and_then(header_hooks::failure_operation);
        let (event, error, cause) = match event {
            Ok(event) => (event, None, None),
            Err(error) => {
                let cause = request_cause(&error);
                (None, Some(sse::failure(&error)), cause)
            }
        };
        if state.closed {
            drop(self.owner.close());
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
            hook_operation,
        })
    }
}

pub(crate) struct ResultData {
    pub(crate) read: sse::Read,
    pub(crate) state: Snapshot,
    pub(crate) hook_operation: Option<u64>,
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
    let hook_operation = header_hooks::failure_operation(&error);
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
        hook_operation,
    }
}

pub(crate) fn open(opening: Opening) -> Result<Execution, Failure> {
    open_with_hooks(opening, 0).map(|(execution, _)| execution)
}

pub(crate) fn open_with_hooks(opening: Opening, count: usize) -> Result<(Execution, u64), Failure> {
    open_with_logical_hooks(opening, count, 0)
}

pub(crate) fn open_with_logical_hooks(
    opening: Opening,
    count: usize,
    phases: u8,
) -> Result<(Execution, u64), Failure> {
    if count > 256 || phases > 7 {
        return Err(Failure::new("invalid_header_hooks"));
    }
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
    if (count != 0 || phases != 0) && state.source_hooks.len() >= super::MAX_HANDLES {
        return Err(Failure::new("capacity"));
    }
    let hook_handle = if count == 0 && phases == 0 {
        0
    } else {
        state.id()?
    };
    let (id, cancel) = state.reserve(Target::EventSourceOpen(opening.client))?;
    let hooks = if count == 0 && phases == 0 {
        None
    } else {
        let owner = header_hooks::Owner::new(opening.client);
        state.source_hooks.insert(hook_handle, Arc::clone(&owner));
        request = request.without_header_hooks();
        if phases != 0 {
            request = request.async_request_hooks(header_hooks::LogicalHooks {
                owner: Arc::clone(&owner),
                phases,
            });
        }
        for index in 0..count {
            let owner = Arc::clone(&owner);
            request = request.async_header_hook(move |context| {
                let owner = Arc::clone(&owner);
                Box::pin(async move { owner.invoke(index, context).await })
            });
        }
        Some(owner)
    };
    drop(state);
    let hook_guard = header_hooks::CloseGuard(hooks.clone());
    global.spawn(id, cancel, async move {
        let mut hook_guard = hook_guard;
        match request.connect().await {
            Err(error) => {
                if let Some(hooks) = &hooks {
                    hooks.close();
                }
                Ok(Outcome::EventSource(Finished::Read(opening_failure(error))))
            }
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
                    hook_operation: None,
                };
                let owner = Arc::new(Owner {
                    client: opening.client,
                    source: Mutex::new((!state.closed).then(|| Box::new(source))),
                    closed: AtomicBool::new(state.closed),
                    busy: AtomicBool::new(false),
                    changed: Notify::new(),
                    hooks,
                });
                if let Some(hooks) = &owner.hooks {
                    hooks.bind_source(&owner);
                }
                drop(hook_guard.0.take());
                if state.closed {
                    drop(owner.close());
                }
                Ok(Outcome::EventSource(Finished::Open {
                    owner,
                    head,
                    result,
                }))
            }
        }
    });
    Ok((Execution::Operation(id), hook_handle))
}

pub(crate) fn next(source: u64) -> Result<Execution, Failure> {
    let global = global()?;
    let state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let owner = state
        .sources
        .get(&source)
        .cloned()
        .ok_or_else(|| Failure::new("sse_closed"))?;
    drop(state);
    let lease = owner.take()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
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
    let mut closed_sources = Vec::new();
    global()?.lock().close_source(source, &mut closed_sources);
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
    closed_sources: &mut Vec<ClosedSource>,
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
                state.close_source(source, closed_sources);
            }
            (Completed::Complete, result)
        }
    };
    if let Some(operation) = state.operations.get_mut(&id) {
        operation.source_result = Some(Arc::new(result));
    }
    Ok(completed)
}

#[cfg(test)]
mod tests;
