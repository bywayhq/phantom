//! Source-owned header rendezvous using the existing request callback custody.

use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex, Weak},
};

use phantom::{HeaderHookContext, HeaderHookError};
use tokio::sync::{mpsc, oneshot, watch};

use super::super::{Execution, Outcome, Target, global};
use crate::error::Failure;

pub(crate) struct Owner {
    pub(crate) client: u64,
    sender: mpsc::Sender<Slot>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<Slot>>,
    closed: watch::Sender<bool>,
    source: Mutex<Weak<super::Owner>>,
}
struct Slot {
    operation: u64,
    done: oneshot::Sender<Result<(), Failure>>,
}
pub(crate) struct CloseGuard(pub(crate) Option<Arc<Owner>>);
impl Drop for CloseGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.close();
        }
    }
}
struct Handback(Option<Slot>);
impl Drop for Handback {
    fn drop(&mut self) {
        if let Some(slot) = self.0.take() {
            // A dropped GET cancels this invocation, not the source's next GET.
            let _ = slot.done.send(Err(Failure::new("source_header_cancelled")));
        }
    }
}
#[derive(Debug)]
struct SourceFailure {
    operation: u64,
    error: HeaderHookError,
}
impl fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventSource header callback failed")
    }
}
impl Error for SourceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}
impl Owner {
    pub(crate) fn new(client: u64) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(1);
        Arc::new(Self {
            client,
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
            closed: watch::channel(false).0,
            source: Mutex::new(Weak::new()),
        })
    }
    pub(crate) fn bind_source(&self, source: &Arc<super::Owner>) {
        *self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::downgrade(source);
    }
    async fn source_idle(&self) {
        let source = self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade();
        if let Some(source) = source {
            loop {
                let changed = source.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if source.is_closed() && !source.busy.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                changed.await;
            }
        }
    }
    pub(crate) fn close(&self) {
        self.closed.send_replace(true);
    }
    async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        if !*closed.borrow_and_update() {
            // The owner retains the sender for this entire wait.
            let _ = closed.wait_for(|closed| *closed).await;
        }
    }
    pub(crate) async fn invoke(
        self: Arc<Self>,
        index: usize,
        context: &mut HeaderHookContext<'_>,
    ) -> Result<(), HeaderHookError> {
        let mut receiver = self.receiver.lock().await;
        let slot = tokio::select! {
            biased;
            () = self.closed() => return Err(HeaderHookError::new(std::io::Error::other("EventSource is closed"))),
            slot = receiver.recv() => slot.ok_or_else(|| HeaderHookError::new(std::io::Error::other("EventSource callback unavailable")))?,
        };
        drop(receiver);
        let operation = slot.operation;
        let mut handback = Handback(Some(slot));
        let result = global()
            .map_err(|_| {
                HeaderHookError::new(std::io::Error::other(
                    "EventSource callback runtime unavailable",
                ))
            })?
            .header_hook(operation, index, context)
            .await;
        let status = if result.is_ok() {
            Ok(())
        } else {
            Err(Failure::new("header_hook"))
        };
        if let Some(slot) = handback.0.take() {
            // The Go invocation may already have been cancelled by source close.
            let _ = slot.done.send(status);
        }
        result.map_err(|error| HeaderHookError::new(SourceFailure { operation, error }))
    }
}

pub(crate) fn next(handle: u64) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let owner = state
        .source_hooks
        .get(&handle)
        .cloned()
        .ok_or_else(|| Failure::new("sse_closed"))?;
    if *owner.closed.borrow() {
        return Err(Failure::new("sse_closed"));
    }
    let (id, cancel) = state.reserve(Target::EventSourceHeader {
        client: owner.client,
        owner: handle,
    })?;
    let (done, received) = oneshot::channel();
    if owner
        .sender
        .try_send(Slot {
            operation: id,
            done,
        })
        .is_err()
    {
        state.operations.remove(&id);
        return Err(Failure::new("source_header_pending"));
    }
    drop(state);
    global.spawn(id, cancel, async move {
        tokio::select! {
            biased;
            () = owner.closed() => { owner.source_idle().await; Err(Failure::new("sse_closed")) },
            result = received => result.map_err(|_| Failure::new("source_header_cancelled"))?.map(|()| Outcome::Complete),
        }
    });
    Ok(Execution::Operation(id))
}

pub(crate) fn close(handle: u64) -> Result<Execution, Failure> {
    if let Some(owner) = global()?.lock().source_hooks.get(&handle) {
        owner.close();
    }
    Ok(Execution::Complete)
}

pub(crate) fn release(handle: u64) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if let Some(owner) = state.source_hooks.get(&handle) {
        owner.close();
        let pending = state.operations.values().any(|operation| {
            let owns_source = matches!(operation.target, Target::EventSourceHeader { owner: current, .. } if current == handle);
            let host_owned = operation.callback_call.as_ref().is_some_and(|call| call.host_owned);
            owns_source && (!operation.finished || host_owned)
        });
        if pending {
            return Err(Failure::new("operation_pending"));
        }
    }
    state.source_hooks.remove(&handle);
    global.settled.notify_waiters();
    Ok(Execution::Complete)
}

pub(crate) fn failure_operation(error: &phantom::SseError) -> Option<u64> {
    let mut source: Option<&(dyn Error + 'static)> = Some(error);
    for _ in 0..16 {
        let error = source?;
        if let Some(error) = error.downcast_ref::<SourceFailure>() {
            return Some(error.operation);
        }
        source = if let Some(error) = error.downcast_ref::<std::io::Error>() {
            error
                .get_ref()
                .map(|error| error as &(dyn Error + 'static))
                .or_else(|| error.source())
        } else {
            error.source()
        };
    }
    None
}

pub(crate) fn active(operation: u64, ticket: u64) -> Result<bool, Failure> {
    let global = global()?;
    let state = global.lock();
    Ok(invocation_active(&state, operation, ticket))
}

fn invocation_active(state: &super::super::State, operation: u64, ticket: u64) -> bool {
    state.operations.get(&operation).is_some_and(|operation| {
        let Target::EventSourceHeader { owner, .. } = operation.target else {
            return false;
        };
        let open = state
            .source_hooks
            .get(&owner)
            .is_some_and(|owner| !*owner.closed.borrow());
        open && !operation.finished
            && !operation.abandoned
            && operation.callback_call.as_ref().is_some_and(|call| {
                call.ticket == ticket && call.host_owned && call.reply.is_some()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::{CallbackCall, CallbackInvocation, State};
    use super::*;
    use crate::header_hook::Invocation;

    #[test]
    fn expired_source_invocations_are_not_dispatched_or_reassigned() -> Result<(), Failure> {
        let mut state = State::default();
        state.source_hooks.insert(2, Owner::new(1));
        let (old, _cancel) = state.reserve(Target::EventSourceHeader {
            client: 1,
            owner: 2,
        })?;
        let (reply, _received) = oneshot::channel();
        state
            .operations
            .get_mut(&old)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket: 3,
            invocation: CallbackInvocation::Header(Arc::new(Invocation {
                index: 0,
                method: "GET".into(),
                uri: "http://127.0.0.1/".into(),
                headers: Vec::new(),
            })),
            reply: Some(reply),
            host_owned: true,
        });
        assert!(invocation_active(&state, old, 3));
        assert!(!invocation_active(&state, old, 4));
        state
            .operations
            .get_mut(&old)
            .and_then(|operation| operation.callback_call.as_mut())
            .ok_or_else(|| Failure::new("test_callback"))?
            .reply
            .take();
        assert!(!invocation_active(&state, old, 3));
        // Custody remains attached to the old operation until actual host reply.
        assert_eq!(
            state
                .reserve(Target::EventSourceHeader {
                    client: 1,
                    owner: 2
                })
                .err()
                .map(|failure| failure.kind),
            Some("source_header_pending")
        );
        let (other, _cancel) = state.reserve(Target::EventSourceHeader {
            client: 1,
            owner: 5,
        })?;
        assert!(!invocation_active(&state, other, 3));
        Ok(())
    }

    #[test]
    fn closing_source_rejects_queued_metadata_before_terminal_delivery() -> Result<(), Failure> {
        let mut state = State::default();
        let owner = Owner::new(1);
        state.source_hooks.insert(2, Arc::clone(&owner));
        let (operation, _cancel) = state.reserve(Target::EventSourceHeader {
            client: 1,
            owner: 2,
        })?;
        let (reply, _received) = oneshot::channel();
        state
            .operations
            .get_mut(&operation)
            .ok_or_else(|| Failure::new("test_operation"))?
            .callback_call = Some(CallbackCall {
            ticket: 3,
            invocation: CallbackInvocation::Header(Arc::new(Invocation {
                index: 0,
                method: "GET".into(),
                uri: "http://127.0.0.1/".into(),
                headers: Vec::new(),
            })),
            reply: Some(reply),
            host_owned: true,
        });
        assert!(invocation_active(&state, operation, 3));

        owner.close();
        assert!(!invocation_active(&state, operation, 3));
        // The wait task has not run: this is still a live, delivered slot whose
        // host custody must be discarded rather than reassigned or forgotten.
        assert!(!state.operations[&operation].finished);
        assert!(
            state.operations[&operation]
                .callback_call
                .as_ref()
                .is_some_and(|call| call.host_owned && call.reply.is_some())
        );
        Ok(())
    }

    #[test]
    fn source_callback_waits_do_not_consume_request_capacity() -> Result<(), Failure> {
        let mut state = State::default();
        let (_operation, _cancel) = state.reserve(Target::EventSourceHeader {
            client: 1,
            owner: 2,
        })?;
        let mut cancellations = Vec::new();
        for _ in 0..super::super::super::MAX_HANDLES {
            cancellations.push(state.reserve(Target::Request(1))?.1);
        }
        assert_eq!(
            state
                .reserve(Target::Request(1))
                .err()
                .map(|failure| failure.kind),
            Some("capacity")
        );
        Ok(())
    }
}
