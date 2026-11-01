//! Request-owned, one-at-a-time header and redirect calls to the JavaScript loop.

use std::{
    fmt, io,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use napi::Result;
use phantom::{
    HeaderHookContext, HeaderHookError, RedirectAttempt, RedirectCallbackError, RedirectDecision,
    RequestBuilder, RequestHeader, SseRequestBuilder,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{error::failure, request::MAXIMUM_HEADER_BYTES};

pub(crate) enum Edit {
    Append(RequestHeader),
    Set(RequestHeader),
    Remove(String),
}

pub(crate) struct Invocation {
    pub(crate) serial: Option<u64>,
    pub(crate) index: u32,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) headers: Vec<RequestHeader>,
    pub(crate) redirect: Option<RedirectInvocation>,
}

pub(crate) struct RedirectInvocation {
    pub(crate) from_url: String,
    pub(crate) to_url: String,
    pub(crate) status: u16,
    pub(crate) method: String,
    pub(crate) next_method: String,
    pub(crate) hop: usize,
}

pub(crate) enum CallbackReply {
    Header(Vec<Edit>),
    Redirect(RedirectDecision),
}

type Reply = std::result::Result<CallbackReply, ()>;

#[derive(PartialEq, Eq)]
pub(crate) enum ReplyKey {
    Header(u32),
    Source(u64),
    Redirect(usize),
}

struct PendingReply {
    key: ReplyKey,
    sender: oneshot::Sender<Reply>,
}

struct QueuedInvocation {
    invocation: Invocation,
    reply: PendingReply,
}

pub(crate) struct HeaderHooks {
    count: u32,
    claimed: AtomicBool,
    closed: watch::Sender<bool>,
    sender: mpsc::Sender<QueuedInvocation>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<QueuedInvocation>>,
    pending: Mutex<Option<PendingReply>>,
    limits: Mutex<Option<(usize, usize)>>,
    source: bool,
    serial: AtomicU64,
    cancelled: watch::Sender<u64>,
}

impl fmt::Debug for HeaderHooks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderHooks")
            .finish_non_exhaustive()
    }
}

impl HeaderHooks {
    pub(crate) fn new(count: u32) -> Result<Arc<Self>> {
        Self::with_lifetime(count, false)
    }

    pub(crate) fn with_lifetime(count: u32, source: bool) -> Result<Arc<Self>> {
        if count > 256 {
            return Err(failure("InputLimit", "headerHooks exceed 256 callbacks"));
        }

        let (sender, receiver) = mpsc::channel(1);
        Ok(Arc::new(Self {
            count,
            claimed: AtomicBool::new(false),
            closed: watch::channel(false).0,
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
            pending: Mutex::new(None),
            limits: Mutex::new(None),
            source,
            serial: AtomicU64::new(0),
            cancelled: watch::channel(0).0,
        }))
    }

    pub(crate) fn claim(
        self: &Arc<Self>,
        mut builder: RequestBuilder,
        trailer_count: usize,
        trailer_bytes: usize,
    ) -> Result<(RequestBuilder, Lease)> {
        if self.source || *self.closed.borrow() || self.claimed.swap(true, Ordering::AcqRel) {
            return Err(failure(
                "InvalidOperation",
                "header hooks belong to one request",
            ));
        }

        for index in 0..self.count {
            let owner = Arc::clone(self);
            builder = builder.async_header_hook(move |context| {
                let owner = Arc::clone(&owner);
                Box::pin(async move {
                    owner
                        .invoke(index, context, trailer_count, trailer_bytes)
                        .await
                })
            });
        }
        Ok((builder, Lease(Arc::clone(self))))
    }

    pub(crate) fn claim_source(
        self: &Arc<Self>,
        mut builder: SseRequestBuilder,
    ) -> Result<(SseRequestBuilder, Lease)> {
        if !self.source || *self.closed.borrow() || self.claimed.swap(true, Ordering::AcqRel) {
            return Err(failure(
                "InvalidOperation",
                "header hooks belong to one event source",
            ));
        }
        for index in 0..self.count {
            let owner = Arc::clone(self);
            builder = builder.async_header_hook(move |context| {
                let owner = Arc::clone(&owner);
                Box::pin(async move { owner.invoke(index, context, 0, 0).await })
            });
        }
        Ok((builder, Lease(Arc::clone(self))))
    }

    async fn invoke(
        self: Arc<Self>,
        index: u32,
        context: &mut HeaderHookContext<'_>,
        trailer_count: usize,
        trailer_bytes: usize,
    ) -> std::result::Result<(), HeaderHookError> {
        let serial = if self.source {
            Some(
                self.serial
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| hook_error())?
                    + 1,
            )
        } else {
            None
        };
        let mut cancellation = InvocationGuard {
            owner: Arc::clone(&self),
            serial,
            completed: false,
        };
        let limits = {
            let mut limits = self.limits.lock().unwrap_or_else(PoisonError::into_inner);
            if self.source && index == 0 {
                *limits = None;
            }
            *limits.get_or_insert_with(|| {
                (
                    context
                        .headers()
                        .len()
                        .max(256_usize.saturating_sub(trailer_count)),
                    header_bytes(context.headers())
                        .max(MAXIMUM_HEADER_BYTES.saturating_sub(trailer_bytes)),
                )
            })
        };
        let (reply, received) = oneshot::channel();
        let invocation = Invocation {
            serial,
            index,
            method: context.method().to_string(),
            uri: context.uri().to_string(),
            headers: context.headers().to_vec(),
            redirect: None,
        };
        self.sender
            .send(QueuedInvocation {
                invocation,
                reply: PendingReply {
                    key: serial.map_or(ReplyKey::Header(index), ReplyKey::Source),
                    sender: reply,
                },
            })
            .await
            .map_err(|_| hook_error())?;
        let edits = tokio::select! {
            biased;
            () = self.closed() => return Err(hook_error()),
            reply = received => reply.map_err(|_| hook_error())?.map_err(|()| hook_error())?,
        };
        let CallbackReply::Header(edits) = edits else {
            return Err(hook_error());
        };

        // Prepared bodies can add fields after the public request-input bound.
        // Preserve those fields while bounding any growth caused by callbacks.
        let (count_limit, bytes_limit) = limits;
        for edit in edits {
            match edit {
                Edit::Append(header) => context.append(header)?,
                Edit::Set(header) => context.set(header)?,
                Edit::Remove(name) => context.remove(&name)?,
            }
            if context.headers().len() > count_limit
                || header_bytes(context.headers()) > bytes_limit
            {
                return Err(HeaderHookError::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "header hook fields exceed the request input limit",
                )));
            }
        }
        cancellation.completed = true;
        Ok(())
    }

    pub(crate) async fn redirect(
        self: Arc<Self>,
        attempt: &RedirectAttempt<'_>,
    ) -> std::result::Result<RedirectDecision, RedirectCallbackError> {
        let bytes = attempt
            .from_url()
            .as_str()
            .len()
            .saturating_add(attempt.to_url().as_str().len())
            .saturating_add(attempt.method().as_str().len())
            .saturating_add(attempt.next_method().as_str().len());
        if bytes > 256 * 1024 {
            return Err(redirect_error());
        }
        let mut cancellation = InvocationGuard {
            owner: Arc::clone(&self),
            serial: None,
            completed: false,
        };
        let (reply, received) = oneshot::channel();
        let invocation = Invocation {
            serial: None,
            index: 0,
            method: String::new(),
            uri: String::new(),
            headers: Vec::new(),
            redirect: Some(RedirectInvocation {
                from_url: attempt.from_url().to_string(),
                to_url: attempt.to_url().to_string(),
                status: attempt.status().as_u16(),
                method: attempt.method().to_string(),
                next_method: attempt.next_method().to_string(),
                hop: attempt.hop(),
            }),
        };
        self.sender
            .send(QueuedInvocation {
                invocation,
                reply: PendingReply {
                    key: ReplyKey::Redirect(attempt.hop()),
                    sender: reply,
                },
            })
            .await
            .map_err(|_| redirect_error())?;
        let reply = tokio::select! {
            biased;
            () = self.closed() => return Err(redirect_error()),
            reply = received => reply.map_err(|_| redirect_error())?.map_err(|()| redirect_error())?,
        };
        let CallbackReply::Redirect(decision) = reply else {
            return Err(redirect_error());
        };
        if *self.closed.borrow() {
            return Err(redirect_error());
        }
        cancellation.completed = true;
        Ok(decision)
    }

    pub(crate) async fn next(&self) -> Result<Option<Invocation>> {
        let mut receiver = self.receiver.try_lock().map_err(|_| {
            failure(
                "InvalidOperation",
                "only one header hook read may be pending",
            )
        })?;
        {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if pending
                .as_ref()
                .is_some_and(|reply| reply.sender.is_closed())
            {
                pending.take();
            }
            if pending.is_some() {
                return Err(failure(
                    "InvalidOperation",
                    "complete the current header hook first",
                ));
            }
        }
        loop {
            let invocation = tokio::select! {
                biased;
                () = self.closed() => return Ok(None),
                invocation = receiver.recv() => invocation,
            };
            let Some(queued) = invocation else {
                return Ok(None);
            };
            // A timed-out GET can leave an undelivered item in the bounded channel.
            if queued.reply.sender.is_closed() {
                continue;
            }
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if *self.closed.borrow() {
                return Ok(None);
            }
            if queued.reply.sender.is_closed() {
                continue;
            }
            *pending = Some(queued.reply);
            return Ok(Some(queued.invocation));
        }
    }

    pub(crate) fn reply(&self, key: ReplyKey, edits: Reply) -> Result<()> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if *self.closed.borrow()
            || !pending
                .as_ref()
                .is_some_and(|reply| reply.key == key && !reply.sender.is_closed())
        {
            return Err(failure(
                "InvalidOperation",
                "header hook invocation is no longer active",
            ));
        }
        let Some(reply) = pending.take() else {
            return Err(failure(
                "InvalidOperation",
                "header hook invocation is unavailable",
            ));
        };
        drop(pending);
        reply.sender.send(edits).map_err(|_| {
            failure(
                "InvalidOperation",
                "header hook invocation is no longer active",
            )
        })
    }

    pub(crate) fn close(&self) {
        self.closed.send_replace(true);
        drop(
            self.pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
    }

    pub(crate) fn active(&self, serial: u64) -> bool {
        !*self.closed.borrow()
            && self
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(|reply| {
                    reply.key == ReplyKey::Source(serial) && !reply.sender.is_closed()
                })
    }

    fn cancel(&self, serial: u64) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending
            .as_ref()
            .is_some_and(|reply| reply.key == ReplyKey::Source(serial))
        {
            pending.take();
        }
        drop(pending);
        self.cancelled.send_if_modified(|current| {
            if serial > *current {
                *current = serial;
                true
            } else {
                false
            }
        });
    }

    pub(crate) async fn next_cancelled(&self, after: u64) -> Option<u64> {
        let mut cancelled = self.cancelled.subscribe();
        loop {
            let serial = *cancelled.borrow_and_update();
            if *self.closed.borrow() {
                return None;
            }
            if serial > after {
                return Some(serial);
            }
            tokio::select! {
                () = self.closed() => return None,
                changed = cancelled.changed() => { if changed.is_err() { return None; } }
            }
        }
    }

    pub(crate) async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        if !*closed.borrow_and_update() {
            // The owner holds the sender throughout this wait.
            let _ = closed.wait_for(|closed| *closed).await;
        }
    }
}

fn header_bytes(headers: &[RequestHeader]) -> usize {
    headers.iter().fold(0, |total, header| {
        total
            .saturating_add(header.name().len())
            .saturating_add(header.value().len())
    })
}

fn hook_error() -> HeaderHookError {
    HeaderHookError::new(io::Error::other("caller header hook failed"))
}

pub(crate) fn redirect_error() -> RedirectCallbackError {
    RedirectCallbackError::new(io::Error::other("caller redirect callback failed"))
}

pub(crate) struct Lease(Arc<HeaderHooks>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct InvocationGuard {
    owner: Arc<HeaderHooks>,
    serial: Option<u64>,
    completed: bool,
}

impl Drop for InvocationGuard {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(serial) = self.serial {
                self.owner.cancel(serial);
            } else {
                self.owner.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_replies_require_the_active_kind_and_hop() -> Result<()> {
        let owner = HeaderHooks::new(0)?;
        let (sender, mut received) = oneshot::channel();
        *owner.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(PendingReply {
            key: ReplyKey::Redirect(2),
            sender,
        });
        assert!(owner.reply(ReplyKey::Header(2), Err(())).is_err());
        assert!(owner.reply(ReplyKey::Redirect(1), Err(())).is_err());
        owner.reply(
            ReplyKey::Redirect(2),
            Ok(CallbackReply::Redirect(RedirectDecision::Stop)),
        )?;
        assert!(matches!(
            received.try_recv(),
            Ok(Ok(CallbackReply::Redirect(RedirectDecision::Stop)))
        ));
        assert!(owner.reply(ReplyKey::Redirect(2), Err(())).is_err());
        Ok(())
    }

    #[test]
    fn closing_discards_a_pending_redirect_reply() -> Result<()> {
        let owner = HeaderHooks::new(0)?;
        let (sender, mut received) = oneshot::channel();
        *owner.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(PendingReply {
            key: ReplyKey::Redirect(1),
            sender,
        });
        owner.close();
        assert!(owner.reply(ReplyKey::Redirect(1), Err(())).is_err());
        assert!(matches!(
            received.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn cancelling_one_source_get_rejects_stale_replies_without_closing_the_next() -> Result<()> {
        let owner = HeaderHooks::with_lifetime(1, true)?;
        let (sender, mut first) = oneshot::channel();
        *owner.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(PendingReply {
            key: ReplyKey::Source(1),
            sender,
        });
        drop(InvocationGuard {
            owner: Arc::clone(&owner),
            serial: Some(1),
            completed: false,
        });
        assert!(!*owner.closed.borrow());
        assert_eq!(*owner.cancelled.borrow(), 1);
        assert!(matches!(
            first.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let (sender, mut second) = oneshot::channel();
        *owner.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(PendingReply {
            key: ReplyKey::Source(2),
            sender,
        });
        owner.cancel(1);
        assert!(owner.reply(ReplyKey::Source(1), Err(())).is_err());
        assert!(owner.reply(ReplyKey::Header(0), Err(())).is_err());
        assert!(owner.active(2));
        owner.reply(ReplyKey::Source(2), Ok(CallbackReply::Header(Vec::new())))?;
        assert!(second.try_recv().is_ok());
        Ok(())
    }
}
