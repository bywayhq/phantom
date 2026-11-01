//! Request-owned, one-at-a-time header calls to the owning JavaScript loop.

use std::{
    fmt, io,
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use napi::Result;
use phantom::{HeaderHookContext, HeaderHookError, RequestBuilder, RequestHeader};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{error::failure, request::MAXIMUM_HEADER_BYTES};

pub(crate) enum Edit {
    Append(RequestHeader),
    Set(RequestHeader),
    Remove(String),
}

pub(crate) struct Invocation {
    pub(crate) index: u32,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) headers: Vec<RequestHeader>,
}

type Reply = std::result::Result<Vec<Edit>, ()>;

struct PendingReply {
    index: u32,
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
    limits: OnceLock<(usize, usize)>,
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
        if !(1..=256).contains(&count) {
            return Err(failure(
                "InputLimit",
                "headerHooks require 1..256 callbacks",
            ));
        }

        let (sender, receiver) = mpsc::channel(1);
        Ok(Arc::new(Self {
            count,
            claimed: AtomicBool::new(false),
            closed: watch::channel(false).0,
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
            pending: Mutex::new(None),
            limits: OnceLock::new(),
        }))
    }

    pub(crate) fn claim(
        self: &Arc<Self>,
        mut builder: RequestBuilder,
        trailer_count: usize,
        trailer_bytes: usize,
    ) -> Result<(RequestBuilder, Lease)> {
        if *self.closed.borrow() || self.claimed.swap(true, Ordering::AcqRel) {
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

    async fn invoke(
        self: Arc<Self>,
        index: u32,
        context: &mut HeaderHookContext<'_>,
        trailer_count: usize,
        trailer_bytes: usize,
    ) -> std::result::Result<(), HeaderHookError> {
        let mut cancellation = InvocationGuard {
            owner: Arc::clone(&self),
            completed: false,
        };
        let (reply, received) = oneshot::channel();
        let invocation = Invocation {
            index,
            method: context.method().to_string(),
            uri: context.uri().to_string(),
            headers: context.headers().to_vec(),
        };
        self.sender
            .send(QueuedInvocation {
                invocation,
                reply: PendingReply {
                    index,
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

        // Prepared bodies can add fields after the public request-input bound.
        // Preserve those fields while bounding any growth caused by callbacks.
        let &(count_limit, bytes_limit) = self.limits.get_or_init(|| {
            (
                context
                    .headers()
                    .len()
                    .max(256_usize.saturating_sub(trailer_count)),
                header_bytes(context.headers())
                    .max(MAXIMUM_HEADER_BYTES.saturating_sub(trailer_bytes)),
            )
        });
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

    pub(crate) async fn next(&self) -> Result<Option<Invocation>> {
        let mut receiver = self.receiver.try_lock().map_err(|_| {
            failure(
                "InvalidOperation",
                "only one header hook read may be pending",
            )
        })?;
        if self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
        {
            return Err(failure(
                "InvalidOperation",
                "complete the current header hook first",
            ));
        }
        let invocation = tokio::select! {
            biased;
            () = self.closed() => return Ok(None),
            invocation = receiver.recv() => invocation,
        };
        let Some(queued) = invocation else {
            return Ok(None);
        };
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if *self.closed.borrow() {
            return Ok(None);
        }
        *pending = Some(queued.reply);
        Ok(Some(queued.invocation))
    }

    pub(crate) fn reply(&self, index: u32, edits: Reply) -> Result<()> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if *self.closed.borrow()
            || !pending
                .as_ref()
                .is_some_and(|reply| reply.index == index && !reply.sender.is_closed())
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

pub(crate) struct Lease(Arc<HeaderHooks>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct InvocationGuard {
    owner: Arc<HeaderHooks>,
    completed: bool,
}

impl Drop for InvocationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.close();
        }
    }
}
