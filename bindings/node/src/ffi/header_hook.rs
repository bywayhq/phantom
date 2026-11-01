//! Bounded owned request-call metadata and synchronous host replies.

use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, BigInt, Buffer},
};
use napi_derive::napi;

use super::{
    buffer::copy_buffer,
    options::{WireHeader, positive_count},
};
use crate::{
    error::failure,
    header_hook::{CallbackReply, Edit, HeaderHooks, ReplyKey},
    request::MAXIMUM_HEADER_BYTES,
    response::Exchange,
};

/// Private snapshot for one awaited callback; no live Rust borrow escapes.
#[napi(object, object_from_js = false)]
pub struct HeaderHookInvocation {
    /// Position in the request's callback list.
    pub index: u32,
    /// Prepared HTTP method.
    pub method: String,
    /// Prepared request URI.
    pub uri: String,
    /// Ordered caller fields, including duplicate names.
    pub headers: Vec<WireHeader>,
    /// Present only for a redirect decision invocation.
    pub redirect: Option<RedirectHookInvocation>,
}

/// Immutable owned redirect metadata; URLs are omitted from debug output.
#[napi(object, object_from_js = false)]
pub struct RedirectHookInvocation {
    /// Resolved source URL.
    pub from_url: String,
    /// Resolved destination URL.
    pub to_url: String,
    /// Redirect response status.
    pub status: u16,
    /// Current method.
    pub method: String,
    /// Method after redirect rewriting.
    pub next_method: String,
    /// One-based hop number.
    pub hop: BigInt,
}

impl fmt::Debug for RedirectHookInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectHookInvocation")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for HeaderHookInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderHookInvocation")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Private ordered edit, validated and copied before returning to JavaScript.
#[napi(object)]
pub struct HeaderHookEdit {
    /// Append, set or remove.
    pub action: String,
    /// HTTP field name.
    pub name: String,
    /// Owned bytes for append or set; absent for remove.
    pub value: Option<Buffer>,
    /// Whether compression must treat the field as sensitive.
    pub sensitive: Option<bool>,
}

impl fmt::Debug for HeaderHookEdit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderHookEdit")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

/// One logical request's callback handoff and producer admission custody.
#[derive(Debug)]
#[napi]
pub struct NativeHeaderHooks {
    pub(super) state: Arc<HeaderHooks>,
    pub(super) owner: Mutex<Option<Arc<Exchange>>>,
}

#[napi]
impl NativeHeaderHooks {
    /// Creates one bounded request-owned callback handoff.
    #[napi(constructor)]
    pub fn new(count: u32) -> Result<Self> {
        Ok(Self {
            state: HeaderHooks::new(count)?,
            owner: Mutex::new(None),
        })
    }

    /// Waits for the next callback, or returns none when the request ends.
    #[napi]
    pub fn next(&self, env: Env) -> Result<AsyncBlock<Option<HeaderHookInvocation>>> {
        let state = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            Ok(state.next().await?.map(|invocation| HeaderHookInvocation {
                index: invocation.index,
                method: invocation.method,
                uri: invocation.uri,
                headers: invocation
                    .headers
                    .into_iter()
                    .map(|header| WireHeader {
                        name: header.name().to_owned(),
                        value: header.value().to_vec().into(),
                        sensitive: Some(header.is_sensitive()),
                    })
                    .collect(),
                redirect: invocation.redirect.map(|redirect| RedirectHookInvocation {
                    from_url: redirect.from_url,
                    to_url: redirect.to_url,
                    status: redirect.status,
                    method: redirect.method,
                    next_method: redirect.next_method,
                    hop: BigInt::from(redirect.hop as u64),
                }),
            }))
        })
        .build(&env)
    }

    /// Copies and validates the current callback's ordered edits.
    #[napi]
    pub fn complete(&self, env: Env, index: u32, edits: Vec<HeaderHookEdit>) -> Result<()> {
        if edits.len() > 256 {
            return Err(failure("InputLimit", "a header hook exceeds 256 edits"));
        }
        let mut remaining = MAXIMUM_HEADER_BYTES;
        let mut owned = Vec::with_capacity(edits.len());
        for edit in edits {
            remaining = remaining
                .checked_sub(edit.name.len())
                .ok_or_else(|| failure("InputLimit", "header hook edits exceed 65536 bytes"))?;
            if edit.action == "remove" && edit.value.is_none() && edit.sensitive.is_none() {
                owned.push(Edit::Remove(edit.name));
                continue;
            }
            if edit.action != "append" && edit.action != "set" {
                return Err(failure(
                    "InvalidArgument",
                    "choose append, set or remove header edits",
                ));
            }
            let value = edit
                .value
                .ok_or_else(|| failure("InvalidArgument", "header edits require a value"))?;
            let value = copy_buffer(&env, value, remaining)?;
            remaining -= value.len();
            let header = phantom::RequestHeader::new(edit.name, value);
            let header = if edit.sensitive.unwrap_or(false) {
                header.sensitive()
            } else {
                header
            };
            owned.push(if edit.action == "append" {
                Edit::Append(header)
            } else {
                Edit::Set(header)
            });
        }
        self.state
            .reply(ReplyKey::Header(index), Ok(CallbackReply::Header(owned)))
    }

    /// Reports a host exception without copying it through native storage.
    #[napi]
    pub fn fail(&self, index: u32) -> Result<()> {
        self.state.reply(ReplyKey::Header(index), Err(()))
    }

    /// Completes the current redirect without copying any host exception.
    #[napi]
    pub fn complete_redirect(&self, hop: BigInt, decision: String) -> Result<()> {
        let decision = match decision.as_str() {
            "follow" => phantom::RedirectDecision::Follow,
            "stop" => phantom::RedirectDecision::Stop,
            "reject" => phantom::RedirectDecision::Reject,
            _ => return Err(failure("InvalidArgument", "choose follow, stop or reject")),
        };
        self.state.reply(
            ReplyKey::Redirect(positive_count(hop)?.get()),
            Ok(CallbackReply::Redirect(decision)),
        )
    }

    /// Reports a redirect callback failure while the facade retains its cause.
    #[napi]
    pub fn fail_redirect(&self, hop: BigInt) -> Result<()> {
        self.state
            .reply(ReplyKey::Redirect(positive_count(hop)?.get()), Err(()))
    }

    /// Resolves when the request no longer accepts callbacks.
    #[napi]
    pub fn closed(&self, env: Env) -> Result<AsyncBlock<()>> {
        let state = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            state.closed().await;
            Ok(())
        })
        .build(&env)
    }

    /// Cancels further callback delivery.
    #[napi]
    pub fn stop(&self) {
        self.state.close();
    }

    /// Releases admission after the actual host callback has returned.
    #[napi]
    pub fn settled(&self) {
        if let Some(owner) = self
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            owner.header_hooks_settled();
        }
    }
}

impl Drop for NativeHeaderHooks {
    fn drop(&mut self) {
        self.state.close();
        self.settled();
    }
}
