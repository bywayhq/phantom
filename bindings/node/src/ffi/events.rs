//! Native SSE events decoded from an admitted response without host parsing.

use std::{fmt, sync::Arc};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, BigInt},
};
use napi_derive::napi;

use crate::{client::ClientState, response::Exchange};

/// One decoded event and the retry state observed at dispatch.
#[napi(object, object_from_js = false)]
pub struct SseEvent {
    /// Data fields joined by newlines, with invalid UTF-8 replaced.
    pub data: String,
    /// Event type, defaulting to message.
    pub event: String,
    /// Persistent event ID at dispatch.
    pub id: String,
    /// Latest retry delay in exact milliseconds; absent before a valid retry.
    pub retry_ms: Option<BigInt>,
}

/// Exclusive SSE consumption of an existing response body.
#[napi]
pub struct NativeEventStream {
    pub(super) exchange: Arc<Exchange>,
    pub(super) owner: Arc<ClientState>,
}

impl fmt::Debug for SseEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SseEvent").finish_non_exhaustive()
    }
}

impl fmt::Debug for NativeEventStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeEventStream")
            .finish_non_exhaustive()
    }
}

fn milliseconds(value: u64) -> BigInt {
    BigInt {
        sign_bit: false,
        words: vec![value],
    }
}

#[napi]
impl NativeEventStream {
    /// Latest persistent ID observed by a completed read, including EOF.
    #[napi(getter)]
    #[must_use]
    pub fn last_event_id(&self) -> String {
        self.exchange.event_state().last_event_id.clone()
    }

    /// Latest valid retry delay, preserving zero and all u64 values.
    #[napi(getter)]
    #[must_use]
    pub fn retry_ms(&self) -> Option<BigInt> {
        self.exchange.event_state().retry_ms.map(milliseconds)
    }

    /// Pulls one event without prefetching another one.
    #[napi]
    pub fn read(&self, env: Env) -> Result<AsyncBlock<Option<SseEvent>>> {
        let exchange = Arc::clone(&self.exchange);
        let owner = Arc::clone(&self.owner);
        AsyncBlockBuilder::new(async move {
            let _owner = owner;
            let event = Arc::clone(&exchange).next_event().await?;
            Ok(event.map(|event| {
                let (data, event, id) = event.into_parts();
                SseEvent {
                    data,
                    event,
                    id,
                    retry_ms: exchange.event_state().retry_ms.map(milliseconds),
                }
            }))
        })
        .build(&env)
    }

    /// Cancels the selected stream and wakes its pending read.
    #[napi]
    pub fn close(&self) {
        self.exchange.cancel();
    }
}

impl Drop for NativeEventStream {
    fn drop(&mut self) {
        self.exchange.cancel();
    }
}
