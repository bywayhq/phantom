//! The public futures are `Send`, so a caller can spawn them.
//!
//! Proving that is deep enough to reach the compiler's recursion limit
//! (rust-lang/rust#159228). The stable toolchain does not report it; the
//! gate's `nightly-recursion` step builds this module with the pinned nightly,
//! which does.

use phantom::RequestBuilder;
#[cfg(feature = "websocket")]
use phantom::WebSocketRequestBuilder;
#[cfg(feature = "sse")]
use phantom::{SseEventSource, SseRequestBuilder};

fn assert_send<T: Send>(_: &T) {}

#[allow(dead_code)]
fn request_futures_are_send(builder: RequestBuilder) {
    assert_send(&builder.send());
}

#[cfg(feature = "websocket")]
#[allow(dead_code)]
fn websocket_futures_are_send(builder: WebSocketRequestBuilder) {
    assert_send(&builder.connect());
}

#[cfg(feature = "sse")]
#[allow(dead_code)]
fn event_source_futures_are_send(builder: SseRequestBuilder, source: &mut SseEventSource) {
    assert_send(&builder.connect());
    assert_send(&source.next_event());
}
