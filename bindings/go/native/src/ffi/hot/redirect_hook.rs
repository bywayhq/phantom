//! Optional redirect callbacks sharing the request-owned header rendezvous.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use super::{Arena, Error, Reply, Request, Slice, Span, request, submitted};
use crate::{error::Failure, operations};

#[repr(C)]
#[derive(Default)]
struct Invocation {
    from: Slice,
    to: Slice,
    method: Slice,
    next_method: Slice,
    status: u64,
    hop: u64,
    arena: u64,
    error: Error,
}

#[repr(C)]
struct SseLimits {
    line: u64,
    event: u64,
}

// SAFETY: Pointer-free capability negotiation.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_redirect_hook_version() -> u64 {
    1
}

// SAFETY: All descriptors, optional limits and nested request/body spans are
// readable call-scoped storage. They are bounded and copied before admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_redirect_hook_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    count: u64,
    limits: *const SseLimits,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let count = usize::try_from(count).map_err(|_| Failure::new("invalid_header_hooks"))?;
        if count > 256 {
            return Err(Failure::new("invalid_header_hooks"));
        }
        // SAFETY: value is readable and aligned for this call. Optional limits
        // is either null or one readable aligned descriptor supplied by Go.
        let command = unsafe {
            if limits.is_null() {
                request(&*value)?
            } else {
                super::sse::request_with_limits(&*value, (*limits).line, (*limits).event)?
            }
        };
        // SAFETY: bytes validates and copies the borrowed bounded body span.
        let bytes = unsafe {
            super::bytes(
                Span {
                    pointer: body,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute_with_callbacks(command, bytes, count, true)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: reply is one aligned writable output descriptor.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: result and arena are writable, aligned and disjoint for this call.
// Only caller-owned arena offsets escape; no Rust or Go pointer is retained.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_redirect_hook_copy(
    operation: u64,
    ticket: u64,
    result: *mut Invocation,
    arena: *mut u8,
    length: usize,
) -> u64 {
    if result.is_null() || arena.is_null() || length != operations::MAX_METADATA {
        return 0;
    }
    let value = catch_unwind(AssertUnwindSafe(|| {
        let mut value = Invocation::default();
        let copied = (|| {
            let call = operations::redirect_invocation(operation, ticket)?;
            // SAFETY: the caller lends length writable bytes, checked above.
            let bytes = unsafe { slice::from_raw_parts_mut(arena, length) };
            let mut arena = Arena { bytes, used: 0 };
            value.from = arena.put(call.from.as_bytes())?;
            value.to = arena.put(call.to.as_bytes())?;
            value.method = arena.put(call.method.as_bytes())?;
            value.next_method = arena.put(call.next_method.as_bytes())?;
            value.status = u64::from(call.status);
            value.hop = call.hop as u64;
            value.arena = arena.used as u64;
            Ok::<_, Failure>(())
        })();
        if let Err(error) = copied {
            value.error = error.into();
        }
        value
    }));
    let Ok(value) = value else {
        return 0;
    };
    // SAFETY: result is one aligned writable output descriptor.
    unsafe {
        ptr::write(result, value);
    }
    1
}

// SAFETY: Scalar replies borrow only one aligned writable output descriptor.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_redirect_hook_reply(
    operation: u64,
    ticket: u64,
    outcome: u64,
    decision: u64,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let decision = match (outcome, decision) {
            (0, 1) => phantom::RedirectDecision::Follow,
            (0, 2) => phantom::RedirectDecision::Stop,
            (0, 3) => phantom::RedirectDecision::Reject,
            (1 | 2, 0) => phantom::RedirectDecision::Reject,
            _ => return Err(Failure::new("invalid_redirect_decision")),
        };
        operations::reply_redirect_hook(operation, ticket, outcome, decision)
            .map(|()| operations::Execution::Complete)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: reply is one aligned writable output descriptor.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}
