//! Optional source-lifetime hooks; existing EventSource and HTTP ABIs are unchanged.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

use super::{Error, Reply, event_source, submitted};
use crate::{
    error::Failure,
    operations::{self, Execution},
};

#[repr(C)]
#[derive(Default)]
pub(super) struct OpenReply {
    operation: u64,
    owner: u64,
    error: Error,
}

// SAFETY: Pointer-free independent capability negotiation.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_event_source_hooks_version() -> u64 {
    1
}

// SAFETY: Opening and its nested spans are readable during this call; reply is
// one aligned writable descriptor. Native work owns every input before return.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_hooks_open(
    value: *const event_source::Opening,
    count: u64,
    reply: *mut OpenReply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if !(1..=256).contains(&count) {
            return Err(Failure::new("invalid_header_hooks"));
        }
        // SAFETY: The caller lends the opening and its bounded nested spans.
        let opening = unsafe { event_source::opening(&*value)? };
        operations::event_source::open_with_hooks(opening, count as usize)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let value = open_reply(result);
    // SAFETY: The caller lends one aligned writable result.
    unsafe {
        ptr::write(reply, value);
    }
    1
}

// SAFETY: Scalar next/close/release select source-owned hook custody. The caller
// lends one aligned writable result; no pointer survives the call.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_hooks_operation(
    verb: u64,
    owner: u64,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| match verb {
        1 => operations::event_source::header_hooks::next(owner),
        2 => operations::event_source::header_hooks::close(owner),
        3 => operations::event_source::header_hooks::release(owner),
        _ => Err(Failure::new("invalid_command")),
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable result.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The result and reply are aligned writable output descriptors. The
// operation retains its source outcome until acknowledgement.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_hooks_failure(
    operation: u64,
    result: *mut u64,
    reply: *mut Reply,
) -> u64 {
    if result.is_null() || reply.is_null() {
        return 0;
    }
    let found = catch_unwind(AssertUnwindSafe(|| {
        operations::event_source::result(operation)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let (ticket, status) = match found {
        Ok(value) => (value.hook_operation.unwrap_or(0), Ok(Execution::Complete)),
        Err(error) => (0, Err(error)),
    };
    // SAFETY: Both disjoint outputs are writable for this call.
    unsafe {
        ptr::write(result, ticket);
        ptr::write(reply, submitted(status));
    }
    1
}

// SAFETY: Scalars identify one source invocation. The caller lends one aligned
// writable reply; the activity check takes no foreign data or custody.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_hooks_active(
    operation: u64,
    ticket: u64,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let found = catch_unwind(AssertUnwindSafe(|| {
        operations::event_source::header_hooks::active(operation, ticket)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let value = match found {
        Ok(active) => Reply {
            operation: u64::from(active),
            error: Error::default(),
        },
        Err(error) => Reply {
            error: error.into(),
            ..Reply::default()
        },
    };
    // SAFETY: The caller lends one aligned writable reply.
    unsafe {
        ptr::write(reply, value);
    }
    1
}

pub(super) fn open_reply(result: Result<(Execution, u64), Failure>) -> OpenReply {
    match result {
        Ok((Execution::Operation(operation), owner)) => OpenReply {
            operation,
            owner,
            error: Error::default(),
        },
        Ok(_) => OpenReply {
            error: Failure::new("internal").into(),
            ..OpenReply::default()
        },
        Err(error) => OpenReply {
            error: error.into(),
            ..OpenReply::default()
        },
    }
}
