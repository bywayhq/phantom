//! Optional SSE ABI 1. ABI 2 request and completion layouts remain unchanged.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

use super::{Error, Reply, Request, Span, bytes, request, submitted};
use crate::{
    error::Failure,
    operations::{self, Command, sse},
};

#[repr(C)]
#[derive(Default)]
pub(super) struct Event {
    data_length: u64,
    type_length: u64,
    id_length: u64,
    retry_milliseconds: u64,
    flags: u64,
    error: Error,
    cause: Error,
}

impl Event {
    pub(super) fn from_failure(error: Failure) -> Self {
        Self {
            error: error.into(),
            ..Self::default()
        }
    }
}

// SAFETY: This uniquely named, pointer-free symbol negotiates the separate SSE
// contract before any of its pointer-bearing entry points can be called.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_sse_version() -> u64 {
    1
}

// SAFETY: The caller lends the existing aligned ABI 2 request, bounded body and
// writable reply for this call. Every nested input is copied before admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_sse_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    line: u64,
    event: u64,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let limits = sse::Limits {
            line: usize::try_from(line).map_err(|_| Failure::new("invalid_sse_limits"))?,
            event: usize::try_from(event).map_err(|_| Failure::new("invalid_sse_limits"))?,
        };
        limits.core()?;
        // SAFETY: The caller lends one aligned request; nested spans are checked
        // and copied by the same decoder used by ordinary requests.
        let mut command = unsafe { request(&*value)? };
        if let Command::Request { events, .. } = &mut command {
            *events = Some(limits);
        }
        // SAFETY: bytes checks null/length under the caller's readable contract.
        let body = unsafe {
            bytes(
                Span {
                    pointer: body,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute(command, body)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: One aligned writable reply is borrowed for this call.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Reply lends one aligned writable descriptor for this entire call. The
// operation owns every value used after it returns; no foreign pointer remains.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_sse_next(body: u64, reply: *mut Reply) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        operations::execute(Command::NextEvent { body }, &[])
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller provides one aligned writable reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The caller lends a writable Event and a disjoint writable byte buffer
// for this synchronous copy. Zero capacity probes exact lengths. The operation
// owns its result until ack/cancel; a cloned Arc keeps it alive during this call.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_sse_result(
    operation: u64,
    event: *mut Event,
    output: *mut u8,
    capacity: usize,
) -> u64 {
    if event.is_null() || (output.is_null() && capacity != 0) || capacity > sse::MAX_RESULT {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let read = operations::event_result(operation)?;
        // SAFETY: The entry point checks capacity and the caller lends output.
        unsafe { project(&read, output, capacity) }
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let result = result.unwrap_or_else(|error| Event {
        error: error.into(),
        ..Event::default()
    });
    // SAFETY: The caller lends one aligned writable Event for the complete call.
    unsafe {
        ptr::write(event, result);
    }
    1
}

// SAFETY: output is writable for capacity bytes and disjoint from read.
pub(super) unsafe fn project(
    read: &sse::Read,
    output: *mut u8,
    capacity: usize,
) -> Result<Event, Failure> {
    let data = read.event.as_ref().map_or("", phantom::SseEvent::data);
    let kind = read.event.as_ref().map_or("", phantom::SseEvent::event);
    let id = read.id();
    let length = data
        .len()
        .checked_add(kind.len())
        .and_then(|length| length.checked_add(id.len()))
        .filter(|length| *length <= sse::MAX_RESULT)
        .ok_or_else(|| Failure::new("sse_result_limit"))?;
    if capacity != 0 && capacity < length {
        return Err(Failure::new("sse_result_capacity"));
    }
    let retry = read
        .retry
        .map(|value| u64::try_from(value.as_millis()))
        .transpose()
        .map_err(|_| Failure::new("sse_retry_range"))?;
    let result = Event {
        data_length: data.len() as u64,
        type_length: kind.len() as u64,
        id_length: id.len() as u64,
        retry_milliseconds: retry.unwrap_or_default(),
        flags: u64::from(read.event.is_none()) | (u64::from(retry.is_some()) << 1),
        error: read.error.clone().map_or_else(Error::default, Error::from),
        cause: read.cause.clone().map_or_else(Error::default, Error::from),
    };
    if capacity != 0 {
        // SAFETY: Total length fits the checked output capacity. These
        // slices address Rust-owned strings and do not overlap caller output.
        unsafe {
            super::super::output(output, data.as_bytes());
            super::super::output(output.add(data.len()), kind.as_bytes());
            super::super::output(output.add(data.len() + kind.len()), id.as_bytes());
        }
    }
    Ok::<_, Failure>(result)
}
