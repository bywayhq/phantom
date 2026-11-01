//! Optional logical observations on the existing typed callback rendezvous.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use super::{Arena, Error, OutputField, Reply, Request, Slice, Span, request, submitted};
use crate::{error::Failure, operations};

#[repr(C)]
struct Limits {
    line: u64,
    event: u64,
}
#[repr(C)]
struct Options {
    headers: u64,
    redirect: u64,
    phases: u64,
    limits: *const Limits,
}
#[repr(C)]
#[derive(Default)]
struct Invocation {
    phase: u64,
    cause_operation: u64,
    method: Slice,
    uri: Slice,
    status: u64,
    protocol: u64,
    effective_uri: Slice,
    redirects: u64,
    retries: u64,
    fields: u64,
    codings: u64,
    arena: u64,
    failure: Error,
    error: Error,
}

// SAFETY: Pointer-free capability negotiation.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_logical_hook_version() -> u64 {
    1
}

// SAFETY: Call-scoped descriptors and all nested spans are copied before admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_logical_hook_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    options: *const Options,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || options.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller lends aligned readable descriptors for this call.
        let options = unsafe { &*options };
        if options.headers > 256 || options.redirect > 1 || !(1..=7).contains(&options.phases) {
            return Err(Failure::new("invalid_request_hooks"));
        }
        // SAFETY: The optional limits pointer is null or one readable descriptor.
        let command = unsafe {
            if options.limits.is_null() {
                request(&*value)?
            } else {
                super::sse::request_with_limits(
                    &*value,
                    (*options.limits).line,
                    (*options.limits).event,
                )?
            }
        };
        // SAFETY: bytes validates and copies this call-scoped body.
        let body = unsafe {
            super::bytes(
                Span {
                    pointer: body,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute_with_logical_hooks(
            command,
            body,
            options.headers as usize,
            options.redirect != 0,
            options.phases as u8,
        )
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: reply is one aligned writable output.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The result, field descriptors and byte arena are aligned disjoint
// writable outputs. Only offsets into caller storage escape this function.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_logical_hook_copy(
    operation: u64,
    ticket: u64,
    result: *mut Invocation,
    output: *mut OutputField,
    capacity: usize,
    arena: *mut u8,
    length: usize,
) -> u64 {
    if result.is_null()
        || output.is_null()
        || arena.is_null()
        || capacity != operations::MAX_METADATA / size_of::<OutputField>()
        || length != operations::MAX_METADATA
    {
        return 0;
    }
    let value = catch_unwind(AssertUnwindSafe(|| {
        let mut value = Invocation::default();
        let copied = (|| {
            let call = operations::logical_hooks::invocation(operation, ticket)?;
            // SAFETY: Required capacities and non-null outputs were checked above.
            let (output, bytes) = unsafe {
                (
                    slice::from_raw_parts_mut(output, capacity),
                    slice::from_raw_parts_mut(arena, length),
                )
            };
            let mut arena = Arena { bytes, used: 0 };
            value.phase = call.phase;
            value.cause_operation = call.cause_operation;
            value.method = arena.put(call.method.as_bytes())?;
            value.uri = arena.put(call.uri.as_bytes())?;
            if let Some(response) = &call.response {
                value.status = u64::from(response.status);
                value.protocol = match response.protocol {
                    "h1" => 1,
                    "h2" => 2,
                    "h3" => 3,
                    _ => 0,
                };
                value.effective_uri = arena.put(response.effective_uri.as_bytes())?;
                value.redirects = response.redirects as u64;
                value.retries = response.retries as u64;
                value.fields = arena.fields(&response.headers, output)?;
                for (index, coding) in response.codings.iter().enumerate() {
                    let field = output
                        .get_mut(response.headers.len() + index)
                        .ok_or_else(|| Failure::new("metadata_limit"))?;
                    *field = OutputField {
                        name: arena.put(coding.as_bytes())?,
                        value: Slice::default(),
                        sensitive: 0,
                    };
                }
                value.codings = response.codings.len() as u64;
            }
            if let Some(failure) = &call.error {
                value.failure = failure.clone().into();
            }
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
    // SAFETY: result is one aligned writable descriptor.
    unsafe {
        ptr::write(result, value);
    }
    1
}

// SAFETY: Scalar reply borrows only one writable aligned result.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_logical_hook_reply(
    operation: u64,
    ticket: u64,
    outcome: u64,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if outcome > 2 {
            return Err(Failure::new("invalid_request_hook_reply"));
        }
        operations::logical_hooks::reply(operation, ticket, outcome)
            .map(|()| operations::Execution::Complete)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: reply is one aligned writable result.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The unchanged source opening is readable for this call; reply is
// aligned writable storage. Every span is copied before asynchronous admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_logical_hook_source_open(
    value: *const super::event_source::Opening,
    count: u64,
    phases: u64,
    reply: *mut super::event_source_header::OpenReply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if count > 256 || !(1..=7).contains(&phases) {
            return Err(Failure::new("invalid_request_hooks"));
        }
        // SAFETY: The caller lends one aligned opening and its nested spans.
        let opening = unsafe { super::event_source::opening(&*value)? };
        operations::event_source::open_with_logical_hooks(opening, count as usize, phases as u8)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: reply is one aligned writable output descriptor.
    unsafe {
        ptr::write(reply, super::event_source_header::open_reply(result));
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logical_descriptor_layout_matches_go() {
        assert_eq!(size_of::<Options>(), 32);
        assert_eq!(size_of::<Invocation>(), 504);
    }
}
