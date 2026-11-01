//! Optional header-hook ABI. All borrowed edit data is copied synchronously.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use super::{
    Arena, Error, Field, OutputField, Reply, Request, Slice, Span, fields, request, submitted,
};
use crate::{error::Failure, header_hook::Edit, operations};

#[repr(C)]
#[derive(Default)]
struct Invocation {
    index: u64,
    method: Slice,
    uri: Slice,
    fields: u64,
    arena: u64,
    error: Error,
}

#[repr(C)]
struct EditDescriptor {
    kind: u64,
    field: Field,
}

// SAFETY: Pointer-free capability negotiation.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_header_hook_version() -> u64 {
    1
}

// SAFETY: The request, body and reply follow the ordinary request ABI. Every
// nested span is copied during this call, before runtime admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_header_hook_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    count: u64,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let count = usize::try_from(count).map_err(|_| Failure::new("invalid_header_hooks"))?;
        if count == 0 || count > 256 {
            return Err(Failure::new("invalid_header_hooks"));
        }
        // SAFETY: The caller lends one aligned Request and bounded body storage.
        let (command, bytes) = unsafe {
            (
                request(&*value)?,
                super::bytes(
                    Span {
                        pointer: body,
                        length,
                    },
                    operations::MAX_UPLOAD,
                )?,
            )
        };
        operations::execute_with_header_hooks(command, bytes, count)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The caller lends the existing request, bounded body and writable reply
// during this call. Nested input spans are copied before asynchronous admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_header_hook_sse_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    line: u64,
    event: u64,
    count: u64,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let count = usize::try_from(count).map_err(|_| Failure::new("invalid_header_hooks"))?;
        if count == 0 || count > 256 {
            return Err(Failure::new("invalid_header_hooks"));
        }
        // SAFETY: The caller lends one aligned request and its readable spans.
        let command = unsafe { super::sse::request_with_limits(&*value, line, event)? };
        // SAFETY: bytes bounds the body borrowed for this synchronous call.
        let body = unsafe {
            super::bytes(
                Span {
                    pointer: body,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute_with_header_hooks(command, body, count)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Output descriptors and arena are aligned, writable, disjoint and live
// for this entire call. Only offsets into that caller-owned arena are returned.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_header_hook_copy(
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
            let call = operations::header_invocation(operation, ticket)?;
            // SAFETY: Required capacities and null pointers were checked above.
            let (output, bytes) = unsafe {
                (
                    slice::from_raw_parts_mut(output, capacity),
                    slice::from_raw_parts_mut(arena, length),
                )
            };
            let mut arena = Arena { bytes, used: 0 };
            value.index = call.index as u64;
            value.method = arena.put(call.method.as_bytes())?;
            value.uri = arena.put(call.uri.as_bytes())?;
            value.fields = arena.fields(&call.headers, output)?;
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
    // SAFETY: The caller lends one aligned writable Invocation.
    unsafe {
        ptr::write(result, value);
    }
    1
}

// SAFETY: Edit descriptors and their spans are aligned readable call-scoped
// storage. The reply is aligned and writable. No input pointer is retained.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_header_hook_reply(
    operation: u64,
    ticket: u64,
    outcome: u64,
    edits: *const EditDescriptor,
    count: usize,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if outcome > 2
            || count > 256
            || (outcome != 0 && count != 0)
            || (count != 0 && edits.is_null())
        {
            return Err(Failure::new("invalid_header_edits"));
        }
        let values = if count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller lends count bounded aligned edit descriptors.
            unsafe { slice::from_raw_parts(edits, count) }
        };
        let mut remaining = operations::MAX_COMMAND;
        let mut copied = Vec::with_capacity(values.len());
        for value in values {
            // SAFETY: fields copies one field and checks all nested span bounds.
            let field = unsafe { fields(&value.field, 1, &mut remaining)? }
                .pop()
                .ok_or_else(|| Failure::new("invalid_header_edits"))?;
            copied.push(match value.kind {
                1 => Edit::Append(field),
                2 => Edit::Set(field),
                3 if field.value.is_empty() && !field.sensitive => Edit::Remove(field.name),
                _ => return Err(Failure::new("invalid_header_edits")),
            });
        }
        operations::reply_header_hook(operation, ticket, outcome, copied)
            .map(|()| operations::Execution::Complete)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Cancellation takes scalar handles and one aligned writable reply.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_header_hook_cancel(operation: u64, reply: *mut Reply) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        operations::cancel_header_request(operation).map(|()| operations::Execution::Complete)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}
