//! Private C ABI boundary. Callers supply valid, nonoverlapping byte buffers
//! for the full call. No Go pointer is stored in the runtime or a task.
//! Only the completion pump blocks here; worker tasks never receive its buffers.
//!
//! The two symbols use the target C ABI and usize/size_t widths. Clients pass
//! only bytes and monotonic integer handles; no foreign callback or allocation
//! ownership crosses this module. Lengths are bounded before slices are formed.
//! Metadata and body copies finish before returning, including the blocking
//! wait. Empty inputs may be null; outputs must be valid writable buffers.
//! Rust unwinding is contained here. State poisoning completes pending operation
//! IDs with terminal errors and rejects new work; it never yields an anonymous
//! completion. The shared runtime and loaded library live for the process.

use crate::{error::Failure, operations};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

unsafe fn input<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
    if length == 0 {
        return &[];
    }
    // SAFETY: The ABI caller guarantees readable storage for length bytes;
    // entry points reject null pointers and bound lengths before calling this.
    unsafe { slice::from_raw_parts(pointer, length) }
}

unsafe fn output(pointer: *mut u8, bytes: &[u8]) {
    // SAFETY: The ABI caller guarantees writable, nonoverlapping output storage.
    // Entry points verify its capacity before copying; no output escapes the call.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len());
    }
}

// SAFETY: This uniquely prefixed symbol implements the documented pointer/length
// C ABI. It catches Rust unwinding before it can cross the foreign call boundary.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn phantom_go_dispatch(
    command: *const u8,
    command_len: usize,
    body: *const u8,
    body_len: usize,
    result: *mut u8,
    result_capacity: usize,
) -> usize {
    if result.is_null() || result_capacity < operations::MAX_METADATA {
        return 0;
    }
    let bytes = catch_unwind(AssertUnwindSafe(|| {
        if command_len > operations::MAX_COMMAND
            || body_len > operations::MAX_UPLOAD
            || (command.is_null() && command_len != 0)
            || (body.is_null() && body_len != 0)
        {
            return operations::failure(Failure::new("input_limit"));
        }
        // SAFETY: Validity is required by the ABI; lengths/nulls are checked above.
        let command = unsafe { input(command, command_len) };
        // SAFETY: Same caller-owned buffer contract; empty input may be null.
        let body = unsafe { input(body, body_len) };
        operations::dispatch(command, body)
    }))
    .unwrap_or_else(|_| operations::failure(Failure::new("internal")));
    if bytes.len() > result_capacity {
        return 0;
    }
    // SAFETY: The caller's result capacity was checked before executing anything.
    unsafe {
        output(result, &bytes);
    }
    bytes.len()
}

// SAFETY: This uniquely prefixed symbol copies one bounded completion into
// caller-owned buffers, synchronously, and contains unwinding at the C boundary.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn phantom_go_wait(
    metadata: *mut u8,
    metadata_capacity: usize,
    data: *mut u8,
    data_capacity: usize,
) -> usize {
    if metadata.is_null()
        || data.is_null()
        || metadata_capacity < operations::MAX_METADATA
        || data_capacity < operations::MAX_CHUNK
    {
        return 0;
    }
    let completion = catch_unwind(AssertUnwindSafe(operations::wait));
    let completion = match completion {
        Ok(Ok(completion)) => completion,
        _ => return 0,
    };
    if completion.metadata.len() > metadata_capacity || completion.data.len() > data_capacity {
        return 0;
    }
    // SAFETY: Both capacities and nulls are checked above. The caller guarantees
    // that these buffers do not overlap; the task/queue contains only owned bytes.
    unsafe {
        output(metadata, &completion.metadata);
        output(data, &completion.data);
    }
    completion.metadata.len()
}
