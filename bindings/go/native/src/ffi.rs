//! Private C ABI boundary. Callers supply valid, nonoverlapping byte buffers
//! for the full call. No Go pointer is stored in the runtime or a task.
//! Only the completion pump waits on external completion. Profile/checkpoint
//! calls run synchronous CPU work; worker tasks never receive foreign buffers.
//!
//! The symbols use the target C ABI and usize/size_t widths. Clients pass
//! concrete C descriptors, bytes and monotonic handles; no foreign callback or allocation
//! ownership crosses this module. Lengths are bounded before slices are formed.
//! Metadata and body copies finish before returning, including the blocking
//! wait. Empty inputs may be null; outputs must be valid writable buffers.
//! Rust unwinding is contained here. State poisoning completes pending operation
//! IDs with terminal errors and rejects new work; it never yields an anonymous
//! completion. The shared runtime and loaded library live for the process.

use crate::{error::Failure, operations, profile, session};
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

// SAFETY: The caller provides nonoverlapping borrowed buffers for this complete
// synchronous authoring call. Nulls and lengths are checked before forming slices;
// no pointer is retained by the profile registry, and unwinding is contained here.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn phantom_go_profile(
    command: *const u8,
    command_len: usize,
    document: *const u8,
    document_len: usize,
    metadata: *mut u8,
    metadata_capacity: usize,
    result: *mut u8,
    result_capacity: usize,
) -> usize {
    if metadata.is_null() || metadata_capacity < operations::MAX_METADATA {
        return 0;
    }
    let (reply, document) = catch_unwind(AssertUnwindSafe(|| {
        if command_len > operations::MAX_COMMAND
            || document_len > profile::MAX_DOCUMENT
            || result_capacity > profile::MAX_DOCUMENT
            || (command.is_null() && command_len != 0)
            || (document.is_null() && document_len != 0)
            || (result.is_null() && result_capacity != 0)
        {
            return (operations::failure(Failure::new("input_limit")), Vec::new());
        }
        // SAFETY: The ABI requires valid readable caller storage; lengths/nulls
        // are checked above. All borrowed input is consumed before returning.
        let command = unsafe { input(command, command_len) };
        // SAFETY: Same checked caller-owned buffer contract; empty may be null.
        let document = unsafe { input(document, document_len) };
        profile::dispatch(command, document, result_capacity)
    }))
    .unwrap_or_else(|_| (operations::failure(Failure::new("internal")), Vec::new()));
    if reply.len() > metadata_capacity || document.len() > result_capacity {
        return 0;
    }
    // SAFETY: Capacities were checked and caller guarantees writable disjoint
    // buffers. Neither metadata nor document storage survives this call.
    unsafe {
        output(metadata, &reply);
        if !document.is_empty() {
            output(result, &document);
        }
    }
    reply.len()
}

// SAFETY: The caller supplies disjoint command/key/ciphertext/output buffers
// valid for this entire synchronous call. Lengths and nulls are checked before
// slices are formed; core work retains no foreign pointers. Unwinding is caught.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn phantom_go_session(
    command: *const u8,
    command_len: usize,
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    metadata: *mut u8,
    metadata_capacity: usize,
    result: *mut u8,
    result_capacity: usize,
) -> usize {
    if metadata.is_null() || metadata_capacity < operations::MAX_METADATA {
        return 0;
    }
    let (reply, snapshot) = catch_unwind(AssertUnwindSafe(|| {
        if command_len > operations::MAX_COMMAND
            || key_len > 32
            || ciphertext_len > session::MAX_SNAPSHOT
            || result_capacity > session::MAX_SNAPSHOT
            || (command.is_null() && command_len != 0)
            || (key.is_null() && key_len != 0)
            || (ciphertext.is_null() && ciphertext_len != 0)
            || (result.is_null() && result_capacity != 0)
        {
            return (operations::failure(Failure::new("input_limit")), None);
        }
        // SAFETY: All three readable caller-owned buffers are checked above;
        // their pointers remain live for this call, and no slice escapes it.
        let command = unsafe { input(command, command_len) };
        // SAFETY: Same checked caller-owned contract; empty key may be null.
        let key = unsafe { input(key, key_len) };
        // SAFETY: Same checked contract; ciphertext is never interpreted as JSON.
        let ciphertext = unsafe { input(ciphertext, ciphertext_len) };
        session::dispatch(command, key, ciphertext, result_capacity)
    }))
    .unwrap_or_else(|_| (operations::failure(Failure::new("internal")), None));
    if reply.len() > metadata_capacity {
        return 0;
    }
    // SAFETY: Writable disjoint output capacities were checked before execution.
    // A retained core snapshot owns its bytes until these copies have completed.
    unsafe {
        output(metadata, &reply);
        if let Some(snapshot) = snapshot {
            let bytes = snapshot.as_bytes();
            if bytes.len() > result_capacity {
                return 0;
            }
            output(result, bytes);
        }
    }
    reply.len()
}

mod hot;
