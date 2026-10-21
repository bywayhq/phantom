//! Synchronous validation and ownership of ordinary Node byte buffers.

use std::{ffi::c_void, ptr};

use napi::{
    Env, Result,
    bindgen_prelude::{Buffer, ToNapiValue},
};
use zeroize::Zeroizing;

use crate::{error::failure, session};

// The returned pointer is used only by private synchronous code in this Env;
// callers must not invoke JS or await before copying its validated extent.
pub(super) fn buffer_info(env: &Env, buffer: Buffer) -> Result<(*mut c_void, usize)> {
    // SAFETY: This is the owning Env's synchronous callback. The generated
    // Buffer conversion retained this value without reading its backing bytes.
    // Converting it back only creates a local handle; no JS is invoked.
    let value = unsafe { Buffer::to_napi_value(env.raw(), buffer) }?;
    let mut kind = 0;
    let mut length = 0;
    let mut data: *mut c_void = ptr::null_mut();
    let mut backing = ptr::null_mut();
    let mut offset = 0;
    // SAFETY: All out-pointers refer to initialized, live local storage. `value`
    // is rooted in this callback's handle scope; Node returns the view's actual
    // pointer/extent/backing, without reading overridable JS properties.
    let status = unsafe {
        napi::sys::napi_get_typedarray_info(
            env.raw(),
            value,
            &mut kind,
            &mut length,
            &mut data,
            &mut backing,
            &mut offset,
        )
    };
    if status != napi::sys::Status::napi_ok || kind != napi::sys::TypedarrayType::uint8_array {
        return Err(failure(
            "InvalidArgument",
            "bytes must be an ordinary Buffer",
        ));
    }
    let mut ordinary = false;
    // SAFETY: `backing` was returned for this live typed-array view in this Env.
    // SharedArrayBuffer is deliberately not an ordinary ArrayBuffer here.
    let status = unsafe { napi::sys::napi_is_arraybuffer(env.raw(), backing, &mut ordinary) };
    if status != napi::sys::Status::napi_ok || !ordinary {
        return Err(failure(
            "InvalidArgument",
            "shared byte buffers are unsupported",
        ));
    }
    let mut detached = false;
    // SAFETY: The previous check established that this handle is an ArrayBuffer.
    let status =
        unsafe { napi::sys::napi_is_detached_arraybuffer(env.raw(), backing, &mut detached) };
    if status != napi::sys::Status::napi_ok || detached || (length != 0 && data.is_null()) {
        return Err(failure(
            "InvalidArgument",
            "detached byte buffers are unsupported",
        ));
    }
    Ok((data, length))
}

pub(super) fn copy_buffer(env: &Env, buffer: Buffer, maximum: usize) -> Result<Vec<u8>> {
    copy_buffer_info(buffer_info(env, buffer)?, maximum)
}

pub(super) fn copy_buffer_info(
    (data, length): (*mut c_void, usize),
    maximum: usize,
) -> Result<Vec<u8>> {
    if length > maximum {
        return Err(failure(
            "InputLimit",
            "byte input exceeds the binding limit",
        ));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(length)
        .map_err(|_| failure("Allocation", "could not allocate byte input"))?;
    // SAFETY: Node supplied this non-null view pointer and length, including the
    // view's offset. Its ordinary, attached backing cannot be mutated/detached
    // by another Worker. No JS or await runs before the synchronous copy ends.
    copied.extend_from_slice(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) });
    Ok(copied)
}

pub(super) fn checkpoint_bytes(
    env: &Env,
    input: Buffer,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    copy_buffer(env, input, maximum)
        .map(Zeroizing::new)
        .map_err(|error| {
            if error.reason.starts_with("PHANTOM:InputLimit:") {
                session::failure("too_large")
            } else {
                error
            }
        })
}

pub(super) fn checkpoint_key(env: &Env, input: Buffer) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = copy_buffer(env, input, 32).map_err(|error| {
        if error.reason.starts_with("PHANTOM:InputLimit:") {
            session::failure("invalid_key_length")
        } else {
            error
        }
    })?;
    session::key(Zeroizing::new(bytes))
}
