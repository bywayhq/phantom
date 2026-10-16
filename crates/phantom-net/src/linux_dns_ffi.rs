//! Linux DNS native witnesses and owned change notification.
//!
//! GNU libc's `csu/version.c` at glibc-2.42 returns a static version string.
//! `gethostname(2)` defines the bounded output/ENAMETOOLONG contract. Foreign
//! pointers remain here; callers receive plain values and recoverable errors.

pub(crate) mod configuration_watch;

use std::io;

/// Reads the actual linked GNU libc; other libc environments are unsupported.
#[cfg(target_env = "gnu")]
pub(crate) fn glibc_version() -> io::Result<(u32, u32)> {
    // SAFETY: GNU libc returns a pointer to its static, NUL-terminated version
    // string. It remains valid and immutable for the process lifetime.
    let pointer = unsafe { libc::gnu_get_libc_version() };
    if pointer.is_null() {
        return Err(invalid("GNU libc returned no version"));
    }
    // SAFETY: the non-null pointer has the static terminated-string contract
    // above. No pointer or native borrow escapes this function.
    let value = unsafe { std::ffi::CStr::from_ptr(pointer) }.to_bytes();
    parse_glibc_version(value)
}

#[cfg(not(target_env = "gnu"))]
pub(crate) fn glibc_version() -> io::Result<(u32, u32)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux DNS projection requires a GNU libc witness",
    ))
}

#[cfg(any(target_env = "gnu", test))]
fn parse_glibc_version(value: &[u8]) -> io::Result<(u32, u32)> {
    if value.len() > 64 {
        return Err(invalid("GNU libc version is too long"));
    }
    let value = std::str::from_utf8(value).map_err(|_| invalid("invalid GNU libc version"))?;
    let mut components = value.split('.');
    let component = |value: Option<&str>| -> io::Result<u32> {
        let value = value.ok_or_else(|| invalid("incomplete GNU libc version"))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("invalid GNU libc version"));
        }
        value
            .parse()
            .map_err(|_| invalid("invalid GNU libc version"))
    };
    let major = component(components.next())?;
    let minor = component(components.next())?;
    for value in components {
        component(Some(value))?;
    }
    if major == 0 {
        return Err(invalid("invalid GNU libc version"));
    }
    Ok((major, minor))
}

/// Returns a complete native hostname, with no truncation or lossy decoding.
pub(crate) fn hostname() -> io::Result<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: buffer is writable for exactly the supplied length and remains
    // local throughout the synchronous call. No native pointer is retained.
    let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    copy_hostname(&buffer)
}

/// Resolves one actual interface index; route notifications invalidate it.
pub(crate) fn interface_index(name: &str) -> io::Result<u32> {
    let native = interface_name(name)?;
    // SAFETY: native is a checked IF_NAMESIZE buffer with a terminating NUL
    // after the complete name. The call retains no pointer and mutates no host
    // configuration. Only the returned index crosses this boundary.
    let index = unsafe { libc::if_nametoindex(native.as_ptr().cast()) };
    if index == 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error().is_some_and(|code| code != 0) {
            error
        } else {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Linux interface index is unavailable",
            )
        });
    }
    Ok(index)
}

fn interface_name(name: &str) -> io::Result<[u8; libc::IF_NAMESIZE]> {
    // Linux's interface name size includes the NUL; dev_valid_name also rejects
    // dot names, slash, colon and whitespace. Do not include the name in errors.
    if name.is_empty()
        || name.len() >= libc::IF_NAMESIZE
        || matches!(name, "." | "..")
        || name.bytes().any(|byte| {
            byte == 0
                || byte == b'/'
                || byte == b':'
                || byte.is_ascii_whitespace()
                || byte.is_ascii_control()
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Linux interface name",
        ));
    }
    let mut native = [0u8; libc::IF_NAMESIZE];
    native[..name.len()].copy_from_slice(name.as_bytes());
    Ok(native)
}

fn copy_hostname(buffer: &[u8]) -> io::Result<String> {
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("native hostname is not terminated"))?;
    let value = std::str::from_utf8(&buffer[..length])
        .map_err(|_| invalid("native hostname is not UTF-8"))?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid("invalid native hostname"));
    }
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(io::Error::other)?;
    result.push_str(value);
    Ok(result)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
