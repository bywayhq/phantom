//! Windows source-port randomization through Winsock's `SO_RANDOMIZE_PORT`.
//!
//! No safe Rust API sets the option: socket2 0.6.5 has no method for it, and
//! its general `setsockopt` is private. The module calls Winsock and ntdll
//! through the `windows-sys` declarations instead, and keeps each call in its
//! own block with the invariants it relies on.

use std::{io, os::windows::io::BorrowedSocket};

use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::STATUS_SUCCESS,
        Networking::WinSock::{
            SO_RANDOMIZE_PORT, SOCKET_ERROR, SOL_SOCKET, WSAENOPROTOOPT, setsockopt,
        },
        System::SystemInformation::OSVERSIONINFOW,
    },
};

use super::raw_socket;

/// The Windows version that [`RtlGetVersion`] reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVersion {
    pub(crate) major: u32,
    pub(crate) build: u32,
}

/// Asks Windows to choose `socket`'s local port at random when the socket is
/// bound or connects, rather than the next free port in sequence.
///
/// Windows rejects the option with `WSAEINVAL` once the socket is bound.
/// A Windows that does not know the option fails with `WSAENOPROTOOPT`,
/// which this returns as [`io::ErrorKind::Unsupported`].
pub(crate) fn enable(socket: BorrowedSocket<'_>) -> io::Result<()> {
    let socket = raw_socket(socket)?;
    // A Winsock `BOOL`: a 32-bit integer, nonzero for true.
    let enabled: i32 = 1;
    let length = option_length()?;
    // SAFETY: `socket` comes from a `BorrowedSocket`, so it is an open socket
    // handle that the caller keeps open for the borrow, which outlives this
    // call. `optval` points to `enabled`, a live, initialized local `i32`, and
    // `optlen` is its size, so Winsock reads exactly the four bytes it owns.
    // Winsock only reads through the pointer, and nothing else references
    // `enabled`. The call does not retain the pointer after it returns.
    let result = unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RANDOMIZE_PORT,
            (&raw const enabled).cast::<u8>(),
            length,
        )
    };
    if result == SOCKET_ERROR {
        return Err(last_socket_error());
    }
    Ok(())
}

/// Reads whether `SO_RANDOMIZE_PORT` is set on `socket`.
#[cfg(test)]
pub(crate) fn is_enabled(socket: BorrowedSocket<'_>) -> io::Result<bool> {
    use windows_sys::Win32::Networking::WinSock::getsockopt;

    let socket = raw_socket(socket)?;
    let mut value: i32 = 0;
    let mut length = option_length()?;
    // SAFETY: `socket` is an open handle kept open for the borrow, as in
    // `enable`. `optval` points to `value`, a live, initialized, writable
    // local `i32`, and `optlen` points to `length`, which holds its size, so
    // Winsock writes at most four bytes into `value` and stores the count
    // in `length`. Both are exclusive local borrows that nothing else
    // references, and the call does not retain either pointer.
    let result = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_RANDOMIZE_PORT,
            (&raw mut value).cast::<u8>(),
            &raw mut length,
        )
    };
    if result == SOCKET_ERROR {
        return Err(last_socket_error());
    }
    // Windows reports a one-byte value for some sockets. `value` started at
    // zero and every Windows target is little-endian, so a shorter write
    // still leaves `value` nonzero exactly when the option is set.
    if !(1..=4).contains(&length) {
        return Err(io::Error::other(format!(
            "SO_RANDOMIZE_PORT returned {length} bytes"
        )));
    }
    Ok(value != 0)
}

/// Returns the version of the running Windows, or `None` if it cannot be
/// read.
///
/// `RtlGetVersion` reports the real version. `GetVersionExW` does not: it
/// reports Windows 8 to an executable whose manifest does not declare a later
/// Windows, which no Rust test binary or typical application declares.
pub(crate) fn windows_version() -> Option<WindowsVersion> {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(size_of::<OSVERSIONINFOW>()).ok()?,
        ..OSVERSIONINFOW::default()
    };
    // SAFETY: `info` is a live, writable, zero-initialized `OSVERSIONINFOW`
    // whose `dwOSVersionInfoSize` is its own size, which `RtlGetVersion`
    // requires in order to know how much it may write. The pointer is an
    // exclusive local borrow that the call does not retain.
    let status = unsafe { RtlGetVersion(&raw mut info) };
    (status == STATUS_SUCCESS).then_some(WindowsVersion {
        major: info.dwMajorVersion,
        build: info.dwBuildNumber,
    })
}

fn option_length() -> io::Result<i32> {
    i32::try_from(size_of::<i32>()).map_err(io::Error::other)
}

/// The error of the Winsock call that just failed on this thread.
///
/// Winsock keeps its last error in the thread's last-error value, which
/// `io::Error::last_os_error` reads, as socket2 0.6.5 does for its own
/// Winsock calls (`src/sys/windows.rs:149-158`). Callers come here straight
/// from the failed call, before anything else can change that value.
fn last_socket_error() -> io::Error {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(WSAENOPROTOOPT) {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            "this Windows does not support SO_RANDOMIZE_PORT",
        );
    }
    error
}
