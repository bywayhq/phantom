//! Windows source-port randomization through Winsock's `SO_RANDOMIZE_PORT`.
//!
//! This module is the crate's only FFI boundary and the only code in it that
//! may use `unsafe`. No safe Rust API sets the option: socket2 0.6.5 has no
//! method for it, and its general `setsockopt` is private. The module calls
//! Winsock and ntdll through the `windows-sys` declarations instead, and
//! keeps each call in its own block with the invariants it relies on.

use std::{
    io,
    os::windows::io::{AsRawSocket, BorrowedSocket},
};

use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::STATUS_SUCCESS,
        Networking::WinSock::{
            SO_RANDOMIZE_PORT, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSAENOPROTOOPT, WSAGetLastError,
            setsockopt,
        },
        System::SystemInformation::OSVERSIONINFOW,
    },
};

/// The Windows version that [`RtlGetVersion`] reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WindowsVersion {
    pub(super) major: u32,
    pub(super) build: u32,
}

/// Asks Windows to choose `socket`'s local port at random when the socket is
/// bound or connects, rather than the next free port in sequence.
///
/// Windows rejects the option with `WSAEINVAL` once the socket is bound.
/// A Windows that does not know the option fails with `WSAENOPROTOOPT`,
/// which this returns as [`io::ErrorKind::Unsupported`].
pub(super) fn enable(socket: BorrowedSocket<'_>) -> io::Result<()> {
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
pub(super) fn is_enabled(socket: BorrowedSocket<'_>) -> io::Result<bool> {
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
    // Windows reports a one-byte `BOOL` for some sockets. `value` started at
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
pub(super) fn windows_version() -> Option<WindowsVersion> {
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

fn raw_socket(socket: BorrowedSocket<'_>) -> io::Result<SOCKET> {
    SOCKET::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket handle out of range"))
}

fn option_length() -> io::Result<i32> {
    i32::try_from(size_of::<i32>()).map_err(io::Error::other)
}

/// The Winsock error of the call that just failed on this thread.
fn last_socket_error() -> io::Error {
    // SAFETY: `WSAGetLastError` takes no arguments, has no preconditions,
    // and only reads the calling thread's last Winsock error. Callers reach
    // it straight from the failed Winsock call, so the code is that call's.
    let code = unsafe { WSAGetLastError() };
    if code == WSAENOPROTOOPT {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            "this Windows does not support SO_RANDOMIZE_PORT",
        );
    }
    io::Error::from_raw_os_error(code)
}
