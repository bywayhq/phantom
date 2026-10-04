//! The crate's only FFI boundary and the only code in it that may use
//! `unsafe`: socket calls that no safe Rust API makes.
//!
//! Each submodule keeps every foreign call in its own block with the
//! invariants it relies on, and passes only safe types across its API:
//! borrowed sockets, interface names, plain values, and `io::Result`s.
//! `docs/explanation/design.md#unsafe-code` audits every block.

pub(crate) mod interface;
#[cfg(windows)]
pub(crate) mod port_randomization;

#[cfg(windows)]
use std::{
    io,
    os::windows::io::{AsRawSocket, BorrowedSocket},
};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKET;

/// Returns the Winsock handle of `socket`, converted with `try_from` rather
/// than a cast.
#[cfg(windows)]
fn raw_socket(socket: BorrowedSocket<'_>) -> io::Result<SOCKET> {
    SOCKET::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket handle out of range"))
}
