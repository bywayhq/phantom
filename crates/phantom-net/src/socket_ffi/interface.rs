//! Network interface indexes looked up by name and, on Windows, the
//! `IP_UNICAST_IF` and `IPV6_UNICAST_IF` socket options.
//!
//! socket2 0.6.5 binds a socket to an interface index on Apple platforms,
//! but no safe Rust API turns a name into that index, and none sets the
//! Windows options: socket2's general `setsockopt` is private. The lookups
//! call `if_nametoindex` through `libc` and the IP Helper LUID conversions
//! through `windows-sys`.

use std::{io, num::NonZeroU32};

#[cfg(windows)]
use std::os::windows::io::BorrowedSocket;

#[cfg(windows)]
use socket2::Domain;
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, ConvertInterfaceNameToLuidW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    },
};

/// Returns the index of the network interface named `name`.
///
/// Fails with [`io::ErrorKind::NotFound`] when no interface has the name.
#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
pub(crate) fn index(name: &str) -> io::Result<NonZeroU32> {
    let name = std::ffi::CString::new(name).map_err(|_| nul_in_name())?;
    // SAFETY: `name` is a live, NUL-terminated C string that outlives the
    // call. `if_nametoindex` only reads it, up to its NUL, and does not keep
    // the pointer after it returns.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index).ok_or_else(|| {
        // Nothing runs between the failed call and this read of `errno`.
        // A missing interface is `ENODEV` from glibc and bionic, which ask
        // the kernel with `SIOCGIFINDEX`, and `ENXIO` from Apple's libc.
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            None | Some(0 | libc::ENODEV | libc::ENXIO) => no_such_interface(),
            Some(_) => error,
        }
    })
}

/// Returns the index of the network interface whose alias, such as
/// `Ethernet`, or NDIS name, such as `ethernet_32768`, is `name`.
///
/// The alias is tried first, as the name Windows shows. Fails with
/// [`io::ErrorKind::NotFound`] when no interface has the name.
#[cfg(windows)]
pub(crate) fn index(name: &str) -> io::Result<NonZeroU32> {
    if name.contains('\0') {
        return Err(nul_in_name());
    }
    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer that outlives
    // the call, and the function only reads it, up to its NUL. `luid` is a
    // live, writable local `NET_LUID_LH`, so the call may write the whole
    // value through the pointer. Both are exclusive local borrows that the
    // call does not keep after it returns.
    let mut status = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &raw mut luid) };
    if status != NO_ERROR {
        // SAFETY: the same buffer and local as in the alias lookup above,
        // with the same reads and writes, and no pointer kept.
        status = unsafe { ConvertInterfaceNameToLuidW(name.as_ptr(), &raw mut luid) };
    }
    if status != NO_ERROR {
        return Err(no_such_interface());
    }
    let mut index: u32 = 0;
    // SAFETY: `luid` is an initialized local that the call only reads, and
    // `index` is a live, writable local `u32` that it may write. Both are
    // exclusive local borrows that the call does not keep.
    let status = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    NonZeroU32::new(index).ok_or_else(no_such_interface)
}

/// Sets `IP_UNICAST_IF` on an IPv4 `socket`, or `IPV6_UNICAST_IF` on an IPv6
/// one, to interface `index`, so that Windows sends the socket's unicast
/// traffic through that interface.
///
/// Windows reads the option only before the socket binds or connects.
#[cfg(windows)]
pub(crate) fn set_unicast_interface(
    socket: BorrowedSocket<'_>,
    domain: Domain,
    index: NonZeroU32,
) -> io::Result<()> {
    let socket = super::raw_socket(socket)?;
    let (level, option) = unicast_interface_option(domain);
    let value = crate::source_binding::unicast_interface_value(index.get(), domain);
    let length = i32::try_from(value.len()).map_err(io::Error::other)?;
    // SAFETY: `socket` comes from a `BorrowedSocket`, so it is an open socket
    // handle that the caller keeps open for the borrow, which outlives this
    // call. `optval` points to `value`, a live, initialized local `[u8; 4]`,
    // and `optlen` is its length, so Winsock reads exactly the four bytes it
    // owns. Winsock only reads through the pointer and does not keep it.
    let result = unsafe { setsockopt(socket, level, option, value.as_ptr(), length) };
    if result == SOCKET_ERROR {
        // Winsock keeps its last error in the thread's last-error value,
        // read here straight after the failed call.
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads the `IP_UNICAST_IF` or `IPV6_UNICAST_IF` value of `socket`, in the
/// byte order Windows stores it.
#[cfg(all(windows, test))]
pub(crate) fn unicast_interface(socket: BorrowedSocket<'_>, domain: Domain) -> io::Result<[u8; 4]> {
    use windows_sys::Win32::Networking::WinSock::getsockopt;

    let socket = super::raw_socket(socket)?;
    let (level, option) = unicast_interface_option(domain);
    let mut value = [0_u8; 4];
    let mut length = i32::try_from(value.len()).map_err(io::Error::other)?;
    // SAFETY: `socket` is an open handle kept open for the borrow, as in
    // `set_unicast_interface`. `optval` points to `value`, a live, writable
    // local `[u8; 4]`, and `optlen` points to `length`, which holds its size,
    // so Winsock writes at most four bytes into `value` and stores the count
    // in `length`. Both are exclusive local borrows that the call does not
    // keep.
    let result = unsafe { getsockopt(socket, level, option, value.as_mut_ptr(), &raw mut length) };
    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(value.len()) {
        return Err(io::Error::other(format!(
            "the unicast interface option returned {length} bytes"
        )));
    }
    Ok(value)
}

/// The option level and name that steer `domain`'s unicast traffic.
#[cfg(windows)]
fn unicast_interface_option(domain: Domain) -> (i32, i32) {
    if domain == Domain::IPV6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF)
    }
}

fn no_such_interface() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no network interface has this name",
    )
}

fn nul_in_name() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "an interface name cannot hold a NUL byte",
    )
}
