//! Windows system addresses and Firefox's native DNS TTL query options.
//!
//! The address and DNS record lists stay owned here until copied or inspected.
//! No native pointer, borrowed record or callback crosses this module's API.

#[cfg(feature = "https-records")]
pub(crate) mod configuration;
#[cfg(feature = "https-records")]
pub(crate) mod configuration_watch;

use std::{
    ffi::{CStr, CString},
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr,
    time::Instant,
};

use windows_sys::Win32::{
    NetworkManagement::Dns::{
        DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE, DNS_QUERY_DONT_RESET_TTL_VALUES,
        DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_NO_MULTICAST, DNS_QUERY_NO_NETBT, DNS_RECORDA,
        DNS_TYPE_A, DNS_TYPE_AAAA, DnsFree, DnsFreeRecordList, DnsQuery_A,
    },
    Networking::WinSock::{
        ADDRINFOA, AF_INET, AF_INET6, AF_UNSPEC, AI_CANONNAME, SOCK_STREAM, SOCKADDR_IN,
        SOCKADDR_IN6, WSACleanup, WSADATA, WSAStartup, WSAVERNOTSUPPORTED, freeaddrinfo,
        getaddrinfo,
    },
};

use crate::host_resolver::system_ttl::{QueryTtl, SystemTtl};

// A traversal limit abandons optional TTL metadata, or rejects an oversized
// address list; it must never silently truncate connection addresses.
const MAX_NATIVE_RECORDS: usize = 1024;
const MAX_CANONICAL_NAME_BYTES: usize = 255;

// Firefox 157 GetAddrInfo.cpp:157-162. These options permit OS DNS wire I/O;
// DNS_QUERY_NO_WIRE_QUERY would implement a different policy.
const TTL_QUERY_OPTIONS: u32 = DNS_QUERY_NO_NETBT
    | DNS_QUERY_NO_HOSTS_FILE
    | DNS_QUERY_NO_MULTICAST
    | DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE
    | DNS_QUERY_DONT_RESET_TTL_VALUES;

/// Resolves ASCII input once, with the standard resolver's hints plus CANONNAME.
pub(crate) fn resolve(host: &str) -> io::Result<(Vec<SocketAddr>, SystemTtl)> {
    if !host.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native DNS TTL input must be ASCII",
        ));
    }
    let name = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS name contains a NUL byte"))?;
    let _winsock = WinsockLease::new()?;
    let hints = ADDRINFOA {
        ai_flags: AI_CANONNAME.cast_signed(),
        ai_family: i32::from(AF_UNSPEC),
        ai_socktype: SOCK_STREAM,
        ..ADDRINFOA::default()
    };
    let mut head = ptr::null_mut();
    // SAFETY: name/hints/output remain live for this synchronous call. The
    // lease initialized Winsock; all unused hint fields and service are null.
    let status = unsafe { getaddrinfo(name.as_ptr().cast(), ptr::null(), &hints, &mut head) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let list = AddressList(head);

    let addresses = list.addresses()?;
    let ttl = if addresses.is_empty() {
        SystemTtl::Unavailable
    } else {
        match list.canonical_name() {
            Ok(canonical) => {
                let query_name = canonical.as_deref().unwrap_or(&name);
                query_ttl(query_name, DNS_TYPE_A).earliest(query_ttl(query_name, DNS_TYPE_AAAA))
            }
            // Malformed or non-ASCII canonical metadata cannot turn a
            // successful system address resolution into a failure.
            Err(_) => SystemTtl::Unavailable,
        }
    };
    Ok((addresses, ttl))
}

struct WinsockLease;

impl WinsockLease {
    fn new() -> io::Result<Self> {
        let mut data = WSADATA::default();
        // SAFETY: data is a writable SDK structure. Success acquires one
        // local Winsock reference; its negotiated version is checked below.
        let status = unsafe { WSAStartup(0x0202, &mut data) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        let lease = Self;
        validate_winsock_version(data.wVersion)?;
        Ok(lease)
    }
}

fn validate_winsock_version(version: u16) -> io::Result<()> {
    if version == 0x0202 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(WSAVERNOTSUPPORTED))
    }
}

impl Drop for WinsockLease {
    fn drop(&mut self) {
        // SAFETY: this lease exists only after a successful WSAStartup. All
        // address/DNS calls and list destructors finish before it is dropped.
        // No socket is owned here; release only our matching startup reference.
        let _status = unsafe { WSACleanup() };
    }
}

struct AddressList(*mut ADDRINFOA);

impl AddressList {
    fn addresses(&self) -> io::Result<Vec<SocketAddr>> {
        let mut addresses = Vec::new();
        let mut next = self.0;
        for _ in 0..MAX_NATIVE_RECORDS {
            if next.is_null() {
                return Ok(addresses);
            }
            // SAFETY: successful getaddrinfo owns a linked list of SDK
            // ADDRINFOA nodes, retained by self throughout this traversal.
            let entry = unsafe { &*next };
            // SAFETY: the OS list supplies the live sockaddr allocation
            // described by this entry until freeaddrinfo drops the list.
            if let Some(address) = unsafe { socket_address(entry)? } {
                addresses.try_reserve(1).map_err(io::Error::other)?;
                addresses.push(address);
            }
            next = entry.ai_next;
        }
        if next.is_null() {
            Ok(addresses)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system address list is too large",
            ))
        }
    }

    fn canonical_name(&self) -> io::Result<Option<CString>> {
        if self.0.is_null() {
            return Ok(None);
        }
        // SAFETY: the first node and its optional terminated canonical string
        // remain owned by this successful getaddrinfo result until self drops.
        unsafe { copy_canonical_name((*self.0).ai_canonname) }
    }
}

impl Drop for AddressList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self owns this original getaddrinfo head exactly once;
            // no node/string has been freed or transferred independently.
            unsafe { freeaddrinfo(self.0) };
        }
    }
}

/// The optional sockaddr pointer must be the live allocation described by entry.
unsafe fn socket_address(entry: &ADDRINFOA) -> io::Result<Option<SocketAddr>> {
    let family = entry.ai_family;
    if family != i32::from(AF_INET) && family != i32::from(AF_INET6) {
        return Ok(None);
    }
    let required = if family == i32::from(AF_INET) {
        size_of::<SOCKADDR_IN>()
    } else {
        size_of::<SOCKADDR_IN6>()
    };
    if entry.ai_addr.is_null() || entry.ai_addrlen < required {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system address record is truncated",
        ));
    }
    if family == i32::from(AF_INET) {
        // SAFETY: the caller owns this valid sockaddr allocation; its family
        // and byte length were checked above. Unaligned read needs no stronger
        // alignment. S_addr is the native union's four network-order bytes.
        let native = unsafe { ptr::read_unaligned(entry.ai_addr.cast::<SOCKADDR_IN>()) };
        // SAFETY: IN_ADDR's S_addr member contains exactly the four address
        // bytes, initialized by the IPv4 sockaddr returned by getaddrinfo.
        let bytes = unsafe { native.sin_addr.S_un.S_addr.to_ne_bytes() };
        return Ok(Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(bytes),
            u16::from_be(native.sin_port),
        ))));
    }

    // SAFETY: the caller owns this sockaddr allocation, with IPv6 family and
    // byte length checked above. read_unaligned avoids an alignment assumption.
    let native = unsafe { ptr::read_unaligned(entry.ai_addr.cast::<SOCKADDR_IN6>()) };
    // SAFETY: the SDK unions contain the initialized IPv6 bytes and scope ID
    // of this sockaddr. Neither read accesses data outside the copied value.
    let (bytes, scope) = unsafe { (native.sin6_addr.u.Byte, native.Anonymous.sin6_scope_id) };
    Ok(Some(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(bytes),
        u16::from_be(native.sin6_port),
        native.sin6_flowinfo,
        scope,
    ))))
}

/// A nonnull pointer must address a live OS-provided NUL-terminated ANSI name.
unsafe fn copy_canonical_name(name: *const u8) -> io::Result<Option<CString>> {
    if name.is_null() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for offset in 0..=MAX_CANONICAL_NAME_BYTES {
        // SAFETY: the caller guarantees an OS-provided terminated string.
        // Previous iterations found no NUL, so this byte remains in that
        // allocation; the bound also limits the amount of metadata inspected.
        let byte = unsafe { *name.add(offset) };
        if byte == 0 {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                CString::new(bytes).map(Some).map_err(io::Error::other)
            };
        }
        if !byte.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system canonical name is not ASCII",
            ));
        }
        bytes.try_reserve(1).map_err(io::Error::other)?;
        bytes.push(byte);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "system canonical name is too long",
    ))
}

fn query_ttl(name: &CStr, record_type: u16) -> SystemTtl {
    let started_at = Instant::now();
    let mut head = ptr::null_mut();
    // SAFETY: name remains live/terminated through the synchronous call;
    // output is writable, reserved arguments are null, and SDK options/types
    // request a parsed record list rather than a raw DNS message.
    let status = unsafe {
        DnsQuery_A(
            name.as_ptr().cast(),
            record_type,
            TTL_QUERY_OPTIONS,
            ptr::null_mut(),
            &mut head,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return SystemTtl::Unavailable;
    }
    let _records = RecordList(head);
    let mut selected = QueryTtl::new(record_type, started_at);
    let mut next = head;
    for _ in 0..MAX_NATIVE_RECORDS {
        if next.is_null() {
            return selected.finish();
        }
        // SAFETY: this successful parsed list remains owned by _records.
        // Each node has the SDK fixed header; no full RDATA union is required.
        let header = unsafe { record_header(next) };
        selected.observe(header.record_type, header.section, header.ttl);
        next = header.next;
    }
    if next.is_null() {
        selected.finish()
    } else {
        SystemTtl::Unavailable
    }
}

struct RecordHeader {
    next: *mut DNS_RECORDA,
    record_type: u16,
    section: u32,
    ttl: u32,
}

/// The pointer must address a live initialized SDK DNS record fixed header.
unsafe fn record_header(record: *const DNS_RECORDA) -> RecordHeader {
    // SAFETY: the caller supplies the initialized fixed header. All projected
    // fields precede Data (DNS_RECORD_FIXED_SIZE); no whole DNS_RECORDA
    // reference or RDATA union is created. Unaligned reads need no alignment.
    let (next, record_type, flags, ttl) = unsafe {
        (
            ptr::addr_of!((*record).pNext).read_unaligned(),
            ptr::addr_of!((*record).wType).read_unaligned(),
            ptr::addr_of!((*record).Flags.DW).read_unaligned(),
            ptr::addr_of!((*record).dwTtl).read_unaligned(),
        )
    };
    RecordHeader {
        next,
        record_type,
        section: flags & 3,
        ttl,
    }
}

struct RecordList(*mut DNS_RECORDA);

impl Drop for RecordList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the original parsed list from a successful
            // DnsQuery_A, adopted once. DnsFreeRecordList deep-frees that
            // allocation; no node has been independently freed or fabricated.
            unsafe { DnsFree(self.0.cast(), DnsFreeRecordList) };
        }
    }
}

#[cfg(test)]
mod tests;
