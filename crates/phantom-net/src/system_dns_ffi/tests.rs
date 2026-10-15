//! Native layout controls use live owned SDK values, not invented DNS records.

use super::*;
use windows_sys::Win32::NetworkManagement::Dns::DNS_QUERY_NO_WIRE_QUERY;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ipv4_conversion_keeps_network_bytes_and_port() -> TestResult {
    let mut native = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 8443_u16.to_be(),
        ..SOCKADDR_IN::default()
    };
    native.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 9, 17, 3]);
    let entry = ADDRINFOA {
        ai_family: i32::from(AF_INET),
        ai_addr: (&raw mut native).cast(),
        ai_addrlen: size_of::<SOCKADDR_IN>(),
        ..ADDRINFOA::default()
    };
    // SAFETY: entry points at the live initialized native value above, whose
    // family and byte length match the allocation. No foreign owner is forged.
    let address = unsafe { socket_address(&entry)? };
    assert_eq!(address, Some("127.9.17.3:8443".parse()?));
    Ok(())
}

#[test]
fn ipv6_conversion_keeps_scope_flow_and_port() -> TestResult {
    let mut native = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 443_u16.to_be(),
        sin6_flowinfo: 47,
        ..SOCKADDR_IN6::default()
    };
    native.sin6_addr.u.Byte = Ipv6Addr::LOCALHOST.octets();
    native.Anonymous.sin6_scope_id = 9;
    let entry = ADDRINFOA {
        ai_family: i32::from(AF_INET6),
        ai_addr: (&raw mut native).cast(),
        ai_addrlen: size_of::<SOCKADDR_IN6>(),
        ..ADDRINFOA::default()
    };
    // SAFETY: entry borrows the live initialized SDK sockaddr above with its
    // exact family and size; the conversion copies it before these locals drop.
    let address = unsafe { socket_address(&entry)? };
    assert_eq!(
        address,
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            47,
            9
        )))
    );
    Ok(())
}

#[test]
fn null_or_short_known_addresses_are_rejected_before_reading() {
    for family in [AF_INET, AF_INET6] {
        let entry = ADDRINFOA {
            ai_family: i32::from(family),
            ..ADDRINFOA::default()
        };
        // SAFETY: the optional pointer is null, which the conversion checks
        // without dereferencing; no dangling memory is used as a fixture.
        let result = unsafe { socket_address(&entry) };
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }

    let mut v4 = SOCKADDR_IN::default();
    let mut v6 = SOCKADDR_IN6::default();
    for entry in [
        ADDRINFOA {
            ai_family: i32::from(AF_INET),
            ai_addr: (&raw mut v4).cast(),
            ai_addrlen: size_of::<SOCKADDR_IN>() - 1,
            ..ADDRINFOA::default()
        },
        ADDRINFOA {
            ai_family: i32::from(AF_INET6),
            ai_addr: (&raw mut v6).cast(),
            ai_addrlen: size_of::<SOCKADDR_IN6>() - 1,
            ..ADDRINFOA::default()
        },
    ] {
        // SAFETY: both entries borrow live SDK allocations. Their deliberately
        // short advertised lengths must be rejected before either is read.
        let result = unsafe { socket_address(&entry) };
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
}

#[test]
fn canonical_names_are_copied_and_invalid_metadata_is_rejected() -> TestResult {
    let name = CString::new("origin.example.")?;
    // SAFETY: each pointer is null or points to the live terminated allocation
    // passed here; none is used after its owner drops.
    let copied = unsafe { copy_canonical_name(name.as_ptr().cast())? };
    assert_eq!(copied.as_deref(), Some(name.as_c_str()));
    // SAFETY: a null canonical pointer is an explicitly supported API result.
    assert!(unsafe { copy_canonical_name(ptr::null())? }.is_none());
    for bytes in [
        vec![0xff, 0],
        vec![b'a'; MAX_CANONICAL_NAME_BYTES + 1]
            .into_iter()
            .chain([0])
            .collect(),
    ] {
        // SAFETY: bytes owns a terminated allocation for the whole call,
        // including every byte the bounded scan can inspect.
        assert!(unsafe { copy_canonical_name(bytes.as_ptr()) }.is_err());
    }
    Ok(())
}

#[test]
fn ttl_flags_match_firefox_and_permit_native_wire_queries() {
    assert_eq!(TTL_QUERY_OPTIONS, 0x0010_08c1);
    assert_eq!(TTL_QUERY_OPTIONS & DNS_QUERY_NO_WIRE_QUERY, 0);
}

#[test]
fn only_winsock_2_2_is_accepted() -> TestResult {
    validate_winsock_version(0x0202)?;
    for version in [0, 0x0001, 0x0101, 0x0002, 0x0102, 0x0201, 0x0303] {
        assert_eq!(
            validate_winsock_version(version)
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(WSAVERNOTSUPPORTED)
        );
    }
    Ok(())
}

#[test]
fn dns_header_reads_do_not_require_a_record_data_allocation() {
    // DNS_RECORD_FIXED_SIZE is FIELD_OFFSET(DNS_RECORD, Data) in the SDK.
    // This local prefix is deliberately too small for the complete RDATA union.
    let mut bytes = [0_u8; std::mem::offset_of!(DNS_RECORDA, Data)];
    assert!(bytes.len() < size_of::<DNS_RECORDA>());
    let record = bytes.as_mut_ptr().cast::<DNS_RECORDA>();
    // SAFETY: all projected fields are within this initialized fixed-header
    // allocation. Unaligned writes/reads need no DNS_RECORDA alignment. This
    // local buffer is never wrapped as an OS list or passed to an OS free.
    let header = unsafe {
        ptr::addr_of_mut!((*record).pNext).write_unaligned(ptr::null_mut());
        ptr::addr_of_mut!((*record).wType).write_unaligned(DNS_TYPE_AAAA);
        ptr::addr_of_mut!((*record).Flags.DW).write_unaligned(0xa5a5_0001);
        ptr::addr_of_mut!((*record).dwTtl).write_unaligned(47);
        record_header(record)
    };
    assert!(header.next.is_null());
    assert_eq!(header.record_type, DNS_TYPE_AAAA);
    assert_eq!(header.section, 1);
    assert_eq!(header.ttl, 47);
}

#[test]
#[ignore = "uses example.com; run explicitly after native boundary review"]
fn example_com_exact_native_ttl_options() -> TestResult {
    let (addresses, ttl) = resolve("example.com")?;
    assert!(!addresses.is_empty());
    let SystemTtl::Deadline(deadline) = ttl else {
        return Err("native example.com query returned no usable TTL".into());
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    eprintln!("Firefox native options={TTL_QUERY_OPTIONS:#x}, remaining={remaining:?}");
    Ok(())
}
