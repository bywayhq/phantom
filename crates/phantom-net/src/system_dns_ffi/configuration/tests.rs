use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Only integer and raw-pointer fields are written. Avoid copying a padded SDK
// struct into u64 storage: its Rust padding need not be initialized.
fn put<T: Copy>(buffer: &mut AlignedBuffer, offset: usize, value: T) {
    assert!(offset + size_of::<T>() <= buffer.bytes);
    // SAFETY: the assertion bounds the write in the owned allocation; call sites
    // use primitive/pointer values with no uninitialized padding or destructors.
    unsafe {
        buffer
            .words
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<T>()
            .write_unaligned(value);
    }
}

fn pointer<T>(buffer: &AlignedBuffer, offset: usize) -> *mut T {
    buffer
        .words
        .as_ptr()
        .cast::<u8>()
        .wrapping_add(offset)
        .cast_mut()
        .cast()
}

fn adapter(
    buffer: &mut AlignedBuffer,
    offset: usize,
    next: Option<usize>,
    dns: Option<usize>,
    suffix: Option<usize>,
) {
    let next = next.map_or(ptr::null_mut(), |offset| {
        pointer::<IP_ADAPTER_ADDRESSES_LH>(buffer, offset)
    });
    let dns = dns.map_or(ptr::null_mut(), |offset| {
        pointer::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(buffer, offset)
    });
    let suffix = suffix.map_or(ptr::null_mut(), |offset| pointer::<u16>(buffer, offset));
    put(buffer, offset, size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32);
    put(buffer, offset + 4, 7u32);
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, Next),
        next,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, Ipv6IfIndex),
        11u32,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, IfType),
        6u32,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, OperStatus),
        1i32,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, FirstDnsServerAddress),
        dns,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_ADDRESSES_LH, DnsSuffix),
        suffix,
    );
}

fn dns_node(
    buffer: &mut AlignedBuffer,
    offset: usize,
    next: Option<usize>,
    socket: usize,
    length: i32,
) {
    let next = next.map_or(ptr::null_mut(), |offset| {
        pointer::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(buffer, offset)
    });
    let socket = pointer::<windows_sys::Win32::Networking::WinSock::SOCKADDR>(buffer, socket);
    put(
        buffer,
        offset,
        size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>() as u32,
    );
    put(
        buffer,
        offset + offset_of!(IP_ADAPTER_DNS_SERVER_ADDRESS_XP, Next),
        next,
    );
    let address = offset + offset_of!(IP_ADAPTER_DNS_SERVER_ADDRESS_XP, Address);
    put(
        buffer,
        address + offset_of!(SOCKET_ADDRESS, lpSockaddr),
        socket,
    );
    put(
        buffer,
        address + offset_of!(SOCKET_ADDRESS, iSockaddrLength),
        length,
    );
}

#[test]
fn copies_ordered_owned_ipv4_ipv6_addresses_and_suffix() -> TestResult {
    let mut buffer = AlignedBuffer::new(4096)?;
    adapter(&mut buffer, 0, None, Some(1024), Some(2048));
    dns_node(
        &mut buffer,
        1024,
        Some(1088),
        1200,
        size_of::<SOCKADDR_IN>() as i32,
    );
    dns_node(
        &mut buffer,
        1088,
        None,
        1280,
        size_of::<SOCKADDR_IN6>() as i32,
    );
    put(&mut buffer, 1200, AF_INET);
    put(
        &mut buffer,
        1200 + offset_of!(SOCKADDR_IN, sin_port),
        5353u16.to_be(),
    );
    put(
        &mut buffer,
        1200 + offset_of!(SOCKADDR_IN, sin_addr),
        u32::from_ne_bytes([192, 0, 2, 17]),
    );
    put(&mut buffer, 1280, AF_INET6);
    put(
        &mut buffer,
        1280 + offset_of!(SOCKADDR_IN6, sin6_port),
        53u16.to_be(),
    );
    put(
        &mut buffer,
        1280 + offset_of!(SOCKADDR_IN6, sin6_flowinfo),
        123u32,
    );
    put(
        &mut buffer,
        1280 + offset_of!(SOCKADDR_IN6, sin6_addr),
        [0xfeu8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    put(
        &mut buffer,
        1280 + offset_of!(SOCKADDR_IN6, Anonymous),
        9u32,
    );
    for (index, unit) in "owned.example".encode_utf16().chain(Some(0)).enumerate() {
        put(&mut buffer, 2048 + index * 2, unit);
    }
    let result = decode_adapters(&buffer.view(), pointer(&buffer, 0))?;
    drop(buffer);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].servers,
        [
            "192.0.2.17:5353".parse()?,
            SocketAddrV6::new("fe80::1".parse()?, 53, 123, 9).into()
        ]
    );
    assert_eq!(result[0].suffix, "owned.example");
    assert_eq!((result[0].if_index, result[0].ipv6_if_index), (7, 11));
    Ok(())
}

#[test]
fn rejects_short_or_oversize_native_nodes_before_field_reads() -> TestResult {
    for length in [0u32, 3, 8, 4097, u32::MAX] {
        let mut buffer = AlignedBuffer::new(4096)?;
        put(&mut buffer, 0, length);
        assert!(decode_adapters(&buffer.view(), pointer(&buffer, 0)).is_err());
    }
    let buffer = AlignedBuffer::new(3)?;
    assert!(decode_adapters(&buffer.view(), pointer(&buffer, 0)).is_err());
    Ok(())
}

#[test]
fn rejects_outside_pointers_and_adapter_or_dns_cycles() -> TestResult {
    let mut buffer = AlignedBuffer::new(4096)?;
    adapter(&mut buffer, 0, Some(0), None, None);
    assert!(matches!(
        decode_adapters(&buffer.view(), pointer(&buffer, 0)),
        Err(ConfigurationError::InvalidData("adapter cycle or alias"))
    ));
    adapter(&mut buffer, 0, Some(5000), None, None);
    assert!(decode_adapters(&buffer.view(), pointer(&buffer, 0)).is_err());
    adapter(&mut buffer, 0, None, Some(1024), None);
    dns_node(
        &mut buffer,
        1024,
        Some(1024),
        1200,
        size_of::<SOCKADDR_IN>() as i32,
    );
    put(&mut buffer, 1200, AF_INET);
    assert!(matches!(
        decode_adapters(&buffer.view(), pointer(&buffer, 0)),
        Err(ConfigurationError::InvalidData("adapter cycle or alias"))
    ));
    dns_node(
        &mut buffer,
        1024,
        None,
        5000,
        size_of::<SOCKADDR_IN>() as i32,
    );
    assert!(decode_adapters(&buffer.view(), pointer(&buffer, 0)).is_err());
    Ok(())
}

#[test]
fn rejects_unknown_truncated_and_negative_socket_lengths() -> TestResult {
    let mut buffer = AlignedBuffer::new(4096)?;
    for (family, length) in [
        (AF_INET, -1),
        (AF_INET, 0),
        (AF_INET, 1),
        (AF_INET, 8),
        (AF_INET6, 16),
        (0xffff, 32),
    ] {
        put(&mut buffer, 1200, family);
        let socket = SOCKET_ADDRESS {
            lpSockaddr: pointer(&buffer, 1200),
            iSockaddrLength: length,
        };
        assert!(decode_socket(&buffer.view(), socket).is_err());
    }
    Ok(())
}

#[test]
fn suffix_reads_require_bounded_terminated_valid_utf16() -> TestResult {
    let mut buffer = AlignedBuffer::new(4096)?;
    for index in 0..MAX_SUFFIX_UNITS {
        put(&mut buffer, index * 2, u16::from(b'x'));
    }
    assert!(matches!(
        buffer.view().wide_string(pointer::<u16>(&buffer, 0).addr()),
        Err(ConfigurationError::Limit("suffix termination"))
    ));
    put(&mut buffer, 0, 0xd800u16);
    put(&mut buffer, 2, 0u16);
    assert!(matches!(
        buffer.view().wide_string(pointer::<u16>(&buffer, 0).addr()),
        Err(ConfigurationError::InvalidData("suffix UTF-16"))
    ));
    assert!(
        buffer
            .view()
            .wide_string(pointer::<u16>(&buffer, 4095).addr())
            .is_err()
    );
    assert_eq!(buffer.view().wide_string(0)?, "");
    Ok(())
}

#[test]
fn aggregate_native_node_budget_includes_adapters_and_dns_nodes() -> TestResult {
    let mut visited = Vec::new();
    for address in 1..=MAX_ADAPTER_NODES {
        visit(address, &mut visited)?;
    }
    assert!(matches!(
        visit(MAX_ADAPTER_NODES + 1, &mut visited),
        Err(ConfigurationError::Limit(_))
    ));
    Ok(())
}

#[test]
fn adapter_resize_retries_are_bounded_and_only_follow_strict_growth() -> TestResult {
    assert_eq!(
        retry_size(ERROR_BUFFER_OVERFLOW, INITIAL_BUFFER_BYTES, 20_000, 0)?,
        20_000
    );
    assert_eq!(
        retry_size(ERROR_BUFFER_OVERFLOW, 20_000, MAX_BUFFER_BYTES, 1)?,
        MAX_BUFFER_BYTES
    );
    for (current, required, attempt) in [
        (INITIAL_BUFFER_BYTES, INITIAL_BUFFER_BYTES, 0),
        (INITIAL_BUFFER_BYTES, 1, 0),
        (INITIAL_BUFFER_BYTES, MAX_BUFFER_BYTES + 1, 0),
        (20_000, 30_000, 2),
    ] {
        assert!(retry_size(ERROR_BUFFER_OVERFLOW, current, required, attempt).is_err());
    }
    assert_eq!(
        retry_size(5, INITIAL_BUFFER_BYTES, 20_000, 0),
        Err(ConfigurationError::Native {
            operation: "GetAdaptersAddresses",
            code: 5
        })
    );
    assert!(AlignedBuffer::new(MAX_BUFFER_BYTES + 1).is_err());
    Ok(())
}

#[test]
fn only_missing_registry_keys_and_values_are_absent() -> TestResult {
    assert!(present(ERROR_SUCCESS, "query")?);
    assert!(!present(ERROR_FILE_NOT_FOUND, "query")?);
    assert!(!present(ERROR_PATH_NOT_FOUND, "open")?);
    for code in [5, 6, 234, 1018] {
        assert_eq!(
            present(code, "query"),
            Err(ConfigurationError::Native {
                operation: "query",
                code
            })
        );
    }
    Ok(())
}

#[test]
fn registry_strings_require_exact_type_size_termination_and_utf16() -> TestResult {
    let buffer = [u16::from(b'x'), 0];
    assert_eq!(registry_units(REG_SZ, 4, &buffer)?, &buffer);
    assert_eq!(registry_units(REG_EXPAND_SZ, 4, &buffer)?, &buffer);
    for (kind, bytes) in [(REG_DWORD, 4), (REG_SZ, 0), (REG_SZ, 3), (REG_SZ, 6)] {
        assert!(registry_units(kind, bytes, &buffer).is_err());
    }
    assert!(registry_units(REG_SZ, 2, &buffer).is_err());
    assert!(registry_units(REG_SZ, 6, &[1, 0, 0]).is_err());
    assert!(decode_wide(&[0xd800]).is_err());
    Ok(())
}

#[test]
fn expansion_counts_include_nul_and_cannot_silently_truncate() -> TestResult {
    let buffer = [u16::from(b'x'), 0, 0, 0];
    assert_eq!(expansion_units(2, &buffer)?, &[u16::from(b'x')]);
    assert!(expansion_units(1, &[0])?.is_empty());
    assert!(expansion_units(0, &buffer).is_err());
    assert!(expansion_units(5, &buffer).is_err());
    assert!(expansion_units(1, &buffer).is_err());
    assert!(expansion_units(4, &buffer).is_err());
    Ok(())
}

#[test]
fn registry_dword_rejects_other_types_and_nonfour_byte_results() -> TestResult {
    assert_eq!(registry_dword(REG_DWORD, 4, u32::MAX)?, u32::MAX);
    for (kind, bytes) in [(REG_SZ, 4), (REG_DWORD, 0), (REG_DWORD, 3), (REG_DWORD, 8)] {
        assert!(registry_dword(kind, bytes, 7).is_err());
    }
    Ok(())
}

#[test]
fn actual_native_traversal_enforces_one_shared_adapter_and_dns_budget() -> TestResult {
    let mut buffer = AlignedBuffer::new(256 * 1024)?;
    adapter(&mut buffer, 0, None, Some(1024), None);
    let stride = 64;
    let socket = 128 * 1024;
    put(&mut buffer, socket, AF_INET);
    for index in 0..MAX_ADAPTER_NODES - 1 {
        let next = (index < MAX_ADAPTER_NODES - 2).then_some(1024 + (index + 1) * stride);
        dns_node(
            &mut buffer,
            1024 + index * stride,
            next,
            socket,
            size_of::<SOCKADDR_IN>() as i32,
        );
    }
    let result = decode_adapters(&buffer.view(), pointer(&buffer, 0))?;
    assert_eq!(result[0].servers.len(), MAX_ADAPTER_NODES - 1);
    let last = 1024 + (MAX_ADAPTER_NODES - 2) * stride;
    dns_node(
        &mut buffer,
        last,
        Some(last + stride),
        socket,
        size_of::<SOCKADDR_IN>() as i32,
    );
    dns_node(
        &mut buffer,
        last + stride,
        None,
        socket,
        size_of::<SOCKADDR_IN>() as i32,
    );
    assert!(matches!(
        decode_adapters(&buffer.view(), pointer(&buffer, 0)),
        Err(ConfigurationError::Limit("adapter and DNS node count"))
    ));
    Ok(())
}
