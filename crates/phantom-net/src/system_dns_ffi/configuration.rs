//! Read-only Windows adapter and registry DNS snapshot.
//!
//! All returned data is owned. API-produced pointers are checked against the
//! original allocation before projecting individual fixed-size fields. No DNS
//! query, socket, notification registration or network-setting mutation occurs.

use std::mem::{align_of, offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GetLastError,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, REG_DWORD, REG_EXPAND_SZ,
    REG_SZ, RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
};

use crate::dns::system_configuration::{
    AdapterDns, ConfigurationError, Devolution, MAX_ADAPTER_NODES, MAX_SUFFIX_UNITS,
    RegistryDnsSettings, WindowsDnsSettings,
};

const _: () = assert!(align_of::<IP_ADAPTER_ADDRESSES_LH>() <= align_of::<u64>());
const _: () = assert!(align_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>() <= align_of::<u64>());

const MAX_BUFFER_BYTES: usize = 1024 * 1024;
const INITIAL_BUFFER_BYTES: usize = 15_000;
const ADAPTER_FLAGS: u32 = 0x27;
const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
const CACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
const PRIMARY: &str = r"SOFTWARE\Policies\Microsoft\System\DNSClient";

pub(crate) fn read_windows_settings() -> Result<WindowsDnsSettings, ConfigurationError> {
    // Registry-view equivalence on WOW64 has not been established for this API.
    if size_of::<usize>() != 8 {
        return Err(ConfigurationError::UnsupportedArchitecture);
    }
    Ok(WindowsDnsSettings {
        adapters: read_adapters()?,
        registry: read_registry()?,
    })
}

fn read_adapters() -> Result<Vec<AdapterDns>, ConfigurationError> {
    let mut requested = INITIAL_BUFFER_BYTES;
    for attempt in 0..3 {
        let mut allocation = AlignedBuffer::new(requested)?;
        let mut length = requested as u32;
        // SAFETY: u64 storage supplies the SDK's 8-byte alignment, with at least
        // `length` writable bytes, and remains exclusively owned through copying.
        // Reserved is null. No pointer is adopted on an error return.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                ADAPTER_FLAGS,
                ptr::null(),
                allocation.words.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if status == ERROR_SUCCESS {
            return decode_adapters(&allocation.view(), allocation.words.as_ptr().cast());
        }
        requested = retry_size(status, requested, length as usize, attempt)?;
    }
    Err(ConfigurationError::Limit("adapter resize attempts"))
}

fn retry_size(
    status: u32,
    current: usize,
    required: usize,
    attempt: usize,
) -> Result<usize, ConfigurationError> {
    if status != ERROR_BUFFER_OVERFLOW {
        return Err(native("GetAdaptersAddresses", status));
    }
    if attempt >= 2 {
        return Err(ConfigurationError::Limit("adapter resize attempts"));
    }
    if required <= current || required > MAX_BUFFER_BYTES {
        return Err(ConfigurationError::Limit("adapter allocation"));
    }
    Ok(required)
}

struct AlignedBuffer {
    words: Vec<u64>,
    bytes: usize,
}

impl AlignedBuffer {
    fn new(bytes: usize) -> Result<Self, ConfigurationError> {
        if bytes == 0 || bytes > MAX_BUFFER_BYTES {
            return Err(ConfigurationError::Limit("adapter allocation"));
        }
        let count = bytes.div_ceil(size_of::<u64>());
        let mut words = Vec::new();
        words
            .try_reserve_exact(count)
            .map_err(|_| ConfigurationError::Allocation)?;
        words.resize(count, 0);
        Ok(Self { words, bytes })
    }

    fn view(&self) -> BufferView<'_> {
        BufferView {
            words: &self.words,
            bytes: self.bytes,
        }
    }
}

struct BufferView<'a> {
    words: &'a [u64],
    bytes: usize,
}

impl BufferView<'_> {
    fn offset(&self, address: usize, length: usize) -> Result<usize, ConfigurationError> {
        let start = address
            .checked_sub(self.words.as_ptr().addr())
            .ok_or(ConfigurationError::InvalidData("adapter pointer"))?;
        let end = start
            .checked_add(length)
            .ok_or(ConfigurationError::InvalidData("adapter span"))?;
        if end > self.bytes {
            return Err(ConfigurationError::InvalidData("adapter span"));
        }
        Ok(start)
    }

    /// The caller must select a native field whose type admits every bit pattern.
    unsafe fn field<T: Copy>(
        &self,
        node: usize,
        declared: usize,
        offset: usize,
    ) -> Result<T, ConfigurationError> {
        let end = offset
            .checked_add(size_of::<T>())
            .ok_or(ConfigurationError::InvalidData("field span"))?;
        if end > declared {
            return Err(ConfigurationError::InvalidData("node length"));
        }
        let address = node
            .checked_add(offset)
            .ok_or(ConfigurationError::InvalidData("field pointer"))?;
        let index = self.offset(address, size_of::<T>())?;
        // SAFETY: the checks above bound all bytes within the owned allocation;
        // the caller's field contract guarantees a valid bit pattern. Reading
        // through the original base retains allocation provenance. No reference
        // to the variable-length native struct is created; alignment is optional.
        Ok(unsafe {
            self.words
                .as_ptr()
                .cast::<u8>()
                .add(index)
                .cast::<T>()
                .read_unaligned()
        })
    }

    fn wide_string(&self, address: usize) -> Result<String, ConfigurationError> {
        if address == 0 {
            return Ok(String::new());
        }
        let mut units = Vec::new();
        units
            .try_reserve_exact(MAX_SUFFIX_UNITS)
            .map_err(|_| ConfigurationError::Allocation)?;
        for index in 0..MAX_SUFFIX_UNITS {
            // SAFETY: u16 permits every bit pattern; field checks each pair of
            // bytes against the original allocation before reading it.
            let unit = unsafe { self.field::<u16>(address, MAX_SUFFIX_UNITS * 2, index * 2)? };
            if unit == 0 {
                return String::from_utf16(&units)
                    .map_err(|_| ConfigurationError::InvalidData("suffix UTF-16"));
            }
            units.push(unit);
        }
        Err(ConfigurationError::Limit("suffix termination"))
    }
}

// Only primitive/pointer types and SOCKET_ADDRESS (pointer + i32) are selected.
macro_rules! field {
    ($view:expr, $node:expr, $declared:expr, $owner:ty, $name:ident, $value:ty) => {{
        // SAFETY: each invocation selects an SDK field whose explicit value
        // type has no invalid bit patterns. The view validates its byte span.
        unsafe { $view.field::<$value>($node, $declared, offset_of!($owner, $name))? }
    }};
}

fn visit(address: usize, visited: &mut Vec<usize>) -> Result<(), ConfigurationError> {
    if visited.len() >= MAX_ADAPTER_NODES {
        return Err(ConfigurationError::Limit("adapter and DNS node count"));
    }
    if visited.contains(&address) {
        return Err(ConfigurationError::InvalidData("adapter cycle or alias"));
    }
    visited
        .try_reserve(1)
        .map_err(|_| ConfigurationError::Allocation)?;
    visited.push(address);
    Ok(())
}

fn decode_adapters(
    view: &BufferView<'_>,
    head: *const IP_ADAPTER_ADDRESSES_LH,
) -> Result<Vec<AdapterDns>, ConfigurationError> {
    let mut result = Vec::new();
    let mut visited = Vec::new();
    let mut current = head.addr();
    while current != 0 {
        visit(current, &mut visited)?;
        // SAFETY: the SDK union starts with its u32 Length, whose bit pattern is
        // unrestricted; field bounds it before reading even a truncated node.
        let declared = unsafe { view.field::<u32>(current, 4, 0)? } as usize;
        view.offset(current, declared)?;
        let next = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            Next,
            *mut IP_ADAPTER_ADDRESSES_LH
        );
        // SAFETY: the first union is Length:u32 followed by IfIndex:u32.
        // Both fields are fixed-width integers. No union reference is formed.
        let if_index = unsafe { view.field::<u32>(current, declared, size_of::<u32>())? };
        let ipv6_if_index = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            Ipv6IfIndex,
            u32
        );
        let if_type = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            IfType,
            u32
        );
        let oper_status = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            OperStatus,
            i32
        );
        let suffix = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            DnsSuffix,
            *mut u16
        );
        let dns = field!(
            view,
            current,
            declared,
            IP_ADAPTER_ADDRESSES_LH,
            FirstDnsServerAddress,
            *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP
        );
        let mut servers = Vec::new();
        let mut node = dns.addr();
        while node != 0 {
            visit(node, &mut visited)?;
            // SAFETY: this SDK union also starts with the unrestricted u32 Length.
            let length = unsafe { view.field::<u32>(node, 4, 0)? } as usize;
            view.offset(node, length)?;
            let next_dns = field!(
                view,
                node,
                length,
                IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
                Next,
                *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP
            );
            let address = field!(
                view,
                node,
                length,
                IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
                Address,
                SOCKET_ADDRESS
            );
            let server = decode_socket(view, address)?;
            servers
                .try_reserve(1)
                .map_err(|_| ConfigurationError::Allocation)?;
            servers.push(server);
            node = next_dns.addr();
        }
        let suffix = view.wide_string(suffix.addr())?;
        result
            .try_reserve(1)
            .map_err(|_| ConfigurationError::Allocation)?;
        result.push(AdapterDns {
            if_index,
            ipv6_if_index,
            if_type,
            oper_status,
            servers,
            suffix,
        });
        current = next.addr();
    }
    Ok(result)
}

fn decode_socket(
    view: &BufferView<'_>,
    socket: SOCKET_ADDRESS,
) -> Result<SocketAddr, ConfigurationError> {
    let length = usize::try_from(socket.iSockaddrLength)
        .map_err(|_| ConfigurationError::InvalidData("sockaddr length"))?;
    let address = socket.lpSockaddr.addr();
    view.offset(address, length)?;
    // SAFETY: the family is a u16 within the checked caller-provided length.
    let family = unsafe { view.field::<u16>(address, length, 0)? };
    match family {
        AF_INET => {
            let port = field!(view, address, length, SOCKADDR_IN, sin_port, u16);
            let ip = field!(view, address, length, SOCKADDR_IN, sin_addr, u32);
            if length < size_of::<SOCKADDR_IN>() {
                return Err(ConfigurationError::InvalidData("IPv4 sockaddr length"));
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip.to_ne_bytes()),
                u16::from_be(port),
            )))
        }
        AF_INET6 => {
            let port = field!(view, address, length, SOCKADDR_IN6, sin6_port, u16);
            let flow = field!(view, address, length, SOCKADDR_IN6, sin6_flowinfo, u32);
            let ip = field!(view, address, length, SOCKADDR_IN6, sin6_addr, [u8; 16]);
            let scope = field!(view, address, length, SOCKADDR_IN6, Anonymous, u32);
            if length < size_of::<SOCKADDR_IN6>() {
                return Err(ConfigurationError::InvalidData("IPv6 sockaddr length"));
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                u16::from_be(port),
                flow,
                scope,
            )))
        }
        _ => Err(ConfigurationError::InvalidData("sockaddr family")),
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: only a successful open creates this unique owning handle;
        // RegCloseKey is its matching close operation. It is never cloned.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

impl RegistryKey {
    fn open(path: &str) -> Result<Option<Self>, ConfigurationError> {
        let name = terminated(path);
        let mut handle = ptr::null_mut();
        // SAFETY: name is terminated and live through the call; output storage
        // is writable. HKLM is predefined. Rights are read-only. On failure the
        // output is never owned or closed.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                name.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                &mut handle,
            )
        };
        if !present(status, "RegOpenKeyExW")? {
            return Ok(None);
        }
        if handle.is_null() {
            return Err(ConfigurationError::InvalidData("registry handle"));
        }
        Ok(Some(Self(handle)))
    }

    fn string(&self, name: &str) -> Result<Option<String>, ConfigurationError> {
        let name = terminated(name);
        let mut units = [0u16; MAX_SUFFIX_UNITS];
        let mut kind = 0;
        let mut bytes = (units.len() * 2) as u32;
        // SAFETY: initialized aligned storage has exactly `bytes` writable
        // bytes; name is terminated; handle is owned and open for queries.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                units.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if !present(status, "RegQueryValueExW")? {
            return Ok(None);
        }
        let raw = registry_units(kind, bytes as usize, &units)?;
        if kind == REG_EXPAND_SZ {
            let mut expanded = [0u16; MAX_SUFFIX_UNITS];
            // SAFETY: raw includes its checked terminating NUL; separate writable
            // output has nSize units. No process environment is modified.
            let copied = unsafe {
                ExpandEnvironmentStringsW(
                    raw.as_ptr(),
                    expanded.as_mut_ptr(),
                    MAX_SUFFIX_UNITS as u32,
                )
            };
            if copied == 0 {
                // SAFETY: read the calling thread's error immediately after the
                // failing expansion, before another Windows call can replace it.
                return Err(native("ExpandEnvironmentStringsW", unsafe {
                    GetLastError()
                }));
            }
            let expanded = expansion_units(copied as usize, &expanded)?;
            return decode_wide(expanded).map(Some);
        }
        decode_wide(&raw[..raw.len() - 1]).map(Some)
    }

    fn dword(&self, name: &str) -> Result<Option<u32>, ConfigurationError> {
        let name = terminated(name);
        let mut value = 0u32;
        let mut bytes = size_of::<u32>() as u32;
        let mut kind = 0;
        // SAFETY: value supplies 4 writable initialized bytes, and both output
        // metadata pointers are valid. The key and terminated name remain live.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                (&raw mut value).cast(),
                &mut bytes,
            )
        };
        if !present(status, "RegQueryValueExW")? {
            return Ok(None);
        }
        registry_dword(kind, bytes, value).map(Some)
    }

    fn has_subkeys(&self) -> Result<bool, ConfigurationError> {
        let mut count = 0;
        // SAFETY: count is writable, all other optional outputs are null. The
        // handle remains owned and open with read-only enumeration rights.
        let status = unsafe {
            RegQueryInfoKeyW(
                self.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                &mut count,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(native("RegQueryInfoKeyW", status));
        }
        Ok(count != 0)
    }

    fn devolution(&self) -> Result<Devolution, ConfigurationError> {
        Ok(Devolution {
            enabled: self.dword("UseDomainNameDevolution")?,
            level: self.dword("DomainNameDevolutionLevel")?,
        })
    }
}

fn terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn native(operation: &'static str, code: u32) -> ConfigurationError {
    ConfigurationError::Native { operation, code }
}

fn present(status: u32, operation: &'static str) -> Result<bool, ConfigurationError> {
    match status {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(false),
        _ => Err(native(operation, status)),
    }
}

fn registry_dword(kind: u32, bytes: u32, value: u32) -> Result<u32, ConfigurationError> {
    if kind != REG_DWORD || bytes != 4 {
        return Err(ConfigurationError::InvalidData("registry DWORD"));
    }
    Ok(value)
}

fn registry_units(kind: u32, bytes: usize, buffer: &[u16]) -> Result<&[u16], ConfigurationError> {
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return Err(ConfigurationError::InvalidData("registry string type"));
    }
    if bytes == 0 || !bytes.is_multiple_of(2) || bytes / 2 > buffer.len() {
        return Err(ConfigurationError::InvalidData("registry string size"));
    }
    let units = &buffer[..bytes / 2];
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(ConfigurationError::InvalidData(
            "registry string termination",
        ));
    }
    Ok(units)
}

fn expansion_units(copied: usize, buffer: &[u16]) -> Result<&[u16], ConfigurationError> {
    if copied == 0 || copied > buffer.len() {
        return Err(ConfigurationError::Limit("expanded registry string"));
    }
    let units = &buffer[..copied];
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(ConfigurationError::InvalidData(
            "expanded registry string termination",
        ));
    }
    Ok(&units[..units.len() - 1])
}

fn decode_wide(units: &[u16]) -> Result<String, ConfigurationError> {
    String::from_utf16(units).map_err(|_| ConfigurationError::InvalidData("registry UTF-16"))
}

fn subkeys(path: &str) -> Result<bool, ConfigurationError> {
    RegistryKey::open(path)?
        .map(|key| key.has_subkeys())
        .transpose()
        .map(|value| value.unwrap_or(false))
}

fn read_registry() -> Result<RegistryDnsSettings, ConfigurationError> {
    let mut settings = RegistryDnsSettings::default();
    if let Some(key) = RegistryKey::open(TCPIP)? {
        settings.tcpip_search = key.string("SearchList")?;
        settings.tcpip_domain = key.string("Domain")?;
        settings.tcpip_devolution = key.devolution()?;
    }
    if let Some(key) = RegistryKey::open(CACHE)? {
        settings.cache_devolution = key.devolution()?;
    }
    if let Some(key) = RegistryKey::open(POLICY)? {
        settings.policy_search = key.string("SearchList")?;
        settings.policy_devolution = key.devolution()?;
        settings.append_to_multi_label = key.dword("AppendToMultiLabelName")?;
    }
    if let Some(key) = RegistryKey::open(PRIMARY)? {
        settings.primary_suffix = key.string("PrimaryDnsSuffix")?;
    }
    // Evaluate every path, even when the first is present. An unreadable second
    // policy must not be mistaken for a complete configuration snapshot.
    let policy_nrpt = subkeys(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig")?;
    let cache_nrpt =
        subkeys(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig")?;
    let connections =
        subkeys(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsConnections")?;
    let proxies =
        subkeys(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsConnectionsProxies")?;
    settings.nrpt_present = policy_nrpt || cache_nrpt;
    settings.proxy_present = connections || proxies;
    Ok(settings)
}

#[cfg(test)]
mod tests;
