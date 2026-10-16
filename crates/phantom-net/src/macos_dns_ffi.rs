//! Private macOS DNS read/watch boundary; no native pointer crosses its API.
//!
//! `native/macos_dns.c` projects SDK-owned libresolv state and the optional
//! dnsinfo witness. All native reads and shutdown belong in blocking work.
//! The paired resolver and cache integration is deliberately outside this module.

pub(crate) mod configuration;
pub(crate) mod configuration_watch;

use std::ffi::{c_char, c_void};

const OK: u32 = 0;
const UNAVAILABLE: u32 = 1;
const INVALID: u32 = 2;
const ABI: u32 = 1;
const OPTIONS: u32 = 1;
const RESOLVERS: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawAddress {
    family: u32,
    port: u32,
    scope: u32,
    flow: u32,
    address: [u8; 16],
}

#[repr(C)]
struct RawSettings {
    abi: u32,
    ineligible: u32,
    nameserver_count: u32,
    search_count: u32,
    ndots: u32,
    attempts: u32,
    retrans_seconds: u32,
    rotate: u32,
    nameservers: [RawAddress; 3],
    search: [[u8; 256]; 6],
}

impl Default for RawSettings {
    fn default() -> Self {
        Self {
            abi: 0,
            ineligible: 0,
            nameserver_count: 0,
            search_count: 0,
            ndots: 0,
            attempts: 0,
            retrans_seconds: 0,
            rotate: 0,
            nameservers: [RawAddress::default(); 3],
            search: [[0; 256]; 6],
        }
    }
}

const _: () = assert!(std::mem::size_of::<RawAddress>() == 32);
const _: () = assert!(std::mem::size_of::<RawSettings>() == 1664);

unsafe extern "C" {
    fn phantom_macos_dns_read(out: *mut RawSettings, detail: *mut u32) -> u32;
    fn phantom_macos_dns_watch_start(
        hosts_path: *const c_char,
        out: *mut *mut c_void,
        detail: *mut u32,
    ) -> u32;
    fn phantom_macos_dns_watch_wait(
        owner: *mut c_void,
        control: i32,
        event: *mut u32,
        detail: *mut u32,
    ) -> u32;
    fn phantom_macos_dns_watch_check(
        owner: *mut c_void,
        changed: *mut u32,
        detail: *mut u32,
    ) -> u32;
    fn phantom_macos_dns_watch_close(owner: *mut c_void, detail: *mut u32) -> u32;
}

#[cfg(test)]
mod tests;
