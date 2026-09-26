//! `phantom-http` integration tests: HTTP/3, Alt-Svc upgrades, HTTPS records, and CONNECT-UDP.
//!
//! Each module covers one area of the public API. `support` holds the loopback
//! servers and helpers that the crate's test binaries share.

#[path = "../support/mod.rs"]
mod support;

mod alt_svc_frames;
mod alt_svc_persistence;
mod alt_svc_race;
mod connect_udp;
mod http3;
mod http3_early_data;
mod http3_retries;
mod http3_session_resumption;
mod http3_upgrade;
mod http3_upgrade_socks5;
#[cfg(feature = "https-records")]
mod https_record_ech;
#[cfg(feature = "https-records")]
mod https_record_ech_exact;
#[cfg(feature = "https-records")]
mod https_record_ech_http3;
#[cfg(feature = "https-records")]
mod https_records;
