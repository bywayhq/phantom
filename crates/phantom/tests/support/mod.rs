//! Loopback servers, fixtures, and helpers shared by the test binaries.

// Each helper serves some of the modules, so each binary and each build
// without every feature leaves some of them unused.
#![allow(dead_code)]

#[cfg(feature = "https-records")]
pub(crate) mod ech;
pub(crate) mod h2;
pub(crate) mod h3;
pub(crate) mod http3_upgrade;
pub(crate) mod masque;
pub(crate) mod reserved_port;
pub(crate) mod socks5;
pub(crate) mod socks5_udp;
pub(crate) mod tls;
pub(crate) mod tracing;
pub(crate) mod tunnel_proxy;
#[cfg(feature = "websocket")]
pub(crate) mod websocket;
#[cfg(feature = "websocket")]
pub(crate) mod websocket_origin;
