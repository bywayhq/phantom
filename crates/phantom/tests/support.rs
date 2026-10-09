//! Loopback servers, fixtures, and helpers shared by the test binaries.

// Each helper serves some of the modules, so each binary and each build
// without every feature leaves some of them unused.
#![allow(dead_code)]

#[path = "support/client_certificate.rs"]
pub(crate) mod client_certificate;
#[cfg(feature = "https-records")]
#[path = "support/ech.rs"]
pub(crate) mod ech;
#[path = "support/h2.rs"]
pub(crate) mod h2;
#[path = "support/h3.rs"]
pub(crate) mod h3;
#[path = "support/http3_upgrade.rs"]
pub(crate) mod http3_upgrade;
#[path = "support/masque.rs"]
pub(crate) mod masque;
#[path = "support/shared_port.rs"]
pub(crate) mod shared_port;
#[path = "support/socks5.rs"]
pub(crate) mod socks5;
#[path = "support/socks5_udp.rs"]
pub(crate) mod socks5_udp;
#[path = "support/tls.rs"]
pub(crate) mod tls;
#[path = "support/tracing.rs"]
pub(crate) mod tracing;
#[path = "support/tunnel_proxy.rs"]
pub(crate) mod tunnel_proxy;
#[cfg(feature = "websocket")]
#[path = "support/websocket.rs"]
pub(crate) mod websocket;
#[cfg(feature = "websocket")]
#[path = "support/websocket_origin.rs"]
pub(crate) mod websocket_origin;
