//! Integration tests of `phantom-profile`, one module per area of the public API.
//!
//! Covers exact catalog definitions and original component values.

mod catalog;
mod client_hints_components;
mod compositions;
mod constructors;
mod cookie_components;
mod dns_components;
mod historical;
mod http1_components;
mod http2_components;
mod http3_components;
mod macos;
mod proxy_connect_components;
mod quic_components;
mod request_templates;
mod tcp_components;
mod udp_components;
mod websocket_components;
