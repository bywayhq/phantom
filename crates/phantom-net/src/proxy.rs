//! Proxy negotiation and tunneled byte streams.

mod authentication;
mod challenge;
mod challenged_connection;
mod connect_udp;
mod connect_udp_pool;
mod credential_cache;
mod credential_frame;
mod credentials;
mod digest;
mod error;
pub(crate) mod http1_opening;
mod http2_connect;
mod http2_pool;
mod http_connect;
mod https_connect;
mod socks4;
mod socks5;
mod socks5_udp;
mod tunnel;

pub use authentication::{HttpBasicCredentials, validate_basic_proxy_challenge};
pub use challenged_connection::MAX_CHALLENGE_BODY_BYTES;
pub(crate) use connect_udp::PreparedConnectUdp;
pub(crate) use connect_udp_pool::prepared_outer_error as connect_udp_prepared_error;
pub(crate) use connect_udp_pool::{
    Acquisition, OuterSession, PoolKey, ProxySettingsId, TunnelLease,
};
pub use connect_udp_pool::{
    ConnectUdpProxyPool, MAX_CONNECT_UDP_POOL_KEYS, PreparedConnectUdpOuter,
};
pub(crate) use credential_cache::{AuthAttempt, AuthStep, BasicAuthPlan};
pub use credential_cache::{MAX_PROXY_CREDENTIAL_ENTRIES, ProxyCredentialCache, ProxyScheme};
pub use credentials::{HttpProxyAuthentication, HttpProxyCredentials};
pub use digest::{
    DigestAuthError, DigestForwardAuthentication, DigestPolicy, DigestResponseAuthentication,
    HttpDigestCredentials,
};
pub use error::{HttpConnectError, HttpConnectErrorKind};
pub use http_connect::{HttpConnectHeader, connect_http_tunnel};
pub(crate) use http_connect::{
    connect_http_tunnel_from_stream, http_connect_tunnel, http_connect_tunnel_with_basic_auth,
    http_connect_tunnel_with_digest_auth, validate_http_tunnel,
};
pub use http2_pool::{
    HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING, Http2ProxyPool, MAX_HTTP2_PROXY_POOL_ROUTES,
    MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION,
};
pub(crate) use https_connect::HttpsProxyTunnel;
pub use https_connect::{HttpsProxyConnector, HttpsProxyProtocol};
pub(crate) use socks4::socks4_tunnel;
pub use socks4::{Socks4Error, Socks4ErrorKind, Socks4UserId};
pub use socks5::{Socks5Auth, Socks5Error, Socks5ErrorKind};
pub(crate) use socks5::{socks5_tunnel_local_dns, socks5_tunnel_remote_dns};
pub(crate) use socks5_udp::{
    associate_socks5_udp_local_with_auth, associate_socks5_udp_remote_with_auth,
    prepare_socks5_udp_remote_target,
};
pub use tunnel::TunnelStream;

#[cfg(test)]
mod tests;
