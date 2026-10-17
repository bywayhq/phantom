//! Connection facts retained independently of request observation.

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use btls::{ssl::SslRef, x509::X509};
use phantom_profile::{CipherSuite, TlsVersion};

/// Endpoint addresses exposed by the transport, rather than inferred from DNS.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectionEndpointScope {
    /// The byte stream does not expose its underlying endpoints.
    #[default]
    Unavailable,
    /// Operating-system TCP socket addresses. A proxied socket reaches the proxy.
    TcpSocket,
    /// QUIC endpoint addresses, which may belong to a virtual proxy transport.
    QuicEndpoint,
}

/// Facts observed when an origin HTTP attempt selects a connection.
///
/// This is separate from TLS session resumption. `reused` means an earlier
/// HTTP request was dispatched on the same HTTP connection, including CONNECT
/// and requests that subsequently failed. It does not prove bytes were sent.
#[derive(Clone, Debug)]
pub struct RequestConnection {
    /// Whether another HTTP request was dispatched on this HTTP connection.
    pub reused: bool,
    /// What the endpoint addresses describe.
    pub endpoint_scope: ConnectionEndpointScope,
    /// Bound local transport address. A QUIC bind can use an unspecified IP.
    pub local_address: Option<SocketAddr>,
    /// Transport peer, which can be a proxy rather than the origin.
    pub peer_address: Option<SocketAddr>,
    /// Origin TLS. An opaque stream may leave it unavailable.
    pub origin_tls: TlsConnectionState,
    /// Outer HTTPS proxy TLS. Virtual QUIC transports may leave it unavailable.
    pub proxy_tls: TlsConnectionState,
}

/// TLS state at the time the connection-use event was recorded.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum TlsConnectionState {
    /// This transport layer does not use TLS.
    NotUsed,
    /// The transport does not expose this layer's TLS metadata.
    Unavailable,
    /// The connection was usable for early data before its handshake completed.
    Pending,
    /// The handshake completed. Verification depends on `peer_verified`.
    Established(Arc<TlsConnectionInfo>),
}

/// Negotiated TLS facts and available peer certificates.
///
/// Certificate bytes are shared across observations. Debug output omits them.
/// A resumed handshake may expose certificates retained from its session.
#[derive(Clone)]
pub struct TlsConnectionInfo {
    /// Whether the completed handshake used server-name and chain verification.
    pub peer_verified: bool,
    /// Negotiated TLS version, if the backend maps it to a supported value.
    pub version: Option<TlsVersion>,
    /// Negotiated cipher suite, if the backend maps its IANA identifier.
    pub cipher_suite: Option<CipherSuite>,
    /// Negotiated ALPN bytes, absent when no protocol was selected.
    pub alpn: Option<Arc<[u8]>>,
    /// Whether this handshake resumed a TLS session.
    pub session_resumed: bool,
    /// Available leaf-first DER chain, without constructing a trust chain.
    /// `None` means the backend supplied none or DER encoding failed.
    pub peer_certificates: Option<Arc<[Arc<[u8]>]>>,
}

impl fmt::Debug for TlsConnectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectionInfo")
            .field("peer_verified", &self.peer_verified)
            .field("version", &self.version)
            .field("cipher_suite", &self.cipher_suite)
            .field("alpn", &self.alpn)
            .field("session_resumed", &self.session_resumed)
            .field(
                "certificate_count",
                &self.peer_certificates.as_ref().map(|chain| chain.len()),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TlsPeerRole {
    #[default]
    Origin,
    Proxy,
}

/// Holds backend certificate references until diagnostics first needs DER.
pub(crate) struct TlsMetadata {
    pub(crate) role: TlsPeerRole,
    verified: bool,
    completed: OnceLock<TlsFacts>,
    encoded: OnceLock<Arc<TlsConnectionInfo>>,
}

struct TlsFacts {
    version: Option<TlsVersion>,
    cipher_suite: Option<CipherSuite>,
    alpn: Option<Arc<[u8]>>,
    resumed: bool,
    certificates: Vec<X509>,
}

impl TlsMetadata {
    pub(crate) fn new(role: TlsPeerRole, verified: bool) -> Arc<Self> {
        Arc::new(Self {
            role,
            verified,
            completed: OnceLock::new(),
            encoded: OnceLock::new(),
        })
    }

    pub(crate) fn complete(&self, ssl: &SslRef) {
        self.completed.get_or_init(|| TlsFacts {
            version: crate::tls::negotiated_tls_version(ssl.version2()),
            cipher_suite: ssl
                .current_cipher()
                .and_then(|cipher| CipherSuite::from_iana_id(cipher.protocol_id())),
            alpn: ssl.selected_alpn_protocol().map(Arc::from),
            resumed: ssl.session_reused(),
            certificates: ssl.peer_cert_chain().map_or_else(Vec::new, |chain| {
                chain.iter().map(|cert| cert.to_owned()).collect()
            }),
        });
    }

    fn snapshot(&self) -> TlsConnectionState {
        let Some(facts) = self.completed.get() else {
            return TlsConnectionState::Pending;
        };
        TlsConnectionState::Established(Arc::clone(self.encoded.get_or_init(|| {
            let certificates = (!facts.certificates.is_empty())
                .then(|| {
                    facts
                        .certificates
                        .iter()
                        .map(|cert| cert.to_der().map(Arc::from))
                        .collect::<Result<Vec<_>, _>>()
                        .ok()
                        .map(Arc::from)
                })
                .flatten();
            Arc::new(TlsConnectionInfo {
                peer_verified: self.verified,
                version: facts.version,
                cipher_suite: facts.cipher_suite,
                alpn: facts.alpn.clone(),
                session_resumed: facts.resumed,
                peer_certificates: certificates,
            })
        })))
    }
}

#[derive(Clone, Default)]
pub(crate) struct ConnectionMetadata {
    pub(crate) scope: ConnectionEndpointScope,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) origin_tls: Option<Arc<TlsMetadata>>,
    pub(crate) proxy_tls: Option<Arc<TlsMetadata>>,
    pub(crate) layers_known: bool,
}

impl ConnectionMetadata {
    fn snapshot(&self, reused: bool) -> RequestConnection {
        RequestConnection {
            reused,
            endpoint_scope: self.scope,
            local_address: self.local,
            peer_address: self.peer,
            origin_tls: self
                .origin_tls
                .as_ref()
                .map_or_else(|| self.absent_tls(), |tls| tls.snapshot()),
            proxy_tls: self
                .proxy_tls
                .as_ref()
                .map_or_else(|| self.absent_tls(), |tls| tls.snapshot()),
        }
    }

    fn absent_tls(&self) -> TlsConnectionState {
        if self.layers_known {
            TlsConnectionState::NotUsed
        } else {
            TlsConnectionState::Unavailable
        }
    }
}

/// Implemented only by transports whose endpoint and TLS ownership is known.
pub(crate) trait ConnectionMetadataSource {
    fn connection_metadata(&self) -> ConnectionMetadata;
}

#[derive(Default)]
pub(crate) struct ConnectionRecord {
    metadata: OnceLock<ConnectionMetadata>,
    used: AtomicBool,
}

impl ConnectionRecord {
    pub(crate) fn mark_used(&self) {
        self.used.store(true, Ordering::Relaxed);
    }
    pub(crate) fn set(&self, metadata: ConnectionMetadata) {
        self.metadata.get_or_init(|| metadata);
    }

    pub(crate) fn metadata(&self) -> ConnectionMetadata {
        self.metadata.get().cloned().unwrap_or_default()
    }

    pub(crate) fn observe(&self, protocol: http::Version) {
        self.observe_with(protocol, |reused| {
            self.metadata
                .get()
                .cloned()
                .unwrap_or_default()
                .snapshot(reused)
        });
    }

    pub(crate) fn observe_with(
        &self,
        protocol: http::Version,
        details: impl FnOnce(bool) -> RequestConnection,
    ) {
        // Count unobserved dispatches too, so later diagnostics reports reuse.
        let reused = self.used.swap(true, Ordering::Relaxed);
        crate::request_diagnostics::PhaseObservation::connection(protocol, || details(reused));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_absent_and_incomplete_tls_are_distinct() {
        let unknown = ConnectionMetadata::default().snapshot(false);
        assert!(matches!(
            unknown.origin_tls,
            TlsConnectionState::Unavailable
        ));
        assert!(matches!(unknown.proxy_tls, TlsConnectionState::Unavailable));
        let plain = ConnectionMetadata {
            layers_known: true,
            ..Default::default()
        }
        .snapshot(false);
        assert!(matches!(plain.origin_tls, TlsConnectionState::NotUsed));
        let tls = TlsMetadata::new(TlsPeerRole::Origin, true);
        assert!(matches!(tls.snapshot(), TlsConnectionState::Pending));
    }

    #[test]
    fn debug_omits_certificate_bytes() {
        let tls = TlsConnectionInfo {
            peer_verified: false,
            version: None,
            cipher_suite: None,
            alpn: None,
            session_resumed: false,
            peer_certificates: Some(Arc::from([Arc::from(&b"secret-certificate"[..])])),
        };
        let debug = format!("{tls:?}");
        assert!(debug.contains("certificate_count: Some(1)"));
        assert!(!debug.contains("secret-certificate"));
        assert!(!debug.contains("115, 101, 99"));
    }
}
