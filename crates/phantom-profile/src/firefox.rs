//! Wire settings retained from Firefox browser observations.

use crate::{
    cookie::CookiePlacement,
    http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings},
    tcp::TcpSettings,
    tls::{
        CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
        EchGreaseAead, NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
    },
    websocket::{
        WebSocketConnectionPolicy, WebSocketField, WebSocketNewConnection, WebSocketSettings,
    },
};

/// Returns the automatic `Cookie` field position for Firefox 156.
///
/// Firefox adds `Cookie` in `nsHttpChannel::PrepareToConnect`, then
/// `Upgrade-Insecure-Requests` and the `Sec-Fetch-*` fields in
/// `OnBeforeConnect`, and `Priority`, `Pragma`, and `Cache-Control` in
/// `SetupChannelForTransaction`; its HTTP/2 compressor appends `te` last. The
/// retained Firefox 156 HTTP/1.1 EventSource reconnect capture sends `Cookie`
/// after `Referer` and before `Sec-Fetch-Dest`. The other neighbors come from
/// Firefox source, not from a capture.
#[must_use]
pub fn v156_cookie_placement() -> CookiePlacement {
    CookiePlacement::before_fields([
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "priority",
        "pragma",
        "cache-control",
        "te",
    ])
}

/// Returns TLS settings captured from Firefox 154.0 on macOS 15.5 and Windows 11.
///
/// Captures on both platforms (Windows 11 build 26200) match this recipe on
/// every compared field, so the name carries no platform.
///
/// The fixed extension order and exact ECH GREASE payload length retain the
/// stable wire shape observed across the local captures. Firefox picks its ECH
/// GREASE AEAD per connection from AES-128-GCM and ChaCha20-Poly1305 with equal
/// probability; this recipe lists both, so each connection draws one the same
/// way. The delegated-credential vector includes legacy
/// ECDSA-SHA1 because Firefox advertised it; TLS 1.3 authentication cannot
/// select that legacy scheme. The returned value is an ordinary owned
/// [`TlsSettings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::RsaAes256CbcSha,
        ],
        groups: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
            NamedGroup::Ffdhe2048,
            NamedGroup::Ffdhe3072,
        ],
        key_shares: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
        ],
        signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::RsaPkcs1Sha1,
        ],
        delegated_credential_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ],
        session_tickets: true,
        record_size_limit: Some(16_385),
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::Fixed(vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ExtendedMasterSecret,
            ClientHelloExtension::RenegotiationInfo,
            ClientHelloExtension::SupportedGroups,
            ClientHelloExtension::EcPointFormats,
            ClientHelloExtension::SessionTicket,
            ClientHelloExtension::Alpn,
            ClientHelloExtension::StatusRequest,
            ClientHelloExtension::DelegatedCredential,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::RecordSizeLimit,
            ClientHelloExtension::CertificateCompression,
            ClientHelloExtension::EncryptedClientHello,
        ]),
        ech_grease: true,
        ech_grease_payload_length: Some(239),
        ech_grease_aeads: vec![EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305],
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

/// Returns HTTP/2 settings observed from Firefox 154.0 on macOS 15.5 and Windows 11.
///
/// Captures on both platforms (Windows 11 build 26200) match this recipe on
/// every compared field, so the name carries no platform.
///
/// The initial SETTINGS and connection window come from the retained local raw
/// startup-frame capture. Pseudo-header order and request priority come from
/// matching supplemental Peet and Pingly observations; the local capture ends
/// before a request HEADERS frame. The returned value is an ordinary owned
/// [`Http2Settings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ],
        initial_connection_window_size: 12_582_912,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ],
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
    }
}

/// Returns TLS settings captured from Firefox 156.0 on Windows 11.
///
/// Captured from Firefox 156.0 (Windows 11 build 26200) in twelve fresh
/// processes. It reuses [`v154_tls`] and changes only the two fields that
/// differ from Firefox 154: the supported groups no longer offer FFDHE-2048 or
/// FFDHE-3072, and the ECH GREASE payload is 240 bytes instead of 239. Every
/// other compared field, including the fixed extension order, matches 154.
/// Firefox still picks its ECH GREASE AEAD per connection from AES-128-GCM and
/// ChaCha20-Poly1305; this recipe keeps both choices from [`v154_tls`]. The
/// returned value is an ordinary owned [`TlsSettings`].
#[must_use]
pub fn v156_tls() -> TlsSettings {
    let mut settings = v154_tls();
    settings.groups = vec![
        NamedGroup::X25519MlKem768,
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
        NamedGroup::Secp521r1,
    ];
    settings.ech_grease_payload_length = Some(240);
    settings
}

/// Returns the TCP socket options Firefox 156.0 sets on every socket.
///
/// From Firefox source at tag `FIREFOX_156_0_RELEASE`, not from a capture:
/// `nsSocketTransport::InitiateSocket` sets `PR_SockOpt_NoDelay` on each new
/// socket before connecting (`netwerk/base/nsSocketTransport2.cpp:1449-1454`).
///
/// Firefox's TCP keepalive is not modeled, so this recipe leaves
/// `SO_KEEPALIVE` untouched. Firefox changes keepalive per HTTP connection
/// over time: a 10-second idle time for roughly the first 60 seconds of an
/// HTTP/1 connection, then 600 seconds, with a probe interval derived from the
/// measured RTT, and none once a connection negotiates HTTP/2
/// (`netwerk/protocol/http/nsHttpConnection.cpp:405-406`, `:2124-2239`;
/// `modules/libpref/init/all.js:1270-1278`). One fixed socket option cannot
/// reproduce that schedule.
///
/// Firefox's address selection is not modeled either, so addresses are tried
/// one at a time in resolver order. Firefox 156 release builds keep the Happy
/// Eyeballs implementation behind the nightly-only
/// `network.http.happy_eyeballs_enabled` pref
/// (`modules/libpref/init/StaticPrefList.yaml:17057-17060`). The release path
/// opens a backup connection restricted to IPv4 250 ms after the first
/// (`modules/libpref/init/all.js:1213`, `:1245`;
/// `netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`), and its primary
/// connection's address order also depends on per-host family preferences
/// learned from earlier connections and on the DNS record's failure history
/// (`netwerk/protocol/http/DnsAndConnectSocket.cpp:170-178`,
/// `netwerk/base/nsSocketTransport2.cpp:1742-1745`, `:1785-1787`).
#[must_use]
pub fn v156_tcp() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: None,
        address_racing: None,
    }
}

/// Returns HTTP/2 settings observed from Firefox 156.0 on Windows 11.
///
/// Firefox 156.0 (Windows 11 build 26200) matches [`v154_http2`] on every
/// compared field, so this reuses that recipe. The initial SETTINGS,
/// connection window, request pseudo-header order, and HEADERS priority come
/// from the retained local H2 session captures of the WebSocket fixture set,
/// three fresh-profile runs.
///
/// It adds the extended CONNECT shape from the same captures: `:method`,
/// `:path`, `:authority`, `:scheme`, `:protocol`, and HEADERS priority
/// non-exclusive on stream 0 with weight 22 instead of the navigation's 42.
#[must_use]
pub fn v156_http2() -> Http2Settings {
    let mut settings = v154_http2();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Protocol,
    ]);
    settings.extended_connect_priority = Some(Http2Priority {
        dependency_stream_id: 0,
        weight: 22,
        exclusive: false,
    });
    settings
}

/// Returns WebSocket settings observed from Firefox 156.0 on Windows 11.
///
/// From the retained Windows 11 (build 26200) WebSocket captures. A `wss://`
/// WebSocket uses a pooled H2 session to the origin when its peer enabled
/// extended CONNECT. With no H2 session, Firefox opens a new connection with
/// its ordinary `h2,http/1.1` offer and sends extended CONNECT. When the
/// session's peer did not enable extended CONNECT, it opens a new TLS
/// connection offering only `http/1.1` and sends an HTTP/1.1 Upgrade. The
/// captures record that connection's ALPN offer, not its complete
/// ClientHello.
///
/// The opening templates keep the captured field order and spelling.
/// `User-Agent`, `Accept-Language`, `Accept-Encoding`, `Origin`, and
/// `Sec-Fetch-Site` are caller slots because their values are persona and
/// page data; the H2 template also places `sec-fetch-storage-access`, which
/// Firefox sent from a cross-site page. The captures carry no cookies, so the
/// cookie placeholder's final position is not observed. The compression
/// offer is bare `permessage-deflate`; Firefox always sends it, while Phantom
/// sends it only when the caller enables compression.
#[must_use]
pub fn v156_websocket() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http2ExtendedConnect,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
        },
        http1_fields: vec![
            WebSocketField::authority("Host"),
            WebSocketField::caller("User-Agent"),
            WebSocketField::literal("Accept", "*/*"),
            WebSocketField::caller("Accept-Language"),
            WebSocketField::caller("Accept-Encoding"),
            WebSocketField::literal("Sec-WebSocket-Version", "13"),
            WebSocketField::caller("Origin"),
            WebSocketField::permessage_deflate("Sec-WebSocket-Extensions"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::literal("Connection", "Upgrade"),
            WebSocketField::literal("Sec-Fetch-Dest", "empty"),
            WebSocketField::literal("Sec-Fetch-Mode", "websocket"),
            WebSocketField::caller("Sec-Fetch-Site"),
            WebSocketField::literal("Pragma", "no-cache"),
            WebSocketField::literal("Cache-Control", "no-cache"),
            WebSocketField::literal("Upgrade", "websocket"),
            WebSocketField::client_cookies("Cookie"),
        ],
        http2_fields: vec![
            WebSocketField::caller("user-agent"),
            WebSocketField::literal("accept", "*/*"),
            WebSocketField::caller("accept-language"),
            WebSocketField::caller("accept-encoding"),
            WebSocketField::literal("sec-websocket-version", "13"),
            WebSocketField::caller("origin"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::caller("sec-fetch-storage-access"),
            WebSocketField::literal("sec-fetch-dest", "empty"),
            WebSocketField::literal("sec-fetch-mode", "websocket"),
            WebSocketField::caller("sec-fetch-site"),
            WebSocketField::literal("pragma", "no-cache"),
            WebSocketField::literal("cache-control", "no-cache"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: Vec::new(),
    }
}

// Compatibility aliases for the names used before the Windows parity
// captures showed these transport recipes are platform-independent.

/// Compatibility alias for [`v154_tls`].
#[doc(hidden)]
#[must_use]
pub fn v154_macos_tls() -> TlsSettings {
    v154_tls()
}

/// Compatibility alias for [`v154_http2`].
#[doc(hidden)]
#[must_use]
pub fn v154_macos_http2() -> Http2Settings {
    v154_http2()
}

#[cfg(test)]
mod tests;
