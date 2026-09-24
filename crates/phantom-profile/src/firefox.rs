//! Wire settings retained from Firefox browser observations.

use crate::{
    cookie::CookiePlacement,
    http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings},
    request_template::{ProductVersion, RequestField, RequestIdentity, RequestTemplate},
    tcp::TcpSettings,
    tls::{
        CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
        EchGreaseAead, NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
    },
    websocket::{
        WebSocketConnectionPolicy, WebSocketEmptyMessageCompression, WebSocketField,
        WebSocketNewConnection, WebSocketRefusedStreamRetry, WebSocketSettings,
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

/// Returns TLS settings captured from Firefox 156.0 on Windows 11.
///
/// Captured from Firefox 156.0 (Windows 11 build 26200) in twelve fresh
/// processes. The fixed extension order and the exact ECH GREASE payload
/// length retain the stable wire shape observed across those captures.
/// Firefox picks its ECH GREASE AEAD per connection from AES-128-GCM and
/// ChaCha20-Poly1305 with equal probability; this recipe lists both, so each
/// connection draws one the same way. The delegated-credential vector includes
/// legacy ECDSA-SHA1 because Firefox advertised it; TLS 1.3 authentication
/// cannot select that legacy scheme. The returned value is an ordinary owned
/// [`TlsSettings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v156_tls() -> TlsSettings {
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
        ech_grease_payload_length: Some(240),
        ech_grease_aeads: vec![EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305],
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
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
/// The initial SETTINGS, connection window, request pseudo-header order, and
/// navigation HEADERS priority come from the retained local H2 session
/// captures of the Firefox 156 WebSocket fixture set, three fresh-profile runs
/// over six connections. No raw Firefox 156 startup-frame fixture exists: the
/// raw startup tool needs WebDriver certificate trust for Firefox, and
/// geckodriver is not installed on the capture host.
///
/// The extended CONNECT shape comes from the same captures: `:method`,
/// `:path`, `:authority`, `:scheme`, `:protocol`, and HEADERS priority
/// non-exclusive on stream 0 with weight 22 instead of the navigation's 42.
#[must_use]
pub fn v156_http2() -> Http2Settings {
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
        extended_connect_pseudo_header_order: Some(vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Protocol,
        ]),
        extended_connect_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        }),
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
    }
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
///
/// In the `refused-stream` captures Firefox answers
/// `RST_STREAM(REFUSED_STREAM)` by failing the WebSocket with close code
/// 1006, on every run, so its refusal is not retried. In the `accept-deflate`
/// captures it sends a zero-length text message uncompressed, with RSV1 clear
/// and an empty payload, while compressing every non-empty message.
#[must_use]
pub fn v156_websocket() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http2ExtendedConnect,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::None,
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
        empty_message_compression: WebSocketEmptyMessageCompression::Uncompressed,
    }
}

const V156_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V156_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V156_NAVIGATION_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const V156_WINDOWS_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";

/// Returns navigation request fields observed from Firefox 156.0 on Windows 11.
///
/// A top-level navigation the user starts from the address bar: an HTML
/// document request with `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
/// The HTTP/1.1 order comes from plaintext loopback page loads in the
/// retained SSE and WebSocket captures and the HTTP/2 order from the page
/// requests of the WebSocket captures; every run agrees. Firefox sends
/// `Priority` on HTTP/1.1 too and ends HTTP/2 requests with `te: trailers`.
/// There is no Firefox HTTP/3 recipe, so [`RequestTemplate::http3_fields`] is
/// `None`. Each captured HTTP/2 page request carries HEADERS priority weight
/// 42, not exclusive, on stream 0, which is also [`v156_http2`]'s connection
/// priority.
///
/// The `User-Agent` value is the one Firefox sent in those headless
/// captures. `Accept-Language` is the capture machine's `en-US` locale. A
/// caller field with the same name replaces a captured value in place.
/// Firefox sends no client hints, so the template has no client-hint slot,
/// and the `phantom` client refuses it with a profile that sends default
/// client hints.
#[must_use]
pub fn v156_windows_navigation_template() -> RequestTemplate {
    RequestTemplate {
        identity: v156_identity(),
        http1_fields: vec![
            RequestField::literal("User-Agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("Accept", V156_NAVIGATION_ACCEPT),
            RequestField::literal("Accept-Language", V156_ACCEPT_LANGUAGE),
            RequestField::literal("Accept-Encoding", V156_ACCEPT_ENCODING),
            RequestField::literal("Connection", "keep-alive"),
            RequestField::literal("Upgrade-Insecure-Requests", "1"),
            RequestField::literal("Sec-Fetch-Dest", "document"),
            RequestField::literal("Sec-Fetch-Mode", "navigate"),
            RequestField::literal("Sec-Fetch-Site", "none"),
            RequestField::literal("Sec-Fetch-User", "?1"),
            RequestField::literal("Priority", "u=0, i"),
        ],
        http2_fields: vec![
            RequestField::literal("user-agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("accept", V156_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V156_ACCEPT_LANGUAGE),
            RequestField::literal("accept-encoding", V156_ACCEPT_ENCODING),
            RequestField::literal("upgrade-insecure-requests", "1"),
            RequestField::literal("sec-fetch-dest", "document"),
            RequestField::literal("sec-fetch-mode", "navigate"),
            RequestField::literal("sec-fetch-site", "none"),
            RequestField::literal("sec-fetch-user", "?1"),
            RequestField::literal("priority", "u=0, i"),
            RequestField::literal("te", "trailers"),
        ],
        http3_fields: None,
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
        requested_client_hint_placement: false,
    }
}

/// Returns same-origin `fetch` request fields observed from Firefox 156.0 on Windows 11.
///
/// A script `fetch(url, {cache: "no-store"})` GET to the page's own origin;
/// the cache mode adds `Pragma` and `Cache-Control`, which Firefox sends
/// last on HTTP/1.1 and before `te: trailers` on HTTP/2. The orders come from
/// the final report request of the WebSocket captures, and every run agrees.
/// Each captured HTTP/2 fetch carries HEADERS priority weight 22, not
/// exclusive, on stream 0, unlike the navigation's 42 in [`v156_http2`];
/// [`RequestTemplate::http2_priority`] records it so the fetch does not go
/// out with the connection's navigation weight.
/// `Referer` is a caller slot because its value is the page URL. The
/// `User-Agent` value matches [`v156_windows_navigation_template`]. Like it,
/// this template has no client-hint slot, and the `phantom` client refuses
/// it with a profile that sends default client hints.
#[must_use]
pub fn v156_windows_fetch_no_store_template() -> RequestTemplate {
    RequestTemplate {
        identity: v156_identity(),
        http1_fields: vec![
            RequestField::literal("User-Agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("Accept", "*/*"),
            RequestField::literal("Accept-Language", V156_ACCEPT_LANGUAGE),
            RequestField::literal("Accept-Encoding", V156_ACCEPT_ENCODING),
            RequestField::caller("Referer"),
            RequestField::literal("Connection", "keep-alive"),
            RequestField::literal("Sec-Fetch-Dest", "empty"),
            RequestField::literal("Sec-Fetch-Mode", "cors"),
            RequestField::literal("Sec-Fetch-Site", "same-origin"),
            RequestField::literal("Priority", "u=4"),
            RequestField::literal("Pragma", "no-cache"),
            RequestField::literal("Cache-Control", "no-cache"),
        ],
        http2_fields: vec![
            RequestField::literal("user-agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("accept", "*/*"),
            RequestField::literal("accept-language", V156_ACCEPT_LANGUAGE),
            RequestField::literal("accept-encoding", V156_ACCEPT_ENCODING),
            RequestField::caller("referer"),
            RequestField::literal("sec-fetch-dest", "empty"),
            RequestField::literal("sec-fetch-mode", "cors"),
            RequestField::literal("sec-fetch-site", "same-origin"),
            RequestField::literal("priority", "u=4"),
            RequestField::literal("pragma", "no-cache"),
            RequestField::literal("cache-control", "no-cache"),
            RequestField::literal("te", "trailers"),
        ],
        http3_fields: None,
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        }),
        requested_client_hint_placement: false,
    }
}

fn v156_identity() -> RequestIdentity {
    RequestIdentity {
        user_agent_products: vec![ProductVersion::new("Firefox", 156)],
        excluded_user_agent_products: vec![
            Box::from("Chrome"),
            Box::from("HeadlessChrome"),
            Box::from("Edg"),
        ],
        client_hint_brands: None,
    }
}

#[cfg(test)]
mod tests;
