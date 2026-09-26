//! Wire settings retained from Firefox browser observations.

use std::{num::NonZeroUsize, time::Duration};

use crate::{
    cookie::CookiePlacement,
    dns_cache::DnsCacheSettings,
    http1::Http1Settings,
    http2::{
        Http2CookieCrumbs, Http2HpackSettings, Http2HuffmanCoding, Http2Priority,
        Http2PseudoHeader, Http2Setting, Http2Settings, Http2StaticNameIndex,
    },
    proxy_connect::{
        Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate,
    },
    request_template::{ProxyAuthorizationAttempt, RequestField, RequestTemplate},
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
/// cannot select that legacy scheme.
///
/// Ticket resumption over TCP follows the retained `resumption-*.txt`
/// captures. A resumed ClientHello omits the empty `session_ticket`
/// extension and adds `pre_shared_key` last. Firefox used each of the eight
/// tickets one connection issued, once, so the recipe keeps up to eight per
/// origin, the TCP cache's bound. When a ticket permits early data, Firefox
/// also offers `early_data` and sends safe requests in it; Phantom never
/// offers early data over TCP, so that resumed ClientHello lacks the
/// extension.
///
/// The returned value is an ordinary owned [`TlsSettings`], so callers can
/// customize it before constructing a transport.
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
        session_tickets_per_origin: 8,
        session_ticket_extension_when_resuming: false,
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
        ech_from_https_records: false,
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

/// Returns the address cache of Firefox 156.0 release builds.
///
/// From Firefox source at tag `FIREFOX_156_0_RELEASE`, not from a capture.
/// `network.dnsCacheEntries` is 1600 outside nightly builds
/// (`modules/libpref/init/StaticPrefList.yaml:15551-15559`), and an answer
/// without a TTL from the operating system is kept for
/// `network.dnsCacheExpiration`, 60 seconds (`:15561-15565`;
/// `netwerk/dns/nsHostResolver.cpp:1310-1317`). A failed lookup is kept for
/// `NEGATIVE_RECORD_LIFETIME`, 60 seconds
/// (`netwerk/dns/nsHostResolver.cpp:65-67`, `:1303-1308`).
///
/// Two parts are not modeled. On Windows `network.dns.get-ttl` is on
/// (`modules/libpref/init/StaticPrefList.yaml:15567-15575`), so Firefox keeps
/// an answer for its record TTL; Phantom sees no TTL and keeps each answer
/// for 60 seconds. Firefox also serves an expired answer for up to
/// `network.dnsCacheExpirationGracePeriod`, 600 seconds, while it resolves
/// the name again in the background (`:15584-15589`;
/// `netwerk/dns/nsHostResolver.cpp:1265-1283`); Phantom resolves an expired
/// name before it connects.
#[must_use]
pub fn v156_dns_cache() -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(1600).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(60),
        negative_ttl: Some(Duration::from_secs(60)),
    }
}

/// Returns the HTTP/1.1 connection policy of Firefox 156.0.
///
/// From Firefox source at tag `FIREFOX_156_0_RELEASE`, not from a capture:
/// `network.http.max-persistent-connections-per-server` is 6
/// (`modules/libpref/init/all.js:1158-1161`). Firefox applies it to direct
/// and CONNECT-tunneled connections and counts active connections together
/// with those still connecting
/// (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1150-1157`, `:1342-1378`;
/// `netwerk/protocol/http/ConnectionEntry.cpp:284-292`).
///
/// Three differences are not modeled. Phantom also counts idle connections,
/// which Firefox reuses before it opens another. Firefox uses
/// `network.http.max-persistent-connections-per-proxy`, 32, for plaintext
/// requests forwarded through an HTTP proxy (`modules/libpref/init/all.js:1167-1170`),
/// where this recipe keeps 6. And urgent-start requests may exceed the limit
/// by `network.http.max-urgent-start-excessive-connections-per-host`, 3
/// (`modules/libpref/init/all.js:1163-1165`).
#[must_use]
pub fn v156_http1() -> Http1Settings {
    Http1Settings {
        max_connections_per_origin: NonZeroUsize::new(6).unwrap_or(NonZeroUsize::MIN),
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
///
/// The HPACK choices come from every block in those captures. Every
/// pseudo-header may enter the dynamic table, so `:method: CONNECT` and
/// `:protocol` are indexed incrementally. A repeated static name takes the
/// higher entry, which names `:method` with 3 and `:path` with 5 on every
/// request rather than only on extended CONNECT. A literal string is
/// Huffman-coded whenever the coded form is no longer than the raw one: all
/// 831 coding decisions in the retained Firefox captures follow that rule,
/// and the 135 ties among them are coded.
///
/// Each `cookie` field is split at `"; "` into one field per cookie. A crumb
/// shorter than 20 bytes is a never-indexed literal and a longer one is
/// inserted into the dynamic table ([`Http2CookieCrumbs::NeverIndexShort`]),
/// as the retained cookie captures (`fixtures/cookies/`) show for crumbs of
/// 19 and 20 bytes and as `Http2Compressor::EncodeHeaderBlock` states.
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
        hpack: Http2HpackSettings {
            literal_pseudo_headers: Vec::new(),
            static_name_index: Http2StaticNameIndex::Highest,
            huffman_coding: Http2HuffmanCoding::WhenNotLonger,
            cookie_crumbs: Http2CookieCrumbs::NeverIndexShort,
        },
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
/// `User-Agent`, `Accept-Language`, and `Origin` are caller slots because
/// their values are persona and page data; the H2 template also places
/// `sec-fetch-storage-access`, which Firefox sent from a cross-site page. The
/// captures carry no cookies, so the cookie placeholder's final position is
/// not observed. The compression offer is bare `permessage-deflate`; Firefox
/// always sends it, while Phantom sends it only when the caller enables
/// compression.
///
/// `Accept-Encoding` and the three `Sec-Fetch-*` fields are
/// [`WebSocketField::ByTrust`] entries, as on ordinary requests: Firefox
/// offers `br` and `zstd`, and sends `Sec-Fetch-*` at all, only to a
/// potentially trustworthy URL. The retained proxy route captures show the
/// `ws://` Upgrade to `127.0.0.1` with `gzip, deflate, br, zstd` and
/// `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, and `Sec-Fetch-Site` between
/// `Connection` and `Pragma`, and the one to the plaintext name
/// `origin.phantom.test` with `gzip, deflate` and no `Sec-Fetch-*` field,
/// direct and through both proxies; the remaining fields keep their order.
/// `Sec-Fetch-Site` defaults to `same-origin`, the value every same-origin
/// page in the captures sent; a page on another site sends `cross-site`, as
/// in the `fresh-origin` capture. A caller field with the name of any of
/// these entries replaces the recipe's value in place, to any URL.
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
            websocket_accept_encoding("Accept-Encoding"),
            WebSocketField::literal("Sec-WebSocket-Version", "13"),
            WebSocketField::caller("Origin"),
            WebSocketField::permessage_deflate("Sec-WebSocket-Extensions"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::literal("Connection", "Upgrade"),
            WebSocketField::trustworthy_only("Sec-Fetch-Dest", "empty"),
            WebSocketField::trustworthy_only("Sec-Fetch-Mode", "websocket"),
            WebSocketField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
            WebSocketField::literal("Pragma", "no-cache"),
            WebSocketField::literal("Cache-Control", "no-cache"),
            WebSocketField::literal("Upgrade", "websocket"),
            WebSocketField::client_cookies("Cookie"),
        ],
        http2_fields: vec![
            WebSocketField::caller("user-agent"),
            WebSocketField::literal("accept", "*/*"),
            WebSocketField::caller("accept-language"),
            websocket_accept_encoding("accept-encoding"),
            WebSocketField::literal("sec-websocket-version", "13"),
            WebSocketField::caller("origin"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::caller("sec-fetch-storage-access"),
            WebSocketField::trustworthy_only("sec-fetch-dest", "empty"),
            WebSocketField::trustworthy_only("sec-fetch-mode", "websocket"),
            WebSocketField::trustworthy_only("sec-fetch-site", "same-origin"),
            WebSocketField::literal("pragma", "no-cache"),
            WebSocketField::literal("cache-control", "no-cache"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: Vec::new(),
        empty_message_compression: WebSocketEmptyMessageCompression::Uncompressed,
    }
}

/// Returns the CONNECT request fields observed from Firefox 156.0 on Windows 11.
///
/// From the retained proxy route captures, three runs of each scenario.
/// Every HTTP/1.1 CONNECT for the page's `ws://` origin sends `User-Agent`,
/// `Proxy-Connection: keep-alive`, `Connection: keep-alive`, and `Host`,
/// then `Proxy-Authorization` when the proxy asked for credentials
/// (`http-proxy-*` and `http-proxy-auth-*`). Every HTTP/2 CONNECT to the TLS
/// proxy sends `user-agent` after `:method` and `:authority`, then
/// `proxy-authorization` (`https-proxy-*` and `https-proxy-auth-*`). The
/// `*-secure-hostname` captures show the same fields on the CONNECT for an
/// `https://` fetch and a `wss://` opening, anonymous, challenged, on the
/// replay after a `407`, and with remembered credentials.
///
/// Firefox's `User-Agent` there is its own, which the captures show equal to
/// the page request's. The recipe copies the `User-Agent` of the request
/// that opens the tunnel: the caller's field, or the request template's
/// value.
///
/// After an HTTP/2 CONNECT is challenged, Firefox sends nothing more on the
/// challenged stream (`https-proxy-auth-secure-hostname`).
///
/// In every `https-proxy-*` capture, Firefox opens three HTTP/2 connections
/// to the proxy for one page: one for the navigation and `fetch()`, one for
/// the `https://` CONNECTs, and one for the `ws://` and `wss://` CONNECTs,
/// so the recipe keeps the three apart ([`Http2ProxyConnections::ByPurpose`]).
#[must_use]
pub fn v156_proxy_connect() -> ProxyConnectTemplate {
    ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::from_request("User-Agent"),
            ProxyConnectField::literal("Proxy-Connection", "keep-alive"),
            ProxyConnectField::literal("Connection", "keep-alive"),
            ProxyConnectField::authority("Host"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            ProxyConnectField::from_request("user-agent"),
            ProxyConnectField::proxy_authorization("proxy-authorization"),
        ],
        http2_rejected: Http2RejectedConnect::LeaveOpen,
        http2_connections: Http2ProxyConnections::ByPurpose,
    }
}

const V156_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V156_PLAINTEXT_ACCEPT_ENCODING: &str = "gzip, deflate";
const V156_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V156_NAVIGATION_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const V156_WINDOWS_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";

/// Returns Firefox 156's `Accept-Encoding` entry: `br` and `zstd` are offered
/// only to a potentially trustworthy URL.
///
/// `HttpBaseChannel::Init` passes `isSecureOrTrustworthyURL` (an `https`
/// scheme, or a loopback URL while `network.http.encoding.trustworthy_is_https`
/// is true, its default) to `nsHttpHandler::AddStandardRequestHeaders`, which
/// then sends `network.http.accept-encoding.secure` instead of
/// `network.http.accept-encoding` (`netwerk/protocol/http/HttpBaseChannel.cpp`
/// lines 325-329 and 351, `nsHttpHandler.cpp` lines 806-812, and
/// `modules/libpref/init/all.js` lines 1187-1188 at `FIREFOX_156_0_RELEASE`).
fn accept_encoding(name: &str) -> RequestField {
    RequestField::by_trust(name, V156_ACCEPT_ENCODING, V156_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns [`accept_encoding`] for a WebSocket opening template.
fn websocket_accept_encoding(name: &str) -> WebSocketField {
    WebSocketField::by_trust(name, V156_ACCEPT_ENCODING, V156_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns Firefox 156's position of forwarded proxy credentials it
/// remembers from an earlier challenge: before `Connection` on HTTP/1.1, and
/// where `Connection` would be on HTTP/2.
///
/// The retained `http-proxy-auth-*` and `https-proxy-auth-*` proxy route
/// captures show it after `Referer` on the `fetch()` that follows the
/// challenged navigation, and the `*-auth-remembered-hostname` captures show
/// it after `Accept-Encoding` on a navigation sent with remembered
/// credentials.
fn preemptive_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Preemptive)
}

/// Returns Firefox 156's position of forwarded proxy credentials on the
/// replay after a `407`: after every template field on HTTP/1.1, and before
/// `te` on HTTP/2.
///
/// The same captures show it there on the replayed navigation, the
/// `*-auth-remembered-hostname` captures on a replayed default-mode
/// `fetch()`, and the `*-auth-nostore-*` captures on a replayed no-store
/// `fetch()`, after `Pragma` and `Cache-Control`. Those captures also show
/// the remembered-credentials slot on a no-store `fetch()`.
fn replay_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Replay)
}

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
///
/// Firefox sends the `Sec-Fetch-*` fields, and `br` and `zstd` in
/// `Accept-Encoding`, only to a potentially trustworthy URL, so those entries
/// are [`RequestField::ByTrust`]. `SecFetch::AddSecFetchHeader` returns early
/// unless `nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin` holds
/// (`dom/security/SecFetch.cpp` lines 383-387 at `FIREFOX_156_0_RELEASE`). The
/// retained proxy route captures show the navigation to the plaintext name
/// `origin.phantom.test` without them, with `Accept-Encoding: gzip, deflate`,
/// and with the remaining fields in the same order on HTTP/1.1 and HTTP/2.
#[must_use]
pub fn v156_windows_navigation_template() -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("User-Agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("Accept", V156_NAVIGATION_ACCEPT),
            RequestField::literal("Accept-Language", V156_ACCEPT_LANGUAGE),
            accept_encoding("Accept-Encoding"),
            preemptive_proxy_authorization("Proxy-Authorization"),
            RequestField::literal("Connection", "keep-alive"),
            RequestField::literal("Upgrade-Insecure-Requests", "1"),
            RequestField::trustworthy_only("Sec-Fetch-Dest", "document"),
            RequestField::trustworthy_only("Sec-Fetch-Mode", "navigate"),
            RequestField::trustworthy_only("Sec-Fetch-Site", "none"),
            RequestField::trustworthy_only("Sec-Fetch-User", "?1"),
            RequestField::literal("Priority", "u=0, i"),
            replay_proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            RequestField::literal("user-agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("accept", V156_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V156_ACCEPT_LANGUAGE),
            accept_encoding("accept-encoding"),
            preemptive_proxy_authorization("proxy-authorization"),
            RequestField::literal("upgrade-insecure-requests", "1"),
            RequestField::trustworthy_only("sec-fetch-dest", "document"),
            RequestField::trustworthy_only("sec-fetch-mode", "navigate"),
            RequestField::trustworthy_only("sec-fetch-site", "none"),
            RequestField::trustworthy_only("sec-fetch-user", "?1"),
            RequestField::literal("priority", "u=0, i"),
            replay_proxy_authorization("proxy-authorization"),
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
///
/// As on the navigation, the `Sec-Fetch-*` fields and the `br` and `zstd`
/// codings are sent only to a potentially trustworthy URL. The proxy route
/// captures back that shape with a same-origin `fetch()` in the default cache
/// mode, and the `*-auth-nostore-*` captures with a no-store `fetch()` through
/// a proxy to both kinds of origin, `Pragma` and `Cache-Control` included.
#[must_use]
pub fn v156_windows_fetch_no_store_template() -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("User-Agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("Accept", "*/*"),
            RequestField::literal("Accept-Language", V156_ACCEPT_LANGUAGE),
            accept_encoding("Accept-Encoding"),
            RequestField::caller("Referer"),
            preemptive_proxy_authorization("Proxy-Authorization"),
            RequestField::literal("Connection", "keep-alive"),
            RequestField::trustworthy_only("Sec-Fetch-Dest", "empty"),
            RequestField::trustworthy_only("Sec-Fetch-Mode", "cors"),
            RequestField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
            RequestField::literal("Priority", "u=4"),
            RequestField::literal("Pragma", "no-cache"),
            RequestField::literal("Cache-Control", "no-cache"),
            replay_proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            RequestField::literal("user-agent", V156_WINDOWS_USER_AGENT),
            RequestField::literal("accept", "*/*"),
            RequestField::literal("accept-language", V156_ACCEPT_LANGUAGE),
            accept_encoding("accept-encoding"),
            RequestField::caller("referer"),
            preemptive_proxy_authorization("proxy-authorization"),
            RequestField::trustworthy_only("sec-fetch-dest", "empty"),
            RequestField::trustworthy_only("sec-fetch-mode", "cors"),
            RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
            RequestField::literal("priority", "u=4"),
            RequestField::literal("pragma", "no-cache"),
            RequestField::literal("cache-control", "no-cache"),
            replay_proxy_authorization("proxy-authorization"),
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

#[cfg(test)]
mod tests;
