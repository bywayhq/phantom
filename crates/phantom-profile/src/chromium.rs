//! Wire settings retained from Chromium-family browser observations.

use std::{num::NonZeroUsize, time::Duration};

use crate::{
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    cookie::CookiePlacement,
    dns_cache::DnsCacheSettings,
    http1::Http1Settings,
    http2::{
        Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
        Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader, Http2Setting,
        Http2Settings, Http2StaticNameIndex, Http2StreamSettings, Http2TableSizeUpdates,
        Http2UnindexedMatch,
    },
    http3::{
        Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream,
        Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings, Http3Setting,
        Http3SettingOrder, Http3Settings,
    },
    proxy_connect::{
        Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate,
    },
    request_template::{ProxyAuthorizationAttempt, RequestField, RequestTemplate},
    tls::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtensionOrder, NamedGroup,
        SignatureScheme, TlsSettings, TlsVersion,
    },
    websocket::{
        WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
        WebSocketField, WebSocketNewConnection, WebSocketRefusedStreamRetry, WebSocketSettings,
    },
};

use crate::tcp::{TcpAddressRacing, TcpKeepalive, TcpSettings};

use crate::quic::{
    GoogleConnectionOption, QuicTransportGrease, QuicTransportParameter,
    QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
    QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
};

// Chrome 154 sorts the trust-anchor ID list once, when it builds the SSL
// configuration (`net/cert/x509_util.cc:708-717` at 154.0.8037.58, from
// Chromium commit `942bda4298c1`), so every connection of every process emits
// these 28 identifiers in ascending byte order. All 60 fresh processes of the
// retained `trust-anchor-orders.txt` capture and all 132 retained desktop
// ClientHellos, up to 13 from one process, carry exactly this order.
const V154_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0f],
];

/// Returns client-hint fields observed from Chrome 154 on Windows 11 x64.
///
/// Field values, relative order, and delivery come from the retained
/// fresh-profile navigation capture of Chrome 154.0.8037.58 on Windows 11
/// (build 26200): fields on the first navigation are sent by default, the rest
/// only after the origin requests them through `Accept-CH`. Three headless runs
/// agree, and the headful launch-mode captures carry the same values. The
/// values carry the exact 154.0.8037.58 build and Windows platform data.
///
/// Chrome 154 reorders the `sec-ch-ua` brand list and renames its greased
/// brand: `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`,
/// where Chrome 153 sent `"Google Chrome"`, `"Not_A Brand";v="8"`, and
/// `"Chromium"` in that order. `sec-ch-ua-full-version-list` follows the same
/// list. The returned value is owned and may be customized before client
/// creation.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.58""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Google Chrome";v="154.0.8037.58", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns client-hint fields observed from Chrome 154 on macOS 15.5 arm64.
///
/// Names, order, delivery, and the brand and version values match
/// [`v154_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Chrome 154.0.8037.58 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. The returned value is owned and may be
/// customized before client creation, for example to carry another macOS
/// version.
#[must_use]
pub fn v154_macos_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.58""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Google Chrome";v="154.0.8037.58", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns the automatic `Cookie` field position for Chrome 154.
///
/// Chrome appends `Cookie` after every other request field it builds:
/// `URLRequestHttpJob::AddCookieHeaderAndStart` sets it on the extra headers
/// last (`net/url_request/url_request_http_job.cc:799-871` at Chromium tag
/// `154.0.8037.58`). The retained Chrome 154 HTTP/1.1 EventSource reconnect
/// capture `set-cookie-then-close.txt` sends it last on every run. For H2 and
/// H3, `CreateSpdyHeadersFromHttpRequest` copies those fields in order and then
/// appends `priority` (`net/spdy/spdy_http_utils.cc:32`, `:199-236`), so
/// `Cookie` precedes a `priority` field. The retained cookie captures of
/// Chrome 154, Edge 154, Brave 154, and Opera 135 (`fixtures/cookies/`) show
/// both positions on every run: `Cookie` last over HTTP/1.1, and the crumbs
/// right before `priority` over HTTP/2 and HTTP/3. Edge, Brave, and Opera
/// use this recipe.
#[must_use]
pub fn v154_cookie_placement() -> CookiePlacement {
    CookiePlacement::before_fields(["priority"])
}

/// Returns TLS settings captured from Chrome 154.0.8037.58 on Windows 11.
///
/// Captured from branded Chrome 154.0.8037.58 on Windows 11 (build 26200) with
/// the retained Chrome launch flags and its default field-trial configuration.
/// Every field comes from the retained `client-hello.txt` ClientHello: the
/// cipher suites, supported groups, key shares, signature algorithms, ALPN
/// offer, ALPS protocol on the new codepoint, Brotli certificate compression,
/// the offered TLS versions, and the OCSP, SCT, and session-ticket requests.
/// GREASE, the permuted extension order, and the ECH GREASE payload length are
/// per-connection randomness; 61 fresh-process ClientHellos agree on everything
/// else.
///
/// The requested trust-anchor IDs are the 28 identifiers Chrome 153 also
/// advertised, but Chrome 154 sorts them: Chromium commit `942bda4298c1` sorts
/// the list before encoding, so the order no longer differs between browser
/// processes. All 60 processes of the retained `trust-anchor-orders.txt`
/// capture emit the one ascending order this recipe carries.
///
/// Chrome 154 offers real Encrypted Client Hello on a direct connection
/// whose HTTPS record carries `ech`, so
/// [`TlsSettings::ech_from_https_records`] is set; it applies only on a
/// client that looks up HTTPS records.
///
/// Ticket resumption over TCP follows the retained `resumption-*.txt`
/// captures. Chrome kept the two newest tickets for an origin, presented the
/// newest first, and used each once; a resumed ClientHello adds only
/// `pre_shared_key`, last, and never offers early data over TCP.
///
/// The returned value is an ordinary owned [`TlsSettings`], so callers can
/// customize it before constructing a transport.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
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
        ],
        key_shares: vec![NamedGroup::X25519MlKem768, NamedGroup::X25519],
        signature_schemes: vec![
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha512,
        ],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: Some(AlpsSettings {
            protocol: Box::from(&b"h2"[..]),
            settings: Box::default(),
            use_new_codepoint: true,
        }),
        certificate_compression: vec![CertificateCompression::Brotli],
        session_tickets: true,
        session_tickets_per_origin: 2,
        session_ticket_extension_when_resuming: true,
        record_size_limit: None,
        requested_trust_anchor_ids: Some(trust_anchor_ids(V154_TRUST_ANCHOR_IDS)),
        grease: true,
        grease_signature_algorithms: true,
        extension_order: ClientHelloExtensionOrder::Permuted,
        ech_grease: true,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: true,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

/// Returns the TCP socket options Chromium 154.0.8037.58 sets on Windows and Linux.
///
/// From Chromium source at tag `154.0.8037.58`, not from a capture: socket
/// options are not visible on the wire. `TCPClientSocket` calls
/// `SetDefaultOptionsForClient` when it opens each socket, before connecting
/// (`net/socket/tcp_client_socket.cc:173` and `:558`). On Windows that sets
/// `TCP_NODELAY` and enables keepalive through `SIO_KEEPALIVE_VALS` with
/// `kTCPKeepAliveSeconds = 45` as both the idle time and the probe interval
/// (`net/socket/tcp_socket_win.cc:50`, `:55-72`, `:815-818`). The POSIX path
/// sets the same values through `TCP_KEEPIDLE` and `TCP_KEEPINTVL` on Linux
/// (`net/socket/tcp_socket_posix.cc:88-100`, `:493-517`).
///
/// Addresses race as Chromium 154's default Happy Eyeballs v2 `TcpConnectJob`
/// does (`net/base/features.cc:114-122`,
/// `net/socket/transport_connect_job.cc:118-123`): a second attempt starts
/// `kIPv6FallbackTime = 300` ms after the first
/// (`net/socket/tcp_connect_job.h:85`,
/// `net/socket/tcp_connect_job.cc:573-610`). The field trials that change that
/// delay, `kAdjustIPv6FallbackTime` and `kIPv6FallbackBasedOnRTT`, and Happy
/// Eyeballs v3 are disabled by default (`net/base/features.cc:124`, `:128`,
/// `:136`). [`TcpAddressRacing`] describes the rest of the algorithm; its own
/// line numbers were read at tag `153.0.8010.48` and have not been re-read at
/// 154.
///
/// On macOS Chromium sets only the idle time, through `TCP_KEEPALIVE`
/// (`net/socket/tcp_socket_posix.cc:101-105`); set [`TcpKeepalive::interval`]
/// to `None` for that platform. Android and iOS builds enable no keepalive.
/// Chromium ignores a failure to set either option
/// (`net/socket/tcp_socket_win.cc:70-71`); Phantom instead fails the connection
/// attempt rather than connect with options the profile did not ask for.
///
/// Brave 1.96.59 builds the same Chromium tag and changes none of the cited
/// values, so this recipe also serves Brave 154 (see [`crate::brave`]).
#[must_use]
pub fn v154_tcp() -> TcpSettings {
    const KEEPALIVE: Duration = Duration::from_secs(45);

    TcpSettings {
        nodelay: true,
        keepalive: Some(TcpKeepalive {
            idle: KEEPALIVE,
            interval: Some(KEEPALIVE),
        }),
        address_racing: Some(TcpAddressRacing {
            fallback_delay: Duration::from_millis(300),
        }),
    }
}

/// Returns the address cache of Chromium 154.0.8037.58's system-resolver
/// path.
///
/// From Chromium source at tag `154.0.8037.58`, not from a capture: a DNS
/// cache is not visible on the wire, only the queries it saves. Each
/// `URLRequestContext`, one per browser profile, creates its resolver with
/// caching enabled (`net/url_request/url_request_context_builder.cc:363-382`),
/// and its `ResolveContext` holds a `HostCache` of `kDefaultCacheSize = 1000`
/// entries in builds with the built-in DNS client, which every Blink build
/// has (`net/dns/resolve_context.cc:109-121`, `net/dns/BUILD.gn:9`).
///
/// An answer from the operating system resolver carries no TTL, so Chromium
/// keeps it for `kCacheEntryTTLSeconds = 60` and a failure for
/// `kNegativeCacheEntryTTLSeconds = 0`
/// (`net/dns/host_resolver_manager_job.cc:54-58`, `:799-815`). A failure
/// without a positive TTL is never cached
/// (`net/dns/host_resolver_manager.cc:1284-1291`). When the cache is full,
/// the entry that expires soonest is evicted, stale entries first
/// (`net/dns/host_cache.cc:886-916`, `:1289-1319`).
///
/// Chromium's built-in DNS client, enabled by default on Windows, macOS,
/// Linux, ChromeOS, and Android (`net/base/features.cc:42-48`), instead keeps
/// an answer for its record TTL, at least 60 seconds
/// (`net/dns/host_resolver_manager_job.cc:61`, `:965-966`), and a negative
/// answer for its SOA TTL (`:907-908`). Phantom resolves through the operating
/// system and sees no TTL, so this recipe follows the system-resolver path.
///
/// Brave 1.96.59 builds the same Chromium tag and changes none of the cited
/// values, so this recipe also serves Brave 154. Brave enables
/// `kPartitionConnectionsByNetworkIsolationKey`, which keys the cache by
/// top-level site as well (see [`crate::brave`]).
#[must_use]
pub fn v154_dns_cache() -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(1000).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(60),
        negative_ttl: None,
    }
}

/// Returns the HTTP/1.1 connection policy of Chromium 154.0.8037.58.
///
/// From Chromium source at tag `154.0.8037.58`, not from a capture: the
/// normal socket pool allows six sockets per group, `g_max_sockets_per_group`
/// (`net/socket/client_socket_pool_manager.cc:46-58`). A group is one
/// scheme, host, and port within the pool of one proxy chain
/// (`net/socket/client_socket_pool.h:130-153`,
/// `net/socket/client_socket_pool_manager_impl.h:48`), which Phantom keys as
/// one origin and route. Idle sockets, connecting sockets, and sockets in use all
/// occupy a slot (`net/socket/transport_client_socket_pool.h:356-363`), and a
/// request takes the most recently used idle socket before it opens another
/// (`net/socket/transport_client_socket_pool.cc:530-560`).
///
/// Chromium's other socket limits are not modeled: 256 sockets per pool and
/// 128 per proxy chain (`net/socket/client_socket_pool_manager.cc:37-44`,
/// `:60-66`), and 255 per group for WebSocket connections.
///
/// Brave 1.96.59 builds the same Chromium tag and changes none of the cited
/// values, so this recipe also serves Brave 154. Brave enables
/// `kPartitionConnectionsByNetworkIsolationKey`, which keys each socket group
/// by top-level site as well (see [`crate::brave`]).
#[must_use]
pub fn v154_http1() -> Http1Settings {
    Http1Settings {
        max_connections_per_origin: NonZeroUsize::new(6).unwrap_or(NonZeroUsize::MIN),
    }
}

/// Returns HTTP/2 settings observed from Chrome 154.0.8037.58 on Windows 11.
///
/// The initial SETTINGS, their order, and the connection WINDOW_UPDATE come
/// from the retained raw startup-frame capture, whose frames are byte-identical
/// to the Chrome 153 capture. The request pseudo-header order and the
/// navigation HEADERS priority, exclusive on stream 0 with weight 256, come
/// from the page request of the retained H2 WebSocket session captures, three
/// fresh-profile runs.
///
/// The extended CONNECT shape comes from the same captures: `:method`,
/// `:authority`, `:scheme`, `:path`, `:protocol`, and HEADERS priority
/// exclusive on stream 0 with weight 147 instead of the navigation's 256.
///
/// The HPACK choices come from every block in those captures. `:method` and
/// `:protocol` are never inserted into the dynamic table, so `:method:
/// CONNECT` is sent as a literal without indexing naming static entry 2, and
/// `:protocol` as a literal without indexing with a literal name. A repeated
/// static name takes the lower entry, `:method` 2 and `:path` 4. A literal
/// string is Huffman-coded only when the coded form is strictly shorter: all
/// 774 coding decisions in the retained Chrome and Edge captures follow that
/// rule, and the 105 ties among them, such as `CONNECT` and `13`, are raw.
///
/// Each `cookie` field is split into one field per cookie, and each crumb is
/// inserted into the dynamic table and sent as an index on later requests
/// ([`Http2CookieCrumbs::IndexAll`]). The retained two-request cookie
/// captures (`fixtures/cookies/`) show this for five cookies on every run;
/// quiche's `HpackEncoder::CookieToCrumbs` is the split rule.
///
/// The rest of the indexing policy is quiche's `HpackEncoder` at the revision
/// Chromium 154 pins. Every ordinary field may enter the dynamic table,
/// `authorization` and `content-length` included ([`Http2FieldIndexing::All`]).
/// A literal names the static entry when one has its name, otherwise the
/// newest dynamic entry ([`Http2NameReference::StaticThenNewest`]). A field of
/// any size is inserted, evicting older entries, and one larger than the whole
/// table empties it ([`Http2IndexingLimit::Unlimited`]). A table size setting
/// equal to the current size is not announced. Every HEADERS block of the
/// retained Chrome and Edge WebSocket and cookie sessions equals Phantom's
/// byte for byte.
///
/// Each connection's first request is stream 1 (`kFirstStreamId`,
/// `net/spdy/spdy_session.h:93` at tag `154.0.8037.58`), as in every retained
/// Chrome, Edge, Brave, and Opera HTTP/2 session. Until the peer states
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, at most 100 streams are open:
/// `SpdySession` starts at `kInitialMaxConcurrentStreams` (`:84`;
/// `net/spdy/spdy_session.cc:837`), creates a stream only below it
/// (`:1696-1699`), and replaces it only with a stated value (`:2355-2358`). No
/// capture shows the limit, because every capture server states 100. A stated
/// value above 256 is lowered to 256 (`kMaxConcurrentStreamLimit`, `:383`,
/// applied at `:2355-2358`).
///
/// On a connection that has read nothing for more than 10 seconds, a PING
/// follows the next request HEADERS or non-empty DATA frame.
/// `SpdySession::MaybeSendPrefacePing` runs as the write loop builds each such
/// frame (`:1088`, `:1205-1207`) and queues one when no PING of its own is in
/// flight and `kSpdyDefaultConnectionAtRiskOfLossSeconds`, 10, has passed
/// since the last read (`:2446-2456`; `net/spdy/spdy_session.h:111`). Its
/// payload is a counter from 1, sent as a 64-bit big-endian value
/// (`:2479-2499`). The check is on by default
/// (`net/http/http_network_session.h:88`). The retained loopback capture
/// (`fixtures/http2/chrome/154.0.8037.58/windows-11-26200/preface-ping.txt`)
/// shows the PING right after the HEADERS of a request sent after 11.5 idle
/// seconds.
///
/// A PING that goes unanswered while nothing is read for 10 seconds closes
/// the connection. Sending it schedules `SpdySession::CheckPingStatus` after
/// `kHungIntervalSeconds`, 10 (`:102`, `:2500-2510`); the check closes the
/// session with `ERR_HTTP2_PING_FAILED` when the ACK is still missing and
/// nothing has been read since the PING or for 10 seconds, and otherwise
/// checks again 10 seconds after the last read (`:2512-2538`). Closing sends
/// `GOAWAY` with last stream ID 0, `PROTOCOL_ERROR`, and the debug data
/// `Failed ping.` (`:2719-2738`) and fails every stream (`:2753`).
///
/// The returned value is an ordinary owned [`Http2Settings`], so callers can
/// customize it before constructing a transport.
#[must_use]
pub fn v154_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(6_291_456),
            Http2Setting::MaxHeaderListSize(262_144),
        ],
        initial_connection_window_size: 15_728_640,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: Some(vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Protocol,
        ]),
        extended_connect_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 147,
            exclusive: true,
        }),
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 256,
            exclusive: true,
        }),
        hpack: Http2HpackSettings {
            literal_pseudo_headers: vec![Http2PseudoHeader::Method, Http2PseudoHeader::Protocol],
            static_name_index: Http2StaticNameIndex::Lowest,
            huffman_coding: Http2HuffmanCoding::WhenShorter,
            cookie_crumbs: Http2CookieCrumbs::IndexAll,
            field_indexing: Http2FieldIndexing::All,
            name_reference: Http2NameReference::StaticThenNewest,
            unindexed_match: Http2UnindexedMatch::Index,
            indexing_limit: Http2IndexingLimit::Unlimited,
            table_size_updates: Http2TableSizeUpdates::WhenChanged,
        },
        streams: Http2StreamSettings {
            first_stream_id: 1,
            assumed_max_concurrent_streams: Some(100),
            max_concurrent_streams_cap: Some(256),
        },
        preface_ping_after: Some(Duration::from_secs(10)),
        ping_timeout: Some(Duration::from_secs(10)),
    }
}

/// Returns WebSocket settings observed from Chrome 154.0.8037.58 on Windows 11.
///
/// From the retained Windows 11 (build 26200) WebSocket captures, three runs of
/// each of nine scenarios. A `wss://` WebSocket uses a pooled H2 session to the
/// origin only when its peer enabled extended CONNECT. Otherwise, with or
/// without such a session, Chrome opens a new TLS connection offering only
/// `http/1.1` and sends an HTTP/1.1 Upgrade; it never opens a new H2 connection
/// for a WebSocket. The `fresh-origin` and `no-connect-protocol` captures
/// record that connection's ALPN offer, not its complete ClientHello.
///
/// The opening templates keep the captured field order and spelling.
/// `User-Agent`, `Origin`, and `Accept-Language` are caller slots because
/// their values are persona and page data. The captures carry no cookies, so
/// the cookie placeholder's final position is not observed. The
/// compression offer is `permessage-deflate; client_max_window_bits`; Chrome
/// always sends it, while Phantom sends it only when the caller enables
/// compression. Edge 154.0.4258.37, Brave 154.1.96.59, and Opera
/// 135.0.5973.92 match this recipe on every compared field.
///
/// `Accept-Encoding` is a [`WebSocketField::ByTrust`] entry, as on
/// ordinary requests: Chrome offers `br` and `zstd` only to a potentially
/// trustworthy URL. The retained proxy route captures show the `ws://`
/// Upgrade to `127.0.0.1` with `gzip, deflate, br, zstd` and the one to
/// the plaintext name `origin.phantom.test` with `gzip, deflate`, direct and
/// through both proxies; every other field is the same in both. Chrome
/// sends no `Sec-Fetch-*` field on a WebSocket opening to either. A caller
/// field named `Accept-Encoding` replaces the recipe's value in place.
///
/// The `refused-stream` captures show Chrome answering
/// `RST_STREAM(REFUSED_STREAM)` with one further extended CONNECT on the same
/// H2 session and the next client stream id, which the peer then accepted; no
/// data frame had been sent on the refused stream. The `accept-deflate`
/// captures show a zero-length text message compressed into one byte with RSV1
/// set.
///
/// The 240-second handshake timeout is Chromium's own constant, not a
/// capture: `WebSocketStreamRequestImpl::Start` starts a one-shot timer of
/// `kHandshakeTimeoutIntervalInSeconds` before the opening request starts,
/// `PerformUpgrade` stops it once the handshake stream is upgraded, and
/// `OnTimeout` cancels the request with `ERR_TIMED_OUT`
/// (`net/websockets/websocket_stream.cc` lines 60-64, 248-262, and 338-340
/// at tag `154.0.8037.58`). The source comment sets it equal to the TCP
/// connect timeout so that a page cannot tell which step timed out.
#[must_use]
pub fn v154_websocket() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http1Upgrade,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::SameSessionOnce,
        },
        http1_fields: vec![
            WebSocketField::authority("Host"),
            WebSocketField::literal("Connection", "Upgrade"),
            WebSocketField::literal("Pragma", "no-cache"),
            WebSocketField::literal("Cache-Control", "no-cache"),
            WebSocketField::caller("User-Agent"),
            WebSocketField::literal("Upgrade", "websocket"),
            WebSocketField::caller("Origin"),
            WebSocketField::literal("Sec-WebSocket-Version", "13"),
            websocket_accept_encoding("Accept-Encoding"),
            WebSocketField::caller("Accept-Language"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::permessage_deflate("Sec-WebSocket-Extensions"),
            WebSocketField::client_cookies("Cookie"),
        ],
        http2_fields: vec![
            WebSocketField::literal("pragma", "no-cache"),
            WebSocketField::literal("cache-control", "no-cache"),
            WebSocketField::caller("user-agent"),
            WebSocketField::caller("origin"),
            WebSocketField::literal("sec-websocket-version", "13"),
            websocket_accept_encoding("accept-encoding"),
            WebSocketField::caller("accept-language"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: vec![WebSocketDeflateParameter::ClientMaxWindowBits(None)],
        empty_message_compression: WebSocketEmptyMessageCompression::Compressed,
        handshake_timeout: Some(Duration::from_secs(240)),
    }
}

/// Returns the CONNECT request fields observed from Chrome 154.0.8037.58 on
/// Windows 11.
///
/// From the retained proxy route captures, three runs of each scenario.
/// Every HTTP/1.1 CONNECT for the page's `ws://` origin sends `Host`,
/// `Proxy-Connection: keep-alive`, and `User-Agent`, then
/// `Proxy-Authorization` when the proxy asked for credentials
/// (`http-proxy-*` and `http-proxy-auth-*`). Every HTTP/2 CONNECT to the TLS
/// proxy sends `user-agent` after `:method` and `:authority`, then
/// `proxy-authorization` (`https-proxy-*` and `https-proxy-auth-*`). The
/// `*-secure-hostname` captures show the same fields on the CONNECT for an
/// `https://` fetch and a `wss://` opening, anonymous, challenged, on the
/// replay after a `407`, and with remembered credentials. Edge
/// 154.0.4258.37, Brave 154.1.96.59, and Opera 135.0.5973.92 send the same
/// fields in the same order.
///
/// Chrome's `User-Agent` there is its own, which the captures show equal to
/// the page request's. The recipe copies the `User-Agent` of the request
/// that opens the tunnel: the caller's field, or the request template's
/// value.
///
/// After an HTTP/2 CONNECT is challenged, Chrome and Edge end the challenged
/// stream with an empty END_STREAM DATA frame before the replay
/// (`https-proxy-auth-secure-hostname`).
///
/// A page's navigation, `fetch()`, and every CONNECT it opens, for
/// `https://`, `ws://`, and `wss://` origins, are streams of one HTTP/2
/// connection to the proxy in every `https-proxy-*` capture of Chrome, Edge,
/// Brave, and Opera, so the recipe shares one connection among them
/// ([`Http2ProxyConnections::Shared`]).
#[must_use]
pub fn v154_proxy_connect() -> ProxyConnectTemplate {
    ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::authority("Host"),
            ProxyConnectField::literal("Proxy-Connection", "keep-alive"),
            ProxyConnectField::from_request("User-Agent"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            ProxyConnectField::from_request("user-agent"),
            ProxyConnectField::proxy_authorization("proxy-authorization"),
        ],
        http2_rejected: Http2RejectedConnect::EndStream,
        http2_connections: Http2ProxyConnections::Shared,
    }
}

const V154_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const V154_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V154_PLAINTEXT_ACCEPT_ENCODING: &str = "gzip, deflate";
const V154_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V154_WINDOWS_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

/// Returns Chromium 154's `Accept-Encoding` entry: `br` and `zstd` are
/// offered only to a potentially trustworthy URL.
///
/// `HttpRequestHeaders::SetAcceptEncodingIfMissing` adds them only when the
/// URL is cryptographic or `net::IsLocalhost`
/// (`net/http/http_request_headers.cc` lines 261-275 at Chromium tag
/// `154.0.8037.58`). The retained proxy route captures show `gzip, deflate`
/// to `origin.phantom.test` and the full list to `127.0.0.1`, direct and
/// through both proxies.
fn accept_encoding(name: &str) -> RequestField {
    RequestField::by_trust(name, V154_ACCEPT_ENCODING, V154_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns [`accept_encoding`] for a WebSocket opening template.
fn websocket_accept_encoding(name: &str) -> WebSocketField {
    WebSocketField::by_trust(name, V154_ACCEPT_ENCODING, V154_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns navigation request fields observed from Chrome 154.0.8037.58 on Windows 11.
///
/// A top-level navigation the user starts from the address bar: an HTML
/// document request with `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
/// The HTTP/1.1 order comes from plaintext loopback page loads in the retained
/// Chrome 154 SSE, WebSocket, and client-hint captures; the HTTP/2 order from
/// the page requests of the WebSocket captures; the HTTP/3 order from the H3
/// startup capture. Every run agrees. Each captured HTTP/2 page request carries
/// HEADERS priority weight 256, exclusive, on stream 0, which is also
/// [`v154_http2`]'s connection priority.
///
/// The client hints form one block in profile order after `Connection` or
/// `Proxy-Connection` (on HTTP/1.1) and before `Upgrade-Insecure-Requests`; after `Accept-CH` the
/// requested hints join that block, as the HTTP/1.1 client-hint capture shows.
/// No capture records an HTTP/2 or HTTP/3 navigation after `Accept-CH`; the
/// same placement on those protocols is inferred from the default block, which
/// every protocol's capture places identically. The `User-Agent` value is the
/// one headful Chrome sent in the retained launch-mode SSE capture; the other
/// captures ran headless and sent `HeadlessChrome`. `Accept-Language` is the
/// capture machine's `en-US` locale. A caller field with the same name replaces
/// a captured value in place.
///
/// Chrome sends the `Sec-Fetch-*` fields, and `br` and `zstd` in
/// `Accept-Encoding`, only to a potentially trustworthy URL, so those entries
/// are [`RequestField::ByTrust`]: `network::SetFetchMetadataHeaders` returns
/// before adding any `Sec-Fetch-*` field when `IsUrlPotentiallyTrustworthy`
/// is false (`services/network/sec_header_helpers.cc` lines 288-292 at tag
/// `154.0.8037.58`); `HttpRequestHeaders::SetAcceptEncodingIfMissing` adds
/// `br` and `zstd` only for a cryptographic or `net::IsLocalhost` URL
/// (`net/http/http_request_headers.cc` lines 261-275). The retained proxy
/// route captures show the
/// navigation to the plaintext name `origin.phantom.test` without them, with
/// `Accept-Encoding: gzip, deflate`, and with the remaining fields in the same
/// order on HTTP/1.1 and HTTP/2; Chrome sends no client hints there either.
///
/// When an HTTP/1.1 proxy forwards the request, Chrome sends
/// `Proxy-Connection: keep-alive` where a direct request has
/// `Connection: keep-alive`, so both are [`RequestField::ByForwarding`]
/// entries. The retained `http-proxy-*` proxy route captures show this on
/// every forwarded page request and `fetch()`, with the other fields
/// unchanged.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    v154_navigation_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Returns same-origin `fetch` request fields observed from Chrome 154.0.8037.58 on
/// Windows 11.
///
/// A script `fetch(url, {cache: "no-store"})` GET to the page's own origin;
/// the cache mode adds `Pragma` and `Cache-Control`. The HTTP/1.1 and HTTP/2
/// orders come from the final report request of the retained Chrome 154
/// WebSocket captures, and every run agrees. No capture backs this request kind
/// on HTTP/3, so [`RequestTemplate::http3_fields`] is `None`.
///
/// Each captured HTTP/2 fetch carries HEADERS priority weight 220, exclusive,
/// on stream 0, unlike the navigation's 256 in [`v154_http2`];
/// [`RequestTemplate::http2_priority`] records it so the fetch does not go out
/// with the connection's navigation weight. Chrome can make a stream depend on
/// another open stream of equal or higher priority
/// (`net/spdy/http2_priority_dependencies.cc`); in the captures the only open
/// stream was a lower-priority WebSocket, the dependency was stream 0, and the
/// template always sends stream 0.
///
/// Unlike a navigation, the default client hints are split:
/// `sec-ch-ua-platform` precedes `User-Agent`, and `sec-ch-ua` and
/// `sec-ch-ua-mobile` follow it. Where Chrome puts hints requested through
/// `Accept-CH` on such a request is not captured, so
/// [`RequestTemplate::requested_client_hint_placement`] is `false` and the
/// `phantom` client refuses to send a requested hint with this template.
/// `Referer` is a caller slot because its value is the page URL. The
/// `User-Agent` value matches [`v154_windows_navigation_template`].
///
/// As on the navigation, the `Sec-Fetch-*` fields and the `br` and `zstd`
/// codings are sent only to a potentially trustworthy URL. The proxy route
/// captures back that shape with a same-origin `fetch()` in the default cache
/// mode, and the `*-auth-nostore-*` captures with a no-store `fetch()` through
/// a proxy to both kinds of origin, `Pragma` and `Cache-Control` included. Forwarded through an HTTP/1.1
/// proxy, `Connection` becomes `Proxy-Connection`, as on the navigation.
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    v154_fetch_no_store_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Returns navigation request fields observed from Chrome 154.0.8037.58 on
/// macOS 15.5 arm64.
///
/// The fields, order, values, and HTTP/2 priority are those of
/// [`v154_windows_navigation_template`], which the headless page loads of
/// the retained macOS WebSocket captures and the macOS H3 startup capture
/// match on HTTP/1.1, HTTP/2, and HTTP/3 with [`v154_macos_client_hints`].
/// `User-Agent` is a required caller slot: every macOS capture ran headless
/// and sent `HeadlessChrome/154.0.0.0` with `Macintosh; Intel Mac OS X
/// 10_15_7`, and no headful macOS capture backs a literal value.
#[must_use]
pub fn v154_macos_navigation_template() -> RequestTemplate {
    v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Chrome
/// 154.0.8037.58 on macOS 15.5 arm64.
///
/// The fields, order, values, and HTTP/2 priority are those of
/// [`v154_windows_fetch_no_store_template`], with `User-Agent` as a required
/// caller slot for the reason given in [`v154_macos_navigation_template`].
#[must_use]
pub fn v154_macos_fetch_no_store_template() -> RequestTemplate {
    v154_fetch_no_store_template(None)
}

/// Returns Chromium 154's position of forwarded proxy credentials, on the
/// replay after a `407` and on later requests alike: after
/// `Proxy-Connection` on HTTP/1.1 and first after the pseudo-header fields
/// on HTTP/2, except that the `Pragma` and `Cache-Control` fields of a
/// no-store `fetch()` come before it.
///
/// The retained `http-proxy-auth-*` and `https-proxy-auth-*` proxy route
/// captures of Chrome 154 and Edge 154 show this on the replayed navigation
/// and on the default-mode `fetch()` that follows it, to loopback and named
/// origins, with a loopback origin's client hints after it. The
/// `*-auth-remembered-hostname` captures show the same place on a replayed
/// `fetch()` and on a navigation with remembered credentials, and the
/// `*-auth-nostore-*` captures show a no-store `fetch()`, challenged,
/// replayed, and with remembered credentials, placing it after
/// `Cache-Control` and before the client hints.
fn chromium_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Every)
}

/// Builds the Chromium 154 navigation lists with a literal or required caller
/// `User-Agent`.
pub(crate) fn v154_navigation_template(user_agent: Option<&str>) -> RequestTemplate {
    let user_agent = |name: &str| match user_agent {
        Some(value) => RequestField::literal(name, value),
        None => RequestField::required_caller(name),
    };
    let http2_fields = vec![
        chromium_proxy_authorization("proxy-authorization"),
        RequestField::ClientHints,
        RequestField::literal("upgrade-insecure-requests", "1"),
        user_agent("user-agent"),
        RequestField::literal("accept", V154_NAVIGATION_ACCEPT),
        RequestField::trustworthy_only("sec-fetch-site", "none"),
        RequestField::trustworthy_only("sec-fetch-mode", "navigate"),
        RequestField::trustworthy_only("sec-fetch-user", "?1"),
        RequestField::trustworthy_only("sec-fetch-dest", "document"),
        accept_encoding("accept-encoding"),
        RequestField::literal("accept-language", V154_ACCEPT_LANGUAGE),
        RequestField::literal("priority", "u=0, i"),
    ];
    RequestTemplate {
        http1_fields: vec![
            RequestField::unless_forwarded("Connection", "keep-alive"),
            RequestField::when_forwarded("Proxy-Connection", "keep-alive"),
            chromium_proxy_authorization("Proxy-Authorization"),
            RequestField::ClientHints,
            RequestField::literal("Upgrade-Insecure-Requests", "1"),
            user_agent("User-Agent"),
            RequestField::literal("Accept", V154_NAVIGATION_ACCEPT),
            RequestField::trustworthy_only("Sec-Fetch-Site", "none"),
            RequestField::trustworthy_only("Sec-Fetch-Mode", "navigate"),
            RequestField::trustworthy_only("Sec-Fetch-User", "?1"),
            RequestField::trustworthy_only("Sec-Fetch-Dest", "document"),
            accept_encoding("Accept-Encoding"),
            RequestField::literal("Accept-Language", V154_ACCEPT_LANGUAGE),
        ],
        // An HTTP proxy never forwards HTTP/3, so that list has no
        // credentials slot.
        http3_fields: Some(http2_fields[1..].to_vec()),
        http2_fields,
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 256,
            exclusive: true,
        }),
        requested_client_hint_placement: true,
    }
}

/// Builds the Chromium 154 no-store fetch lists with a literal or required
/// caller `User-Agent`.
pub(crate) fn v154_fetch_no_store_template(user_agent: Option<&str>) -> RequestTemplate {
    let user_agent = |name: &str| match user_agent {
        Some(value) => RequestField::literal(name, value),
        None => RequestField::required_caller(name),
    };
    RequestTemplate {
        http1_fields: vec![
            RequestField::unless_forwarded("Connection", "keep-alive"),
            RequestField::when_forwarded("Proxy-Connection", "keep-alive"),
            RequestField::literal("Pragma", "no-cache"),
            RequestField::literal("Cache-Control", "no-cache"),
            chromium_proxy_authorization("Proxy-Authorization"),
            RequestField::client_hint("sec-ch-ua-platform"),
            user_agent("User-Agent"),
            RequestField::client_hint("sec-ch-ua"),
            RequestField::client_hint("sec-ch-ua-mobile"),
            RequestField::ClientHints,
            RequestField::literal("Accept", "*/*"),
            RequestField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
            RequestField::trustworthy_only("Sec-Fetch-Mode", "cors"),
            RequestField::trustworthy_only("Sec-Fetch-Dest", "empty"),
            RequestField::caller("Referer"),
            accept_encoding("Accept-Encoding"),
            RequestField::literal("Accept-Language", V154_ACCEPT_LANGUAGE),
        ],
        http2_fields: vec![
            RequestField::literal("pragma", "no-cache"),
            RequestField::literal("cache-control", "no-cache"),
            chromium_proxy_authorization("proxy-authorization"),
            RequestField::client_hint("sec-ch-ua-platform"),
            user_agent("user-agent"),
            RequestField::client_hint("sec-ch-ua"),
            RequestField::client_hint("sec-ch-ua-mobile"),
            RequestField::ClientHints,
            RequestField::literal("accept", "*/*"),
            RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
            RequestField::trustworthy_only("sec-fetch-mode", "cors"),
            RequestField::trustworthy_only("sec-fetch-dest", "empty"),
            RequestField::caller("referer"),
            accept_encoding("accept-encoding"),
            RequestField::literal("accept-language", V154_ACCEPT_LANGUAGE),
            RequestField::literal("priority", "u=1, i"),
        ],
        http3_fields: None,
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 220,
            exclusive: true,
        }),
        requested_client_hint_placement: false,
    }
}

/// Returns HTTP/3 settings observed from Chrome 154.0.8037.58 on Windows 11.
///
/// The five settings, their ascending order, their id and value widths, and the
/// randomized reserved setting come from the retained Chrome 154 raw
/// control-stream capture, three fresh processes. The QPACK encoding and the
/// empty decoder-stream prefix come from the same capture. The QPACK stream
/// order and the encoder stream's lazy type follow the retained resumption
/// captures: Chrome 154 opens its decoder stream before its encoder stream, so
/// the encoder is client stream 10, and writes the encoder stream type only
/// with its first instructions. The returned value is owned and can be
/// customized before constructing a transport.
#[must_use]
pub fn v154_http3() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(65_536),
            Http3Setting::MaxFieldSectionSize(262_144),
            Http3Setting::QpackBlockedStreams(100),
            Http3Setting::H3Datagram(true),
            Http3Setting::RandomizedGrease,
        ],
        setting_order: Http3SettingOrder::Ascending,
        qpack_encoding: Http3QpackEncoding::Dynamic,
        qpack_decoder_stream: Http3QpackDecoderStream::OnFeedback,
        qpack_encoder_stream: Http3QpackEncoderStream::OnFirstInstruction,
        qpack_stream_order: Http3QpackStreamOrder::DecoderFirst,
    }
}

/// Returns TLS settings for the Chrome 154.0.8037.58 HTTP/3 offer on Windows 11.
///
/// The wire-visible offer fields come from the retained Chrome 154 QUIC
/// ClientHellos. They match [`v154_tls`], including the sorted trust-anchor ID
/// list, except for the fields this function replaces: TLS 1.3 only, three
/// cipher suites with no GREASE, the nine non-ML-DSA signature schemes ending
/// in `rsa_pkcs1_sha1`, an `h3` ALPN offer and `h3` ALPS protocol, and no
/// GREASE, OCSP staple, or SCT request. The empty application-settings value
/// follows Chromium's QUIC configuration. The returned value is owned and can
/// be customized before transport setup.
///
/// `session_tickets` is enabled because Chrome 154 resumes QUIC sessions with
/// TLS 1.3 tickets. `QuicSessionPool::CreateCryptoConfigHandle` gives each
/// crypto configuration a `quic::QuicClientSessionCache`
/// (`net/quic/quic_session_pool.cc` at tag `154.0.8037.58`), and
/// `TlsClientConnection::CreateSslCtx` enables BoringSSL client session
/// caching (`quiche/quic/core/crypto/tls_client_connection.cc` at quiche
/// revision `80bf9559`, which Chromium's `DEPS` pins at that tag). A TLS
/// 1.3-only offer never carries the TLS 1.2 `session_ticket` extension, so a
/// first ClientHello is unchanged. The retained resumption captures show a
/// resumed Chrome 154 ClientHello adding `early_data` and, last,
/// `pre_shared_key`; [`v154_quic`] sets `early_data` so a resumed connection
/// offers it too.
///
/// [`TlsSettings::ech_from_https_records`] stays set from [`v154_tls`]:
/// given an HTTPS record that lists `h3` and carries `ech`, Chrome 154
/// encrypted its QUIC ClientHello with the record's configuration, under the
/// public name, with the extension set of its ECH GREASE QUIC ClientHello.
/// After a rejection it did not open another QUIC connection with the
/// server's retry configurations; the request went over TCP instead.
/// Phantom's exact HTTP/3 requests, and negotiated requests under the
/// sequential Alt-Svc policy, have no such fallback and keep failing on a
/// stale configuration until the cached record expires. Set
/// `ech_from_https_records = false` on the returned value to send ECH
/// GREASE instead.
#[must_use]
pub fn v154_http3_tls() -> TlsSettings {
    let mut settings = v154_tls();
    settings.min_version = TlsVersion::Tls13;
    settings.max_version = TlsVersion::Tls13;
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ];
    settings.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPkcs1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::RsaPssRsaeSha384,
        SignatureScheme::RsaPkcs1Sha384,
        SignatureScheme::RsaPssRsaeSha512,
        SignatureScheme::RsaPkcs1Sha512,
        SignatureScheme::RsaPkcs1Sha1,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h3"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });
    settings.session_tickets = true;
    settings.grease = false;
    settings.grease_signature_algorithms = false;
    settings.request_ocsp_staple = false;
    settings.request_signed_certificate_timestamps = false;
    settings
}

/// Returns HTTP/3 request ordering observed from Chrome 154.0.8037.58 on Windows 11.
///
/// The retained Chrome 154 H3 startup capture sends `:method`, `:authority`,
/// `:scheme`, and `:path` in that order ahead of the ordinary request fields.
/// No capture backs an HTTP/3 extended CONNECT, so
/// [`Http3RequestSettings::extended_connect_pseudo_header_order`] is `None`.
///
/// Each `cookie` field is split into one field per cookie
/// ([`Http3CookieCrumbs::Split`]). The retained cookie captures
/// (`fixtures/cookies/`) show Chrome 154, Edge 154, Brave 154, and Opera 135
/// inserting each crumb into the QPACK dynamic table with a static name
/// reference and sending it as an indexed field line, at the position of the
/// joined field.
#[must_use]
pub fn v154_http3_request() -> Http3RequestSettings {
    Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
        cookie_crumbs: Http3CookieCrumbs::Split,
    }
}

/// Returns QUIC transport settings observed from Chrome 154.0.8037.58 on Windows 11.
///
/// Every parameter, id width, length width, and value comes from the retained
/// Chrome 154 QUIC startup capture, three fresh processes. Chrome ran without
/// `--disable-field-trial-config`, so `max_idle_timeout` is 30000 ms and the
/// Google connection option is `ORIG`.
///
/// The parameter vector retains one captured order as a permutation template;
/// Chrome varies that order between connections. Connection IDs, the reserved
/// version, and the reserved transport parameter remain runtime-generated.
/// This is a QUIC transport recipe; use it with [`v154_http3`] for the HTTP/3
/// application settings captured from the same client.
///
/// The retained resumption captures of Chrome 154 and Edge 154 add two
/// things to a resumed connection. Its ClientHello offers early data, so
/// `early_data` is set; it takes effect with H3 TLS settings that enable
/// session tickets, such as [`v154_http3_tls`]. Its transport parameters add
/// `initial_rtt_us` (`0x3127`) with a two-byte id, a one-byte length, and a
/// minimal-length value, at a position permuted with the others. A fresh
/// connection sends neither.
#[must_use]
pub fn v154_quic() -> QuicTransportSettings {
    use QuicTransportParameterKind as Kind;
    use QuicVarIntWidth::{Eight, Four, One, Two};

    let parameter = |kind, id_width, length_width| QuicTransportParameter {
        kind,
        id_width,
        length_width,
    };

    QuicTransportSettings {
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 1_472,
        initial_max_data: 15_728_640,
        initial_max_stream_data_bidi_local: 6_291_456,
        initial_max_stream_data_bidi_remote: 6_291_456,
        initial_max_stream_data_uni: 6_291_456,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 103,
        max_datagram_frame_size: Some(65_536),
        wire_parameters: vec![
            parameter(Kind::InitialMaxStreamsBidi { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataUni { value_width: Four },
                One,
                One,
            ),
            parameter(
                Kind::VersionInformation(QuicVersionInformation {
                    available_version_count: 1,
                    grease: QuicVersionGrease::Permuted,
                }),
                One,
                One,
            ),
            parameter(Kind::InitialMaxData { value_width: Four }, One, One),
            parameter(Kind::InitialMaxStreamsUni { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataBidiRemote { value_width: Four },
                One,
                One,
            ),
            parameter(Kind::MaxIdleTimeout { value_width: Four }, One, One),
            parameter(
                Kind::GoogleConnectionOptions(vec![GoogleConnectionOption::RequestOriginFrame]),
                Two,
                One,
            ),
            parameter(Kind::MaxDatagramFrameSize { value_width: Four }, One, One),
            parameter(
                Kind::Grease(QuicTransportGrease {
                    minimum_payload_length: 0,
                    maximum_payload_length: 15,
                }),
                Eight,
                One,
            ),
            parameter(Kind::MaxUdpPayloadSize { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataBidiLocal { value_width: Four },
                One,
                One,
            ),
            parameter(Kind::InitialSourceConnectionId { length: 0 }, One, One),
            parameter(Kind::InitialRtt, Two, One),
        ],
        parameter_order: QuicTransportParameterOrder::Permuted,
        early_data: true,
    }
}

fn trust_anchor_ids(ids: &[&[u8]]) -> Vec<Box<[u8]>> {
    ids.iter().map(|id| Box::from(*id)).collect()
}

#[cfg(test)]
mod http3_tests;
#[cfg(test)]
mod quic_tests;
#[cfg(test)]
mod tests;
