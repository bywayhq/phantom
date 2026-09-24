//! Wire settings retained from Chromium-family browser observations.

use std::{num::NonZeroUsize, time::Duration};

use crate::{
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    cookie::CookiePlacement,
    http1::Http1Settings,
    http2::{
        Http2HpackSettings, Http2HuffmanCoding, Http2Priority, Http2PseudoHeader, Http2Setting,
        Http2Settings, Http2StaticNameIndex,
    },
    http3::{
        Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3RequestSettings,
        Http3Setting, Http3SettingOrder, Http3Settings,
    },
    request_template::{RequestField, RequestTemplate},
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

// Chrome 154 sorts the trust-anchor ID list before encoding it (Chromium
// commit `942bda4298c1`), so every process emits these 28 identifiers in
// ascending byte order. All 60 fresh processes of the retained
// `trust-anchor-orders.txt` capture, the retained `client-hello.txt`, and both
// retained QUIC ClientHellos carry exactly this order.
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

/// Returns the automatic `Cookie` field position for Chrome 154.
///
/// Chrome appends `Cookie` after every other request field it builds:
/// `URLRequestHttpJob::AddCookieHeaderAndStart` sets it on the extra headers
/// last (`net/url_request/url_request_http_job.cc:799-871` at Chromium tag
/// `154.0.8037.58`). The retained Chrome 154 HTTP/1.1 EventSource reconnect
/// capture `set-cookie-then-close.txt` sends it last on every run. For H2 and
/// H3, `CreateSpdyHeadersFromHttpRequest` copies those fields in order and then
/// appends `priority` (`net/spdy/spdy_http_utils.cc:32`, `:199-236`), so
/// `Cookie` precedes a `priority` field. That H2 and H3 position comes from
/// Chromium source, not from a capture.
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
        record_size_limit: None,
        requested_trust_anchor_ids: Some(trust_anchor_ids(V154_TRUST_ANCHOR_IDS)),
        grease: true,
        grease_signature_algorithms: true,
        extension_order: ClientHelloExtensionOrder::Permuted,
        ech_grease: true,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
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
        },
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
/// `User-Agent`, `Origin`, `Accept-Encoding`, and `Accept-Language` are caller
/// slots because their values are persona and page data. The captures carry no
/// cookies, so the cookie placeholder's final position is not observed. The
/// compression offer is `permessage-deflate; client_max_window_bits`; Chrome
/// always sends it, while Phantom sends it only when the caller enables
/// compression. Edge 153.0.4234.48 matches this recipe on every compared field.
///
/// The `refused-stream` captures show Chrome answering
/// `RST_STREAM(REFUSED_STREAM)` with one further extended CONNECT on the same
/// H2 session and the next client stream id, which the peer then accepted; no
/// data frame had been sent on the refused stream. The `accept-deflate`
/// captures show a zero-length text message compressed into one byte with RSV1
/// set.
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
            WebSocketField::caller("Accept-Encoding"),
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
            WebSocketField::caller("accept-encoding"),
            WebSocketField::caller("accept-language"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: vec![WebSocketDeflateParameter::ClientMaxWindowBits(None)],
        empty_message_compression: WebSocketEmptyMessageCompression::Compressed,
    }
}

const V154_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const V154_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V154_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V154_WINDOWS_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

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
/// The client hints form one block in profile order after `Connection` (on
/// HTTP/1.1) and before `Upgrade-Insecure-Requests`; after `Accept-CH` the
/// requested hints join that block, as the HTTP/1.1 client-hint capture shows.
/// No capture records an HTTP/2 or HTTP/3 navigation after `Accept-CH`; the
/// same placement on those protocols is inferred from the default block, which
/// every protocol's capture places identically. The `User-Agent` value is the
/// one headful Chrome sent in the retained launch-mode SSE capture; the other
/// captures ran headless and sent `HeadlessChrome`. `Accept-Language` is the
/// capture machine's `en-US` locale. A caller field with the same name replaces
/// a captured value in place.
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
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    v154_fetch_no_store_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Builds the Chromium 154 navigation lists with a literal or required caller
/// `User-Agent`.
pub(crate) fn v154_navigation_template(user_agent: Option<&str>) -> RequestTemplate {
    let user_agent = |name: &str| match user_agent {
        Some(value) => RequestField::literal(name, value),
        None => RequestField::required_caller(name),
    };
    let http2_fields = vec![
        RequestField::ClientHints,
        RequestField::literal("upgrade-insecure-requests", "1"),
        user_agent("user-agent"),
        RequestField::literal("accept", V154_NAVIGATION_ACCEPT),
        RequestField::literal("sec-fetch-site", "none"),
        RequestField::literal("sec-fetch-mode", "navigate"),
        RequestField::literal("sec-fetch-user", "?1"),
        RequestField::literal("sec-fetch-dest", "document"),
        RequestField::literal("accept-encoding", V154_ACCEPT_ENCODING),
        RequestField::literal("accept-language", V154_ACCEPT_LANGUAGE),
        RequestField::literal("priority", "u=0, i"),
    ];
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("Connection", "keep-alive"),
            RequestField::ClientHints,
            RequestField::literal("Upgrade-Insecure-Requests", "1"),
            user_agent("User-Agent"),
            RequestField::literal("Accept", V154_NAVIGATION_ACCEPT),
            RequestField::literal("Sec-Fetch-Site", "none"),
            RequestField::literal("Sec-Fetch-Mode", "navigate"),
            RequestField::literal("Sec-Fetch-User", "?1"),
            RequestField::literal("Sec-Fetch-Dest", "document"),
            RequestField::literal("Accept-Encoding", V154_ACCEPT_ENCODING),
            RequestField::literal("Accept-Language", V154_ACCEPT_LANGUAGE),
        ],
        http3_fields: Some(http2_fields.clone()),
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
            RequestField::literal("Connection", "keep-alive"),
            RequestField::literal("Pragma", "no-cache"),
            RequestField::literal("Cache-Control", "no-cache"),
            RequestField::client_hint("sec-ch-ua-platform"),
            user_agent("User-Agent"),
            RequestField::client_hint("sec-ch-ua"),
            RequestField::client_hint("sec-ch-ua-mobile"),
            RequestField::ClientHints,
            RequestField::literal("Accept", "*/*"),
            RequestField::literal("Sec-Fetch-Site", "same-origin"),
            RequestField::literal("Sec-Fetch-Mode", "cors"),
            RequestField::literal("Sec-Fetch-Dest", "empty"),
            RequestField::caller("Referer"),
            RequestField::literal("Accept-Encoding", V154_ACCEPT_ENCODING),
            RequestField::literal("Accept-Language", V154_ACCEPT_LANGUAGE),
        ],
        http2_fields: vec![
            RequestField::literal("pragma", "no-cache"),
            RequestField::literal("cache-control", "no-cache"),
            RequestField::client_hint("sec-ch-ua-platform"),
            user_agent("user-agent"),
            RequestField::client_hint("sec-ch-ua"),
            RequestField::client_hint("sec-ch-ua-mobile"),
            RequestField::ClientHints,
            RequestField::literal("accept", "*/*"),
            RequestField::literal("sec-fetch-site", "same-origin"),
            RequestField::literal("sec-fetch-mode", "cors"),
            RequestField::literal("sec-fetch-dest", "empty"),
            RequestField::caller("referer"),
            RequestField::literal("accept-encoding", V154_ACCEPT_ENCODING),
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
/// empty decoder-stream prefix come from the same capture. The returned value
/// is owned and can be customized before constructing a transport.
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
    }
}

/// Returns TLS settings for the Chrome 154.0.8037.58 HTTP/3 offer on Windows 11.
///
/// The wire-visible offer fields come from the retained Chrome 154 QUIC
/// ClientHellos. They match [`v154_tls`], including the sorted trust-anchor ID
/// list, except for the fields this function replaces: TLS 1.3 only, three
/// cipher suites with no GREASE, the nine non-ML-DSA signature schemes ending
/// in `rsa_pkcs1_sha1`, an `h3` ALPN offer and `h3` ALPS protocol, and no
/// session ticket, GREASE, OCSP staple, or SCT request. The empty
/// application-settings value follows Chromium's QUIC configuration. The
/// returned value is owned and can be customized before transport setup.
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
    settings.session_tickets = false;
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
        ],
        parameter_order: QuicTransportParameterOrder::Permuted,
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
