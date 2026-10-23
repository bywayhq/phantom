//! Firefox connection settings and request templates.
//!
//! Desktop recipes target Firefox 157. Android provides TCP and TLS settings
//! for Firefox 156.0.1; other Android layers are unavailable.

pub use crate::catalog::browser_profiles::firefox::*;

mod android;

pub use android::{v156_android_tcp, v156_android_tcp_tls};

use crate::{
    cookie::CookiePlacement,
    dns_cache::DnsCacheSettings,
    http1::Http1Settings,
    http2::{Http2Priority, Http2Settings},
    http3::{Http3RequestSettings, Http3Settings},
    proxy_connect::ProxyConnectTemplate,
    quic::QuicTransportSettings,
    request_template::{ProxyAuthorizationAttempt, RequestField, RequestTemplate},
    tcp::TcpSettings,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

/// Returns Firefox 157's automatic `Cookie` position.
///
/// Places it after `Referer`, before fetch metadata, revalidation fields,
/// `Priority` and cache controls. HTTP/2 appends `te` last.
#[must_use]
pub fn v157_cookie_placement() -> CookiePlacement {
    crate::catalog::cookie_components::firefox_157_cookie()
}

/// Returns Firefox 157.0 TLS settings for Windows 11.
///
/// Keeps a fixed extension order. ECH GREASE chooses AES-128-GCM or
/// ChaCha20-Poly1305 per connection and sizes its payload from the ClientHello,
/// using a maximum name length of 100.
///
/// Keeps ten tickets per origin and offers the earliest connection's tickets
/// first, with that connection's last ticket first. Each ticket is used once.
/// Replay-safe requests can use early data on direct TCP connections;
/// proxy connections disable it. Resumed handshakes omit the empty
/// `session_ticket` extension and put `pre_shared_key` last.
///
/// The delegated-credential list includes ECDSA-SHA1, which TLS 1.3 cannot
/// select for authentication. TLS 1.2 compatibility extensions remain present
/// in a TLS 1.3-only ClientHello, as needed by [`v157_quic_tls`].
#[must_use]
pub fn v157_tcp_tls() -> TlsSettings {
    crate::tls::components::firefox_157_tcp_tls()
}

/// Returns Firefox 157.0 TCP settings for Windows.
///
/// Sets `TCP_NODELAY` and a 524,288-byte send buffer. Keepalive uses
/// [`crate::TcpKeepaliveSchedule`]: 10 seconds idle initially, 600 seconds
/// once long-lived, with the interval derived from connection setup time.
/// HTTP/2 disables it; WebSocket upgrades switch to long-lived settings.
///
/// [`crate::TcpBackupConnection`] starts an IPv4 backup after 250 ms and keeps
/// the slower successful connection. Later attempts use the remembered address
/// family and a five-second backup timeout. With [`v157_dns_cache`], cached
/// answers skip addresses that failed earlier. Port selection stays unchanged.
///
/// Use [`v157_macos_tcp`], [`v157_linux_tcp`] or [`v156_android_tcp`] elsewhere.
/// Phantom prunes address-family history on its idle timer, so server closes
/// can leave that history longer than in Firefox. It uses normal socket
/// shutdown rather than Firefox's Windows `SO_LINGER` setting.
///
/// See `nsSocketTransport2.cpp` and `DnsAndConnectSocket.cpp` at
/// `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_tcp() -> TcpSettings {
    crate::catalog::tcp_components::firefox_157_tcp()
}

/// Returns Firefox 157.0 TCP settings for macOS.
///
/// Keepalive sets the idle time while leaving interval and probe count
/// unchanged. The switch timer assumes eight probes. The send buffer stays
/// unchanged. Address selection follows [`v157_tcp`].
#[must_use]
pub fn v157_macos_tcp() -> TcpSettings {
    crate::catalog::tcp_components::firefox_157_macos_tcp()
}

/// Returns Firefox 157.0 TCP settings for Linux.
///
/// Keepalive sets the idle time, computed interval and four probes. The send
/// buffer stays unchanged. Address selection follows [`v157_tcp`].
#[must_use]
pub fn v157_linux_tcp() -> TcpSettings {
    crate::catalog::tcp_components::firefox_157_linux_tcp()
}

/// Returns Firefox 157.0 address-cache settings.
///
/// Keeps up to 1,600 entries. System answers and failed lookups live for
/// 60 seconds. On Windows, uses the smallest native A/AAAA TTL without a
/// minimum. Non-ASCII names use the standard resolver without optional TTLs.
///
/// Reuses positive answers for another ten minutes while refreshing them in
/// the background. Phantom obtains native TTLs before publishing an answer;
/// Firefox can obtain them in a second lookup.
///
/// See `netwerk/dns/nsHostResolver.cpp` at `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_dns_cache() -> DnsCacheSettings {
    crate::catalog::dns_components::firefox_157_dns_cache()
}

/// Returns Firefox 157.0 HTTP/1.1 connection settings.
///
/// Allows six connections per origin and route, including idle connections.
/// Closes them after 115 seconds idle using a timer.
///
/// Phantom keeps that limit for forwarded proxy requests, where Firefox
/// allows 32. It omits Firefox's three urgent-start excess slots and ignores
/// response `Keep-Alive` timeout values.
///
/// See `nsHttpConnectionMgr.cpp` and `nsHttpConnection.cpp` at
/// `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_http1() -> Http1Settings {
    crate::catalog::http1_components::firefox_157_http1()
}

/// Returns Firefox 157.0 HTTP/2 settings.
///
/// The first request uses stream 3. Navigation HEADERS use non-exclusive
/// priority on stream 0 with weight 42; extended CONNECT uses weight 22.
/// The initial stream limit is 100, replaced by the peer's stated limit.
///
/// HPACK indexes pseudo-headers except `:path`, always uses Huffman coding,
/// and prefers the oldest dynamic name reference. `authorization` is
/// never indexed; other fields may be indexed up to half the table size.
/// Every peer table-size setting is announced. Cookie crumbs shorter than
/// 20 bytes are never indexed. See [`crate::Http2CookieCrumbs::NeverIndexShort`]
/// and [`crate::Http2NameReference::OldestDynamic`].
///
/// After 58 seconds without a read, sends a zero-payload PING. Eight seconds
/// without an answer or another read closes the connection with
/// `GOAWAY(0, INTERNAL_ERROR)`; affected requests are not replayed. Phantom
/// uses a timer at 58 seconds rather than Firefox's periodic timeout tick.
/// Network changes do not trigger a PING.
///
/// After 170 seconds without response HEADERS or DATA, stops accepting new
/// streams and closes when idle. PING ACKs do not extend this period.
/// Requests raise the advertised 131,072-byte stream window to 12,582,912
/// bytes after HEADERS. See `Http2Session.cpp` at `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_http2() -> Http2Settings {
    crate::catalog::http2_components::firefox_157_http2()
}

/// Returns Firefox 157.0 WebSocket settings.
///
/// Direct `ws://` openings keep their address-family state separate from HTTP.
///
/// Reuses a capable HTTP/2 session, including through a proxy. With no
/// session, opens HTTP/2; if an existing session forbids extended CONNECT,
/// opens HTTP/1.1 instead. Refused extended CONNECT is not retried.
///
/// Supply `User-Agent`, `Accept-Language` and `Origin`. Compression is offered
/// when you enable it, using bare `permessage-deflate`. Empty messages stay
/// uncompressed. Trustworthy URLs receive `Sec-Fetch-*` and the `br`/`zstd`
/// codings. Override `Sec-Fetch-Site: same-origin` for a cross-site page;
/// matching caller fields replace template values in place.
///
/// The opening deadline is 20 seconds, including DNS lookup. Firefox's timer
/// starts after its per-host admission lookup. See `WebSocketChannel.cpp`
/// at `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_websocket() -> WebSocketSettings {
    crate::catalog::websocket_components::firefox_157_websocket()
}

/// Returns Firefox 157.0 proxy CONNECT settings.
///
/// HTTP/1.1 sends `User-Agent`, `Proxy-Connection`, `Connection` and `Host`,
/// then challenged credentials. HTTP/2 sends `user-agent` after the two
/// pseudo-headers, then credentials. Copies the opening request's user agent.
///
/// Leaves a challenged HTTP/2 CONNECT stream open. Separates proxy HTTP/2
/// connections for forwarding, HTTPS tunnels and WebSocket tunnels.
#[must_use]
pub fn v157_proxy_connect() -> ProxyConnectTemplate {
    crate::catalog::proxy_connect_components::firefox_157_proxy_connect()
}

/// Returns Firefox 157.0 TLS settings for HTTP/3.
///
/// Uses TLS 1.3 and `h3` ALPN. Compared with [`v157_tcp_tls`], changes the
/// signature order, omits ML-DSA, and offers zlib, zstd and brotli certificate
/// compression. Omits `ec_point_formats`, `session_ticket` and SCT requests.
///
/// Permutes extensions except the trailing QUIC parameters and ECH, followed
/// by `pre_shared_key` on resumption. Keeps TLS 1.2 compatibility extensions
/// and `record_size_limit`, although QUIC carries no TLS records. Session
/// tickets enable early data with [`v157_quic`].
#[must_use]
pub fn v157_quic_tls() -> TlsSettings {
    crate::tls::components::firefox_157_quic_tls()
}

/// Returns Firefox 157.0 QUIC transport settings.
///
/// Receive windows are 12 MiB for locally opened streams, 1 MiB for peer
/// streams and 24 MiB per connection. Uses a 20 ms maximum ACK delay,
/// eight active connection IDs and a three-byte source connection ID.
///
/// Starts fresh connections with QUIC v1, supports compatible negotiation
/// to v2, and resumes with the ticket's version. Advertises `reset_stream_at`,
/// a 1,000-microsecond draft minimum ACK delay and 65,535-byte datagrams.
/// Omits `max_udp_payload_size`, `grease_quic_bit` and reserved parameters.
///
/// A 1,280-byte path MTU leaves Initial datagrams of 1,252 bytes over IPv4
/// and 1,232 over IPv6. The initial destination ID length follows neqo's
/// `max(8, 5 + (b & (b >> 4)))` for a random byte b (`neqo-transport/src/cid.rs`
/// in neqo 0.31.1). Resumption permits early data with [`v157_quic_tls`]
/// and omits `initial_rtt_us`.
#[must_use]
pub fn v157_quic() -> QuicTransportSettings {
    crate::catalog::quic_components::firefox_157_quic()
}

/// Returns Firefox 157.0 HTTP/3 settings.
///
/// Uses a 64 KiB QPACK table and 20 blocked streams. Enables both draft and
/// final datagrams and extended CONNECT, with draft WebTransport disabled.
/// A reserved frame follows SETTINGS.
///
/// Opens control stream 2, QPACK encoder 6 and decoder 10, writing each type
/// immediately. QPACK uses [`crate::Http3QpackEncoding::DynamicUnmatchedNames`].
#[must_use]
pub fn v157_http3() -> Http3Settings {
    crate::catalog::http3_components::firefox_157_http3()
}

/// Returns Firefox 157.0 HTTP/3 request settings.
///
/// Orders pseudo-headers as `:method`, `:scheme`, `:authority`, `:path` and
/// keeps cookies in one field. Extended CONNECT ordering is unavailable.
///
/// Uses [`crate::Http3AltUsed::ValidatedMapping`] with
/// [`crate::Http3AltUsedPort::OmitDefault`]. Learned alternatives become
/// eligible after authenticated setup; pinned alternatives are eligible
/// immediately. The template's [`RequestField::AltUsed`] slot selects the
/// position, or the field is appended if the template has no slot.
#[must_use]
pub fn v157_http3_request() -> Http3RequestSettings {
    crate::catalog::http3_components::firefox_157_http3_request()
}

const V157_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V157_PLAINTEXT_ACCEPT_ENCODING: &str = "gzip, deflate";
const V157_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V157_NAVIGATION_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const V157_WINDOWS_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0";
const V157_MACOS_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101 Firefox/157.0";

/// Offers `br` and `zstd` only to potentially trustworthy URLs.
///
/// Follows `HttpBaseChannel::Init` and `nsHttpHandler::AddStandardRequestHeaders`
/// at `FIREFOX_157_0_RELEASE`.
fn accept_encoding(name: &str) -> RequestField {
    RequestField::by_trust(name, V157_ACCEPT_ENCODING, V157_PLAINTEXT_ACCEPT_ENCODING)
}

/// Places remembered forwarding credentials before `Connection` on HTTP/1.1,
/// and at the corresponding position on HTTP/2.
fn preemptive_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Preemptive)
}

/// Places credentials on a `407` replay after all template fields on
/// HTTP/1.1, and before `te` on HTTP/2.
fn replay_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Replay)
}

/// Returns Firefox 157 Windows address-bar navigation fields.
///
/// Uses `Sec-Fetch-Site: none`, `Sec-Fetch-User: ?1` and non-exclusive HTTP/2
/// weight 42 on stream 0. HTTP/1.1 includes `Priority`; HTTP/2 ends with
/// `te: trailers`. HTTP/3 places generated `Alt-Used` after `accept-encoding`
/// and before optional `referer`.
///
/// Uses an `en-US` language preference. Caller fields replace matching values.
/// Client hints are unavailable. `Sec-Fetch-*` and `br`/`zstd` require a
/// potentially trustworthy URL.
#[must_use]
pub fn v157_windows_navigation_template() -> RequestTemplate {
    navigation_template(V157_WINDOWS_USER_AGENT)
}

/// Returns Firefox 157 macOS navigation fields.
///
/// Uses [`v157_windows_navigation_template`]'s ordering and priority with
/// the macOS user agent. Its reduced platform string is `Intel Mac OS X 10.15`,
/// including on Apple silicon. Language defaults to `en-US`.
#[must_use]
pub fn v157_macos_navigation_template() -> RequestTemplate {
    navigation_template(V157_MACOS_USER_AGENT)
}

/// Builds the Firefox navigation lists with a literal `User-Agent`.
fn navigation_template(user_agent: &str) -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("User-Agent", user_agent),
            RequestField::literal("Accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("Accept-Language", V157_ACCEPT_LANGUAGE),
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
            RequestField::literal("user-agent", user_agent),
            RequestField::literal("accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
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
        http3_fields: Some(vec![
            RequestField::literal("user-agent", user_agent),
            RequestField::literal("accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
            accept_encoding("accept-encoding"),
            RequestField::AltUsed,
            RequestField::caller("referer"),
            RequestField::literal("upgrade-insecure-requests", "1"),
            RequestField::trustworthy_only("sec-fetch-dest", "document"),
            RequestField::trustworthy_only("sec-fetch-mode", "navigate"),
            RequestField::trustworthy_only("sec-fetch-site", "none"),
            RequestField::trustworthy_only("sec-fetch-user", "?1"),
            RequestField::literal("priority", "u=0, i"),
        ]),
        http2_priority: Some(crate::Http2RequestPriority::Fixed(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        })),
        requested_client_hint_placement: false,
        // Firefox sends no client hints and ignores ACCEPT_CH.
        restarts_for_connection_accept_ch: false,
    }
}

/// Returns Firefox 157 Windows same-origin no-store GET fields.
///
/// Adds `Pragma` and `Cache-Control` last on HTTP/1.1 and before `te` on
/// HTTP/2. Uses non-exclusive HTTP/2 weight 22 on stream 0. Supply `Referer`.
/// Other values and trust rules match [`v157_windows_navigation_template`].
/// Client hints are unavailable.
#[must_use]
pub fn v157_windows_fetch_no_store_template() -> RequestTemplate {
    fetch_template(V157_WINDOWS_USER_AGENT, FetchCache::NoStore)
}

/// Returns Firefox 157 macOS same-origin no-store GET fields.
///
/// Uses [`v157_windows_fetch_no_store_template`]'s ordering and priority
/// with the user agent from [`v157_macos_navigation_template`].
#[must_use]
pub fn v157_macos_fetch_no_store_template() -> RequestTemplate {
    fetch_template(V157_MACOS_USER_AGENT, FetchCache::NoStore)
}

/// Returns Firefox 157 Windows same-origin GET fields in default cache mode.
///
/// Uses [`v157_windows_fetch_no_store_template`] without `Pragma` and
/// `Cache-Control`. Supply optional `If-Modified-Since`, then `If-None-Match`
/// to revalidate your cached response. They follow `Sec-Fetch-Site` and
/// precede `Priority`, following `nsHttpChannel::OnCacheEntryCheck` at
/// `FIREFOX_157_0_RELEASE`.
#[must_use]
pub fn v157_windows_fetch_template() -> RequestTemplate {
    fetch_template(V157_WINDOWS_USER_AGENT, FetchCache::Default)
}

/// Returns Firefox 157 Windows same-origin POST upload fields.
///
/// Supply `Origin`, `Referer` and HTTP/1.1 `Priority`. `Content-Type` and
/// `Content-Length` are optional slots. `prepared_body()` supplies the type
/// and, without trailers, the length. A raw `body()` appends an omitted length
/// for a nonempty body with a known length and no trailers.
///
/// Uses [`v157_windows_fetch_template`]'s other values, HTTP/2 priority and
/// proxy credential placement. Provides HTTP/1.1 and HTTP/2 upload ordering;
/// HTTP/3, navigation POSTs and form submissions have no template.
#[must_use]
pub fn v157_windows_fetch_upload_template() -> RequestTemplate {
    let mut template = v157_windows_fetch_template();
    for (fields, content_type, length, origin, referer) in [
        (
            &mut template.http1_fields,
            "Content-Type",
            "Content-Length",
            "Origin",
            "Referer",
        ),
        (
            &mut template.http2_fields,
            "content-type",
            "content-length",
            "origin",
            "referer",
        ),
    ] {
        let mut upload = Vec::with_capacity(fields.len() + 1);
        for field in fields.drain(..) {
            let name = field.name().unwrap_or("");
            if name.eq_ignore_ascii_case("if-none-match")
                || name.eq_ignore_ascii_case("if-modified-since")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("referer") {
                upload.extend([
                    RequestField::required_caller(referer),
                    RequestField::caller(content_type),
                    RequestField::caller(length),
                    RequestField::required_caller(origin),
                ]);
            } else if name == "Priority" {
                upload.push(RequestField::required_caller("Priority"));
            } else {
                upload.push(field);
            }
        }
        *fields = upload;
    }
    template.http3_fields = None;
    template
}

/// Returns Firefox 157 macOS same-origin GET fields in default cache mode.
///
/// Uses [`v157_windows_fetch_template`]'s ordering and validator slots
/// with the user agent from [`v157_macos_navigation_template`].
#[must_use]
pub fn v157_macos_fetch_template() -> RequestTemplate {
    fetch_template(V157_MACOS_USER_AGENT, FetchCache::Default)
}

/// The cache mode of a same-origin `fetch`, which decides its cache fields.
#[derive(Clone, Copy, Eq, PartialEq)]
enum FetchCache {
    /// The default mode: no cache fields of its own, and the validators of a
    /// cached response when the cache revalidates it.
    Default,
    /// `no-store`: `Pragma` and `Cache-Control` set to `no-cache`.
    NoStore,
}

/// Builds the Firefox `fetch` lists for `cache` with a literal `User-Agent`.
fn fetch_template(user_agent: &str, cache: FetchCache) -> RequestTemplate {
    let cache_fields = |pragma: &str, cache_control: &str| match cache {
        FetchCache::NoStore => vec![
            RequestField::literal(pragma, "no-cache"),
            RequestField::literal(cache_control, "no-cache"),
        ],
        FetchCache::Default => Vec::new(),
    };
    let validators = |if_modified_since: &str, if_none_match: &str| match cache {
        FetchCache::Default => vec![
            RequestField::caller(if_modified_since),
            RequestField::caller(if_none_match),
        ],
        FetchCache::NoStore => Vec::new(),
    };
    let mut http1_fields = vec![
        RequestField::literal("User-Agent", user_agent),
        RequestField::literal("Accept", "*/*"),
        RequestField::literal("Accept-Language", V157_ACCEPT_LANGUAGE),
        accept_encoding("Accept-Encoding"),
        RequestField::caller("Referer"),
        preemptive_proxy_authorization("Proxy-Authorization"),
        RequestField::literal("Connection", "keep-alive"),
        RequestField::trustworthy_only("Sec-Fetch-Dest", "empty"),
        RequestField::trustworthy_only("Sec-Fetch-Mode", "cors"),
        RequestField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
    ];
    http1_fields.extend(validators("If-Modified-Since", "If-None-Match"));
    http1_fields.push(RequestField::literal("Priority", "u=4"));
    http1_fields.extend(cache_fields("Pragma", "Cache-Control"));
    http1_fields.push(replay_proxy_authorization("Proxy-Authorization"));
    let mut http2_fields = vec![
        RequestField::literal("user-agent", user_agent),
        RequestField::literal("accept", "*/*"),
        RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
        accept_encoding("accept-encoding"),
        RequestField::caller("referer"),
        preemptive_proxy_authorization("proxy-authorization"),
        RequestField::trustworthy_only("sec-fetch-dest", "empty"),
        RequestField::trustworthy_only("sec-fetch-mode", "cors"),
        RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
    ];
    http2_fields.extend(validators("if-modified-since", "if-none-match"));
    http2_fields.push(RequestField::literal("priority", "u=4"));
    http2_fields.extend(cache_fields("pragma", "cache-control"));
    http2_fields.extend([
        replay_proxy_authorization("proxy-authorization"),
        RequestField::literal("te", "trailers"),
    ]);
    let mut http3_fields = vec![
        RequestField::literal("user-agent", user_agent),
        RequestField::literal("accept", "*/*"),
        RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
        accept_encoding("accept-encoding"),
        RequestField::caller("referer"),
        RequestField::AltUsed,
        RequestField::trustworthy_only("sec-fetch-dest", "empty"),
        RequestField::trustworthy_only("sec-fetch-mode", "cors"),
        RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
    ];
    http3_fields.extend(validators("if-modified-since", "if-none-match"));
    http3_fields.push(RequestField::literal("priority", "u=4"));
    http3_fields.extend(cache_fields("pragma", "cache-control"));
    RequestTemplate {
        http1_fields,
        http2_fields,
        http3_fields: Some(http3_fields),
        http2_priority: Some(crate::Http2RequestPriority::Fixed(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        })),
        requested_client_hint_placement: false,
        // Firefox sends no client hints and ignores ACCEPT_CH.
        restarts_for_connection_accept_ch: false,
    }
}

#[cfg(test)]
mod hook_tests;

#[cfg(test)]
mod tests;
