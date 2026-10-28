//! Chrome connection settings and request templates.
//!
//! Desktop recipes provide Windows and macOS settings. Android recipes target
//! Chrome 154.0.8037.57 with Pixel 7 / Android 17 client hints. Android has no
//! HTTP/1.1 pool, address-cache, proxy CONNECT or cookie-placement recipe.
//!
//! Chrome 156 desktop profiles provide `FetchNoStore` for same-origin GETs
//! with `cache: "no-store"`.
//! Select `Fetch` from the `chrome-156-macos` catalog profile for ordinary
//! same-origin GETs. Supply `User-Agent` and any cache validators.

pub use crate::catalog::browser_profiles::chrome::*;

mod android;

pub use android::{
    v154_android_client_hints, v154_android_client_hints_for_model,
    v154_android_fetch_no_store_template, v154_android_http2, v154_android_http3,
    v154_android_http3_request, v154_android_navigation_template, v154_android_quic,
    v154_android_quic_tls, v154_android_tcp, v154_android_tcp_tls, v154_android_websocket,
};

pub(crate) use android::{model_value, validate_model};

use crate::{
    client_hints::ClientHintSettings,
    cookie::CookiePlacement,
    dns_cache::DnsCacheSettings,
    http1::Http1Settings,
    http2::{Http2Priority, Http2Settings},
    http3::{Http3RequestSettings, Http3Settings},
    proxy_connect::ProxyConnectTemplate,
    request_template::{ProxyAuthorizationAttempt, RequestField, RequestTemplate},
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

use crate::udp::UdpSettings;

use crate::tcp::TcpSettings;

use crate::quic::QuicTransportSettings;

/// Returns Chrome 154.0.8037.97 client hints for Windows 11 x64.
///
/// Includes default and `Accept-CH`-requested hints in profile order. You can
/// change the returned values before building a client.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::chrome_windows_154_client_hints()
}

/// Returns Chrome 154.0.8037.95 client hints for macOS 15.5 arm64.
///
/// Uses the Windows recipe's field order with macOS platform values.
#[must_use]
pub fn v154_macos_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::chrome_macos_154_client_hints()
}

/// Returns Chrome 154's automatic `Cookie` position.
///
/// Places it last on HTTP/1.1, before `priority` on HTTP/2 and HTTP/3, and
/// before revalidation fields. Chromium's cache appends validators after
/// cookies (`net/http/http_cache_transaction.cc` at tag `154.0.8037.58`).
#[must_use]
pub fn v154_cookie_placement() -> CookiePlacement {
    crate::catalog::cookie_components::chromium_154_cookie()
}

/// Returns Chrome 154.0.8037.58 TLS settings for Windows 11.
///
/// Uses per-connection GREASE, extension permutation and ECH GREASE sizing,
/// with a sorted list of 28 trust-anchor IDs. Enables ECH from HTTPS records
/// when the client has an HTTPS-record resolver.
///
/// Keeps the two newest tickets per origin and offers the newest first.
/// Each ticket is used once. Resumed TCP connections omit early data.
#[must_use]
pub fn v154_tcp_tls() -> TlsSettings {
    crate::tls::components::chromium_154_tcp_tls()
}

/// Returns Chromium 154.0.8037.58 TCP settings for Windows and Linux.
///
/// Enables `TCP_NODELAY` and keepalive with a 45-second idle time and interval.
/// Address racing uses a 300 ms fallback delay. TCP source-port selection
/// stays with the operating system: Windows randomization can stall new
/// connections under churn. See [`crate::TcpAddressRacing`] for address selection.
///
/// Use [`v154_macos_tcp`] on macOS and [`v154_android_tcp`] on Android.
/// Phantom fails the connection if a requested socket option cannot be set;
/// Chromium ignores those failures.
///
/// These options follow `net/socket/tcp_socket_{win,posix}.cc` at Chromium tag
/// `154.0.8037.58`. Brave 154 uses the same settings.
#[must_use]
pub fn v154_tcp() -> TcpSettings {
    crate::catalog::tcp_components::chromium_154_tcp()
}

/// Returns Chrome 154.0.8037.58 TCP settings for macOS.
///
/// Enables `TCP_NODELAY` and a 45-second keepalive idle time. Leaves the
/// probe interval, probe count, send buffer and port selection unchanged.
#[must_use]
pub fn v154_macos_tcp() -> TcpSettings {
    crate::catalog::tcp_components::chromium_154_macos_tcp()
}

/// Returns Chromium 154.0.8037.58 UDP settings for Windows.
///
/// Randomizes the local port before binding. A failure to set the option
/// fails the connection attempt. Chromium instead sets the option before
/// connecting and ignores a failure (`net/socket/udp_socket_win.cc` at tag
/// `154.0.8037.58`). Brave 154 uses the same settings.
#[must_use]
pub fn v154_udp() -> UdpSettings {
    crate::catalog::udp_components::chromium_154_udp()
}

/// Returns Chromium 154.0.8037.58 address-cache settings.
///
/// Keeps up to 1,000 entries. System answers live for 60 seconds; answers
/// with record TTLs live for at least 60 seconds. Failed lookups are not
/// cached. Eviction removes stale entries first, then the soonest to expire.
///
/// Matches Chromium's `HostCache` and `HostResolverManager` policy at tag
/// `154.0.8037.58`. Brave 154 shares these values; use separate clients when
/// you need caches isolated by top-level site.
#[must_use]
pub fn v154_dns_cache() -> DnsCacheSettings {
    crate::catalog::dns_components::chromium_154_dns_cache()
}

/// Returns Chromium 154.0.8037.58 HTTP/1.1 connection settings.
///
/// Allows six connections per origin and route, counting idle, connecting
/// and active sockets. Reuses the most recently used idle connection. A
/// request closes connections idle for at least 300 seconds before reuse.
///
/// Phantom applies this cleanup to the requested origin and route. It does
/// not apply Chromium's additional pool-wide and proxy-chain limits or open
/// unused preconnect sockets. Brave 154 shares these values; separate clients
/// provide top-level-site isolation.
///
/// See `net/socket/transport_client_socket_pool.cc` at tag `154.0.8037.58`.
#[must_use]
pub fn v154_http1() -> Http1Settings {
    crate::catalog::http1_components::chromium_154_http1()
}

/// Returns Chrome 154.0.8037.58 HTTP/2 settings.
///
/// Navigation HEADERS use exclusive priority on stream 0 with weight 256.
/// Extended CONNECT uses weight 147 and pseudo-headers in this order:
/// `:method`, `:authority`, `:scheme`, `:path`, `:protocol`.
///
/// HPACK excludes `:method` and `:protocol` from dynamic indexing. Literals
/// use Huffman coding only when shorter. Ordinary fields may be indexed;
/// names prefer static entries, then the newest dynamic entry. Cookie crumbs
/// are indexed individually. See [`crate::Http2FieldIndexing::All`],
/// [`crate::Http2NameReference::StaticThenNewest`] and
/// [`crate::Http2IndexingLimit::Unlimited`].
///
/// The first request uses stream 1. The initial concurrent-stream limit is
/// 100; a peer's limit replaces it, capped at 256. A request after more than
/// 10 seconds without a read triggers a PING. An unanswered PING closes the
/// connection after 10 seconds without a read, sending `GOAWAY(0,
/// PROTOCOL_ERROR)` with debug data `Failed ping.`
///
/// A request failed by that PING before its response head can be replayed
/// up to twice per redirect hop. This follows `SpdySession::CheckPingStatus`
/// and `HttpNetworkTransaction::HandleIOError` at tag `154.0.8037.58`.
#[must_use]
pub fn v154_http2() -> Http2Settings {
    crate::catalog::http2_components::chromium_154_http2()
}

/// Returns Chrome 154.0.8037.58 WebSocket settings.
///
/// Reuses a capable HTTP/2 session, including one reached through a proxy.
/// Otherwise opens a new HTTP/1.1 connection. Supply `User-Agent`, `Origin`
/// and `Accept-Language`. Compression is offered when you enable it, using
/// `permessage-deflate; client_max_window_bits`; empty messages are compressed.
///
/// Offers `br` and `zstd` only to potentially trustworthy URLs and sends no
/// `Sec-Fetch-*` fields. Caller fields replace matching template entries.
/// A refused extended CONNECT may be reopened up to twice; session selection
/// can choose another capable session. The opening deadline is 240 seconds.
///
/// See `net/websockets/websocket_stream.cc` and
/// `net/http/http_network_transaction.cc` at tag `154.0.8037.58`.
#[must_use]
pub fn v154_websocket() -> WebSocketSettings {
    crate::catalog::websocket_components::chromium_154_websocket()
}

/// Returns Chrome 154.0.8037.58 proxy CONNECT settings.
///
/// HTTP/1.1 sends `Host`, `Proxy-Connection: keep-alive` and `User-Agent`,
/// then challenged credentials. HTTP/2 sends `user-agent` after the two
/// pseudo-headers, then credentials. The user agent comes from the request
/// that opens the tunnel.
///
/// Ends a challenged HTTP/2 CONNECT with empty END_STREAM DATA before replay.
/// Forwarded requests and CONNECT tunnels share one proxy HTTP/2 connection.
#[must_use]
pub fn v154_proxy_connect() -> ProxyConnectTemplate {
    crate::catalog::proxy_connect_components::chromium_154_proxy_connect()
}

const V154_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const V154_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V154_PLAINTEXT_ACCEPT_ENCODING: &str = "gzip, deflate";
const V154_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V154_WINDOWS_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

/// Returns Chromium 154's `Accept-Encoding` entry.
///
/// Offers `br` and `zstd` only to potentially trustworthy URLs
/// (`net/http/http_request_headers.cc` at tag `154.0.8037.58`).
fn accept_encoding(name: &str) -> RequestField {
    RequestField::by_trust(name, V154_ACCEPT_ENCODING, V154_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns Chrome 154 Windows address-bar navigation fields.
///
/// Uses `Sec-Fetch-Site: none`, `Sec-Fetch-User: ?1` and HTTP/2 weight 256.
/// Default and requested client hints share one block before
/// `Upgrade-Insecure-Requests`. ALPS-requested restart hints follow `Accept`.
///
/// The literal user agent describes headful Chrome; language is `en-US`.
/// Caller fields replace matching values in place. `Sec-Fetch-*`, client hints,
/// and `br`/`zstd` require a potentially trustworthy URL. HTTP/1.1 forwarding
/// replaces `Connection` with `Proxy-Connection`.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    v154_navigation_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Returns Chrome 154 Windows same-origin no-store GET fields.
///
/// Adds `Pragma` and `Cache-Control`. HTTP/2 uses exclusive priority on
/// stream 0 with weight 220. Chrome can select another live stream as a
/// parent; this template always uses stream 0.
///
/// Supply `Referer`. The user agent matches
/// [`v154_windows_navigation_template`]. Requested client hints and HTTP/3
/// are unavailable. Trust and forwarding rules match the navigation template.
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    v154_fetch_no_store_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Returns Chrome 154.0.8037.95 navigation fields for macOS.
///
/// Uses [`v154_windows_navigation_template`]'s ordering and priority with
/// [`v154_macos_client_hints`]. Supply `User-Agent`.
#[must_use]
pub fn v154_macos_navigation_template() -> RequestTemplate {
    v154_navigation_template(None)
}

/// Returns Chrome 154.0.8037.95 same-origin no-store GET fields for macOS.
///
/// Uses [`v154_windows_fetch_no_store_template`]'s ordering and priority.
/// Supply `User-Agent`.
#[must_use]
pub fn v154_macos_fetch_no_store_template() -> RequestTemplate {
    v154_fetch_no_store_template(None)
}

/// Returns Chrome 154 Windows same-origin GET fields in default cache mode.
///
/// Uses [`v154_windows_fetch_no_store_template`] without `Pragma` and
/// `Cache-Control`. Supply optional `If-None-Match`, then `If-Modified-Since`
/// to revalidate your cached response. They follow `Accept-Language` and
/// precede `priority` on HTTP/2; they are last on HTTP/1.1. Cookies precede
/// them. HTTP/3 is unavailable.
///
/// Validator order follows `HttpCache::Transaction::ConditionalizeRequest`
/// at Chromium tag `154.0.8037.58`.
#[must_use]
pub fn v154_windows_fetch_template() -> RequestTemplate {
    v154_fetch_template(Some(V154_WINDOWS_USER_AGENT))
}

/// Returns Chrome 154 Windows same-origin POST upload fields.
///
/// Supply `Origin` and `Referer`. `Content-Type` and `Content-Length` are
/// optional slots. `prepared_body()` supplies the type and, without trailers,
/// the length. A raw `body()` appends an omitted length for a nonempty body
/// with a known length and no trailers.
///
/// Uses [`v154_windows_fetch_template`]'s other values, HTTP/2 priority and
/// proxy credential placement. Provides HTTP/1.1 and HTTP/2 upload ordering;
/// HTTP/3, navigation POSTs and form submissions have no template.
#[must_use]
pub fn v154_windows_fetch_upload_template() -> RequestTemplate {
    let mut template = v154_windows_fetch_template();
    for (fields, length, content_type, origin, referer) in [
        (
            &mut template.http1_fields,
            "Content-Length",
            "Content-Type",
            "Origin",
            "Referer",
        ),
        (
            &mut template.http2_fields,
            "content-length",
            "content-type",
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
            if name == "sec-ch-ua-platform" {
                upload.push(RequestField::caller(length));
            }
            if name.eq_ignore_ascii_case("referer") {
                upload.push(RequestField::required_caller(referer));
            } else if name == "sec-ch-ua" {
                upload.push(field);
                upload.push(RequestField::caller(content_type));
            } else if name.eq_ignore_ascii_case("accept") {
                upload.push(field);
                upload.push(RequestField::required_caller(origin));
            } else {
                upload.push(field);
            }
        }
        *fields = upload;
    }
    template
}

/// Returns Chrome 154 macOS same-origin GET fields in default cache mode.
///
/// Uses [`v154_windows_fetch_template`]'s ordering, priority and validator
/// slots. Supply `User-Agent`.
#[must_use]
pub fn v154_macos_fetch_template() -> RequestTemplate {
    v154_fetch_template(None)
}

/// Places forwarded proxy credentials after `Proxy-Connection` on HTTP/1.1
/// and first after pseudo-headers on HTTP/2. No-store cache fields precede
/// credentials. Replays and later requests use the same position.
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
        RequestField::RestartClientHints,
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
            RequestField::RestartClientHints,
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
        http2_priority: Some(crate::Http2RequestPriority::Fixed(Http2Priority {
            dependency_stream_id: 0,
            weight: 256,
            exclusive: true,
        })),
        requested_client_hint_placement: true,
        restarts_for_connection_accept_ch: true,
    }
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

/// Builds the Chromium 154 no-store fetch lists with a literal or required
/// caller `User-Agent`.
pub(crate) fn v154_fetch_no_store_template(user_agent: Option<&str>) -> RequestTemplate {
    v154_fetch_lists(user_agent, FetchCache::NoStore)
}

/// Builds the Chromium 154 default-mode fetch lists with a literal or
/// required caller `User-Agent`.
fn v154_fetch_template(user_agent: Option<&str>) -> RequestTemplate {
    v154_fetch_lists(user_agent, FetchCache::Default)
}

/// Builds Chromium 154 fetch lists for the selected cache mode.
///
/// No-store cache fields precede merged fields. Validators follow cookies,
/// `Accept-Encoding` and `Accept-Language`, before `priority`.
/// See `net/http/http_cache_transaction.cc` at tag `154.0.8037.58`.
fn v154_fetch_lists(user_agent: Option<&str>, cache: FetchCache) -> RequestTemplate {
    let user_agent = |name: &str| match user_agent {
        Some(value) => RequestField::literal(name, value),
        None => RequestField::required_caller(name),
    };
    let cache_fields = |pragma: &str, cache_control: &str| match cache {
        FetchCache::NoStore => vec![
            RequestField::literal(pragma, "no-cache"),
            RequestField::literal(cache_control, "no-cache"),
        ],
        FetchCache::Default => Vec::new(),
    };
    let validators = |if_none_match: &str, if_modified_since: &str| match cache {
        FetchCache::Default => vec![
            RequestField::caller(if_none_match),
            RequestField::caller(if_modified_since),
        ],
        FetchCache::NoStore => Vec::new(),
    };
    let mut http1_fields = vec![
        RequestField::unless_forwarded("Connection", "keep-alive"),
        RequestField::when_forwarded("Proxy-Connection", "keep-alive"),
    ];
    http1_fields.extend(cache_fields("Pragma", "Cache-Control"));
    http1_fields.extend([
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
    ]);
    http1_fields.extend(validators("If-None-Match", "If-Modified-Since"));
    let mut http2_fields = cache_fields("pragma", "cache-control");
    http2_fields.extend([
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
    ]);
    http2_fields.extend(validators("if-none-match", "if-modified-since"));
    http2_fields.push(RequestField::literal("priority", "u=1, i"));
    RequestTemplate {
        http1_fields,
        http2_fields,
        http3_fields: None,
        http2_priority: Some(crate::Http2RequestPriority::Fixed(Http2Priority {
            dependency_stream_id: 0,
            weight: 220,
            exclusive: true,
        })),
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}

/// Returns Chrome 154.0.8037.58 HTTP/3 settings.
///
/// Orders SETTINGS by identifier and includes a randomized reserved setting.
/// Opens the QPACK decoder before the encoder. The encoder writes its stream
/// type with its first instructions.
#[must_use]
pub fn v154_http3() -> Http3Settings {
    crate::catalog::http3_components::chromium_154_http3()
}

/// Returns Chrome 154.0.8037.58 TLS settings for HTTP/3.
///
/// Uses TLS 1.3, `h3` ALPN and ALPS, and the TCP recipe's sorted trust-anchor
/// IDs. Omits GREASE cipher suites, OCSP and SCT requests. Enables session
/// tickets; resumed connections can offer early data with [`v154_quic`].
///
/// Uses ECH configurations from HTTPS records. Exact HTTP/3 and sequential
/// Alt-Svc requests keep failing on a rejected configuration until its cached
/// record expires. Set `ech` to `EchSettings::Grease` to use GREASE instead.
#[must_use]
pub fn v154_quic_tls() -> TlsSettings {
    crate::tls::components::chromium_154_quic_tls()
}

/// Returns Chrome 154.0.8037.58 HTTP/3 request settings.
///
/// Orders pseudo-headers as `:method`, `:authority`, `:scheme`, `:path`.
/// Extended CONNECT is unavailable. Splits cookies into crumbs, each indexed
/// in QPACK, and omits `Alt-Used`, including on alternative services.
#[must_use]
pub fn v154_http3_request() -> Http3RequestSettings {
    crate::catalog::http3_components::chromium_154_http3_request()
}

/// Returns Chrome 154.0.8037.58 QUIC transport settings.
///
/// Uses a 30-second idle timeout and the `ORIG` connection option. Parameter
/// order is a permutation template; connection IDs, reserved versions and
/// reserved parameters are generated at runtime. Pair with [`v154_http3`].
///
/// Resumed connections can offer early data and add `initial_rtt_us` with
/// a two-byte identifier, one-byte length and minimal-width value.
#[must_use]
pub fn v154_quic() -> QuicTransportSettings {
    crate::catalog::quic_components::chromium_154_quic()
}

#[cfg(test)]
mod hook_tests;

#[cfg(test)]
mod http3_tests;

#[cfg(test)]
mod quic_tests;

#[cfg(test)]
mod tests;
