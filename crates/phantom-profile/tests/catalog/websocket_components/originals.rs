//! Complete original constructors frozen before the declaration migration.

use phantom_profile::{
    WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
    WebSocketField, WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
    WebSocketSettings,
};
use std::time::Duration;

pub(super) fn chrome_original() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http1Upgrade,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::SameSessionOnce,
            proxied_http2_session: WebSocketProxiedSession::Reuse,
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
            original_accept_encoding("Accept-Encoding"),
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
            original_accept_encoding("accept-encoding"),
            WebSocketField::caller("accept-language"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: vec![WebSocketDeflateParameter::ClientMaxWindowBits(None)],
        empty_message_compression: WebSocketEmptyMessageCompression::Compressed,
        handshake_timeout: Some(Duration::from_secs(240)),
    }
}

pub(super) fn firefox_original() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http2ExtendedConnect,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::None,
            proxied_http2_session: WebSocketProxiedSession::Reuse,
        },
        http1_fields: vec![
            WebSocketField::authority("Host"),
            WebSocketField::caller("User-Agent"),
            WebSocketField::literal("Accept", "*/*"),
            WebSocketField::caller("Accept-Language"),
            original_accept_encoding("Accept-Encoding"),
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
            original_accept_encoding("accept-encoding"),
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
        handshake_timeout: Some(Duration::from_secs(20)),
    }
}

fn original_accept_encoding(name: &str) -> WebSocketField {
    WebSocketField::by_trust(name, "gzip, deflate, br, zstd", "gzip, deflate")
}
