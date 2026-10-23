//! Independent ordered values from the two retained openings and pinned source.

use phantom_profile::{
    WebSocketCleartextState, WebSocketConnectionPolicy, WebSocketDeflateParameter,
    WebSocketEmptyMessageCompression, WebSocketField, WebSocketNewConnection,
    WebSocketProxiedSession, WebSocketRefusedStreamRetry, WebSocketSettings,
};
use std::time::Duration;

pub(crate) fn original() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http1Upgrade,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::ReacquireTwice,
            proxied_http2_session: WebSocketProxiedSession::Reuse,
            cleartext_state: WebSocketCleartextState::Shared,
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
            WebSocketField::client_cookies("Cookie"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::permessage_deflate("Sec-WebSocket-Extensions"),
            WebSocketField::caller("Sec-WebSocket-Protocol"),
        ],
        http2_fields: vec![
            WebSocketField::literal("pragma", "no-cache"),
            WebSocketField::literal("cache-control", "no-cache"),
            WebSocketField::caller("user-agent"),
            WebSocketField::caller("origin"),
            WebSocketField::literal("sec-websocket-version", "13"),
            original_accept_encoding("accept-encoding"),
            WebSocketField::caller("accept-language"),
            WebSocketField::client_cookies("cookie"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::caller("sec-websocket-protocol"),
        ],
        permessage_deflate_offer: vec![WebSocketDeflateParameter::ClientMaxWindowBits(None)],
        empty_message_compression: WebSocketEmptyMessageCompression::Compressed,
        handshake_timeout: Some(Duration::from_secs(240)),
    }
}

fn original_accept_encoding(name: &str) -> WebSocketField {
    WebSocketField::by_trust(name, "gzip, deflate, br, zstd", "gzip, deflate")
}

#[test]
fn edge_android_adds_only_the_explicit_websocket_layer_with_owned_values()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::{
        browser::edge,
        catalog::{ProfileLayer, profile},
    };
    let expected = original();
    let mut actual = edge::v153_android_websocket();
    actual.validate()?;
    assert_eq!(actual, expected);
    let definition = profile("edge/153.0.4234.49/android-17-pixel7-emulator/r1")?;
    assert_eq!(
        definition
            .instantiate(&[ProfileLayer::WebSocket])?
            .websocket(),
        Some(&expected)
    );
    assert!(definition.instantiate(&[ProfileLayer::Http1]).is_err());
    actual.http1_fields.clear();
    actual.http2_fields.clear();
    actual.connection.http1_alpn_protocols[0][0] = 0;
    assert_eq!(edge::v153_android_websocket(), expected);
    Ok(())
}
