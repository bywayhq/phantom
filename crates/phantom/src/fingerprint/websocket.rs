//! Complete websocket description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
    WebSocketField, WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
    WebSocketSettings,
};

pub(super) fn parse(v: &Value) -> Result<WebSocketSettings> {
    v.record(
        &[
            "connection",
            "http1_fields",
            "http2_fields",
            "permessage_deflate_offer",
            "empty_message_compression",
            "handshake_timeout",
        ],
        "websocket",
    )?;
    let settings = WebSocketSettings {
        connection: connection(v.member("connection", "websocket.connection")?)?,
        http1_fields: v
            .member("http1_fields", "websocket.http1_fields")?
            .list("websocket.http1_fields", field)?,
        http2_fields: v
            .member("http2_fields", "websocket.http2_fields")?
            .list("websocket.http2_fields", field)?,
        permessage_deflate_offer: v
            .member(
                "permessage_deflate_offer",
                "websocket.permessage_deflate_offer",
            )?
            .list("websocket.permessage_deflate_offer", deflate)?,
        empty_message_compression: empty(v.member(
            "empty_message_compression",
            "websocket.empty_message_compression",
        )?)?,
        handshake_timeout: v
            .member("handshake_timeout", "websocket.handshake_timeout")?
            .optional(|v| v.duration("websocket.handshake_timeout"))?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("websocket", error))?;
    Ok(settings)
}

fn without_http2_session(v: &Value) -> Result<WebSocketNewConnection> {
    match v.text("websocket.connection.without_http2_session")? {
        "Http1Upgrade" => Ok(WebSocketNewConnection::Http1Upgrade),
        "Http2ExtendedConnect" => Ok(WebSocketNewConnection::Http2ExtendedConnect),
        _ => Err(json::unsupported(
            "websocket.connection.without_http2_session",
        )),
    }
}

fn with_incapable_http2_session(v: &Value) -> Result<WebSocketNewConnection> {
    match v.text("websocket.connection.with_incapable_http2_session")? {
        "Http1Upgrade" => Ok(WebSocketNewConnection::Http1Upgrade),
        "Http2ExtendedConnect" => Ok(WebSocketNewConnection::Http2ExtendedConnect),
        _ => Err(json::unsupported(
            "websocket.connection.with_incapable_http2_session",
        )),
    }
}

fn refused_stream_retry(v: &Value) -> Result<WebSocketRefusedStreamRetry> {
    match v.text("websocket.connection.refused_stream_retry")? {
        "None" => Ok(WebSocketRefusedStreamRetry::None),
        "SameSessionOnce" => Ok(WebSocketRefusedStreamRetry::SameSessionOnce),
        "ReacquireTwice" => Ok(WebSocketRefusedStreamRetry::ReacquireTwice),
        _ => Err(json::unsupported(
            "websocket.connection.refused_stream_retry",
        )),
    }
}

fn proxied_http2_session(v: &Value) -> Result<WebSocketProxiedSession> {
    match v.text("websocket.connection.proxied_http2_session")? {
        "Reuse" => Ok(WebSocketProxiedSession::Reuse),
        "Ignore" => Ok(WebSocketProxiedSession::Ignore),
        _ => Err(json::unsupported(
            "websocket.connection.proxied_http2_session",
        )),
    }
}

pub(super) fn connection(v: &Value) -> Result<WebSocketConnectionPolicy> {
    v.record(
        &[
            "without_http2_session",
            "with_incapable_http2_session",
            "refused_stream_retry",
            "proxied_http2_session",
            "http1_alpn_protocols",
        ],
        "websocket.connection",
    )?;
    let settings = WebSocketConnectionPolicy {
        without_http2_session: without_http2_session(v.member(
            "without_http2_session",
            "websocket.connection.without_http2_session",
        )?)?,
        with_incapable_http2_session: with_incapable_http2_session(v.member(
            "with_incapable_http2_session",
            "websocket.connection.with_incapable_http2_session",
        )?)?,
        refused_stream_retry: refused_stream_retry(v.member(
            "refused_stream_retry",
            "websocket.connection.refused_stream_retry",
        )?)?,
        proxied_http2_session: proxied_http2_session(v.member(
            "proxied_http2_session",
            "websocket.connection.proxied_http2_session",
        )?)?,
        http1_alpn_protocols: v
            .member(
                "http1_alpn_protocols",
                "websocket.connection.http1_alpn_protocols",
            )?
            .list("websocket.connection.http1_alpn_protocols", |v| {
                v.bytes("websocket.connection.http1_alpn_protocols")
            })?,
    };
    Ok(settings)
}

fn empty(v: &Value) -> Result<WebSocketEmptyMessageCompression> {
    match v.text("websocket.empty_message_compression")? {
        "Compressed" => Ok(WebSocketEmptyMessageCompression::Compressed),
        "Uncompressed" => Ok(WebSocketEmptyMessageCompression::Uncompressed),
        _ => Err(json::unsupported("websocket.empty_message_compression")),
    }
}

fn field(v: &Value) -> Result<WebSocketField> {
    match v
        .member("kind", "websocket.fields.kind")?
        .text("websocket.fields.kind")?
    {
        "Literal" => {
            v.record(&["kind", "name", "value"], "websocket.fields")?;
            Ok(WebSocketField::Literal {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
                value: v
                    .member("value", "websocket.fields.value")?
                    .text("websocket.fields.value")?
                    .into(),
            })
        }
        "Caller" => {
            v.record(&["kind", "name"], "websocket.fields")?;
            Ok(WebSocketField::Caller {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
            })
        }
        "Authority" => {
            v.record(&["kind", "name"], "websocket.fields")?;
            Ok(WebSocketField::Authority {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
            })
        }
        "Key" => {
            v.record(&["kind", "name"], "websocket.fields")?;
            Ok(WebSocketField::Key {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
            })
        }
        "PerMessageDeflate" => {
            v.record(&["kind", "name"], "websocket.fields")?;
            Ok(WebSocketField::PerMessageDeflate {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
            })
        }
        "ClientCookies" => {
            v.record(&["kind", "name"], "websocket.fields")?;
            Ok(WebSocketField::ClientCookies {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
            })
        }
        "ByTrust" => {
            v.record(
                &["kind", "name", "trustworthy", "untrustworthy"],
                "websocket.fields",
            )?;
            Ok(WebSocketField::ByTrust {
                name: v
                    .member("name", "websocket.fields.name")?
                    .text("websocket.fields.name")?
                    .into(),
                trustworthy: v
                    .member("trustworthy", "websocket.fields.trustworthy")?
                    .optional(|v| Ok(v.text("websocket.fields.trustworthy")?.into()))?,
                untrustworthy: v
                    .member("untrustworthy", "websocket.fields.untrustworthy")?
                    .optional(|v| Ok(v.text("websocket.fields.untrustworthy")?.into()))?,
            })
        }
        _ => Err(json::unsupported("websocket.fields.kind")),
    }
}
fn deflate(v: &Value) -> Result<WebSocketDeflateParameter> {
    match v
        .member("kind", "websocket.permessage_deflate_offer.kind")?
        .text("websocket.permessage_deflate_offer.kind")?
    {
        "ServerNoContextTakeover" => {
            v.record(&["kind"], "websocket.permessage_deflate_offer")?;
            Ok(WebSocketDeflateParameter::ServerNoContextTakeover)
        }
        "ClientNoContextTakeover" => {
            v.record(&["kind"], "websocket.permessage_deflate_offer")?;
            Ok(WebSocketDeflateParameter::ClientNoContextTakeover)
        }
        "ServerMaxWindowBits" => {
            v.record(&["kind", "bits"], "websocket.permessage_deflate_offer")?;
            Ok(WebSocketDeflateParameter::ServerMaxWindowBits(
                v.member("bits", "websocket.permessage_deflate_offer.bits")?
                    .integer("websocket.permessage_deflate_offer.bits")?,
            ))
        }
        "ClientMaxWindowBits" => {
            v.record(&["kind", "bits"], "websocket.permessage_deflate_offer")?;
            Ok(WebSocketDeflateParameter::ClientMaxWindowBits(
                v.member("bits", "websocket.permessage_deflate_offer.bits")?
                    .optional(|v| v.integer("websocket.permessage_deflate_offer.bits"))?,
            ))
        }
        _ => Err(json::unsupported("websocket.permessage_deflate_offer.kind")),
    }
}
