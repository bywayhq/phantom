use phantom_profile::{
    ClientHintDelivery, Http2ProxyConnections, Http2RejectedConnect, Http2RequestPriority,
    ProxyAuthorizationAttempt, WebSocketCleartextState, WebSocketEmptyMessageCompression,
    WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
};

use super::{PreparationError, encoding::Encoder};

fn client_hint_delivery(
    e: &mut Encoder,
    value: &ClientHintDelivery,
) -> Result<(), PreparationError> {
    e.u8(match value {
        ClientHintDelivery::Default => 0,
        ClientHintDelivery::AcceptCh => 1,
        _ => return Err(PreparationError::Unsupported("ClientHintDelivery")),
    })
}

fn proxy_authorization_attempt(
    e: &mut Encoder,
    value: &ProxyAuthorizationAttempt,
) -> Result<(), PreparationError> {
    e.u8(match value {
        ProxyAuthorizationAttempt::Every => 0,
        ProxyAuthorizationAttempt::Preemptive => 1,
        ProxyAuthorizationAttempt::Replay => 2,
        _ => return Err(PreparationError::Unsupported("ProxyAuthorizationAttempt")),
    })
}

fn http2_rejected_connect(
    e: &mut Encoder,
    value: &Http2RejectedConnect,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2RejectedConnect::EndStream => 0,
        Http2RejectedConnect::LeaveOpen => 1,
        _ => return Err(PreparationError::Unsupported("Http2RejectedConnect")),
    })
}

fn http2_proxy_connections(
    e: &mut Encoder,
    value: &Http2ProxyConnections,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2ProxyConnections::Shared => 0,
        Http2ProxyConnections::ByPurpose => 1,
        _ => return Err(PreparationError::Unsupported("Http2ProxyConnections")),
    })
}

fn web_socket_empty_message_compression(
    e: &mut Encoder,
    value: &WebSocketEmptyMessageCompression,
) -> Result<(), PreparationError> {
    e.u8(match value {
        WebSocketEmptyMessageCompression::Compressed => 0,
        WebSocketEmptyMessageCompression::Uncompressed => 1,
        _ => {
            return Err(PreparationError::Unsupported(
                "WebSocketEmptyMessageCompression",
            ));
        }
    })
}

fn web_socket_new_connection(
    e: &mut Encoder,
    value: &WebSocketNewConnection,
) -> Result<(), PreparationError> {
    e.u8(match value {
        WebSocketNewConnection::Http1Upgrade => 0,
        WebSocketNewConnection::Http2ExtendedConnect => 1,
        _ => return Err(PreparationError::Unsupported("WebSocketNewConnection")),
    })
}

fn web_socket_refused_stream_retry(
    e: &mut Encoder,
    value: &WebSocketRefusedStreamRetry,
) -> Result<(), PreparationError> {
    e.u8(match value {
        WebSocketRefusedStreamRetry::None => 0,
        WebSocketRefusedStreamRetry::SameSessionOnce => 1,
        WebSocketRefusedStreamRetry::ReacquireTwice => 2,
        _ => return Err(PreparationError::Unsupported("WebSocketRefusedStreamRetry")),
    })
}

fn web_socket_proxied_session(
    e: &mut Encoder,
    value: &WebSocketProxiedSession,
) -> Result<(), PreparationError> {
    e.u8(match value {
        WebSocketProxiedSession::Reuse => 0,
        WebSocketProxiedSession::Ignore => 1,
        _ => return Err(PreparationError::Unsupported("WebSocketProxiedSession")),
    })
}
use phantom_profile::{
    ClientHintSettings, CookiePlacement, ProxyConnectField, ProxyConnectTemplate, RequestField,
    RequestTemplate, WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketField,
    WebSocketSettings,
};

pub(super) fn hints(e: &mut Encoder, value: &ClientHintSettings) -> Result<(), PreparationError> {
    e.list(value.hints(), |e, hint| {
        e.text(hint.name())?;
        e.bytes(hint.value())?;
        client_hint_delivery(e, &hint.delivery())
    })
}

pub(super) fn cookies(e: &mut Encoder, value: &CookiePlacement) -> Result<(), PreparationError> {
    e.list(value.before(), |e, name| e.text(name))
}

pub(super) fn template(e: &mut Encoder, value: &RequestTemplate) -> Result<(), PreparationError> {
    let RequestTemplate {
        http1_fields,
        http2_fields,
        http3_fields,
        http2_priority,
        requested_client_hint_placement,
        restarts_for_connection_accept_ch,
    } = value;
    e.list(http1_fields, request_field)?;
    e.list(http2_fields, request_field)?;
    e.option(http3_fields.as_ref(), |e, values| {
        e.list(values, request_field)
    })?;
    e.option(http2_priority.as_ref(), |e, priority| match priority {
        Http2RequestPriority::Fixed(priority) => {
            e.u8(0)?;
            super::http::priority(e, priority)
        }
        Http2RequestPriority::WeightBand { weight, exclusive } => {
            e.u8(1)?;
            e.u16(*weight)?;
            e.bool(*exclusive)
        }
    })?;
    e.bool(*requested_client_hint_placement)?;
    e.bool(*restarts_for_connection_accept_ch)
}

fn request_field(e: &mut Encoder, value: &RequestField) -> Result<(), PreparationError> {
    match value {
        RequestField::Literal { name, value } => {
            e.u8(0)?;
            e.text(name)?;
            e.text(value)
        }
        RequestField::Caller { name, required } => {
            e.u8(1)?;
            e.text(name)?;
            e.bool(*required)
        }
        RequestField::ClientHint { name } => {
            e.u8(2)?;
            e.text(name)
        }
        RequestField::ClientHints => e.u8(3),
        RequestField::ByTrust {
            name,
            trustworthy,
            untrustworthy,
        } => {
            e.u8(4)?;
            e.text(name)?;
            optional_text(e, trustworthy.as_deref())?;
            optional_text(e, untrustworthy.as_deref())
        }
        RequestField::ByForwarding {
            name,
            unforwarded,
            forwarded,
        } => {
            e.u8(5)?;
            e.text(name)?;
            optional_text(e, unforwarded.as_deref())?;
            optional_text(e, forwarded.as_deref())
        }
        RequestField::ProxyAuthorization { name, attempt } => {
            e.u8(6)?;
            e.text(name)?;
            proxy_authorization_attempt(e, attempt)
        }
        RequestField::RestartClientHints => e.u8(7),
        RequestField::AltUsed => e.u8(8),
        _ => Err(PreparationError::Unsupported("request_field")),
    }
}

fn optional_text(e: &mut Encoder, value: Option<&str>) -> Result<(), PreparationError> {
    e.bool(value.is_some())?;
    if let Some(value) = value {
        e.text(value)?;
    }
    Ok(())
}

pub(super) fn connect(
    e: &mut Encoder,
    value: &ProxyConnectTemplate,
) -> Result<(), PreparationError> {
    let ProxyConnectTemplate {
        http1_fields,
        http2_fields,
        http2_rejected,
        http2_connections,
    } = value;
    e.list(http1_fields, connect_field)?;
    e.list(http2_fields, connect_field)?;
    http2_rejected_connect(e, http2_rejected)?;
    http2_proxy_connections(e, http2_connections)
}

fn connect_field(e: &mut Encoder, value: &ProxyConnectField) -> Result<(), PreparationError> {
    match value {
        ProxyConnectField::Authority { name } => {
            e.u8(0)?;
            e.text(name)
        }
        ProxyConnectField::Literal { name, value } => {
            e.u8(1)?;
            e.text(name)?;
            e.text(value)
        }
        ProxyConnectField::FromRequest { name } => {
            e.u8(2)?;
            e.text(name)
        }
        ProxyConnectField::ProxyAuthorization { name } => {
            e.u8(3)?;
            e.text(name)
        }
        _ => Err(PreparationError::Unsupported("connect_field")),
    }
}

pub(super) fn websocket(
    e: &mut Encoder,
    value: &WebSocketSettings,
) -> Result<(), PreparationError> {
    let WebSocketSettings {
        connection,
        http1_fields,
        http2_fields,
        permessage_deflate_offer,
        empty_message_compression,
        handshake_timeout,
    } = value;
    let WebSocketConnectionPolicy {
        without_http2_session,
        with_incapable_http2_session,
        http1_alpn_protocols,
        refused_stream_retry,
        proxied_http2_session,
        cleartext_state,
    } = connection;
    web_socket_new_connection(e, without_http2_session)?;
    web_socket_new_connection(e, with_incapable_http2_session)?;
    e.list(http1_alpn_protocols, |e, value| e.bytes(value))?;
    web_socket_refused_stream_retry(e, refused_stream_retry)?;
    web_socket_proxied_session(e, proxied_http2_session)?;
    match cleartext_state {
        WebSocketCleartextState::Shared => e.u8(0)?,
        WebSocketCleartextState::Separate => e.u8(1)?,
        _ => return Err(PreparationError::Unsupported("websocket_cleartext_state")),
    }
    e.list(http1_fields, websocket_field)?;
    e.list(http2_fields, websocket_field)?;
    e.list(permessage_deflate_offer, |e, parameter| match parameter {
        WebSocketDeflateParameter::ServerNoContextTakeover => e.u8(0),
        WebSocketDeflateParameter::ClientNoContextTakeover => e.u8(1),
        WebSocketDeflateParameter::ServerMaxWindowBits(value) => {
            e.u8(2)?;
            e.u8(*value)
        }
        WebSocketDeflateParameter::ClientMaxWindowBits(value) => {
            e.u8(3)?;
            e.option(value.as_ref(), |e, value| e.u8(*value))
        }
        _ => Err(PreparationError::Unsupported("websocket_deflate")),
    })?;
    web_socket_empty_message_compression(e, empty_message_compression)?;
    e.option(handshake_timeout.as_ref(), |e, value| e.duration(*value))
}

fn websocket_field(e: &mut Encoder, value: &WebSocketField) -> Result<(), PreparationError> {
    match value {
        WebSocketField::Literal { name, value } => {
            e.u8(0)?;
            e.text(name)?;
            e.text(value)
        }
        WebSocketField::Caller { name } => {
            e.u8(1)?;
            e.text(name)
        }
        WebSocketField::Authority { name } => {
            e.u8(2)?;
            e.text(name)
        }
        WebSocketField::Key { name } => {
            e.u8(3)?;
            e.text(name)
        }
        WebSocketField::PerMessageDeflate { name } => {
            e.u8(4)?;
            e.text(name)
        }
        WebSocketField::ClientCookies { name } => {
            e.u8(5)?;
            e.text(name)
        }
        WebSocketField::ByTrust {
            name,
            trustworthy,
            untrustworthy,
        } => {
            e.u8(6)?;
            e.text(name)?;
            optional_text(e, trustworthy.as_deref())?;
            optional_text(e, untrustworthy.as_deref())
        }
        _ => Err(PreparationError::Unsupported("websocket_field")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn request_operators_keep_distinct_stable_policy_tags() -> TestResult {
        let fields = [
            RequestField::literal("x-field", "one"),
            RequestField::Caller {
                name: "x-field".into(),
                required: false,
            },
            RequestField::ClientHint {
                name: "sec-ch-ua".into(),
            },
            RequestField::ClientHints,
            RequestField::ByTrust {
                name: "x-field".into(),
                trustworthy: None,
                untrustworthy: None,
            },
            RequestField::ByForwarding {
                name: "x-field".into(),
                unforwarded: None,
                forwarded: None,
            },
            RequestField::ProxyAuthorization {
                name: "Proxy-Authorization".into(),
                attempt: phantom_profile::ProxyAuthorizationAttempt::Every,
            },
            RequestField::RestartClientHints,
            RequestField::AltUsed,
        ];
        for (tag, field) in (0_u8..).zip(fields) {
            let mut encoder = Encoder::new();
            request_field(&mut encoder, &field)?;
            assert_eq!(encoder.finish().first(), Some(&tag));
        }
        Ok(())
    }

    #[test]
    fn firefox_alt_used_placement_participates_in_ticket_policy() -> TestResult {
        use phantom_profile::browser::firefox;
        for request in [
            firefox::v157_windows_navigation_template(),
            firefox::v157_windows_fetch_no_store_template(),
            firefox::v157_macos_navigation_template(),
            firefox::v157_macos_fetch_no_store_template(),
        ] {
            let profile = firefox::v157_windows().with_request_template(request.clone());
            let original = super::super::profile::encode(&profile, None, None)?;
            let mut moved = request.clone();
            moved
                .http3_fields
                .as_mut()
                .ok_or("missing H3 fields")?
                .reverse();
            let changed = profile.clone().with_request_template(moved);
            assert_ne!(
                original,
                super::super::profile::encode(&changed, None, None)?
            );
            let mut removed = request;
            let fields = removed.http3_fields.as_mut().ok_or("missing H3 fields")?;
            let count = fields.len();
            fields.retain(|field| !matches!(field, RequestField::AltUsed));
            assert_eq!(fields.len() + 1, count);
            let changed = profile.with_request_template(removed);
            assert_ne!(
                original,
                super::super::profile::encode(&changed, None, None)?
            );
        }
        Ok(())
    }
}
