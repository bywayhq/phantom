//! WebSocket registration and synchronous ownership of Node inputs.

use std::{fmt, num::NonZeroUsize, sync::Arc, time::Duration};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer},
};
use napi_derive::napi;
use phantom::{
    HttpProtocol, WebSocketCloseFrame, WebSocketLimits, WebSocketMessage, WebSocketRequestBuilder,
    WebSocketRetryPolicy,
};

use super::{buffer::copy_buffer, options::WireHeader, response::NativeResponse};
use crate::{
    client::ClientState,
    error::failure,
    response::{Exchange, Pending},
    websocket::{Socket, error},
};

/// Settings applied to the Rust opening handshake.
#[derive(Debug)]
#[napi(object)]
pub struct WebSocketOptions {
    /// Absolute ws or wss URI.
    pub url: String,
    /// Exact protocol or the profile's connection policy.
    pub protocol: String,
    /// Ordered caller fields filling the profile's opening template.
    pub headers: Option<Vec<WireHeader>>,
    /// Override in milliseconds; zero disables the handshake timeout.
    pub handshake_timeout_ms: Option<u32>,
    /// Largest accepted frame, in bytes.
    pub maximum_frame_bytes: Option<u32>,
    /// Largest accepted or sent complete message, in bytes.
    pub maximum_message_bytes: Option<u32>,
    /// Largest accepted fragment count per message.
    pub maximum_message_fragments: Option<u32>,
    /// Connection-setup failures retried; zero leaves retries disabled.
    pub maximum_connection_failures: Option<u32>,
    /// Delay before a caller-enabled setup retry.
    pub retry_delay_ms: Option<u32>,
}

/// Validated opening response without a body.
#[derive(Debug)]
#[napi(object)]
pub struct WebSocketHandshake {
    /// Accepted opening response status.
    pub status: u32,
    /// Actual HTTP version used by the handshake.
    pub protocol: String,
    /// Server-selected subprotocol, if present.
    pub selected_protocol: Option<String>,
    /// Exact ordered response fields.
    pub headers: Vec<WireHeader>,
}

/// An unsuccessful opening with its unconsumed HTTP response.
#[derive(Debug)]
#[napi(object, object_from_js = false)]
pub struct WebSocketRejection {
    /// Typed failure encoded with the same WebSocket error taxonomy.
    pub error: String,
    /// Original ordered response fields and pull-driven body.
    pub response: NativeResponse,
}

pub(super) fn rejection(
    response: phantom::Response<phantom::ResponseBody>,
    error: String,
    url: String,
    owner: Arc<ClientState>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<WebSocketRejection> {
    let protocol = match response.version() {
        http::Version::HTTP_11 => "http1",
        http::Version::HTTP_2 => "http2",
        http::Version::HTTP_3 => "http3",
        _ => {
            return Err(failure(
                "Internal",
                "WebSocket rejection HTTP version is unsupported",
            ));
        }
    };
    let headers = response
        .extensions()
        .get::<phantom::OrderedResponseHeaders>()
        .ok_or_else(|| {
            failure(
                "Internal",
                "WebSocket rejection header order is unavailable",
            )
        })?
        .iter()
        .map(|field| {
            (
                field.name().to_owned(),
                field.value().to_vec(),
                field.is_sensitive(),
            )
        })
        .collect();
    let status = u32::from(response.status().as_u16());
    let exchange = Exchange::new();
    exchange.claim_shared(permit, None)?;
    let _pending = Pending::new(Arc::clone(&exchange), Arc::clone(&owner));
    owner.register_admitted(&exchange)?;
    exchange.attach(response)?;
    Ok(WebSocketRejection {
        error,
        response: NativeResponse {
            status,
            headers,
            protocol: protocol.to_owned(),
            url,
            redirects: 0,
            connection_retries: None,
            decoded_content_codings: Vec::new(),
            redirect_history: None,
            exchange,
            owner,
        },
    })
}

/// One complete data message or control event.
#[napi(object)]
pub struct WebSocketEvent {
    /// text, binary, ping, pong, or close.
    pub kind: String,
    /// UTF-8 text only for a text message.
    pub text: Option<String>,
    /// Owned bytes for binary, ping and pong messages.
    pub data: Option<Buffer>,
    /// Peer close code, when supplied.
    pub code: Option<u32>,
    /// Peer close reason, when supplied.
    pub reason: Option<String>,
}

impl fmt::Debug for WebSocketEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind.as_str() {
            "text" => "text",
            "binary" => "binary",
            "ping" => "ping",
            "pong" => "pong",
            "close" => "close",
            _ => "unknown",
        };
        formatter
            .debug_struct("WebSocketEvent")
            .field("kind", &kind)
            .field("text_bytes", &self.text.as_ref().map(String::len))
            .field("data_bytes", &self.data.as_ref().map(|data| data.len()))
            .field("code", &self.code)
            .field("reason_bytes", &self.reason.as_ref().map(String::len))
            .finish()
    }
}

/// Native message connection, owned by one JavaScript wrapper.
#[derive(Debug)]
#[napi]
pub struct NativeWebSocket {
    pub(super) socket: Arc<Socket>,
}

#[napi]
impl NativeWebSocket {
    /// Creates an unopened owner so AbortSignal also covers setup.
    #[napi(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            socket: Socket::new(),
        }
    }

    /// Receives at most one message; concurrent receives fail explicitly.
    #[napi]
    pub fn receive(&self, env: Env) -> Result<AsyncBlock<Option<WebSocketEvent>>> {
        let socket = Arc::clone(&self.socket);
        AsyncBlockBuilder::new(async move { socket.receive().await?.map(event).transpose() })
            .build(&env)
    }

    /// Copies one bounded payload on this environment before asynchronous send.
    // Payload alternatives stay fixed typed parameters at the Node-API boundary.
    #[allow(clippy::too_many_arguments)]
    #[napi]
    pub fn send(
        &self,
        env: Env,
        kind: String,
        text: Option<String>,
        data: Option<Buffer>,
        code: Option<u32>,
        reason: Option<String>,
    ) -> Result<AsyncBlock<()>> {
        let message = match kind.as_str() {
            "text" => {
                let text =
                    text.ok_or_else(|| failure("InvalidArgument", "WebSocket text is required"))?;
                if text.len() > 64 * 1024 * 1024 {
                    return Err(failure("InputLimit", "WebSocket text exceeds 64 MiB"));
                }
                WebSocketMessage::Text(text)
            }
            "binary" | "ping" | "pong" => {
                let maximum = if kind == "binary" {
                    64 * 1024 * 1024
                } else {
                    125
                };
                let bytes = copy_buffer(
                    &env,
                    data.ok_or_else(|| failure("InvalidArgument", "WebSocket bytes are required"))?,
                    maximum,
                )?
                .into();
                match kind.as_str() {
                    "binary" => WebSocketMessage::Binary(bytes),
                    "ping" => WebSocketMessage::Ping(bytes),
                    _ => WebSocketMessage::Pong(bytes),
                }
            }
            "close" => {
                let frame = code
                    .map(|code| {
                        let code = u16::try_from(code).map_err(|_| {
                            failure("InvalidArgument", "WebSocket close code exceeds u16")
                        })?;
                        WebSocketCloseFrame::new(code, reason.unwrap_or_default()).map_err(error)
                    })
                    .transpose()?;
                WebSocketMessage::Close(frame)
            }
            _ => return Err(failure("InvalidArgument", "unknown WebSocket message kind")),
        };
        let socket = Arc::clone(&self.socket);
        AsyncBlockBuilder::new(async move { socket.send(message).await }).build(&env)
    }

    /// Drops only this upgraded connection or extended CONNECT stream.
    #[napi]
    pub fn abort(&self) {
        self.socket.abort();
    }
}

impl Default for NativeWebSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NativeWebSocket {
    fn drop(&mut self) {
        self.socket.abort();
    }
}

pub(super) fn prepare(
    env: &Env,
    client: &ClientState,
    options: &mut WebSocketOptions,
) -> Result<WebSocketRequestBuilder> {
    client.check_open()?;
    if options.url.len() > 64 * 1024 {
        return Err(failure("InputLimit", "WebSocket URL exceeds 65536 bytes"));
    }
    let mut builder = match options.protocol.as_str() {
        "profile" => client.core.websocket_with_profile_policy(&options.url),
        "http1" => client
            .core
            .websocket_with_protocol(HttpProtocol::Http1, &options.url),
        "http2" => client
            .core
            .websocket_with_protocol(HttpProtocol::Http2, &options.url),
        "http3" => client
            .core
            .websocket_with_protocol(HttpProtocol::Http3, &options.url),
        _ => {
            return Err(failure(
                "InvalidProtocol",
                "WebSocket protocol must be profile, http1, http2 or http3",
            ));
        }
    }
    .map_err(error)?;
    let defaults = WebSocketLimits::default();
    let positive = |value: u32| {
        NonZeroUsize::new(value as usize)
            .ok_or_else(|| failure("InvalidArgument", "WebSocket limits must be positive"))
    };
    let message = options
        .maximum_message_bytes
        .map(positive)
        .transpose()?
        .unwrap_or(defaults.max_message_size());
    let frame = options
        .maximum_frame_bytes
        .map(positive)
        .transpose()?
        .unwrap_or(defaults.max_frame_size().min(message));
    if message.get() > 64 * 1024 * 1024 {
        return Err(failure(
            "InputLimit",
            "WebSocket message limit exceeds 64 MiB",
        ));
    }
    let mut limits = WebSocketLimits::new(frame, message).map_err(error)?;
    if let Some(fragments) = options.maximum_message_fragments {
        limits = limits.with_max_message_fragments(positive(fragments)?);
    }
    builder = builder.limits(limits);
    if let Some(timeout) = options.handshake_timeout_ms {
        builder = builder
            .handshake_timeout((timeout != 0).then(|| Duration::from_millis(u64::from(timeout))));
    }
    if let Some(maximum) = options
        .maximum_connection_failures
        .filter(|maximum| *maximum != 0)
    {
        builder = builder.retry_policy(WebSocketRetryPolicy::connection_failures(
            positive(maximum)?,
            Duration::from_millis(u64::from(options.retry_delay_ms.unwrap_or(0))),
        ));
    }
    let headers = options.headers.take().unwrap_or_default();
    if headers.len() > 256 {
        return Err(failure("InputLimit", "WebSocket headers exceed 256 fields"));
    }
    let mut remaining = 64 * 1024_usize;
    for header in headers {
        remaining = remaining
            .checked_sub(header.name.len())
            .ok_or_else(|| failure("InputLimit", "WebSocket headers exceed 65536 bytes"))?;
        let bytes = copy_buffer(env, header.value, remaining)?;
        remaining -= bytes.len();
        let field = phantom::RequestHeader::new(header.name, bytes);
        builder = builder.header(if header.sensitive.unwrap_or(false) {
            field.sensitive()
        } else {
            field
        });
    }
    Ok(builder)
}

pub(super) fn handshake(socket: &phantom::WebSocket) -> Result<WebSocketHandshake> {
    let response = socket.handshake_response();
    let protocol = match response.version() {
        http::Version::HTTP_11 => "http1",
        http::Version::HTTP_2 => "http2",
        http::Version::HTTP_3 => "http3",
        _ => {
            return Err(failure(
                "Internal",
                "WebSocket handshake HTTP version is unsupported",
            ));
        }
    };
    let headers = response
        .extensions()
        .get::<phantom::OrderedResponseHeaders>()
        .ok_or_else(|| {
            failure(
                "Internal",
                "WebSocket ordered handshake fields are unavailable",
            )
        })?
        .iter()
        .map(|header| WireHeader {
            name: header.name().to_owned(),
            value: header.value().to_vec().into(),
            sensitive: Some(header.is_sensitive()),
        })
        .collect();
    Ok(WebSocketHandshake {
        status: u32::from(response.status().as_u16()),
        protocol: protocol.to_owned(),
        selected_protocol: socket.selected_protocol().map(str::to_owned),
        headers,
    })
}

fn event(message: WebSocketMessage) -> Result<WebSocketEvent> {
    let mut event = WebSocketEvent {
        kind: String::new(),
        text: None,
        data: None,
        code: None,
        reason: None,
    };
    match message {
        WebSocketMessage::Text(text) => {
            event.kind = "text".to_owned();
            event.text = Some(text);
        }
        WebSocketMessage::Binary(data) => {
            event.kind = "binary".to_owned();
            event.data = Some(data.to_vec().into());
        }
        WebSocketMessage::Ping(data) => {
            event.kind = "ping".to_owned();
            event.data = Some(data.to_vec().into());
        }
        WebSocketMessage::Pong(data) => {
            event.kind = "pong".to_owned();
            event.data = Some(data.to_vec().into());
        }
        WebSocketMessage::Close(frame) => {
            event.kind = "close".to_owned();
            if let Some(frame) = frame {
                event.code = Some(u32::from(frame.code()));
                event.reason = Some(frame.reason().to_owned());
            }
        }
        _ => return Err(failure("Internal", "unsupported WebSocket message kind")),
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::WebSocketEvent;

    #[test]
    fn debug_retains_event_metadata_without_payloads() {
        let event = WebSocketEvent {
            kind: "binary".to_owned(),
            text: Some("private text".to_owned()),
            data: Some(b"private bytes".to_vec().into()),
            code: Some(1000),
            reason: Some("private reason".to_owned()),
        };
        let output = format!("{event:?}");
        assert!(output.contains("kind: \"binary\""));
        assert!(output.contains("text_bytes: Some(12)"));
        assert!(output.contains("data_bytes: Some(13)"));
        assert!(output.contains("code: Some(1000)"));
        assert!(output.contains("reason_bytes: Some(14)"));
        assert!(!output.contains("private"));
        assert!(!output.contains("112, 114, 105, 118"));

        let unknown = WebSocketEvent {
            kind: "private kind".to_owned(),
            text: None,
            data: None,
            code: None,
            reason: None,
        };
        let output = format!("{unknown:?}");
        assert!(output.contains("kind: \"unknown\""));
        assert!(!output.contains("private"));
    }
}
