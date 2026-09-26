//! Backend-neutral WebSocket opening fields and connection choice.

use std::{error::Error, fmt, time::Duration};

use crate::TlsSettings;

const HTTP1_ALPN: &[u8] = b"http/1.1";

/// One field, caller slot, or generated value in an ordered opening template.
///
/// Field-name spelling is emitted exactly as written. HTTP/2 templates must
/// use lowercase names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketField {
    /// A fixed field emitted with this exact name and value.
    Literal {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Exact field value.
        value: Box<str>,
    },
    /// The position of a caller-supplied field with this spelling.
    ///
    /// Values such as `User-Agent`, `Origin`, and `Accept-Language` describe
    /// the persona or page context, so a recipe fixes only their position. The
    /// slot emits nothing when the caller supplies no value.
    Caller {
        /// Exact field-name spelling emitted with the caller's value.
        name: Box<str>,
    },
    /// The HTTP/1.1 `Host` field generated from the request authority.
    Authority {
        /// Exact field-name spelling.
        name: Box<str>,
    },
    /// A fresh HTTP/1.1 `Sec-WebSocket-Key`.
    Key {
        /// Exact field-name spelling.
        name: Box<str>,
    },
    /// The generated `permessage-deflate` offer when compression is enabled.
    PerMessageDeflate {
        /// Exact field-name spelling.
        name: Box<str>,
    },
    /// Client cookies when a cookie jar supplies them.
    ClientCookies {
        /// Exact field-name spelling.
        name: Box<str>,
    },
    /// A field whose captured value depends on whether the WebSocket URL is
    /// potentially trustworthy, as W3C Secure Contexts defines it.
    ///
    /// A `wss://` URL is potentially trustworthy, and so is a `ws://` URL
    /// whose host is a loopback address (`127.0.0.0/8` or `::1`),
    /// `localhost`, or a name under `.localhost`. A caller field with this
    /// name takes this position in either case, as it does for
    /// [`Self::Caller`].
    ByTrust {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Value sent to a potentially trustworthy URL, or `None` to send
        /// nothing there unless the caller supplies the field.
        trustworthy: Option<Box<str>>,
        /// Value sent to any other URL, or `None` to send nothing there
        /// unless the caller supplies the field.
        untrustworthy: Option<Box<str>>,
    },
}

impl WebSocketField {
    /// Creates a fixed field.
    #[must_use]
    pub fn literal(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::Literal {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Creates a caller-supplied field slot.
    #[must_use]
    pub fn caller(name: impl Into<Box<str>>) -> Self {
        Self::Caller { name: name.into() }
    }

    /// Creates an HTTP/1.1 authority placeholder.
    #[must_use]
    pub fn authority(name: impl Into<Box<str>>) -> Self {
        Self::Authority { name: name.into() }
    }

    /// Creates an HTTP/1.1 key placeholder.
    #[must_use]
    pub fn key(name: impl Into<Box<str>>) -> Self {
        Self::Key { name: name.into() }
    }

    /// Creates a compression-offer placeholder.
    #[must_use]
    pub fn permessage_deflate(name: impl Into<Box<str>>) -> Self {
        Self::PerMessageDeflate { name: name.into() }
    }

    /// Creates a client-cookie placeholder.
    #[must_use]
    pub fn client_cookies(name: impl Into<Box<str>>) -> Self {
        Self::ClientCookies { name: name.into() }
    }

    /// Creates a field sent only to a potentially trustworthy URL.
    #[must_use]
    pub fn trustworthy_only(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::ByTrust {
            name: name.into(),
            trustworthy: Some(value.into()),
            untrustworthy: None,
        }
    }

    /// Creates a field with one value for a potentially trustworthy URL and
    /// another for any other URL.
    #[must_use]
    pub fn by_trust(
        name: impl Into<Box<str>>,
        trustworthy: impl Into<Box<str>>,
        untrustworthy: impl Into<Box<str>>,
    ) -> Self {
        Self::ByTrust {
            name: name.into(),
            trustworthy: Some(trustworthy.into()),
            untrustworthy: Some(untrustworthy.into()),
        }
    }

    /// Returns the value this entry sends when the caller supplies no field
    /// of its name: a literal's value, or a trust-dependent entry's value
    /// for `trustworthy`. Slots and placeholders return `None`.
    #[must_use]
    pub fn default_value(&self, trustworthy: bool) -> Option<&str> {
        match self {
            Self::Literal { value, .. } => Some(value),
            Self::ByTrust {
                trustworthy: secure,
                untrustworthy: other,
                ..
            } => if trustworthy { secure } else { other }.as_deref(),
            Self::Caller { .. }
            | Self::Authority { .. }
            | Self::Key { .. }
            | Self::PerMessageDeflate { .. }
            | Self::ClientCookies { .. } => None,
        }
    }
}

/// One parameter in an ordered RFC 7692 `permessage-deflate` offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketDeflateParameter {
    /// `server_no_context_takeover`.
    ServerNoContextTakeover,
    /// `client_no_context_takeover`.
    ClientNoContextTakeover,
    /// `server_max_window_bits` with an 8–15-bit value.
    ServerMaxWindowBits(u8),
    /// `client_max_window_bits`, bare or with an 8–15-bit value.
    ClientMaxWindowBits(Option<u8>),
}

/// Whether an empty data message is compressed once `permessage-deflate` is
/// negotiated.
///
/// This is the only per-message compression decision the retained captures
/// disagree on. Every client in them compresses each non-empty text and binary
/// message and sets RSV1 on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketEmptyMessageCompression {
    /// Compress it like any other message and set RSV1.
    Compressed,
    /// Send a zero-length payload with RSV1 clear.
    Uncompressed,
}

/// The connection opened when no pooled HTTP/2 session can carry a WebSocket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketNewConnection {
    /// A new TLS connection offering
    /// [`WebSocketConnectionPolicy::http1_alpn_protocols`], then an HTTP/1.1
    /// Upgrade.
    Http1Upgrade,
    /// A new connection with the profile's TLS and HTTP/2 settings, then RFC
    /// 8441 extended CONNECT.
    Http2ExtendedConnect,
}

/// What a client does when the peer answers an extended CONNECT with
/// `RST_STREAM(REFUSED_STREAM)`.
///
/// RFC 9113, section 8.7 says such a stream was closed before the peer
/// processed anything on it, so only the HEADERS the client already sent can
/// be sent again. This describes captured client behavior, not caller policy:
/// a client's retry policy stays a caller concern and never applies to a
/// WebSocket opening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketRefusedStreamRetry {
    /// The refusal is reported to the caller.
    None,
    /// One further extended CONNECT opens on the same HTTP/2 session.
    ///
    /// The opening fields are re-encoded for a fresh stream on that same
    /// session. No other failure is retried, and no other connection or
    /// protocol is tried.
    ///
    /// No retained run shows a second consecutive refusal, so what a client
    /// does then is unobserved. Phantom reports it to the caller; that bound
    /// is a choice, not capture evidence.
    SameSessionOnce,
}

/// How a client chooses the connection for a `wss://` WebSocket.
///
/// A pooled HTTP/2 session to the same origin and route whose peer enabled
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` always carries the WebSocket as an
/// extended CONNECT stream. The two remaining cases are profile data. A
/// plaintext `ws://` WebSocket always uses an HTTP/1.1 Upgrade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketConnectionPolicy {
    /// The connection opened when no pooled HTTP/2 session exists.
    pub without_http2_session: WebSocketNewConnection,
    /// The connection opened when the pooled HTTP/2 session's peer did not
    /// enable extended CONNECT.
    pub with_incapable_http2_session: WebSocketNewConnection,
    /// ALPN protocols offered, in order, on a new TLS connection that carries
    /// an HTTP/1.1 Upgrade.
    ///
    /// The list must offer `http/1.1` and must not offer `h2`, so ALPN cannot
    /// select a protocol that the Upgrade cannot use.
    pub http1_alpn_protocols: Vec<Box<[u8]>>,
    /// What happens when the peer refuses the extended CONNECT stream.
    ///
    /// It applies only to an extended CONNECT on a pooled HTTP/2 session,
    /// which is the only case the captures cover.
    pub refused_stream_retry: WebSocketRefusedStreamRetry,
}

impl WebSocketConnectionPolicy {
    /// Derives the TLS offer for a new HTTP/1.1 Upgrade connection.
    ///
    /// The ALPN list is replaced. The ALPS offer is kept only when its
    /// protocol remains in that list, because TLS settings cannot carry
    /// application settings for a protocol they do not offer. Every other
    /// field is unchanged.
    #[must_use]
    pub fn http1_tls_settings(&self, tls: &TlsSettings) -> TlsSettings {
        let mut settings = tls.clone();
        settings
            .alpn_protocols
            .clone_from(&self.http1_alpn_protocols);
        if settings.alps.as_ref().is_some_and(|alps| {
            !settings
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.as_ref() == alps.protocol.as_ref())
        }) {
            settings.alps = None;
        }
        settings
    }

    fn validate(&self) -> Result<(), InvalidWebSocketSettings> {
        const FIELD: &str = "connection.http1_alpn_protocols";
        if !self
            .http1_alpn_protocols
            .iter()
            .any(|protocol| protocol.as_ref() == HTTP1_ALPN)
        {
            return Err(InvalidWebSocketSettings::new(
                FIELD,
                "HTTP/1.1 Upgrade connections must offer http/1.1",
            ));
        }
        if self
            .http1_alpn_protocols
            .iter()
            .any(|protocol| protocol.as_ref() == b"h2")
        {
            return Err(InvalidWebSocketSettings::new(
                FIELD,
                "HTTP/1.1 Upgrade connections must not offer h2",
            ));
        }
        Ok(())
    }
}

/// Ordered WebSocket opening templates and connection choice for one client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketSettings {
    /// Connection choice for `wss://` WebSockets opened by profile policy.
    pub connection: WebSocketConnectionPolicy,
    /// Ordered HTTP/1.1 Upgrade fields.
    pub http1_fields: Vec<WebSocketField>,
    /// Ordered ordinary HTTP/2 extended CONNECT fields.
    ///
    /// Pseudo-header order and HEADERS priority belong to
    /// [`Http2Settings`](crate::Http2Settings).
    pub http2_fields: Vec<WebSocketField>,
    /// Ordered `permessage-deflate` offer parameters.
    ///
    /// An empty list offers bare `permessage-deflate`. The offer is sent only
    /// when the caller enables compression.
    pub permessage_deflate_offer: Vec<WebSocketDeflateParameter>,
    /// How an empty text or binary message is sent once the offer is accepted.
    ///
    /// It applies only while `permessage-deflate` is in use; without it every
    /// message is sent with RSV1 clear.
    pub empty_message_compression: WebSocketEmptyMessageCompression,
    /// The longest one opening handshake may take, from the start of the
    /// connect until the accepting response is validated, or `None` for no
    /// limit.
    ///
    /// This is the browser's own fixed opening timer, not caller policy. It
    /// covers name resolution, proxy setup, TLS, the opening request, and its
    /// response as one deadline, and it applies to every WebSocket the client
    /// opens with this profile unless the caller replaces it for one connect.
    pub handshake_timeout: Option<Duration>,
}

impl WebSocketSettings {
    /// Validates settings that are independent of a particular backend.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWebSocketSettings`] for an ALPN list that cannot carry
    /// an HTTP/1.1 Upgrade, a template that is not usable by its protocol, an
    /// invalid compression offer, or a zero handshake timeout.
    pub fn validate(&self) -> Result<(), InvalidWebSocketSettings> {
        self.connection.validate()?;
        if self.handshake_timeout == Some(Duration::ZERO) {
            return Err(InvalidWebSocketSettings::new(
                "handshake_timeout",
                "a handshake timeout must be positive; None sets no limit",
            ));
        }
        validate_template(&self.http1_fields, "http1_fields", false)?;
        validate_template(&self.http2_fields, "http2_fields", true)?;
        validate_deflate_offer(&self.permessage_deflate_offer)
    }
}

/// Error returned when WebSocket profile settings are inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidWebSocketSettings {
    field: &'static str,
    message: &'static str,
}

impl InvalidWebSocketSettings {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for InvalidWebSocketSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid WebSocket {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidWebSocketSettings {}

fn validate_template(
    fields: &[WebSocketField],
    field: &'static str,
    http2: bool,
) -> Result<(), InvalidWebSocketSettings> {
    let mut authority = 0;
    let mut key = 0;
    let mut deflate = 0;
    let mut cookies = 0;
    for template in fields {
        let name = match template {
            WebSocketField::Literal { name, .. }
            | WebSocketField::Caller { name }
            | WebSocketField::ByTrust { name, .. } => name,
            WebSocketField::Authority { name } => {
                authority += 1;
                name
            }
            WebSocketField::Key { name } => {
                key += 1;
                name
            }
            WebSocketField::PerMessageDeflate { name } => {
                deflate += 1;
                name
            }
            WebSocketField::ClientCookies { name } => {
                cookies += 1;
                name
            }
        };
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(InvalidWebSocketSettings::new(
                field,
                "field names must be non-empty tokens",
            ));
        }
        if http2 && name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(InvalidWebSocketSettings::new(
                field,
                "HTTP/2 field names must be lowercase",
            ));
        }
    }
    let expected_generated = usize::from(!http2);
    if authority != expected_generated || key != expected_generated {
        return Err(InvalidWebSocketSettings::new(
            field,
            "HTTP/1.1 templates need one authority and one key; HTTP/2 templates need neither",
        ));
    }
    if deflate > 1 || cookies > 1 {
        return Err(InvalidWebSocketSettings::new(
            field,
            "compression and cookie placeholders may occur at most once",
        ));
    }
    Ok(())
}

fn validate_deflate_offer(
    parameters: &[WebSocketDeflateParameter],
) -> Result<(), InvalidWebSocketSettings> {
    const FIELD: &str = "permessage_deflate_offer";
    let mut seen = [false; 4];
    for parameter in parameters {
        let (index, bits) = match *parameter {
            WebSocketDeflateParameter::ServerNoContextTakeover => (0, None),
            WebSocketDeflateParameter::ClientNoContextTakeover => (1, None),
            WebSocketDeflateParameter::ServerMaxWindowBits(bits) => (2, Some(bits)),
            WebSocketDeflateParameter::ClientMaxWindowBits(bits) => (3, bits),
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(InvalidWebSocketSettings::new(
                FIELD,
                "each offer parameter may occur once",
            ));
        }
        if bits.is_some_and(|bits| !(8..=15).contains(&bits)) {
            return Err(InvalidWebSocketSettings::new(
                FIELD,
                "window widths must be between 8 and 15 bits",
            ));
        }
    }
    Ok(())
}

const fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

#[cfg(test)]
mod tests;
