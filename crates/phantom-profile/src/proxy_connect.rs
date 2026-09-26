//! Ordered fields of the CONNECT request that opens an HTTP proxy tunnel.
//!
//! A [`ProxyConnectTemplate`] records the fields one browser sends in the
//! CONNECT request for a tunnel, in the order observed on each proxy
//! transport. The `phantom` client applies it to an HTTP proxy route whose
//! CONNECT fields the caller has not set.

use std::{collections::HashSet, error::Error, fmt};

/// One field or placeholder of a CONNECT request.
///
/// Field-name spelling is emitted exactly as written. HTTP/2 lists must use
/// lowercase names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProxyConnectField {
    /// The tunnel's `host:port`, as the HTTP/1.1 `Host` field.
    ///
    /// HTTP/2 sends the authority as the `:authority` pseudo-header field
    /// before every other field, so an HTTP/2 list has no such entry.
    Authority {
        /// Field-name spelling, an ASCII case variant of `Host`.
        name: Box<str>,
    },
    /// A field emitted with this name and value.
    Literal {
        /// Exact field-name spelling.
        name: Box<str>,
        /// Captured field value.
        value: Box<str>,
    },
    /// The value of the field with this name in the request that opens the
    /// tunnel, such as its `User-Agent`.
    ///
    /// The request's own field wins over its template's captured value, and
    /// keeps its sensitive marking. When the request sends no such field, the
    /// CONNECT request sends none either. `Authorization`, `Cookie`, and
    /// `Cookie2` are refused, because the proxy must not receive the origin's
    /// credentials.
    FromRequest {
        /// Exact field-name spelling emitted with the request's value.
        name: Box<str>,
    },
    /// The position of the generated `Proxy-Authorization` field when the
    /// route has Basic credentials.
    ProxyAuthorization {
        /// Field-name spelling, an ASCII case variant of
        /// `Proxy-Authorization`.
        name: Box<str>,
    },
}

impl ProxyConnectField {
    /// Creates the tunnel-authority placeholder.
    #[must_use]
    pub fn authority(name: impl Into<Box<str>>) -> Self {
        Self::Authority { name: name.into() }
    }

    /// Creates a field with a captured value.
    #[must_use]
    pub fn literal(name: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        Self::Literal {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Creates a field that copies the tunnelled request's value.
    #[must_use]
    pub fn from_request(name: impl Into<Box<str>>) -> Self {
        Self::FromRequest { name: name.into() }
    }

    /// Creates the generated-credentials placeholder.
    #[must_use]
    pub fn proxy_authorization(name: impl Into<Box<str>>) -> Self {
        Self::ProxyAuthorization { name: name.into() }
    }

    /// Returns the entry's field name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Authority { name }
            | Self::Literal { name, .. }
            | Self::FromRequest { name }
            | Self::ProxyAuthorization { name } => name,
        }
    }
}

/// What a client sends on an HTTP/2 CONNECT stream after the proxy ended it
/// with a final status other than 2xx, such as a `407` challenge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2RejectedConnect {
    /// An empty DATA frame with END_STREAM, before any later stream opens.
    ///
    /// Chrome 154 and Edge 154 do this in the
    /// `https-proxy-auth-secure-hostname` captures.
    #[default]
    EndStream,
    /// Nothing while the connection carries the tunnel that follows.
    ///
    /// Firefox 156 does this in the `https-proxy-auth-secure-hostname`
    /// captures. The stream stays open on the client side, so it holds one of
    /// the proxy's concurrent streams. When the proxy allows only one
    /// stream, the client ends the stream as in [`Self::EndStream`] instead.
    LeaveOpen,
}

/// Which requests share an HTTP/2 connection to an HTTPS proxy.
///
/// Every variant shares a connection only between requests on the same proxy
/// route with the same credentials. A request past the proxy's
/// `SETTINGS_MAX_CONCURRENT_STREAMS` waits on the connection, and the next
/// request after the proxy's `GOAWAY` opens a new one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2ProxyConnections {
    /// Forwarded `http://` requests, CONNECT tunnels, and WebSocket tunnels
    /// are streams of one connection.
    ///
    /// Chrome 154, Edge 154, Brave 154, and Opera 135 send a page's
    /// navigation, its `fetch()`, and every CONNECT it opens on one
    /// connection in the `https-proxy-*` captures.
    #[default]
    Shared,
    /// Forwarded `http://` requests, CONNECT tunnels for other requests, and
    /// CONNECT tunnels for WebSocket openings each share a connection only
    /// among themselves.
    ///
    /// Firefox 156 opens three connections for one page in the
    /// `https-proxy-*` captures: one for the navigation and `fetch()`, one
    /// for the `https://` CONNECTs, and one for the `ws://` and `wss://`
    /// CONNECTs.
    ByPurpose,
}

/// Ordered CONNECT fields for each HTTP proxy transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConnectTemplate {
    /// Ordered fields of an HTTP/1.1 CONNECT request, after its request line.
    pub http1_fields: Vec<ProxyConnectField>,
    /// Ordered fields of an HTTP/2 CONNECT request, after `:method` and
    /// `:authority`.
    pub http2_fields: Vec<ProxyConnectField>,
    /// What the client sends on an HTTP/2 CONNECT stream the proxy rejected.
    pub http2_rejected: Http2RejectedConnect,
    /// Which requests share an HTTP/2 connection to the proxy.
    pub http2_connections: Http2ProxyConnections,
}

impl ProxyConnectTemplate {
    /// Validates both lists.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProxyConnectTemplate`] when a name is not a token or
    /// repeats, a placeholder's name is not a case variant of its field, a
    /// literal is `Host`, `Proxy-Authorization`, or a framing field, a
    /// request-copied field names one of those or `Authorization`, `Cookie`,
    /// or `Cookie2`, a literal value is invalid, or a list lacks exactly one
    /// `Proxy-Authorization` placeholder. The HTTP/1.1 list must have exactly
    /// one authority placeholder; the HTTP/2 list must have none, use
    /// lowercase names, and carry no connection-specific field.
    pub fn validate(&self) -> Result<(), InvalidProxyConnectTemplate> {
        validate_fields(&self.http1_fields, "http1_fields", false)?;
        validate_fields(&self.http2_fields, "http2_fields", true)
    }
}

/// Error returned when CONNECT template data is inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidProxyConnectTemplate {
    field: &'static str,
    message: &'static str,
}

impl InvalidProxyConnectTemplate {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the invalid list's field name.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the list is invalid.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for InvalidProxyConnectTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid proxy CONNECT template {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidProxyConnectTemplate {}

/// Fields that carry the origin's credentials or cookies. Copying one into
/// a CONNECT request would hand it to the proxy.
const CREDENTIAL_FIELDS: [&str; 3] = ["authorization", "cookie", "cookie2"];

/// Connection-specific fields that HTTP/2 forbids (RFC 9113 section 8.2.2).
const CONNECTION_SPECIFIC: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "upgrade",
];

fn validate_fields(
    fields: &[ProxyConnectField],
    list: &'static str,
    http2: bool,
) -> Result<(), InvalidProxyConnectTemplate> {
    let mut names = HashSet::with_capacity(fields.len());
    let mut authorities = 0_usize;
    let mut authorizations = 0_usize;
    for field in fields {
        let name = field.name();
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(InvalidProxyConnectTemplate::new(
                list,
                "field names must be non-empty tokens",
            ));
        }
        if http2 && name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(InvalidProxyConnectTemplate::new(
                list,
                "HTTP/2 field names must be lowercase",
            ));
        }
        let lower = name.to_ascii_lowercase();
        match field {
            ProxyConnectField::Authority { .. } => {
                if http2 {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "HTTP/2 sends the authority as :authority, so its list has no authority entry",
                    ));
                }
                if lower != "host" {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "the authority placeholder must be named Host",
                    ));
                }
                authorities += 1;
            }
            ProxyConnectField::ProxyAuthorization { .. } => {
                if lower != "proxy-authorization" {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "the credentials placeholder must be named Proxy-Authorization",
                    ));
                }
                authorizations += 1;
            }
            ProxyConnectField::Literal { value, .. } => {
                if !value
                    .bytes()
                    .all(|byte| matches!(byte, b'\t' | b' '..=b'~'))
                {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "literal values must contain only visible ASCII, spaces, or tabs",
                    ));
                }
                if matches!(
                    lower.as_str(),
                    "host" | "proxy-authorization" | "content-length" | "transfer-encoding"
                ) {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "Host, Proxy-Authorization, and framing fields are placeholders or generated",
                    ));
                }
            }
            ProxyConnectField::FromRequest { .. } => {
                if matches!(
                    lower.as_str(),
                    "host" | "proxy-authorization" | "content-length" | "transfer-encoding"
                ) {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "Host, Proxy-Authorization, and framing fields are placeholders or generated",
                    ));
                }
                if CREDENTIAL_FIELDS.contains(&lower.as_str()) {
                    return Err(InvalidProxyConnectTemplate::new(
                        list,
                        "a CONNECT request must not copy the origin's credentials or cookies",
                    ));
                }
            }
        }
        if http2 && CONNECTION_SPECIFIC.contains(&lower.as_str()) {
            return Err(InvalidProxyConnectTemplate::new(
                list,
                "HTTP/2 lists must not carry connection-specific fields",
            ));
        }
        if !names.insert(lower) {
            return Err(InvalidProxyConnectTemplate::new(
                list,
                "field names must not repeat",
            ));
        }
    }
    if !http2 && authorities != 1 {
        return Err(InvalidProxyConnectTemplate::new(
            list,
            "an HTTP/1.1 list needs exactly one authority placeholder",
        ));
    }
    if authorizations != 1 {
        return Err(InvalidProxyConnectTemplate::new(
            list,
            "a list needs exactly one Proxy-Authorization placeholder",
        ));
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
#[path = "proxy_connect/tests.rs"]
mod tests;
