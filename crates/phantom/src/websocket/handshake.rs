use std::{collections::HashSet, fmt};

use http::{
    HeaderName,
    header::{CONNECTION, HOST, PROXY_AUTHORIZATION, UPGRADE},
};
use phantom_net::request::RequestHeader;

use super::WebSocketError;

const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const KEY_NAME: &str = "sec-websocket-key";
const VERSION_NAME: &str = "sec-websocket-version";
const ACCEPT_NAME: &str = "sec-websocket-accept";
const PROTOCOL_NAME: &str = "sec-websocket-protocol";
const EXTENSIONS_NAME: &str = "sec-websocket-extensions";

mod response;
mod syntax;

pub(super) use response::validate_response;
use syntax::{is_token, split_tokens, trim_ows};

/// One field or generated-value placeholder in the opening handshake.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketHeader {
    /// Inserts the URI authority using the supplied field-name spelling.
    Authority {
        /// Exact field-name spelling to emit.
        name: Box<str>,
    },
    /// Inserts a fresh random `Sec-WebSocket-Key` using this spelling.
    Key {
        /// Exact field-name spelling to emit.
        name: Box<str>,
    },
    /// Inserts client cookies at this position when the caller did not supply them.
    ClientCookies {
        /// Exact field-name spelling to emit when cookies are available.
        name: Box<str>,
    },
    /// Compatibility name for [`Self::ClientCookies`].
    #[doc(hidden)]
    SessionCookies {
        /// Exact field-name spelling to emit when cookies are available.
        name: Box<str>,
    },
    /// Inserts the generated `permessage-deflate` offer at this position.
    #[cfg(feature = "websocket-deflate")]
    PerMessageDeflate {
        /// Exact field-name spelling to emit.
        name: Box<str>,
    },
    /// Emits one literal ordered field.
    Field(RequestHeader),
}

impl WebSocketHeader {
    /// Creates an authority placeholder with caller-controlled field-name spelling.
    #[must_use]
    pub fn authority(name: impl Into<Box<str>>) -> Self {
        Self::Authority { name: name.into() }
    }

    /// Creates a nonce placeholder with caller-controlled field-name spelling.
    #[must_use]
    pub fn key(name: impl Into<Box<str>>) -> Self {
        Self::Key { name: name.into() }
    }

    /// Creates a client-cookie placeholder with caller-controlled spelling.
    #[must_use]
    pub fn client_cookies(name: impl Into<Box<str>>) -> Self {
        Self::ClientCookies { name: name.into() }
    }

    /// Compatibility name for [`Self::client_cookies`].
    #[doc(hidden)]
    #[must_use]
    pub fn session_cookies(name: impl Into<Box<str>>) -> Self {
        Self::client_cookies(name)
    }

    /// Creates a generated compression-offer placeholder.
    #[cfg(feature = "websocket-deflate")]
    #[must_use]
    pub fn permessage_deflate(name: impl Into<Box<str>>) -> Self {
        Self::PerMessageDeflate { name: name.into() }
    }

    /// Creates a literal ordered field.
    #[must_use]
    pub fn field(header: RequestHeader) -> Self {
        Self::Field(header)
    }
}

impl fmt::Debug for WebSocketHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, name) = match self {
            Self::Authority { name } => ("authority", name.as_ref()),
            Self::Key { name } => ("key", name.as_ref()),
            Self::ClientCookies { name } => ("client_cookies", name.as_ref()),
            Self::SessionCookies { name } => ("session_cookies", name.as_ref()),
            #[cfg(feature = "websocket-deflate")]
            Self::PerMessageDeflate { name } => ("permessage_deflate", name.as_ref()),
            Self::Field(header) => ("field", header.name()),
        };
        formatter
            .debug_struct("WebSocketHeader")
            .field("kind", &kind)
            .field("name", &name)
            .finish()
    }
}

pub(super) struct PreparedHandshake {
    pub(super) headers: Vec<RequestHeader>,
    pub(super) expected_accept: String,
    pub(super) offered_protocols: Vec<Box<str>>,
}

pub(super) fn default_headers() -> Vec<WebSocketHeader> {
    vec![
        WebSocketHeader::authority("Host"),
        WebSocketHeader::field(RequestHeader::new("Upgrade", "websocket")),
        WebSocketHeader::field(RequestHeader::new("Connection", "Upgrade")),
        WebSocketHeader::key("Sec-WebSocket-Key"),
        WebSocketHeader::field(RequestHeader::new("Sec-WebSocket-Version", "13")),
        #[cfg(feature = "websocket-deflate")]
        WebSocketHeader::permessage_deflate("Sec-WebSocket-Extensions"),
        WebSocketHeader::client_cookies("Cookie"),
    ]
}

pub(super) fn prepare(
    templates: Vec<WebSocketHeader>,
    authority: &str,
    session_cookie: Option<&str>,
    extension_offer: Option<&[u8]>,
) -> Result<PreparedHandshake, WebSocketError> {
    let validation = validate_templates(&templates, extension_offer.is_some())?;
    let mut nonce = [0_u8; 16];
    btls::rand::rand_bytes(&mut nonce).map_err(WebSocketError::random)?;
    let key = btls::base64::encode_block(&nonce);
    let expected_accept = accept_for_key(&key);
    let mut headers = Vec::with_capacity(templates.len());

    for template in templates {
        match template {
            WebSocketHeader::Authority { name } => {
                headers.push(RequestHeader::new(name, authority));
            }
            WebSocketHeader::Key { name } => {
                headers.push(RequestHeader::new(name, &key).sensitive());
            }
            WebSocketHeader::ClientCookies { name } | WebSocketHeader::SessionCookies { name } => {
                if !validation.has_literal_cookie {
                    if let Some(value) = session_cookie {
                        headers.push(RequestHeader::new(name, value).sensitive());
                    }
                }
            }
            #[cfg(feature = "websocket-deflate")]
            WebSocketHeader::PerMessageDeflate { name } => {
                if let Some(value) = extension_offer {
                    headers.push(RequestHeader::new(name, value));
                }
            }
            WebSocketHeader::Field(header) => headers.push(header),
        }
    }

    Ok(PreparedHandshake {
        headers,
        expected_accept,
        offered_protocols: validation.offered_protocols,
    })
}

struct TemplateValidation {
    has_literal_cookie: bool,
    offered_protocols: Vec<Box<str>>,
}

fn validate_templates(
    templates: &[WebSocketHeader],
    extension_required: bool,
) -> Result<TemplateValidation, WebSocketError> {
    let mut authority_count = 0;
    let mut key_count = 0;
    let mut cookie_placeholder_count = 0;
    let mut upgrade_count = 0;
    let mut connection_count = 0;
    let mut version_count = 0;
    let mut protocol_count = 0;
    #[cfg(feature = "websocket-deflate")]
    let mut extension_placeholder_count = 0;
    #[cfg(not(feature = "websocket-deflate"))]
    let extension_placeholder_count = 0;
    let mut has_literal_cookie = false;
    let mut offered_protocols = Vec::new();

    for template in templates {
        match template {
            WebSocketHeader::Authority { name } => {
                validate_placeholder_name(name, "host")?;
                authority_count += 1;
            }
            WebSocketHeader::Key { name } => {
                validate_placeholder_name(name, KEY_NAME)?;
                key_count += 1;
            }
            WebSocketHeader::ClientCookies { name } | WebSocketHeader::SessionCookies { name } => {
                validate_placeholder_name(name, "cookie")?;
                cookie_placeholder_count += 1;
            }
            #[cfg(feature = "websocket-deflate")]
            WebSocketHeader::PerMessageDeflate { name } => {
                validate_placeholder_name(name, EXTENSIONS_NAME)?;
                extension_placeholder_count += 1;
            }
            WebSocketHeader::Field(header) => {
                let name = header.name();
                if name.eq_ignore_ascii_case(HOST.as_str()) {
                    return Err(WebSocketError::invalid_request(
                        "literal Host is forbidden; use the authority placeholder",
                    ));
                }
                if name.eq_ignore_ascii_case(PROXY_AUTHORIZATION.as_str()) {
                    return Err(WebSocketError::invalid_request(
                        "literal Proxy-Authorization is forbidden; configure proxy credentials on the route",
                    ));
                }
                if name.eq_ignore_ascii_case(KEY_NAME) {
                    return Err(WebSocketError::invalid_request(
                        "literal Sec-WebSocket-Key is forbidden; use the key placeholder",
                    ));
                }
                if name.eq_ignore_ascii_case(UPGRADE.as_str()) {
                    upgrade_count += 1;
                    let tokens = request_tokens(header.value())?;
                    if tokens.len() != 1 || !tokens[0].eq_ignore_ascii_case(b"websocket") {
                        return Err(WebSocketError::invalid_request(
                            "opening handshake requires exactly `Upgrade: websocket`",
                        ));
                    }
                } else if name.eq_ignore_ascii_case(CONNECTION.as_str()) {
                    connection_count += 1;
                    let tokens = request_tokens(header.value())?;
                    if tokens
                        .iter()
                        .filter(|token| token.eq_ignore_ascii_case(b"upgrade"))
                        .count()
                        != 1
                    {
                        return Err(WebSocketError::invalid_request(
                            "opening handshake Connection field must contain Upgrade once",
                        ));
                    }
                } else if name.eq_ignore_ascii_case(VERSION_NAME) {
                    version_count += 1;
                    if trim_ows(header.value()) != b"13" {
                        return Err(WebSocketError::invalid_request(
                            "opening handshake requires Sec-WebSocket-Version 13",
                        ));
                    }
                } else if name.eq_ignore_ascii_case(EXTENSIONS_NAME) {
                    return Err(WebSocketError::invalid_request(
                        "literal WebSocket extensions are forbidden without a matching typed codec",
                    ));
                } else if name.eq_ignore_ascii_case(PROTOCOL_NAME) {
                    protocol_count += 1;
                    offered_protocols = parse_protocols(header.value())?;
                } else if name.eq_ignore_ascii_case("cookie") {
                    has_literal_cookie = true;
                }
            }
        }
    }

    if authority_count != 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake requires exactly one authority placeholder",
        ));
    }
    if key_count != 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake requires exactly one key placeholder",
        ));
    }
    if cookie_placeholder_count > 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake permits at most one client-cookie placeholder",
        ));
    }
    if upgrade_count != 1 || connection_count != 1 || version_count != 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake requires one Upgrade, Connection, and Sec-WebSocket-Version field",
        ));
    }
    if protocol_count > 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake permits at most one Sec-WebSocket-Protocol field",
        ));
    }
    if extension_placeholder_count > 1 {
        return Err(WebSocketError::invalid_request(
            "opening handshake permits at most one compression placeholder",
        ));
    }
    if extension_required && extension_placeholder_count != 1 {
        return Err(WebSocketError::invalid_request(
            "enabled WebSocket compression requires one extension placeholder",
        ));
    }

    Ok(TemplateValidation {
        has_literal_cookie,
        offered_protocols,
    })
}

fn validate_placeholder_name(name: &str, expected: &str) -> Result<(), WebSocketError> {
    let parsed = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        WebSocketError::invalid_request("opening-handshake placeholder has an invalid field name")
    })?;
    if !name
        .as_bytes()
        .eq_ignore_ascii_case(parsed.as_str().as_bytes())
        || !parsed.as_str().eq_ignore_ascii_case(expected)
    {
        return Err(WebSocketError::invalid_request(
            "opening-handshake placeholder has the wrong field name",
        ));
    }
    Ok(())
}

fn parse_protocols(value: &[u8]) -> Result<Vec<Box<str>>, WebSocketError> {
    let tokens = request_tokens(value)?;
    let mut seen = HashSet::with_capacity(tokens.len());
    let mut protocols = Vec::with_capacity(tokens.len());
    for token in tokens {
        let protocol = std::str::from_utf8(token).map_err(|_| {
            WebSocketError::invalid_request("WebSocket subprotocol must be an ASCII token")
        })?;
        if !seen.insert(protocol) {
            return Err(WebSocketError::invalid_request(
                "WebSocket subprotocol offers must be unique",
            ));
        }
        protocols.push(protocol.into());
    }
    Ok(protocols)
}

fn request_tokens(value: &[u8]) -> Result<Vec<&[u8]>, WebSocketError> {
    split_tokens(value).map_err(|()| {
        WebSocketError::invalid_request(
            "opening handshake contains an invalid comma-separated token",
        )
    })
}

fn accept_for_key(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + ACCEPT_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(ACCEPT_GUID);
    btls::base64::encode_block(&btls::sha::sha1(&input))
}

#[cfg(test)]
mod tests {
    use super::accept_for_key;

    #[test]
    fn derives_the_rfc_accept_value() {
        assert_eq!(
            accept_for_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
