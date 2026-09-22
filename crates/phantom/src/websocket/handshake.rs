use std::{collections::HashSet, fmt};

use http::{
    HeaderName,
    header::{CONNECTION, HOST, PROXY_AUTHORIZATION, UPGRADE},
};
use phantom_net::request::RequestHeader;
use phantom_profile::WebSocketField;

use super::WebSocketError;

const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const KEY_NAME: &str = "sec-websocket-key";
const VERSION_NAME: &str = "sec-websocket-version";
const ACCEPT_NAME: &str = "sec-websocket-accept";
const PROTOCOL_NAME: &str = "sec-websocket-protocol";
const EXTENSIONS_NAME: &str = "sec-websocket-extensions";

mod response;
mod syntax;

pub(super) use response::{validate_http2_response, validate_response};
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
    /// Reserves the position of a caller-supplied field.
    ///
    /// [`WebSocketRequestBuilder::header`](crate::WebSocketRequestBuilder::header)
    /// with the same case-insensitive name fills the slot with this spelling
    /// and the caller's value. An unfilled slot emits nothing.
    CallerField {
        /// Exact field-name spelling to emit with the caller's value.
        name: Box<str>,
    },
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

    /// Creates a caller-supplied field slot with caller-controlled spelling.
    #[must_use]
    pub fn caller_field(name: impl Into<Box<str>>) -> Self {
        Self::CallerField { name: name.into() }
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
            Self::CallerField { name } => ("caller_field", name.as_ref()),
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

pub(super) struct PreparedHttp2Handshake {
    pub(super) headers: Vec<RequestHeader>,
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

pub(super) fn default_http2_headers() -> Vec<WebSocketHeader> {
    vec![
        WebSocketHeader::field(RequestHeader::new("sec-websocket-version", "13")),
        #[cfg(feature = "websocket-deflate")]
        WebSocketHeader::permessage_deflate("sec-websocket-extensions"),
        WebSocketHeader::client_cookies("cookie"),
    ]
}

pub(super) fn prepare_http2(
    templates: Vec<WebSocketHeader>,
    session_cookie: Option<&str>,
    extension_offer: Option<&[u8]>,
) -> Result<PreparedHttp2Handshake, WebSocketError> {
    let validation = validate_http2_templates(&templates, extension_offer.is_some())?;
    let mut headers = Vec::with_capacity(templates.len());
    for template in templates {
        match template {
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
            WebSocketHeader::CallerField { .. } => {}
            WebSocketHeader::Authority { .. } | WebSocketHeader::Key { .. } => {
                return Err(WebSocketError::invalid_request(
                    "HTTP/2 WebSocket fields must not contain authority or key placeholders",
                ));
            }
        }
    }
    Ok(PreparedHttp2Handshake {
        headers,
        offered_protocols: validation.offered_protocols,
    })
}

/// Reports whether the handshake would carry the jar's cookies: it has a
/// cookie placeholder and no literal `Cookie` field overriding it.
///
/// Callers read the jar only when this holds, because a jar read on the send
/// path counts as a use for eviction.
#[cfg(feature = "cookies")]
pub(super) fn sends_jar_cookie(templates: &[WebSocketHeader]) -> bool {
    let mut has_placeholder = false;
    for template in templates {
        match template {
            WebSocketHeader::ClientCookies { .. } | WebSocketHeader::SessionCookies { .. } => {
                has_placeholder = true;
            }
            WebSocketHeader::Field(header) if header.name().eq_ignore_ascii_case("cookie") => {
                return false;
            }
            _ => {}
        }
    }
    has_placeholder
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
            WebSocketHeader::CallerField { .. } => {}
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

fn validate_http2_templates(
    templates: &[WebSocketHeader],
    extension_required: bool,
) -> Result<TemplateValidation, WebSocketError> {
    let mut cookie_placeholder_count = 0;
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
            WebSocketHeader::Authority { .. } | WebSocketHeader::Key { .. } => {
                return Err(WebSocketError::invalid_request(
                    "HTTP/2 WebSocket fields must not contain authority or key placeholders",
                ));
            }
            WebSocketHeader::ClientCookies { name } | WebSocketHeader::SessionCookies { name } => {
                validate_http2_placeholder_name(name, "cookie")?;
                cookie_placeholder_count += 1;
            }
            WebSocketHeader::CallerField { name } => {
                validate_caller_field_name(name)?;
                if name.as_bytes().iter().any(u8::is_ascii_uppercase) {
                    return Err(WebSocketError::invalid_request(
                        "HTTP/2 WebSocket field names must be lowercase",
                    ));
                }
            }
            #[cfg(feature = "websocket-deflate")]
            WebSocketHeader::PerMessageDeflate { name } => {
                validate_http2_placeholder_name(name, EXTENSIONS_NAME)?;
                extension_placeholder_count += 1;
            }
            WebSocketHeader::Field(header) => {
                let name = header.name();
                if name.as_bytes().iter().any(u8::is_ascii_uppercase) {
                    return Err(WebSocketError::invalid_request(
                        "HTTP/2 WebSocket field names must be lowercase",
                    ));
                }
                if name.eq_ignore_ascii_case(HOST.as_str())
                    || name.eq_ignore_ascii_case(KEY_NAME)
                    || name.eq_ignore_ascii_case(UPGRADE.as_str())
                    || name.eq_ignore_ascii_case(CONNECTION.as_str())
                {
                    return Err(WebSocketError::invalid_request(
                        "HTTP/2 WebSocket request contains an HTTP/1-only field",
                    ));
                }
                if name.eq_ignore_ascii_case(PROXY_AUTHORIZATION.as_str()) {
                    return Err(WebSocketError::invalid_request(
                        "literal Proxy-Authorization is forbidden; configure proxy credentials on the route",
                    ));
                }
                if name.eq_ignore_ascii_case(VERSION_NAME) {
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

    if version_count != 1 {
        return Err(WebSocketError::invalid_request(
            "HTTP/2 opening handshake requires one Sec-WebSocket-Version field",
        ));
    }
    if cookie_placeholder_count > 1 || protocol_count > 1 || extension_placeholder_count > 1 {
        return Err(WebSocketError::invalid_request(
            "HTTP/2 opening handshake contains a duplicate singleton field",
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

fn validate_http2_placeholder_name(name: &str, expected: &str) -> Result<(), WebSocketError> {
    validate_placeholder_name(name, expected)?;
    if name.as_bytes().iter().any(u8::is_ascii_uppercase) {
        return Err(WebSocketError::invalid_request(
            "HTTP/2 WebSocket placeholder names must be lowercase",
        ));
    }
    Ok(())
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
            WebSocketHeader::CallerField { name } => validate_caller_field_name(name)?,
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

fn validate_caller_field_name(name: &str) -> Result<(), WebSocketError> {
    HeaderName::from_bytes(name.as_bytes())
        .map(drop)
        .map_err(|_| {
            WebSocketError::invalid_request(
                "opening-handshake caller slot has an invalid field name",
            )
        })
}

/// Validates both profile-policy sequences before the protocol is chosen.
pub(super) fn validate_policy_templates(
    http1: &[WebSocketHeader],
    http2: &[WebSocketHeader],
    extension_required: bool,
) -> Result<(), WebSocketError> {
    validate_templates(http1, extension_required)?;
    validate_http2_templates(http2, extension_required).map(drop)
}

/// Fills the first matching caller slot, or appends the field.
pub(super) fn fill_or_append(headers: &mut Vec<WebSocketHeader>, header: RequestHeader) {
    let slot = headers.iter_mut().find(|template| {
        matches!(template, WebSocketHeader::CallerField { name } if name.eq_ignore_ascii_case(header.name()))
    });
    match slot {
        Some(slot) => {
            let WebSocketHeader::CallerField { name } = slot else {
                return;
            };
            let filled = RequestHeader::new(name.clone(), header.value());
            *slot = WebSocketHeader::Field(if header.is_sensitive() {
                filled.sensitive()
            } else {
                filled
            });
        }
        None => headers.push(WebSocketHeader::Field(header)),
    }
}

/// Converts a profile opening template into builder fields.
///
/// Without `websocket-deflate` the compression placeholder is omitted: no
/// offer can be generated, so it would never emit a field.
pub(super) fn profile_headers(
    fields: &[WebSocketField],
) -> Result<Vec<WebSocketHeader>, WebSocketError> {
    let mut headers = Vec::with_capacity(fields.len());
    for field in fields {
        headers.push(match field {
            WebSocketField::Literal { name, value } => {
                WebSocketHeader::Field(RequestHeader::new(name.clone(), value.as_bytes()))
            }
            WebSocketField::Caller { name } => WebSocketHeader::caller_field(name.clone()),
            WebSocketField::Authority { name } => WebSocketHeader::authority(name.clone()),
            WebSocketField::Key { name } => WebSocketHeader::key(name.clone()),
            WebSocketField::ClientCookies { name } => WebSocketHeader::client_cookies(name.clone()),
            #[cfg(feature = "websocket-deflate")]
            WebSocketField::PerMessageDeflate { name } => {
                WebSocketHeader::permessage_deflate(name.clone())
            }
            #[cfg(not(feature = "websocket-deflate"))]
            WebSocketField::PerMessageDeflate { .. } => continue,
            _ => {
                return Err(WebSocketError::invalid_request(
                    "profile WebSocket template contains an unsupported field kind",
                ));
            }
        });
    }
    Ok(headers)
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
    use phantom_net::request::RequestHeader;

    use phantom_profile::chromium;

    use super::{
        WebSocketHeader, accept_for_key, default_http2_headers, fill_or_append, prepare,
        prepare_http2, profile_headers,
    };

    #[cfg(feature = "cookies")]
    #[test]
    fn jar_cookies_are_read_only_for_an_unoverridden_placeholder() {
        use super::sends_jar_cookie;

        let placeholder = WebSocketHeader::client_cookies("Cookie");
        let literal = WebSocketHeader::Field(RequestHeader::new("cookie", "a=1"));
        let slot = WebSocketHeader::caller_field("Cookie");
        assert!(sends_jar_cookie(std::slice::from_ref(&placeholder)));
        assert!(sends_jar_cookie(&[placeholder.clone(), slot.clone()]));
        assert!(!sends_jar_cookie(&[placeholder, literal.clone()]));
        assert!(!sends_jar_cookie(&[literal]));
        assert!(!sends_jar_cookie(&[slot]));
        assert!(!sends_jar_cookie(&[]));
    }

    #[test]
    fn derives_the_rfc_accept_value() {
        assert_eq!(
            accept_for_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn http2_template_omits_http1_only_fields_and_requires_lowercase()
    -> Result<(), super::WebSocketError> {
        let prepared = prepare_http2(default_http2_headers(), None, None)?;
        assert_eq!(prepared.headers.len(), 1);
        assert_eq!(prepared.headers[0].name(), "sec-websocket-version");

        let uppercase = vec![WebSocketHeader::field(RequestHeader::new(
            "Sec-WebSocket-Version",
            "13",
        ))];
        assert!(prepare_http2(uppercase, None, None).is_err());
        let key = vec![
            WebSocketHeader::field(RequestHeader::new("sec-websocket-version", "13")),
            WebSocketHeader::key("sec-websocket-key"),
        ];
        assert!(prepare_http2(key, None, None).is_err());
        Ok(())
    }

    #[test]
    fn caller_slots_keep_their_position_and_spelling() -> Result<(), super::WebSocketError> {
        let mut headers = vec![
            WebSocketHeader::field(RequestHeader::new("pragma", "no-cache")),
            WebSocketHeader::caller_field("user-agent"),
            WebSocketHeader::caller_field("origin"),
            WebSocketHeader::field(RequestHeader::new("sec-websocket-version", "13")),
        ];
        fill_or_append(&mut headers, RequestHeader::new("User-Agent", "agent"));
        fill_or_append(&mut headers, RequestHeader::new("user-agent", "second"));
        fill_or_append(
            &mut headers,
            RequestHeader::new("x-extra", "last").sensitive(),
        );

        let prepared = prepare_http2(headers, None, None)?;
        let fields = prepared
            .headers
            .iter()
            .map(|header| (header.name(), header.value(), header.is_sensitive()))
            .collect::<Vec<_>>();
        // The unfilled origin slot emits nothing; a repeated name appends.
        assert_eq!(
            fields,
            [
                ("pragma", &b"no-cache"[..], false),
                ("user-agent", &b"agent"[..], false),
                ("sec-websocket-version", &b"13"[..], false),
                ("user-agent", &b"second"[..], false),
                ("x-extra", &b"last"[..], true),
            ]
        );
        Ok(())
    }

    #[test]
    fn http2_caller_slots_must_be_lowercase() {
        let headers = vec![
            WebSocketHeader::field(RequestHeader::new("sec-websocket-version", "13")),
            WebSocketHeader::caller_field("User-Agent"),
        ];
        assert!(prepare_http2(headers, None, None).is_err());
    }

    #[test]
    fn profile_templates_convert_to_valid_openings() -> Result<(), super::WebSocketError> {
        let settings = chromium::v153_websocket();
        let http1 = prepare(
            profile_headers(&settings.http1_fields)?,
            "example.test",
            None,
            None,
        )?;
        let names = http1
            .headers
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "Host",
                "Connection",
                "Pragma",
                "Cache-Control",
                "Upgrade",
                "Sec-WebSocket-Version",
                "Sec-WebSocket-Key",
            ]
        );
        let http2 = prepare_http2(profile_headers(&settings.http2_fields)?, None, None)?;
        let names = http2
            .headers
            .iter()
            .map(RequestHeader::name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["pragma", "cache-control", "sec-websocket-version"]);
        Ok(())
    }
}
