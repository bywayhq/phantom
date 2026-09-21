use std::fmt;

use http::{HeaderMap, header::PROXY_AUTHENTICATE};

use super::{HttpConnectError, http_connect::MAX_CONNECT_HEAD_BYTES};
use crate::request::RequestHeader;

const BASIC_PREFIX: &[u8] = b"Basic ";
const MAX_AUTH_PARAMS_PER_CHALLENGE: usize = 64;

/// Validated credentials for challenge-driven HTTP Basic proxy authentication.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpBasicCredentials {
    authorization: Box<[u8]>,
}

impl HttpBasicCredentials {
    /// Validates and prepares an HTTP Basic credential pair.
    ///
    /// Usernames and passwords are intentionally restricted to ASCII so the
    /// encoded octets never depend on an implicit character-set convention.
    ///
    /// # Errors
    ///
    /// Returns [`HttpConnectError`] when either value is invalid or the
    /// encoded credentials cannot fit within a bounded CONNECT request.
    pub fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, HttpConnectError> {
        let username = username.as_ref().as_bytes();
        let password = password.as_ref().as_bytes();
        if username.is_empty()
            || !username.is_ascii()
            || username.contains(&b':')
            || username.iter().any(u8::is_ascii_control)
        {
            return Err(HttpConnectError::InvalidBasicUsername);
        }
        if !password.is_ascii() || password.iter().any(u8::is_ascii_control) {
            return Err(HttpConnectError::InvalidBasicPassword);
        }

        let source_len = username
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(password.len()))
            .ok_or(HttpConnectError::BasicCredentialsTooLarge)?;
        let encoded_len = source_len
            .checked_add(2)
            .and_then(|length| length.checked_div(3))
            .and_then(|length| length.checked_mul(4))
            .and_then(|length| length.checked_add(BASIC_PREFIX.len()))
            .ok_or(HttpConnectError::BasicCredentialsTooLarge)?;
        if encoded_len > MAX_CONNECT_HEAD_BYTES {
            return Err(HttpConnectError::BasicCredentialsTooLarge);
        }

        let mut source = Vec::with_capacity(source_len);
        source.extend_from_slice(username);
        source.push(b':');
        source.extend_from_slice(password);
        let encoded = btls::base64::encode_block(&source);

        let mut authorization = Vec::with_capacity(BASIC_PREFIX.len() + encoded.len());
        authorization.extend_from_slice(BASIC_PREFIX);
        authorization.extend_from_slice(encoded.as_bytes());
        Ok(Self {
            authorization: authorization.into_boxed_slice(),
        })
    }

    pub(crate) fn authorization(&self) -> &[u8] {
        &self.authorization
    }

    /// Produces the canonical authorization field for a validated Basic challenge.
    ///
    /// The returned field is marked sensitive so its value is redacted from
    /// diagnostics and cannot be indexed by compression-based HTTP protocols.
    #[must_use]
    pub fn proxy_authorization_header(&self) -> RequestHeader {
        RequestHeader::new("Proxy-Authorization", &self.authorization).sensitive()
    }
}

impl fmt::Debug for HttpBasicCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpBasicCredentials([REDACTED])")
    }
}

pub(super) fn has_valid_basic_challenge(
    headers: &[httparse::Header<'_>],
) -> Result<(), HttpConnectError> {
    validate_basic_challenge_values(headers.iter().filter_map(|header| {
        header
            .name
            .eq_ignore_ascii_case("Proxy-Authenticate")
            .then_some(header.value)
    }))
}

/// Validates the `Proxy-Authenticate` fields from an HTTP 407 response.
///
/// At least one syntactically valid Basic challenge with a realm is required.
/// Every `Proxy-Authenticate` field is parsed strictly, including challenges
/// for other schemes. Field values are borrowed and are never included in
/// returned errors or diagnostics.
///
/// # Errors
///
/// Returns [`HttpConnectError`] when the response contains no supported Basic
/// challenge or any authentication challenge is malformed.
pub fn validate_basic_proxy_challenge(headers: &HeaderMap) -> Result<(), HttpConnectError> {
    validate_basic_challenge_values(
        headers
            .get_all(PROXY_AUTHENTICATE)
            .iter()
            .map(http::HeaderValue::as_bytes),
    )
}

fn validate_basic_challenge_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), HttpConnectError> {
    let mut saw_authenticate = false;
    let mut saw_basic = false;
    for value in values {
        saw_authenticate = true;
        parse_challenge_list(value, &mut saw_basic)
            .map_err(|()| HttpConnectError::MalformedAuthenticationChallenge)?;
    }
    if saw_authenticate && saw_basic {
        Ok(())
    } else {
        Err(HttpConnectError::UnsupportedAuthenticationChallenge)
    }
}

fn parse_challenge_list(value: &[u8], saw_basic: &mut bool) -> Result<(), ()> {
    let mut cursor = Cursor::new(value);
    cursor.skip_ows();
    while cursor.consume(b',') {
        cursor.skip_ows();
    }
    if cursor.is_end() {
        return Err(());
    }

    loop {
        let scheme = cursor.token().ok_or(())?;
        let is_basic = scheme.eq_ignore_ascii_case(b"Basic");
        let had_whitespace = cursor.skip_spaces();
        let mut has_realm = false;

        if !cursor.is_end() && cursor.peek() != Some(b',') {
            if !had_whitespace {
                return Err(());
            }
            let start = cursor.position();
            let is_token68 = cursor.token68().is_some_and(|_| {
                cursor.skip_ows();
                cursor.is_end() || cursor.peek() == Some(b',')
            });
            cursor.set_position(start);
            if is_token68 {
                cursor.token68().ok_or(())?;
                cursor.skip_ows();
                if is_basic {
                    return Err(());
                }
            } else {
                parse_auth_params(&mut cursor, is_basic, &mut has_realm)?;
            }
        }

        if is_basic {
            if !has_realm {
                return Err(());
            }
            *saw_basic = true;
        }

        cursor.skip_ows();
        if cursor.is_end() {
            return Ok(());
        }
        if !cursor.consume(b',') {
            return Err(());
        }
        cursor.skip_ows();
        while cursor.consume(b',') {
            cursor.skip_ows();
        }
        if cursor.is_end() {
            return Ok(());
        }
    }
}

fn parse_auth_params(
    cursor: &mut Cursor<'_>,
    is_basic: bool,
    has_realm: &mut bool,
) -> Result<(), ()> {
    let mut names: Vec<&[u8]> = Vec::new();
    loop {
        let name = cursor.token().ok_or(())?;
        if names
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(name))
        {
            return Err(());
        }
        if names.len() == MAX_AUTH_PARAMS_PER_CHALLENGE {
            return Err(());
        }
        names.push(name);
        cursor.skip_ows();
        if !cursor.consume(b'=') {
            return Err(());
        }
        cursor.skip_ows();
        let requires_utf8 = is_basic && name.eq_ignore_ascii_case(b"charset");
        let valid_value = if cursor.peek() == Some(b'"') {
            cursor
                .quoted_string_matches(requires_utf8.then_some(&b"UTF-8"[..]))
                .ok_or(())?
        } else {
            let value = cursor.token().ok_or(())?;
            !requires_utf8 || value.eq_ignore_ascii_case(b"UTF-8")
        };

        if is_basic && name.eq_ignore_ascii_case(b"realm") {
            *has_realm = true;
        }
        if !valid_value {
            return Err(());
        }

        cursor.skip_ows();
        if cursor.is_end() || cursor.peek() != Some(b',') {
            return Ok(());
        }

        let comma = cursor.position();
        cursor.advance();
        cursor.skip_ows();
        if cursor.is_end() || cursor.peek() == Some(b',') {
            cursor.set_position(comma);
            return Ok(());
        }
        let next = cursor.position();
        if cursor.token().is_none() {
            return Err(());
        }
        cursor.skip_ows();
        if cursor.peek() != Some(b'=') {
            cursor.set_position(comma);
            return Ok(());
        }
        cursor.set_position(next);
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    fn is_end(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn advance(&mut self) {
        self.position += 1;
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn skip_ows(&mut self) -> bool {
        let start = self.position;
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.advance();
        }
        self.position != start
    }

    fn skip_spaces(&mut self) -> bool {
        let start = self.position;
        while self.consume(b' ') {}
        self.position != start
    }

    fn token(&mut self) -> Option<&'a [u8]> {
        let start = self.position;
        while self.peek().is_some_and(is_tchar) {
            self.advance();
        }
        (self.position != start).then(|| &self.bytes[start..self.position])
    }

    fn token68(&mut self) -> Option<&'a [u8]> {
        let start = self.position;
        while self.peek().is_some_and(is_token68_base) {
            self.advance();
        }
        if self.position == start {
            return None;
        }
        while self.consume(b'=') {}
        Some(&self.bytes[start..self.position])
    }

    fn quoted_string_matches(&mut self, expected: Option<&[u8]>) -> Option<bool> {
        if !self.consume(b'"') {
            return None;
        }
        let mut matches = true;
        let mut value_length = 0;
        loop {
            let value = match self.peek()? {
                b'"' => {
                    self.advance();
                    return Some(
                        expected.is_none_or(|expected| matches && value_length == expected.len()),
                    );
                }
                b'\\' => {
                    self.advance();
                    let escaped = self.peek()?;
                    if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                        return None;
                    }
                    self.advance();
                    escaped
                }
                b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {
                    let value = self.peek()?;
                    self.advance();
                    value
                }
                _ => return None,
            };
            if let Some(expected) = expected {
                matches &= expected
                    .get(value_length)
                    .is_some_and(|candidate| value.eq_ignore_ascii_case(candidate));
            }
            value_length += 1;
        }
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
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
        )
}

fn is_token68_base(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}
