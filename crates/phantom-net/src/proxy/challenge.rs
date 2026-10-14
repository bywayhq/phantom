//! Bounded HTTP authentication challenge grammar (RFC 9110 section 11.6.1).

use std::borrow::Cow;

use crate::authorization::is_token68_base;

use super::{HttpConnectError, http_connect::MAX_CONNECT_HEAD_BYTES};

const MAX_CHALLENGES: usize = 32;
const MAX_PARAMETERS: usize = 64;
const MAX_EMPTY_ELEMENTS: usize = 64;

pub(super) struct Challenge<'a> {
    pub(super) scheme: &'a [u8],
    pub(super) token68: Option<&'a [u8]>,
    pub(super) parameters: Vec<Parameter<'a>>,
}

pub(super) struct Parameter<'a> {
    pub(super) name: &'a [u8],
    pub(super) value: Cow<'a, [u8]>,
}

impl Challenge<'_> {
    pub(super) fn parameter(&self, name: &[u8]) -> Option<&[u8]> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
            .map(|parameter| parameter.value.as_ref())
    }
}

/// Every field is parsed, even after finding a supported challenge. This
/// prevents a malformed trailing challenge from changing scheme selection.
pub(super) fn parse<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<Challenge<'a>>, HttpConnectError> {
    let mut bytes = 0_usize;
    let mut challenges = Vec::new();
    for value in values {
        bytes = bytes
            .checked_add(value.len())
            .filter(|length| *length <= MAX_CONNECT_HEAD_BYTES)
            .ok_or(HttpConnectError::MalformedAuthenticationChallenge)?;
        let mut cursor = Cursor::new(value);
        cursor.separators(true)?;
        if cursor.is_end() {
            continue;
        }
        while !cursor.is_end() {
            if challenges.len() == MAX_CHALLENGES {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            let scheme = cursor.token()?;
            let spaced = cursor.spaces();
            let mut challenge = Challenge {
                scheme,
                token68: None,
                parameters: Vec::new(),
            };
            if spaced && cursor.peek() == Some(b',') && cursor.leading_parameters()? {
                challenge.parameters = cursor.parameters()?;
            } else if !cursor.is_end() && cursor.peek() != Some(b',') {
                if !spaced {
                    return Err(HttpConnectError::MalformedAuthenticationChallenge);
                }
                let start = cursor.position;
                if let Some(token) = cursor.token68() {
                    cursor.ows();
                    if cursor.is_end() || cursor.peek() == Some(b',') {
                        challenge.token68 = Some(token);
                    }
                }
                if challenge.token68.is_none() {
                    cursor.position = start;
                    challenge.parameters = cursor.parameters()?;
                }
            }
            challenges.push(challenge);
            cursor.ows();
            if !cursor.is_end() && !cursor.consume(b',') {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            cursor.separators(true)?;
        }
    }
    Ok(challenges)
}

/// Authentication-Info is an auth-param list, with no scheme or token68.
pub(super) fn information<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<Parameter<'a>>, HttpConnectError> {
    let mut bytes = 0_usize;
    let mut parameters: Vec<Parameter<'a>> = Vec::new();
    for value in values {
        bytes = bytes
            .checked_add(value.len())
            .filter(|length| *length <= MAX_CONNECT_HEAD_BYTES)
            .ok_or(HttpConnectError::MalformedAuthenticationChallenge)?;
        let mut cursor = Cursor::new(value);
        cursor.separators(true)?;
        if cursor.is_end() {
            continue;
        }
        let next = cursor.parameters()?;
        cursor.ows();
        if !cursor.is_end() {
            return Err(HttpConnectError::MalformedAuthenticationChallenge);
        }
        for parameter in next {
            if parameters.len() == MAX_PARAMETERS
                || parameters
                    .iter()
                    .any(|existing| existing.name.eq_ignore_ascii_case(parameter.name))
            {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            parameters.push(parameter);
        }
    }
    Ok(parameters)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    empty_elements: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            empty_elements: 0,
        }
    }

    fn is_end(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.position += 1;
        }
    }

    fn spaces(&mut self) -> bool {
        let start = self.position;
        while self.consume(b' ') {}
        self.position != start
    }

    fn separators(&mut self, first_is_empty: bool) -> Result<(), HttpConnectError> {
        self.ows();
        let mut first = true;
        while self.consume(b',') {
            if first_is_empty || !first {
                self.empty_elements += 1;
                if self.empty_elements > MAX_EMPTY_ELEMENTS {
                    return Err(HttpConnectError::MalformedAuthenticationChallenge);
                }
            }
            first = false;
            self.ows();
        }
        Ok(())
    }

    fn token(&mut self) -> Result<&'a [u8], HttpConnectError> {
        let start = self.position;
        while self.peek().is_some_and(is_tchar) {
            self.position += 1;
        }
        if self.position == start {
            return Err(HttpConnectError::MalformedAuthenticationChallenge);
        }
        Ok(&self.bytes[start..self.position])
    }

    /// Commas after a spaced scheme can begin its auth-param list or separate
    /// an empty challenge from the next scheme. The equals sign decides.
    fn leading_parameters(&mut self) -> Result<bool, HttpConnectError> {
        let mut ahead = Self {
            bytes: self.bytes,
            position: self.position,
            empty_elements: self.empty_elements,
        };
        ahead.separators(false)?;
        if ahead.is_end() {
            return Ok(false);
        }
        ahead.token()?;
        ahead.ows();
        if ahead.peek() != Some(b'=') {
            return Ok(false);
        }
        self.separators(true)?;
        Ok(true)
    }

    fn token68(&mut self) -> Option<&'a [u8]> {
        let start = self.position;
        while self.peek().is_some_and(is_token68_base) {
            self.position += 1;
        }
        if self.position == start {
            return None;
        }
        while self.consume(b'=') {}
        Some(&self.bytes[start..self.position])
    }

    fn parameters(&mut self) -> Result<Vec<Parameter<'a>>, HttpConnectError> {
        let mut parameters: Vec<Parameter<'a>> = Vec::new();
        loop {
            let name = self.token()?;
            if parameters.len() == MAX_PARAMETERS
                || parameters
                    .iter()
                    .any(|parameter| parameter.name.eq_ignore_ascii_case(name))
            {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            self.ows();
            if !self.consume(b'=') {
                return Err(HttpConnectError::MalformedAuthenticationChallenge);
            }
            self.ows();
            let value = if self.peek() == Some(b'"') {
                Cow::Owned(self.quoted()?)
            } else {
                Cow::Borrowed(self.token()?)
            };
            parameters.push(Parameter { name, value });
            self.ows();
            if self.peek() != Some(b',') {
                return Ok(parameters);
            }
            let comma = self.position;
            let empty_elements = self.empty_elements;
            self.separators(false)?;
            if self.is_end() {
                return Ok(parameters);
            }
            let next = self.position;
            self.token()?;
            self.ows();
            if self.peek() != Some(b'=') {
                self.position = comma;
                self.empty_elements = empty_elements;
                return Ok(parameters);
            }
            self.position = next;
        }
    }

    fn quoted(&mut self) -> Result<Vec<u8>, HttpConnectError> {
        self.position += 1;
        let mut value = Vec::new();
        loop {
            let byte = self
                .peek()
                .ok_or(HttpConnectError::MalformedAuthenticationChallenge)?;
            self.position += 1;
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    let escaped = self
                        .peek()
                        .ok_or(HttpConnectError::MalformedAuthenticationChallenge)?;
                    self.position += 1;
                    if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                        return Err(HttpConnectError::MalformedAuthenticationChallenge);
                    }
                    value.push(escaped);
                }
                b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {
                    value.push(byte);
                }
                _ => return Err(HttpConnectError::MalformedAuthenticationChallenge),
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{
        HttpDigestCredentials, digest::DigestChallenge, validate_basic_proxy_challenge,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn basic_and_digest_accept_bounded_empty_list_members() -> TestResult {
        let value = ", , Basic , ,realm=proxy,,charset=UTF-8, , Digest ,,realm=proxy,,nonce=x,qop=auth,algorithm=SHA-256, ,";
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::PROXY_AUTHENTICATE, value.parse()?);
        validate_basic_proxy_challenge(&headers)?;
        DigestChallenge::select(
            [value.as_bytes()],
            &HttpDigestCredentials::new("user", "pass")?,
        )?;
        let challenges = parse([value.as_bytes()])?;
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].parameter(b"charset"), Some(&b"UTF-8"[..]));
        assert_eq!(challenges[1].parameter(b"nonce"), Some(&b"x"[..]));
        Ok(())
    }

    #[test]
    fn an_empty_challenge_keeps_the_following_scheme_distinct() -> TestResult {
        let challenges = parse([&b"Negotiate , , Basic realm=proxy"[..]])?;
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, b"Negotiate");
        assert!(challenges[0].parameters.is_empty());
        assert_eq!(challenges[1].scheme, b"Basic");
        assert_eq!(challenges[1].parameter(b"realm"), Some(&b"proxy"[..]));
        Ok(())
    }

    #[test]
    fn authentication_information_accepts_empty_members_but_keeps_duplicates_invalid() -> TestResult
    {
        assert!(information([&b""[..], &b" \t "[..], &b",, "[..]])?.is_empty());
        let parameters = information([&b",,nextnonce=\"new\",,qop=auth, ,"[..]])?;
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0].value.as_ref(), b"new");
        assert!(information([&b"qop=auth,,QOP=auth,"[..]]).is_err());
        assert!(parse([&b"Digest realm=proxy,,REALM=other"[..]]).is_err());
        Ok(())
    }

    #[test]
    fn empty_members_are_bounded_independently_of_nonempty_parameters() -> TestResult {
        let allowed = format!("{}Basic realm=proxy", ",".repeat(MAX_EMPTY_ELEMENTS));
        assert_eq!(parse([allowed.as_bytes()])?.len(), 1);
        let excessive = format!(",{allowed}");
        assert!(parse([excessive.as_bytes()]).is_err());
        let allowed_information = format!("{}nextnonce=x", ",".repeat(MAX_EMPTY_ELEMENTS));
        assert_eq!(information([allowed_information.as_bytes()])?.len(), 1);
        let excessive_information = format!(",{allowed_information}");
        assert!(information([excessive_information.as_bytes()]).is_err());
        let parameters = (0..MAX_PARAMETERS)
            .map(|index| format!("p{index}=x"))
            .collect::<Vec<_>>()
            .join(",");
        let fields = format!("Digest {parameters}, Basic {parameters}");
        assert_eq!(parse([fields.as_bytes()])?.len(), 2);
        Ok(())
    }
}
