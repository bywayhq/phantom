use std::{error::Error as StdError, fmt};

const BASIC_PREFIX: &[u8] = b"Basic ";
const BEARER_PREFIX: &[u8] = b"Bearer ";
pub(crate) const MAX_AUTHORIZATION_VALUE_BYTES: usize = 32 * 1024;

/// The reason an authorization value could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvalidAuthorizationKind {
    /// The Basic username is empty, contains a colon, or is not printable ASCII.
    BasicUsername,
    /// The Basic password contains non-ASCII or control characters.
    BasicPassword,
    /// The Bearer token is empty or does not match the token syntax.
    BearerToken,
    /// The complete authorization value exceeds 32 KiB.
    TooLarge,
}

/// An invalid authorization value, without any retained credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAuthorization {
    kind: InvalidAuthorizationKind,
}

impl InvalidAuthorization {
    pub(crate) const fn new(kind: InvalidAuthorizationKind) -> Self {
        Self { kind }
    }

    /// Returns the stable validation category.
    #[must_use]
    pub const fn kind(self) -> InvalidAuthorizationKind {
        self.kind
    }

    pub(crate) fn basic(error: BasicAuthorizationError) -> Self {
        Self::new(match error {
            BasicAuthorizationError::Username => InvalidAuthorizationKind::BasicUsername,
            BasicAuthorizationError::Password => InvalidAuthorizationKind::BasicPassword,
            BasicAuthorizationError::TooLarge => InvalidAuthorizationKind::TooLarge,
        })
    }
}

impl fmt::Display for InvalidAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            InvalidAuthorizationKind::BasicUsername => "invalid Basic authorization username",
            InvalidAuthorizationKind::BasicPassword => "invalid Basic authorization password",
            InvalidAuthorizationKind::BearerToken => "invalid Bearer authorization token",
            InvalidAuthorizationKind::TooLarge => "authorization value exceeds 32 KiB",
        })
    }
}

impl StdError for InvalidAuthorization {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BasicAuthorizationError {
    Username,
    Password,
    TooLarge,
}

pub(crate) fn basic_value(
    username: &str,
    password: &str,
    maximum: usize,
) -> Result<Box<[u8]>, BasicAuthorizationError> {
    let username = username.as_bytes();
    let password = password.as_bytes();
    if username.is_empty()
        || !username.is_ascii()
        || username.contains(&b':')
        || username.iter().any(u8::is_ascii_control)
    {
        return Err(BasicAuthorizationError::Username);
    }
    if !password.is_ascii() || password.iter().any(u8::is_ascii_control) {
        return Err(BasicAuthorizationError::Password);
    }

    let source_len = username
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(password.len()))
        .ok_or(BasicAuthorizationError::TooLarge)?;
    let encoded_len = basic_encoded_length(source_len).ok_or(BasicAuthorizationError::TooLarge)?;
    if encoded_len > maximum {
        return Err(BasicAuthorizationError::TooLarge);
    }

    let mut source = Vec::with_capacity(source_len);
    source.extend_from_slice(username);
    source.push(b':');
    source.extend_from_slice(password);
    let encoded = btls::base64::encode_block(&source);

    let mut authorization = Vec::with_capacity(encoded_len);
    authorization.extend_from_slice(BASIC_PREFIX);
    authorization.extend_from_slice(encoded.as_bytes());
    Ok(authorization.into_boxed_slice())
}

fn basic_encoded_length(source_len: usize) -> Option<usize> {
    source_len
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .and_then(|length| length.checked_add(BASIC_PREFIX.len()))
}

pub(crate) fn bearer_value(token: &str) -> Result<Box<[u8]>, InvalidAuthorization> {
    let bytes = token.as_bytes();
    let base_len = bytes
        .iter()
        .take_while(|byte| is_token68_base(**byte))
        .count();
    if base_len == 0 || !bytes[base_len..].iter().all(|byte| *byte == b'=') {
        return Err(InvalidAuthorization::new(
            InvalidAuthorizationKind::BearerToken,
        ));
    }
    let length = BEARER_PREFIX
        .len()
        .checked_add(bytes.len())
        .filter(|length| *length <= MAX_AUTHORIZATION_VALUE_BYTES)
        .ok_or_else(|| InvalidAuthorization::new(InvalidAuthorizationKind::TooLarge))?;
    let mut value = Vec::with_capacity(length);
    value.extend_from_slice(BEARER_PREFIX);
    value.extend_from_slice(bytes);
    Ok(value.into_boxed_slice())
}

pub(crate) fn is_token68_base(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

#[cfg(test)]
mod tests {
    use super::{
        BasicAuthorizationError, InvalidAuthorizationKind, MAX_AUTHORIZATION_VALUE_BYTES,
        basic_encoded_length, basic_value, bearer_value,
    };
    use crate::request::RequestHeader;

    fn credential_canary() -> Result<String, std::time::SystemTimeError> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        Ok(format!("{:032x}", elapsed.as_nanos()))
    }

    #[test]
    fn basic_encoder_keeps_the_separator_and_round_trips_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let username = credential_canary()?;
        let password = credential_canary()?;
        let encoded =
            basic_value(&username, &password, 100).map_err(|error| format!("{error:?}"))?;
        assert_eq!(&encoded[..6], b"Basic ");
        let decoded = btls::base64::decode_block(std::str::from_utf8(&encoded[6..])?)?;
        assert_eq!(decoded, format!("{username}:{password}").as_bytes());
        Ok(())
    }

    #[test]
    fn basic_value_limits_are_inclusive_and_checked_before_encoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let password = credential_canary()?;
        assert_eq!(password.len(), 32);
        assert_eq!(basic_encoded_length(3), Some(10));
        assert_eq!(basic_encoded_length(usize::MAX), None);
        assert!(basic_value("Aladdin", &password, 62).is_ok());
        assert_eq!(
            basic_value("Aladdin", &password, 61),
            Err(BasicAuthorizationError::TooLarge)
        );
        assert_eq!(
            basic_value(
                "u",
                &password.repeat(MAX_AUTHORIZATION_VALUE_BYTES / password.len()),
                MAX_AUTHORIZATION_VALUE_BYTES
            ),
            Err(BasicAuthorizationError::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn basic_constructors_reject_invalid_credentials_without_retaining_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let username = credential_canary()?;
        let password = credential_canary()?;
        let mut empty = password.clone();
        empty.clear();
        for (username, password, kind) in [
            (
                empty.clone(),
                password.clone(),
                InvalidAuthorizationKind::BasicUsername,
            ),
            (
                format!("{username}:suffix"),
                password.clone(),
                InvalidAuthorizationKind::BasicUsername,
            ),
            (
                format!("{username}\r\n"),
                password.clone(),
                InvalidAuthorizationKind::BasicUsername,
            ),
            (
                format!("{username}é"),
                password.clone(),
                InvalidAuthorizationKind::BasicUsername,
            ),
            (
                username.clone(),
                format!("{password}\n"),
                InvalidAuthorizationKind::BasicPassword,
            ),
            (
                username.clone(),
                format!("{password}\0"),
                InvalidAuthorizationKind::BasicPassword,
            ),
            (
                username.clone(),
                format!("{password}\u{7f}"),
                InvalidAuthorizationKind::BasicPassword,
            ),
            (
                username,
                format!("{password}é"),
                InvalidAuthorizationKind::BasicPassword,
            ),
        ] {
            let Err(error) = RequestHeader::basic_authorization(&username, &password) else {
                panic!("invalid credentials accepted");
            };
            assert_eq!(error.kind(), kind);
            let diagnostic = format!("{error:?} {error}");
            if !username.is_empty() {
                assert!(!diagnostic.contains(&username));
            }
            if !password.is_empty() {
                assert!(!diagnostic.contains(&password));
            }
        }
        Ok(())
    }

    #[test]
    fn bearer_validation_keeps_only_trailing_padding() {
        for token in [
            "",
            "=",
            "a=b",
            "a= b",
            "a b",
            "a\r\nX: value",
            "a\t",
            "a\0",
            "naïve",
            "\"token\"",
        ] {
            let Err(error) = bearer_value(token) else {
                panic!("invalid token accepted");
            };
            assert_eq!(error.kind(), InvalidAuthorizationKind::BearerToken);
            assert!(!format!("{error:?} {error}").contains(token) || token.is_empty());
        }
        for token in ["a", "a=", "a===", "AZaz09-._~+/"] {
            assert!(bearer_value(token).is_ok());
        }
        let maximum = MAX_AUTHORIZATION_VALUE_BYTES - b"Bearer ".len();
        assert!(bearer_value(&"a".repeat(maximum)).is_ok());
        assert_eq!(
            bearer_value(&"a".repeat(maximum + 1))
                .err()
                .map(|error| error.kind()),
            Some(InvalidAuthorizationKind::TooLarge)
        );
    }

    #[test]
    fn authorization_headers_are_lowercase_sensitive_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let canary = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let basic = RequestHeader::basic_authorization("runtime-user", &canary)?;
        let bearer = RequestHeader::bearer_authorization(&canary)?;
        let expected_basic = basic_value("runtime-user", &canary, MAX_AUTHORIZATION_VALUE_BYTES)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(basic.value(), &*expected_basic);
        assert_eq!(bearer.value(), format!("Bearer {canary}").as_bytes());
        for header in [basic, bearer] {
            assert_eq!(header.name(), "authorization");
            assert!(header.is_sensitive());
            let debug = format!("{header:?}");
            assert!(!debug.contains(&canary));
            assert!(!debug.contains("runtime-user"));
            assert!(debug.contains("<redacted>"));
        }
        Ok(())
    }
}
