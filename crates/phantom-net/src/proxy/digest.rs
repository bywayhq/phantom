//! HTTP Digest response calculations and nonce ownership (RFC 7616).

use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};

use btls::hash::{Hasher, MessageDigest};
use zeroize::{Zeroize, Zeroizing};

use super::{HttpConnectError, challenge, http_connect::MAX_CONNECT_HEAD_BYTES};
use crate::request::RequestHeader;

pub(super) mod cache;
mod forward;
pub(super) mod http1;
mod response;
pub use forward::DigestForwardAuthentication;
pub use response::DigestResponseAuthentication;

/// Algorithms a Digest proxy credential may use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum DigestPolicy {
    /// SHA-256 and SHA-512-256, including their session variants.
    #[default]
    Sha2Only,
    /// Also accept legacy MD5 and MD5-sess when the proxy offers them.
    AllowLegacyMd5,
}

/// Credentials for explicit HTTP Digest proxy authentication.
///
/// Usernames and passwords use printable ASCII. The username must be nonempty
/// and contain no colon. They are bounded to 1,024 and 4,096 bytes respectively.
/// Owned credentials and password-equivalent hashes are zeroized on drop.
#[derive(Clone)]
pub struct HttpDigestCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    policy: DigestPolicy,
    cache: cache::DigestCache,
}

impl HttpDigestCredentials {
    /// Prepares credentials with the SHA-2-only policy.
    ///
    /// # Errors
    ///
    /// Returns [`DigestAuthError::InvalidCredentials`] for invalid octets or
    /// lengths. Rejected input is not retained in the error.
    pub fn new(username: &str, password: &str) -> Result<Self, DigestAuthError> {
        let printable = |value: &str| value.bytes().all(|byte| matches!(byte, b' '..=b'~'));
        if username.is_empty()
            || username.len() > 1024
            || username.contains(':')
            || !printable(username)
            || password.len() > 4096
            || !printable(password)
        {
            return Err(DigestAuthError::InvalidCredentials);
        }
        Ok(Self {
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
            policy: DigestPolicy::Sha2Only,
            cache: cache::DigestCache::default(),
        })
    }

    /// Selects the allowed algorithms. Challenge preference remains proxy order.
    #[must_use]
    pub fn with_policy(mut self, policy: DigestPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Returns the configured algorithm policy.
    #[must_use]
    pub const fn policy(&self) -> DigestPolicy {
        self.policy
    }
}

impl PartialEq for HttpDigestCredentials {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && *self.username == *other.username
            && *self.password == *other.password
    }
}

impl Eq for HttpDigestCredentials {}

impl fmt::Debug for HttpDigestCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpDigestCredentials")
            .field("credentials", &"[REDACTED]")
            .field("policy", &self.policy)
            .finish()
    }
}

/// A Digest validation, calculation, or authentication failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum DigestAuthError {
    /// Credentials violate the printable ASCII or size contract.
    InvalidCredentials,
    /// The proxy challenge grammar or required parameters are invalid.
    MalformedChallenge,
    /// No challenge supports the configured algorithms and `qop=auth`.
    UnsupportedChallenge,
    /// The proxy rejected credentials or repeated a stale challenge.
    AuthenticationRejected,
    /// A nonce has used every representable eight-digit nonce count.
    NonceExhausted,
    /// The method or request target is invalid or the header exceeds its bound.
    InvalidRequest,
    /// The proxy's optional response authentication is invalid.
    InvalidResponseAuthentication,
    /// The cryptographic backend could not hash data or generate a client nonce.
    Backend(btls::error::ErrorStack),
}

impl fmt::Display for DigestAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredentials => "invalid HTTP Digest credentials",
            Self::MalformedChallenge => "malformed HTTP Digest challenge",
            Self::UnsupportedChallenge => "unsupported HTTP Digest challenge",
            Self::AuthenticationRejected => "proxy rejected HTTP Digest authentication",
            Self::NonceExhausted => "HTTP Digest nonce count exhausted",
            Self::InvalidRequest => "invalid HTTP Digest request",
            Self::InvalidResponseAuthentication => "invalid HTTP Digest response authentication",
            Self::Backend(_) => "HTTP Digest cryptographic backend failed",
        })
    }
}

impl Error for DigestAuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            _ => None,
        }
    }
}

impl From<btls::error::ErrorStack> for DigestAuthError {
    fn from(error: btls::error::ErrorStack) -> Self {
        Self::Backend(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Sha256,
    Sha256Session,
    Sha512256,
    Sha512256Session,
    Md5,
    Md5Session,
}

impl Algorithm {
    fn parse(value: &[u8], policy: DigestPolicy) -> Option<Self> {
        [
            Self::Sha256,
            Self::Sha256Session,
            Self::Sha512256,
            Self::Sha512256Session,
            Self::Md5,
            Self::Md5Session,
        ]
        .into_iter()
        .find(|algorithm| {
            value.eq_ignore_ascii_case(algorithm.name().as_bytes())
                && (policy == DigestPolicy::AllowLegacyMd5
                    || !matches!(algorithm, Self::Md5 | Self::Md5Session))
        })
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha256Session => "SHA-256-sess",
            Self::Sha512256 => "SHA-512-256",
            Self::Sha512256Session => "SHA-512-256-sess",
            Self::Md5 => "MD5",
            Self::Md5Session => "MD5-sess",
        }
    }

    const fn session(self) -> bool {
        matches!(
            self,
            Self::Sha256Session | Self::Sha512256Session | Self::Md5Session
        )
    }

    fn digest(self) -> MessageDigest {
        match self {
            Self::Sha256 | Self::Sha256Session => MessageDigest::sha256(),
            Self::Sha512256 | Self::Sha512256Session => MessageDigest::sha512_256(),
            Self::Md5 | Self::Md5Session => MessageDigest::md5(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct DigestChallenge {
    realm: Box<[u8]>,
    nonce: Box<[u8]>,
    opaque: Option<Box<[u8]>>,
    algorithm: Algorithm,
    userhash: bool,
    pub(super) stale: bool,
}

impl DigestChallenge {
    pub(super) fn select<'a>(
        values: impl IntoIterator<Item = &'a [u8]>,
        credentials: &HttpDigestCredentials,
    ) -> Result<Self, DigestAuthError> {
        let challenges = challenge::parse(values).map_err(map_challenge_error)?;
        let mut selected = None;
        for challenge in challenges {
            if !challenge.scheme.eq_ignore_ascii_case(b"Digest") {
                continue;
            }
            let realm = challenge
                .parameter(b"realm")
                .ok_or(DigestAuthError::MalformedChallenge)?;
            let nonce = challenge
                .parameter(b"nonce")
                .filter(|value| !value.is_empty())
                .ok_or(DigestAuthError::MalformedChallenge)?;
            // RFC 7616 section 3.3: omitted algorithm means MD5, never SHA-2.
            let algorithm = Algorithm::parse(
                challenge.parameter(b"algorithm").unwrap_or(b"MD5"),
                credentials.policy,
            );
            if challenge
                .parameter(b"charset")
                .is_some_and(|value| !value.eq_ignore_ascii_case(b"UTF-8"))
            {
                return Err(DigestAuthError::MalformedChallenge);
            }
            let userhash = boolean_parameter(&challenge, b"userhash")?;
            let stale = boolean_parameter(&challenge, b"stale")?;
            let auth = challenge.parameter(b"qop").is_some_and(|qop| {
                qop.split(|byte| *byte == b',')
                    .any(|option| option.trim_ascii().eq_ignore_ascii_case(b"auth"))
            });
            if selected.is_none()
                && auth
                && let Some(algorithm) = algorithm
            {
                selected = Some(Self {
                    realm: realm.into(),
                    nonce: nonce.into(),
                    opaque: challenge.parameter(b"opaque").map(Into::into),
                    algorithm,
                    userhash,
                    stale,
                });
            }
        }
        selected.ok_or(DigestAuthError::UnsupportedChallenge)
    }
}

fn boolean_parameter(
    challenge: &challenge::Challenge<'_>,
    name: &[u8],
) -> Result<bool, DigestAuthError> {
    match challenge.parameter(name) {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case(b"false") => Ok(false),
        Some(value) if value.eq_ignore_ascii_case(b"true") => Ok(true),
        _ => Err(DigestAuthError::MalformedChallenge),
    }
}

fn map_challenge_error(_: HttpConnectError) -> DigestAuthError {
    DigestAuthError::MalformedChallenge
}

/// One challenge's count and client nonce. Clones of a cached session must
/// share this object; cancellation consumes a reserved count and never restores it.
pub(super) struct DigestSession {
    challenge: DigestChallenge,
    username: Zeroizing<String>,
    a1: Zeroizing<String>,
    cnonce: String,
    count: AtomicU32,
}

pub(super) struct DigestRequest {
    pub(super) header: RequestHeader,
    expected_response: Zeroizing<String>,
    cnonce: String,
    nonce_count: String,
}

impl DigestSession {
    pub(super) fn new(
        challenge: DigestChallenge,
        credentials: &HttpDigestCredentials,
    ) -> Result<Self, DigestAuthError> {
        let mut random = [0_u8; 16];
        btls::rand::rand_bytes(&mut random)?;
        Self::with_cnonce(challenge, credentials, hex(&random))
    }

    fn with_cnonce(
        challenge: DigestChallenge,
        credentials: &HttpDigestCredentials,
        cnonce: String,
    ) -> Result<Self, DigestAuthError> {
        let algorithm = challenge.algorithm;
        let mut a1 = hash_parts(
            algorithm,
            &[
                credentials.username.as_bytes(),
                &challenge.realm,
                credentials.password.as_bytes(),
            ],
        )?;
        if algorithm.session() {
            a1 = hash_parts(
                algorithm,
                &[a1.as_bytes(), &challenge.nonce, cnonce.as_bytes()],
            )?;
        }
        Ok(Self {
            challenge,
            username: credentials.username.clone(),
            a1,
            cnonce,
            count: AtomicU32::new(0),
        })
    }

    pub(super) fn request(
        &self,
        method: &http::Method,
        target: &str,
    ) -> Result<DigestRequest, DigestAuthError> {
        if target.is_empty()
            || target.len() > MAX_CONNECT_HEAD_BYTES
            || target.bytes().any(|byte| !matches!(byte, b'!'..=b'~'))
        {
            return Err(DigestAuthError::InvalidRequest);
        }
        let mut previous = self.count.load(Ordering::Relaxed);
        let reserved = loop {
            let next = previous
                .checked_add(1)
                .ok_or(DigestAuthError::NonceExhausted)?;
            match self.count.compare_exchange_weak(
                previous,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break next,
                Err(current) => previous = current,
            }
        };
        let nonce_count = format!("{reserved:08x}");
        let response =
            self.response(method.as_str().as_bytes(), target.as_bytes(), &nonce_count)?;
        let expected_response = self.response(b"", target.as_bytes(), &nonce_count)?;
        let username = if self.challenge.userhash {
            hash_parts(
                self.challenge.algorithm,
                &[self.username.as_bytes(), &self.challenge.realm],
            )?
        } else {
            self.username.clone()
        };
        let mut value = Zeroizing::new(b"Digest ".to_vec());
        for (name, bytes) in [
            ("username", username.as_bytes()),
            ("realm", &self.challenge.realm),
            ("nonce", &self.challenge.nonce),
            ("uri", target.as_bytes()),
            ("response", response.as_bytes()),
            ("cnonce", self.cnonce.as_bytes()),
        ] {
            quoted_parameter(&mut value, name, bytes)?;
        }
        if let Some(opaque) = &self.challenge.opaque {
            quoted_parameter(&mut value, "opaque", opaque)?;
        }
        let suffix = format!(
            "algorithm={}, qop=auth, nc={nonce_count}{}",
            self.challenge.algorithm.name(),
            if self.challenge.userhash {
                ", userhash=true"
            } else {
                ""
            }
        );
        extend(&mut value, suffix.as_bytes())?;
        Ok(DigestRequest {
            header: RequestHeader::new("Proxy-Authorization", &*value).sensitive(),
            expected_response,
            cnonce: self.cnonce.clone(),
            nonce_count,
        })
    }

    fn response(
        &self,
        method: &[u8],
        target: &[u8],
        nc: &str,
    ) -> Result<Zeroizing<String>, DigestAuthError> {
        let a2 = hash_parts(self.challenge.algorithm, &[method, target])?;
        hash_parts(
            self.challenge.algorithm,
            &[
                self.a1.as_bytes(),
                &self.challenge.nonce,
                nc.as_bytes(),
                self.cnonce.as_bytes(),
                b"auth",
                a2.as_bytes(),
            ],
        )
    }
}

impl DigestRequest {
    /// Validate an optional proxy proof before accepting a tunnel or storing a
    /// replacement nonce. Digest does not substitute for proxy TLS authentication.
    pub(super) fn verify<'a>(
        &self,
        values: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Option<Box<[u8]>>, DigestAuthError> {
        let parameters = challenge::information(values)
            .map_err(|_| DigestAuthError::InvalidResponseAuthentication)?;
        if parameters.is_empty() {
            return Ok(None);
        }
        let get = |name: &[u8]| {
            parameters
                .iter()
                .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
                .map(|parameter| parameter.value.as_ref())
        };
        if let Some(proof) = get(b"rspauth") {
            if !equal_hex(proof, self.expected_response.as_bytes())
                || get(b"qop").is_none_or(|value| !value.eq_ignore_ascii_case(b"auth"))
                || get(b"cnonce") != Some(self.cnonce.as_bytes())
                || get(b"nc")
                    .is_none_or(|value| !value.eq_ignore_ascii_case(self.nonce_count.as_bytes()))
            {
                return Err(DigestAuthError::InvalidResponseAuthentication);
            }
        } else if get(b"qop").is_some() || get(b"cnonce").is_some() || get(b"nc").is_some() {
            return Err(DigestAuthError::InvalidResponseAuthentication);
        }
        match get(b"nextnonce") {
            Some([]) => Err(DigestAuthError::InvalidResponseAuthentication),
            nonce => Ok(nonce.map(Into::into)),
        }
    }
}

fn hash_parts(algorithm: Algorithm, parts: &[&[u8]]) -> Result<Zeroizing<String>, DigestAuthError> {
    let mut hash = Hasher::new(algorithm.digest())?;
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            hash.update(b":")?;
        }
        hash.update(part)?;
    }
    let mut digest = hash.finish()?;
    let encoded = Zeroizing::new(hex(&digest));
    digest[..].zeroize();
    Ok(encoded)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn equal_hex(actual: &[u8], expected: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut difference = 0;
    for (actual, expected) in actual.iter().zip(expected) {
        difference |= actual.to_ascii_lowercase() ^ expected;
    }
    difference == 0
}

fn quoted_parameter(value: &mut Vec<u8>, name: &str, bytes: &[u8]) -> Result<(), DigestAuthError> {
    extend(value, name.as_bytes())?;
    extend(value, b"=\"")?;
    for byte in bytes {
        if !matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff) {
            return Err(DigestAuthError::MalformedChallenge);
        }
        if matches!(byte, b'"' | b'\\') {
            extend(value, b"\\")?;
        }
        extend(value, &[*byte])?;
    }
    extend(value, b"\", ")
}

fn extend(value: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DigestAuthError> {
    if value
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > MAX_CONNECT_HEAD_BYTES)
    {
        return Err(DigestAuthError::InvalidRequest);
    }
    value.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests;
