use std::{error::Error as StdError, fmt};

use phantom_net::proxy::Socks5Auth;

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

/// Ownership of SOCKS5 target DNS resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks5DnsMode {
    /// Resolve domain targets on the client before proxy negotiation.
    Local,
    /// Send domain targets to the proxy for resolution.
    Remote,
}

/// SOCKS5 proxy configuration with explicit origin DNS ownership.
///
/// `socks5://` selects local DNS and `socks5h://` selects proxy-owned DNS.
/// Credentials in the URI, paths, and queries are rejected.
#[derive(Clone, Eq, PartialEq)]
pub struct Socks5Proxy {
    endpoint: Endpoint,
    dns_mode: Socks5DnsMode,
    credentials: Option<Socks5Credentials>,
}

#[derive(Clone, Eq, PartialEq)]
struct Socks5Credentials {
    username: Box<str>,
    password: Box<str>,
}

impl Socks5Proxy {
    /// Parses a SOCKS5 proxy URI with explicit DNS ownership.
    ///
    /// Port 1080 is used when omitted. Unicode hostnames are normalized to
    /// their canonical ASCII form.
    ///
    /// # Errors
    ///
    /// Returns [`Socks5ProxyConfigError`] when the URI is malformed or uses an
    /// unsupported shape.
    pub fn new(uri: &str) -> Result<Self, Socks5ProxyConfigError> {
        let uri = parse_absolute_uri(uri).map_err(|error| match error {
            ParseUriError::Syntax(error) => Socks5ProxyConfigError::invalid_uri(error),
            ParseUriError::Authority(error) => Socks5ProxyConfigError::authority(error.message()),
        })?;
        let dns_mode = match uri.scheme_str() {
            Some("socks5") => Socks5DnsMode::Local,
            Some("socks5h") => Socks5DnsMode::Remote,
            _ => return Err(Socks5ProxyConfigError::unsupported_scheme()),
        };
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(Socks5ProxyConfigError::invalid_authority)?;
        if !matches!(
            uri.path_and_query().map(|value| value.as_str()),
            None | Some("/")
        ) {
            return Err(Socks5ProxyConfigError::unexpected_path());
        }
        let endpoint = Endpoint::new(authority, 1080)
            .map_err(|error| Socks5ProxyConfigError::authority(error.message()))?;
        Ok(Self {
            endpoint,
            dns_mode,
            credentials: None,
        })
    }

    /// Configures RFC 1929 username/password authentication.
    ///
    /// The username and password are copied into the route configuration. Each
    /// value must contain between 1 and 255 bytes, inclusive. SOCKS5 method
    /// negotiation offers both no-authentication and username/password; the
    /// proxy selects the method.
    ///
    /// # Errors
    ///
    /// Returns [`Socks5ProxyConfigError`] when either value is empty or exceeds
    /// the RFC 1929 one-octet length limit.
    pub fn with_username_password(
        mut self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, Socks5ProxyConfigError> {
        let username = username.as_ref();
        let password = password.as_ref();
        if !is_valid_credential(username) || !is_valid_credential(password) {
            return Err(Socks5ProxyConfigError::invalid_credentials());
        }
        self.credentials = Some(Socks5Credentials {
            username: username.into(),
            password: password.into(),
        });
        Ok(self)
    }

    pub(crate) fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub(crate) fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub(crate) fn auth(&self) -> Socks5Auth<'_> {
        self.credentials
            .as_ref()
            .map_or(Socks5Auth::None, |credentials| {
                Socks5Auth::UsernamePassword {
                    username: &credentials.username,
                    password: &credentials.password,
                }
            })
    }

    /// Returns where target domain names are resolved.
    #[must_use]
    pub const fn dns_mode(&self) -> Socks5DnsMode {
        self.dns_mode
    }
}

impl fmt::Debug for Socks5Proxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Socks5Proxy")
            .field("authority", self.endpoint.authority())
            .field("dns", &self.dns_mode)
            .field("credentials_configured", &self.credentials.is_some())
            .finish()
    }
}

fn is_valid_credential(value: &str) -> bool {
    (1..=usize::from(u8::MAX)).contains(&value.len())
}

/// Stable category of SOCKS5 proxy-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks5ProxyConfigErrorKind {
    /// The proxy URI is syntactically invalid.
    InvalidUri,
    /// The proxy URI scheme is neither `socks5` nor `socks5h`.
    UnsupportedScheme,
    /// The proxy URI authority is missing or invalid.
    InvalidAuthority,
    /// The proxy URI contains a path or query.
    UnexpectedPath,
    /// A username or password does not fit the RFC 1929 wire format.
    InvalidCredentials,
}

/// Error returned while constructing a [`Socks5Proxy`].
#[derive(Debug)]
pub struct Socks5ProxyConfigError {
    kind: Socks5ProxyConfigErrorKind,
    message: &'static str,
    source: Option<http::uri::InvalidUri>,
}

impl Socks5ProxyConfigError {
    fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self {
            kind: Socks5ProxyConfigErrorKind::InvalidUri,
            message: "invalid SOCKS5 proxy URI",
            source: Some(source),
        }
    }

    fn unsupported_scheme() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::UnsupportedScheme,
            "SOCKS5 proxy URI must use the socks5 or socks5h scheme",
        )
    }

    fn invalid_authority() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::InvalidAuthority,
            "SOCKS5 proxy URI must include an authority",
        )
    }

    fn authority(message: &'static str) -> Self {
        Self::without_source(Socks5ProxyConfigErrorKind::InvalidAuthority, message)
    }

    fn unexpected_path() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::UnexpectedPath,
            "SOCKS5 proxy URI must not contain a path or query",
        )
    }

    fn invalid_credentials() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::InvalidCredentials,
            "SOCKS5 username and password must each contain 1 to 255 bytes",
        )
    }

    fn without_source(kind: Socks5ProxyConfigErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Socks5ProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for Socks5ProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for Socks5ProxyConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use phantom_net::proxy::Socks5Auth;

    use super::{Socks5DnsMode, Socks5Proxy, Socks5ProxyConfigErrorKind};

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        let domain = Socks5Proxy::new("socks5h://proxy.example")?;
        let local = Socks5Proxy::new("socks5://proxy.example")?;
        let ipv4 = Socks5Proxy::new("socks5h://127.0.0.1:8080")?;
        let ipv6 = Socks5Proxy::new("socks5h://[::1]:1081")?;

        assert_eq!(domain.endpoint.host(), "proxy.example");
        assert_eq!(domain.endpoint.port(), 1080);
        assert_eq!(domain.dns_mode(), Socks5DnsMode::Remote);
        assert_eq!(local.dns_mode(), Socks5DnsMode::Local);
        assert_ne!(domain, local);
        assert_eq!(ipv4.endpoint.host(), "127.0.0.1");
        assert_eq!(ipv4.endpoint.port(), 8080);
        assert_eq!(ipv6.endpoint.host(), "::1");
        assert_eq!(ipv6.endpoint.port(), 1081);
        Ok(())
    }

    #[test]
    fn canonicalizes_unicode_proxy_hosts() -> Result<(), Box<dyn std::error::Error>> {
        let proxy = Socks5Proxy::new("socks5h://BÜCHER.Example:1081")?;

        assert_eq!(proxy.endpoint.host(), "xn--bcher-kva.example");
        assert_eq!(
            proxy.endpoint.authority().as_str(),
            "xn--bcher-kva.example:1081"
        );
        Ok(())
    }

    #[test]
    fn rejects_credentials_paths_queries_and_other_schemes() -> Result<(), &'static str> {
        for (uri, kind) in [
            (
                "http://proxy.example",
                Socks5ProxyConfigErrorKind::UnsupportedScheme,
            ),
            (
                "socks5h://proxy.example/path",
                Socks5ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "socks5h://proxy.example/?x=1",
                Socks5ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "socks5h://user:secret@proxy.example",
                Socks5ProxyConfigErrorKind::InvalidAuthority,
            ),
            (
                "socks5h://\u{200d}.example",
                Socks5ProxyConfigErrorKind::InvalidAuthority,
            ),
        ] {
            let error = match Socks5Proxy::new(uri) {
                Ok(_) => return Err("invalid SOCKS5 proxy URI was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), kind, "{uri}");
        }
        Ok(())
    }

    #[test]
    fn owns_username_password_and_includes_them_in_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut username = String::from("route-user");
        let mut password = String::from("route-password");
        let authenticated = Socks5Proxy::new("socks5h://proxy.example")?
            .with_username_password(&username, &password)?;
        let different_username = Socks5Proxy::new("socks5h://proxy.example")?
            .with_username_password("other-user", &password)?;
        let different_password = Socks5Proxy::new("socks5h://proxy.example")?
            .with_username_password(&username, "other-password")?;

        username.clear();
        password.clear();

        let (username, password) = match authenticated.auth() {
            Socks5Auth::UsernamePassword { username, password } => (username, password),
            _ => return Err("credentials were not stored".into()),
        };
        assert_eq!(username, "route-user");
        assert_eq!(password, "route-password");
        assert_ne!(authenticated, different_username);
        assert_ne!(authenticated, different_password);
        assert_ne!(authenticated, Socks5Proxy::new("socks5h://proxy.example")?);
        Ok(())
    }

    #[test]
    fn accepts_rfc_1929_credential_length_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        let shortest =
            Socks5Proxy::new("socks5h://proxy.example")?.with_username_password("u", "p")?;
        let longest = Socks5Proxy::new("socks5h://proxy.example")?
            .with_username_password("u".repeat(255), "p".repeat(255))?;

        assert!(matches!(
            shortest.auth(),
            Socks5Auth::UsernamePassword { username, .. } if username.len() == 1
        ));
        assert!(matches!(
            longest.auth(),
            Socks5Auth::UsernamePassword { password, .. } if password.len() == 255
        ));
        Ok(())
    }

    #[test]
    fn rejects_credentials_outside_rfc_1929_length_bounds_without_exposing_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let marker = "credential-leak-marker";
        let oversized = marker.repeat(13);

        for (username, password) in [
            ("", "password"),
            ("username", ""),
            (oversized.as_str(), "password"),
            ("username", oversized.as_str()),
        ] {
            let error = match Socks5Proxy::new("socks5h://proxy.example")?
                .with_username_password(username, password)
            {
                Ok(_) => return Err("invalid credentials were accepted".into()),
                Err(error) => error,
            };
            assert_eq!(error.kind(), Socks5ProxyConfigErrorKind::InvalidCredentials);
            assert!(!error.to_string().contains("credential-leak-marker"));
            assert!(!format!("{error:?}").contains("credential-leak-marker"));
        }
        Ok(())
    }

    #[test]
    fn debug_output_redacts_username_and_password() -> Result<(), Box<dyn std::error::Error>> {
        let proxy = Socks5Proxy::new("socks5h://proxy.example")?
            .with_username_password("debug-user-marker", "debug-password-marker")?;
        let debug = format!("{proxy:?}");

        assert!(debug.contains("credentials_configured: true"));
        assert!(!debug.contains("debug-user-marker"));
        assert!(!debug.contains("debug-password-marker"));
        Ok(())
    }
}
