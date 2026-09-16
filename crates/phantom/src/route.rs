use std::{error::Error as StdError, fmt};

use http::Uri;
use phantom_net::{proxy::HttpConnectHeader, request::RequestHeader};

use crate::authority::Endpoint;

/// Route used to establish one origin connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Route {
    /// Connect directly to the origin.
    #[default]
    Direct,
    /// Tunnel TCP through a plaintext HTTP proxy using CONNECT.
    HttpConnect(HttpProxy),
}

impl Route {
    /// Returns a direct route.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Returns a plaintext HTTP CONNECT route.
    #[must_use]
    pub fn http_connect(proxy: HttpProxy) -> Self {
        Self::HttpConnect(proxy)
    }

    pub(crate) const fn trace_name(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::HttpConnect(_) => "http_connect",
        }
    }
}

/// Plaintext HTTP proxy configuration for CONNECT tunnels.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpProxy {
    endpoint: Endpoint,
    connect_headers: Vec<HttpConnectHeader>,
}

impl HttpProxy {
    /// Parses a plaintext HTTP proxy URI.
    ///
    /// The URI must use `http`, contain only an authority and optional `/`,
    /// and must not contain credentials. Port 80 is used when omitted. Unicode
    /// hostnames must be normalized to an ASCII A-label by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] when the URI is malformed or uses an
    /// unsupported shape.
    pub fn new(uri: &str) -> Result<Self, ProxyConfigError> {
        let uri = uri.parse::<Uri>().map_err(ProxyConfigError::invalid_uri)?;
        if uri.scheme_str() != Some("http") {
            return Err(ProxyConfigError::unsupported_scheme());
        }
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(ProxyConfigError::invalid_authority)?;
        if !matches!(
            uri.path_and_query().map(|value| value.as_str()),
            None | Some("/")
        ) {
            return Err(ProxyConfigError::unexpected_path());
        }
        let endpoint = Endpoint::new(authority, 80)
            .map_err(|error| ProxyConfigError::authority(error.message()))?;
        Ok(Self {
            endpoint,
            connect_headers: vec![HttpConnectHeader::authority("Host")],
        })
    }

    /// Appends one ordered field to the CONNECT request.
    ///
    /// A literal `Host` or request-framing field is rejected before proxy I/O;
    /// use [`HttpConnectHeader::Authority`] to control `Host` placement.
    #[must_use]
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.connect_headers.push(HttpConnectHeader::field(header));
        self
    }

    /// Replaces the literal CONNECT fields after the default leading `Host`.
    #[must_use]
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.connect_headers = std::iter::once(HttpConnectHeader::authority("Host"))
            .chain(headers.into_iter().map(HttpConnectHeader::field))
            .collect();
        self
    }

    /// Replaces the complete CONNECT field sequence.
    ///
    /// The sequence must contain exactly one
    /// [`HttpConnectHeader::Authority`] placeholder. Validation happens before
    /// proxy I/O when a request is sent.
    #[must_use]
    pub fn connect_headers(mut self, headers: Vec<HttpConnectHeader>) -> Self {
        self.connect_headers = headers;
        self
    }

    pub(crate) fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub(crate) fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub(crate) fn ordered_connect_headers(&self) -> &[HttpConnectHeader] {
        &self.connect_headers
    }
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("authority", self.endpoint.authority())
            .field("connect_header_count", &self.connect_headers.len())
            .finish_non_exhaustive()
    }
}

/// Stable category of proxy-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProxyConfigErrorKind {
    /// The proxy URI is syntactically invalid.
    InvalidUri,
    /// The proxy URI scheme is unsupported.
    UnsupportedScheme,
    /// The proxy URI authority is missing or invalid.
    InvalidAuthority,
    /// The proxy URI contains a path or query.
    UnexpectedPath,
}

/// Error returned while constructing an [`HttpProxy`].
#[derive(Debug)]
pub struct ProxyConfigError {
    kind: ProxyConfigErrorKind,
    message: &'static str,
    source: Option<http::uri::InvalidUri>,
}

impl ProxyConfigError {
    fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self {
            kind: ProxyConfigErrorKind::InvalidUri,
            message: "invalid HTTP proxy URI",
            source: Some(source),
        }
    }

    fn unsupported_scheme() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::UnsupportedScheme,
            "HTTP CONNECT proxy URI must use the http scheme",
        )
    }

    fn invalid_authority() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::InvalidAuthority,
            "HTTP proxy URI must include an authority",
        )
    }

    fn authority(message: &'static str) -> Self {
        Self::without_source(ProxyConfigErrorKind::InvalidAuthority, message)
    }

    fn unexpected_path() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::UnexpectedPath,
            "HTTP proxy URI must not contain a path or query",
        )
    }

    fn without_source(kind: ProxyConfigErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> ProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for ProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for ProxyConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpProxy, ProxyConfigErrorKind};

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        let domain = HttpProxy::new("http://proxy.example")?;
        let ipv4 = HttpProxy::new("http://127.0.0.1:8080")?;
        let ipv6 = HttpProxy::new("http://[::1]:3128")?;

        assert_eq!(domain.endpoint.host(), "proxy.example");
        assert_eq!(domain.endpoint.port(), 80);
        assert_eq!(ipv4.endpoint.host(), "127.0.0.1");
        assert_eq!(ipv4.endpoint.port(), 8080);
        assert_eq!(ipv6.endpoint.host(), "::1");
        assert_eq!(ipv6.endpoint.port(), 3128);
        Ok(())
    }

    #[test]
    fn rejects_credentials_paths_queries_and_other_schemes() -> Result<(), &'static str> {
        for (uri, kind) in [
            (
                "https://proxy.example",
                ProxyConfigErrorKind::UnsupportedScheme,
            ),
            (
                "http://proxy.example/path",
                ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "http://proxy.example/?x=1",
                ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "http://user:secret@proxy.example",
                ProxyConfigErrorKind::InvalidAuthority,
            ),
        ] {
            let error = match HttpProxy::new(uri) {
                Ok(_) => return Err("invalid proxy URI was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), kind, "{uri}");
        }
        Ok(())
    }
}
