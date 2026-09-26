use std::{error::Error as StdError, fmt};

use phantom_net::{
    proxy::{HttpBasicCredentials, HttpsProxyProtocol},
    request::{InvalidOriginForm, OriginForm, RequestHeader},
};

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

const TARGET_HOST: &str = "target_host";
const TARGET_PORT: &str = "target_port";

/// RFC 9298 CONNECT-UDP (MASQUE) proxy.
///
/// The URI template names the proxy and the request path. It must use
/// `https`, contain `{target_host}` and `{target_port}` in its path or query,
/// and use only RFC 6570 simple (`{var}`) or form-style query (`{?var}`,
/// `{&var}`) expressions (RFC 9298 section 2). The proxy authority is
/// canonicalized like other proxy URIs; user information and fragments are
/// rejected. Phantom always sends the target to the proxy as text: an IPv6
/// literal is expanded with its colons percent-encoded, as in
/// `2001%3Adb8%3A%3A42`.
///
/// Only exact HTTP/3 requests accept this route. Each connection opens its
/// own outer connection to the proxy, authenticated with the client's proxy
/// trust roots. The proxy leg is HTTP/3 by default; [`Self::with_http2_transport`]
/// and [`Self::with_http1_transport`] select HTTP/2 extended CONNECT or
/// HTTP/1.1 Upgrade instead. The leg and any credentials are part of route
/// and pool identity, and a leg never falls back to another.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectUdpProxy {
    endpoint: Endpoint,
    template: Vec<TemplatePart>,
    headers: Vec<RequestHeader>,
    transport: ConnectUdpTransport,
    credentials: Option<HttpBasicCredentials>,
}

/// Protocol spoken on the proxy leg of a CONNECT-UDP route.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ConnectUdpTransport {
    /// RFC 9298 section 3.4 over HTTP/3; payloads in QUIC DATAGRAM frames.
    #[default]
    Http3,
    /// RFC 9298 section 3.4 over HTTP/2; payloads in DATAGRAM capsules.
    Http2,
    /// RFC 9298 section 3.2 over HTTP/1.1; payloads in DATAGRAM capsules.
    Http1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TemplatePart {
    Literal(Box<str>),
    Expression {
        operator: Operator,
        variables: Vec<Variable>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operator {
    /// `{var}`: comma-joined, percent-encoded values.
    Simple,
    /// `{?var}`: form-style query start.
    Query,
    /// `{&var}`: form-style query continuation.
    QueryContinuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variable {
    TargetHost,
    TargetPort,
}

impl Variable {
    const fn name(self) -> &'static str {
        match self {
            Self::TargetHost => TARGET_HOST,
            Self::TargetPort => TARGET_PORT,
        }
    }
}

impl ConnectUdpProxy {
    /// Parses a CONNECT-UDP URI template.
    ///
    /// For example,
    /// `https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/`.
    /// The proxy port defaults to 443. The new proxy uses an HTTP/3 leg, sends
    /// no extra fields, and has no credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectUdpProxyConfigError`] with kind:
    ///
    /// - [`ConnectUdpProxyConfigErrorKind::InvalidTemplate`] when the template
    ///   contains bytes other than printable ASCII, is not absolute, has a
    ///   path that does not start with `/`, has unbalanced braces or an empty
    ///   variable name, or does not expand to a valid request target;
    /// - [`ConnectUdpProxyConfigErrorKind::UnsupportedScheme`] for a scheme
    ///   other than `https`;
    /// - [`ConnectUdpProxyConfigErrorKind::InvalidAuthority`] when the
    ///   authority is missing, contains user information, or has an invalid
    ///   host or port;
    /// - [`ConnectUdpProxyConfigErrorKind::Fragment`] for a fragment;
    /// - [`ConnectUdpProxyConfigErrorKind::UnsupportedExpression`] for an
    ///   operator other than simple, `?`, or `&`, a value modifier, or an
    ///   expression in the authority;
    /// - [`ConnectUdpProxyConfigErrorKind::UnknownVariable`] for a variable
    ///   other than `target_host` or `target_port`;
    /// - [`ConnectUdpProxyConfigErrorKind::MissingVariable`] when
    ///   `target_host` or `target_port` is absent.
    pub fn new(template: &str) -> Result<Self, ConnectUdpProxyConfigError> {
        use ConnectUdpProxyConfigErrorKind as Kind;

        if !template.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(ConnectUdpProxyConfigError::new(
                Kind::InvalidTemplate,
                "CONNECT-UDP template must contain only printable ASCII without spaces",
            ));
        }
        let Some((scheme, rest)) = template.split_once("://") else {
            return Err(ConnectUdpProxyConfigError::new(
                Kind::InvalidTemplate,
                "CONNECT-UDP template must be an absolute URI template",
            ));
        };
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(ConnectUdpProxyConfigError::new(
                Kind::UnsupportedScheme,
                "CONNECT-UDP template must use the https scheme",
            ));
        }
        let authority_end = rest.find(['/', '?', '#', '{']).unwrap_or(rest.len());
        let (authority, path_and_query) = rest.split_at(authority_end);
        match path_and_query.as_bytes().first() {
            Some(b'/') => {}
            Some(b'{') => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::UnsupportedExpression,
                    "CONNECT-UDP template variables must be in the path or query",
                ));
            }
            Some(b'#') => return Err(ConnectUdpProxyConfigError::fragment()),
            _ => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::InvalidTemplate,
                    "CONNECT-UDP template path must start with '/'",
                ));
            }
        }
        let endpoint = parse_authority(authority)?;
        let parts = parse_path_and_query(path_and_query)?;
        for variable in [Variable::TargetHost, Variable::TargetPort] {
            if !parts.iter().any(|part| {
                matches!(part, TemplatePart::Expression { variables, .. } if variables.contains(&variable))
            }) {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::MissingVariable,
                    "CONNECT-UDP template must contain target_host and target_port",
                ));
            }
        }
        let proxy = Self {
            endpoint,
            template: parts,
            headers: Vec::new(),
            transport: ConnectUdpTransport::Http3,
            credentials: None,
        };
        // A representative expansion proves the literal text forms a valid
        // origin-form target before any request uses it.
        proxy.expand("example.com", 443).map_err(|_| {
            ConnectUdpProxyConfigError::new(
                Kind::InvalidTemplate,
                "CONNECT-UDP template does not expand to a valid request target",
            )
        })?;
        Ok(proxy)
    }

    /// Appends one ordered field to every CONNECT-UDP request.
    ///
    /// Fields follow the generated fields: `capsule-protocol: ?1` on HTTP/3
    /// and HTTP/2 legs, and `Host`, `Connection: Upgrade`,
    /// `Upgrade: connect-udp`, and `Capsule-Protocol: ?1` on the HTTP/1.1
    /// leg. A generated `Proxy-Authorization` follows them. Fields are
    /// validated before proxy I/O; framing fields, fields that repeat a
    /// generated one, and a literal `Proxy-Authorization` when Basic
    /// credentials are configured are rejected.
    #[must_use]
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Speaks HTTP/2 to the proxy: RFC 9298 section 3.4 extended CONNECT
    /// with `:protocol connect-udp`, UDP payloads in DATAGRAM capsules on the
    /// request stream (RFC 9297 section 3.5).
    ///
    /// Each inner connection opens one dedicated TLS connection to the proxy
    /// that must select `h2`, using the client profile's TLS offer and HTTP/2
    /// settings. The HTTP/2 settings must carry an extended CONNECT
    /// pseudo-header order, and the proxy must send
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 8441 section 3) before the
    /// request is sent. Any other ALPN selection or missing capability is a
    /// typed proxy error; nothing falls back to another leg.
    #[must_use]
    pub fn with_http2_transport(mut self) -> Self {
        self.transport = ConnectUdpTransport::Http2;
        self
    }

    /// Speaks HTTP/1.1 to the proxy: RFC 9298 section 3.2 `GET` with
    /// `Connection: Upgrade`, `Upgrade: connect-udp`, and
    /// `Capsule-Protocol: ?1`, requiring a 101 response (section 3.3). UDP
    /// payloads travel in DATAGRAM capsules on the upgraded stream.
    ///
    /// Each inner connection opens one dedicated TLS connection to the proxy
    /// that must select `http/1.1` or omit ALPN; `h2` is a typed proxy error.
    #[must_use]
    pub fn with_http1_transport(mut self) -> Self {
        self.transport = ConnectUdpTransport::Http1;
        self
    }

    /// Configures challenge-driven HTTP Basic proxy authentication.
    ///
    /// The first CONNECT-UDP request omits credentials. After a 407 response
    /// with a valid Basic challenge, Phantom retries exactly once on a fresh
    /// proxy connection with `Proxy-Authorization` after the route's fields.
    /// HTTP/3 sends it as a never-indexed field; over HTTP/2 the profile's
    /// [`Http2SensitiveProxyAuthorization`](crate::profile::Http2SensitiveProxyAuthorization)
    /// decides, and the browser recipes index it. A second 407 fails
    /// with an authentication error. Credentials never appear in `Debug`
    /// output or diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectUdpProxyConfigError`] with kind
    /// [`ConnectUdpProxyConfigErrorKind::InvalidCredentials`] when the
    /// username is empty or contains a colon, either value contains non-ASCII
    /// or control characters, or the encoded credentials exceed their bounded
    /// size.
    pub fn with_basic_auth(
        mut self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, ConnectUdpProxyConfigError> {
        let credentials = HttpBasicCredentials::new(username, password).map_err(|_| {
            ConnectUdpProxyConfigError::new(
                ConnectUdpProxyConfigErrorKind::InvalidCredentials,
                "HTTP Basic proxy credentials must fit the credential-field bound, use ASCII without control characters, and have a nonempty username without a colon",
            )
        })?;
        self.credentials = Some(credentials);
        Ok(self)
    }

    /// Returns the TCP proxy-leg protocol, or `None` for an HTTP/3 leg.
    pub(crate) const fn tcp_protocol(&self) -> Option<HttpsProxyProtocol> {
        match self.transport {
            ConnectUdpTransport::Http3 => None,
            ConnectUdpTransport::Http2 => Some(HttpsProxyProtocol::Http2),
            ConnectUdpTransport::Http1 => Some(HttpsProxyProtocol::Http1),
        }
    }

    pub(crate) const fn trace_name(&self) -> &'static str {
        match self.transport {
            ConnectUdpTransport::Http3 => "connect_udp",
            ConnectUdpTransport::Http2 => "connect_udp_h2",
            ConnectUdpTransport::Http1 => "connect_udp_http1",
        }
    }

    pub(crate) fn credentials(&self) -> Option<&HttpBasicCredentials> {
        self.credentials.as_ref()
    }

    pub(crate) fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub(crate) fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub(crate) fn authority(&self) -> &str {
        self.endpoint.authority().as_str()
    }

    pub(crate) fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }

    /// Expands the template for one UDP target (RFC 6570 section 3.2).
    pub(crate) fn expand(&self, host: &str, port: u16) -> Result<OriginForm, InvalidOriginForm> {
        let port = port.to_string();
        let value = |variable: Variable| match variable {
            Variable::TargetHost => host,
            Variable::TargetPort => port.as_str(),
        };
        let mut output = String::new();
        for part in &self.template {
            match part {
                TemplatePart::Literal(literal) => output.push_str(literal),
                TemplatePart::Expression {
                    operator: Operator::Simple,
                    variables,
                } => {
                    for (index, variable) in variables.iter().enumerate() {
                        if index > 0 {
                            output.push(',');
                        }
                        percent_encode(value(*variable), &mut output);
                    }
                }
                TemplatePart::Expression {
                    operator,
                    variables,
                } => {
                    for (index, variable) in variables.iter().enumerate() {
                        output.push(match (index, operator) {
                            (0, Operator::Query) => '?',
                            _ => '&',
                        });
                        output.push_str(variable.name());
                        output.push('=');
                        percent_encode(value(*variable), &mut output);
                    }
                }
            }
        }
        OriginForm::parse(&output)
    }
}

impl fmt::Debug for ConnectUdpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectUdpProxy")
            .field("authority", self.endpoint.authority())
            .field(
                "proxy_protocol",
                &match self.transport {
                    ConnectUdpTransport::Http3 => "h3",
                    ConnectUdpTransport::Http2 => "h2",
                    ConnectUdpTransport::Http1 => "http/1.1",
                },
            )
            .field("header_count", &self.headers.len())
            .field("credentials_configured", &self.credentials.is_some())
            .finish_non_exhaustive()
    }
}

fn parse_authority(authority: &str) -> Result<Endpoint, ConnectUdpProxyConfigError> {
    let invalid = |message| {
        ConnectUdpProxyConfigError::new(ConnectUdpProxyConfigErrorKind::InvalidAuthority, message)
    };
    if authority.is_empty() {
        return Err(invalid(
            "CONNECT-UDP template must include a proxy authority",
        ));
    }
    let uri =
        parse_absolute_uri(&format!("https://{authority}/")).map_err(|error| match error {
            ParseUriError::Authority(error) => invalid(error.message()),
            ParseUriError::Syntax(_) | ParseUriError::Fragment => {
                invalid("CONNECT-UDP proxy authority is invalid")
            }
        })?;
    let authority = uri
        .authority()
        .cloned()
        .ok_or_else(|| invalid("CONNECT-UDP template must include a proxy authority"))?;
    Endpoint::new(authority, 443).map_err(|error| invalid(error.message()))
}

fn parse_path_and_query(value: &str) -> Result<Vec<TemplatePart>, ConnectUdpProxyConfigError> {
    use ConnectUdpProxyConfigErrorKind as Kind;

    let mut parts = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let literal_end = rest.find(['{', '}', '#']).unwrap_or(rest.len());
        if literal_end > 0 {
            parts.push(TemplatePart::Literal(rest[..literal_end].into()));
        }
        rest = &rest[literal_end..];
        match rest.as_bytes().first() {
            None => break,
            Some(b'#') => return Err(ConnectUdpProxyConfigError::fragment()),
            Some(b'}') => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::InvalidTemplate,
                    "CONNECT-UDP template has an unmatched '}'",
                ));
            }
            Some(_) => {}
        }
        let end = rest.find('}').ok_or_else(|| {
            ConnectUdpProxyConfigError::new(
                Kind::InvalidTemplate,
                "CONNECT-UDP template has an unterminated expression",
            )
        })?;
        parts.push(parse_expression(&rest[1..end])?);
        rest = &rest[end + 1..];
    }
    Ok(parts)
}

fn parse_expression(expression: &str) -> Result<TemplatePart, ConnectUdpProxyConfigError> {
    use ConnectUdpProxyConfigErrorKind as Kind;

    let (operator, list) = match expression.as_bytes().first() {
        Some(b'?') => (Operator::Query, &expression[1..]),
        Some(b'&') => (Operator::QueryContinuation, &expression[1..]),
        // RFC 9298 section 2 forbids reserved, fragment, label, path-segment,
        // and path-style expansion; the remaining operators are reserved by
        // RFC 6570 section 2.2.
        Some(b'+' | b'#' | b'.' | b'/' | b';' | b'=' | b',' | b'!' | b'@' | b'|') => {
            return Err(ConnectUdpProxyConfigError::new(
                Kind::UnsupportedExpression,
                "CONNECT-UDP template uses an unsupported expression operator",
            ));
        }
        _ => (Operator::Simple, expression),
    };
    let mut variables = Vec::new();
    for name in list.split(',') {
        let variable = match name {
            TARGET_HOST => Variable::TargetHost,
            TARGET_PORT => Variable::TargetPort,
            _ if name.contains([':', '*']) => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::UnsupportedExpression,
                    "CONNECT-UDP template variables must not use value modifiers",
                ));
            }
            "" => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::InvalidTemplate,
                    "CONNECT-UDP template has an empty variable name",
                ));
            }
            _ => {
                return Err(ConnectUdpProxyConfigError::new(
                    Kind::UnknownVariable,
                    "CONNECT-UDP template may use only target_host and target_port",
                ));
            }
        };
        variables.push(variable);
    }
    Ok(TemplatePart::Expression {
        operator,
        variables,
    })
}

/// Percent-encodes everything outside RFC 3986 `unreserved` (RFC 6570
/// section 3.2.1), so IPv6 colons become `%3A` (RFC 9298 section 3).
fn percent_encode(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

/// Stable category of CONNECT-UDP proxy-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectUdpProxyConfigErrorKind {
    /// The template is not a valid absolute URI template.
    InvalidTemplate,
    /// The template scheme is not `https`.
    UnsupportedScheme,
    /// The proxy authority is missing, invalid, or contains user information.
    InvalidAuthority,
    /// The template contains a fragment.
    Fragment,
    /// The template uses an unsupported operator or modifier, or places a
    /// variable outside the path or query.
    UnsupportedExpression,
    /// The template uses a variable other than `target_host` or `target_port`.
    UnknownVariable,
    /// The template omits `target_host` or `target_port`.
    MissingVariable,
    /// The HTTP Basic username or password is invalid.
    InvalidCredentials,
}

/// Error returned while constructing a CONNECT-UDP proxy route.
#[derive(Debug)]
pub struct ConnectUdpProxyConfigError {
    kind: ConnectUdpProxyConfigErrorKind,
    message: &'static str,
}

impl ConnectUdpProxyConfigError {
    const fn new(kind: ConnectUdpProxyConfigErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    const fn fragment() -> Self {
        Self::new(
            ConnectUdpProxyConfigErrorKind::Fragment,
            "CONNECT-UDP template must not contain a fragment",
        )
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> ConnectUdpProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for ConnectUdpProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for ConnectUdpProxyConfigError {}

#[cfg(test)]
mod tests;
