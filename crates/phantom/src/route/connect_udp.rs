use std::{error::Error as StdError, fmt};

use phantom_net::request::{InvalidOriginForm, OriginForm, RequestHeader};

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

const TARGET_HOST: &str = "target_host";
const TARGET_PORT: &str = "target_port";

/// RFC 9298 CONNECT-UDP (MASQUE) proxy reached over HTTP/3.
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
/// own outer HTTP/3 connection to the proxy, authenticated with the client's
/// proxy trust roots.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectUdpProxy {
    endpoint: Endpoint,
    template: Vec<TemplatePart>,
    headers: Vec<RequestHeader>,
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
    /// The proxy port defaults to 443.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectUdpProxyConfigError`] when the template is not a valid
    /// absolute `https` template, its authority is invalid or contains user
    /// information, it contains a fragment, an unsupported expression, an
    /// unknown variable, or omits `target_host` or `target_port`.
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
    /// Fields follow the generated `capsule-protocol: ?1` field. They are
    /// validated before proxy I/O; `content-length` and `capsule-protocol`
    /// are rejected.
    #[must_use]
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
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
            .field("header_count", &self.headers.len())
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
