use http::{Uri, uri::Authority};

pub(crate) fn parse_absolute_uri(value: &str) -> Result<Uri, ParseUriError> {
    if value.contains('#') {
        return Err(ParseUriError::Fragment);
    }
    let Some(scheme_end) = value.find("://") else {
        return value.parse().map_err(ParseUriError::Syntax);
    };
    let authority_start = scheme_end + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |offset| authority_start + offset);
    let authority = canonicalize_authority(&value[authority_start..authority_end])
        .map_err(ParseUriError::Authority)?;

    let mut canonical =
        String::with_capacity(value.len() + authority.len() - (authority_end - authority_start));
    canonical.push_str(&value[..authority_start]);
    canonical.push_str(&authority);
    canonical.push_str(&value[authority_end..]);
    canonical.parse().map_err(ParseUriError::Syntax)
}

#[derive(Debug)]
pub(crate) enum ParseUriError {
    Syntax(http::uri::InvalidUri),
    Authority(AuthorityError),
    Fragment,
}

impl std::fmt::Display for ParseUriError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(error) => error.fmt(formatter),
            Self::Authority(error) => error.fmt(formatter),
            Self::Fragment => formatter.write_str("URI fragments are not sent in HTTP requests"),
        }
    }
}

impl std::error::Error for ParseUriError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Fragment => None,
        }
    }
}

fn canonicalize_authority(value: &str) -> Result<String, AuthorityError> {
    if value.as_bytes().contains(&b'@') {
        return Err(AuthorityError(
            "authority must not contain user information",
        ));
    }
    let (host, suffix) = split_host_and_suffix(value)?;
    let host = url::Host::parse(host).map_err(|_| AuthorityError("host is invalid"))?;

    let mut canonical = host.to_string();
    canonical.push_str(suffix);
    Ok(canonical)
}

fn split_host_and_suffix(value: &str) -> Result<(&str, &str), AuthorityError> {
    if value.starts_with('[') {
        let bracket = value
            .find(']')
            .ok_or(AuthorityError("bracketed host is incomplete"))?;
        let (host, suffix) = value.split_at(bracket + 1);
        if !suffix.is_empty() && !suffix.starts_with(':') {
            return Err(AuthorityError("authority has an invalid suffix"));
        }
        return Ok((host, suffix));
    }

    let Some(colon) = value.rfind(':') else {
        return Ok((value, ""));
    };
    if value[..colon].contains(':') {
        return Err(AuthorityError("IPv6 hosts must use brackets"));
    }
    Ok((&value[..colon], &value[colon..]))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Endpoint {
    authority: Authority,
    host: Box<str>,
    port: u16,
}

impl Endpoint {
    pub(crate) fn new(authority: Authority, default_port: u16) -> Result<Self, AuthorityError> {
        if authority.as_str().as_bytes().contains(&b'@') {
            return Err(AuthorityError(
                "authority must not contain user information",
            ));
        }
        let (host, port) = resolve_host_and_port(&authority, default_port)?;
        Ok(Self {
            authority,
            host,
            port,
        })
    }

    pub(crate) fn authority(&self) -> &Authority {
        &self.authority
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn tunnel_authority(&self) -> Box<str> {
        if self.authority.port_u16().is_some() {
            self.authority.as_str().into()
        } else {
            format!("{}:{}", self.authority, self.port).into()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityError(&'static str);

impl AuthorityError {
    pub(crate) const fn message(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for AuthorityError {}

fn resolve_host_and_port(
    authority: &Authority,
    default_port: u16,
) -> Result<(Box<str>, u16), AuthorityError> {
    let text = authority.as_str();
    if let Some(bracketed) = text.strip_prefix('[') {
        let (literal, suffix) = bracketed
            .split_once(']')
            .ok_or(AuthorityError("bracketed host is incomplete"))?;
        let address = literal
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| AuthorityError("bracketed host must be an IPv6 address"))?;
        let port = parse_port_suffix(suffix, default_port)?;
        return Ok((address.to_string().into(), port));
    }

    let host = authority.host();
    if host.is_empty() {
        return Err(AuthorityError("host must not be empty"));
    }
    if host.contains(':') {
        return Err(AuthorityError("IPv6 hosts must use brackets"));
    }
    let port = match text.strip_prefix(host) {
        Some("") => default_port,
        Some(suffix) => parse_port_suffix(suffix, default_port)?,
        None => return Err(AuthorityError("authority does not match its host")),
    };
    Ok((host.into(), port))
}

fn parse_port_suffix(suffix: &str, default_port: u16) -> Result<u16, AuthorityError> {
    if suffix.is_empty() {
        return Ok(default_port);
    }
    let port = suffix
        .strip_prefix(':')
        .ok_or(AuthorityError("authority has an invalid suffix"))?;
    if port.is_empty() {
        return Err(AuthorityError("port must not be empty"));
    }
    port.parse::<u16>()
        .map_err(|_| AuthorityError("port is invalid"))
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, ParseUriError, parse_absolute_uri};

    #[test]
    fn canonicalizes_url_hosts_without_reserializing_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let uri = parse_absolute_uri("https://BÜCHER.Example:443/a/%2e%2e/final?value=%2f")?;

        assert_eq!(
            uri,
            "https://xn--bcher-kva.example:443/a/%2e%2e/final?value=%2f".parse::<http::Uri>()?
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_whatwg_ip_literals_and_preserves_trailing_dots()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_absolute_uri("https://127.1/")?,
            "https://127.0.0.1/".parse::<http::Uri>()?
        );
        assert_eq!(
            parse_absolute_uri("https://１２７．０．０．１/")?,
            "https://127.0.0.1/".parse::<http::Uri>()?
        );
        assert_eq!(
            parse_absolute_uri("https://[0:0::1]:443/")?,
            "https://[::1]:443/".parse::<http::Uri>()?
        );
        assert_eq!(
            parse_absolute_uri("https://EXAMPLE.Test./")?,
            "https://example.test./".parse::<http::Uri>()?
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_url_hosts_as_authority_errors() {
        for value in [
            "https:///über",
            "https://bad host/",
            "https://user@example.test/",
            "https://2001:db8::1/",
        ] {
            assert!(
                matches!(parse_absolute_uri(value), Err(ParseUriError::Authority(_))),
                "{value}"
            );
        }

        assert!(matches!(
            parse_absolute_uri("https://example.test/path#fragment"),
            Err(ParseUriError::Fragment)
        ));
    }

    #[test]
    fn tunnel_authority_adds_default_port_and_preserves_explicit_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = Endpoint::new("example.test".parse()?, 443)?;
        let ipv6 = Endpoint::new("[::1]".parse()?, 443)?;
        let explicit = Endpoint::new("example.test:8443".parse()?, 443)?;

        assert_eq!(&*domain.tunnel_authority(), "example.test:443");
        assert_eq!(&*ipv6.tunnel_authority(), "[::1]:443");
        assert_eq!(&*explicit.tunnel_authority(), "example.test:8443");
        Ok(())
    }
}
