use http::uri::Authority;

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
    use super::Endpoint;

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
