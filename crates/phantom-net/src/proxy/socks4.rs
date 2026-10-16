use std::{error::Error, fmt, io, net::IpAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp, poll_tokio_io},
    host_resolver::resolve,
    route::{Endpoint, Socks4Target},
    tcp::ProfileTcpStream,
};

/// Stable category of SOCKS4 or SOCKS4a tunnel failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks4ErrorKind {
    /// The target cannot be encoded in a CONNECT request.
    InvalidTarget,
    /// The user ID contains a NUL byte or exceeds 255 UTF-8 bytes.
    InvalidUserId,
    /// SOCKS4 cannot carry the requested IPv6 target.
    UnsupportedTarget,
    /// The operation requires a Tokio I/O runtime.
    RuntimeUnavailable,
    /// Connecting to the proxy failed.
    Connect,
    /// Local target resolution failed or returned no addresses.
    Resolve,
    /// Writing the request or reading a valid reply failed.
    Negotiation,
    /// The proxy rejected the request (status 91).
    Rejected,
    /// The proxy rejected IDENT or user identity (status 92 or 93).
    Authentication,
}

/// Failure before a SOCKS4 tunnel is established; never contains a user ID.
#[derive(Debug)]
pub struct Socks4Error {
    kind: Socks4ErrorKind,
    source: Option<io::Error>,
    reply_version: Option<u8>,
    reply_status: Option<u8>,
}

impl Socks4Error {
    pub(super) fn new(kind: Socks4ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            reply_version: None,
            reply_status: None,
        }
    }

    pub(super) fn io(kind: Socks4ErrorKind, source: io::Error) -> Self {
        Self {
            kind,
            source: Some(source),
            reply_version: None,
            reply_status: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Socks4ErrorKind {
        self.kind
    }

    /// Returns the proxy's reply status, including an unknown status.
    #[must_use]
    pub const fn reply_status(&self) -> Option<u8> {
        self.reply_status
    }

    /// Returns the version byte of a complete proxy reply; SOCKS4 requires zero.
    #[must_use]
    pub const fn reply_version(&self) -> Option<u8> {
        self.reply_version
    }
}

impl fmt::Display for Socks4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            Socks4ErrorKind::InvalidTarget => "invalid SOCKS4 target",
            Socks4ErrorKind::InvalidUserId => "invalid SOCKS4 user ID",
            Socks4ErrorKind::UnsupportedTarget => "SOCKS4 does not support IPv6 targets",
            Socks4ErrorKind::RuntimeUnavailable => "SOCKS4 requires a Tokio I/O runtime",
            Socks4ErrorKind::Connect => "SOCKS4 proxy TCP connection failed",
            Socks4ErrorKind::Resolve => "SOCKS4 target DNS resolution failed",
            Socks4ErrorKind::Negotiation => "SOCKS4 negotiation failed",
            Socks4ErrorKind::Rejected => "SOCKS4 proxy rejected the request",
            Socks4ErrorKind::Authentication => "SOCKS4 proxy rejected user identification",
        })
    }
}

impl Error for Socks4Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// A bounded NUL-free SOCKS4 user ID, sent as UTF-8 bytes.
///
/// Empty is valid. The 255-byte limit is a resource bound, not a protocol
/// length field. This identification string is not a password.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Socks4UserId<'a>(&'a str);

impl<'a> Socks4UserId<'a> {
    pub(super) const fn as_str(self) -> &'a str {
        self.0
    }

    /// Validates a user ID before any connection or request write.
    pub fn new(value: &'a str) -> Result<Self, Socks4Error> {
        if value.len() > 255 || value.as_bytes().contains(&0) {
            return Err(Socks4Error::new(Socks4ErrorKind::InvalidUserId));
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for Socks4UserId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Socks4UserId(<redacted>)")
    }
}

pub(crate) async fn socks4_tunnel(
    dialer: Dialer<'_>,
    proxy: Endpoint<'_>,
    target: Socks4Target<'_>,
    user_id: Socks4UserId<'_>,
) -> Result<ProfileTcpStream, Socks4Error> {
    let endpoint = match target {
        Socks4Target::LocalDns(endpoint) | Socks4Target::RemoteDns(endpoint) => endpoint,
    };
    validate_target(endpoint)?;
    tokio::runtime::Handle::try_current()
        .map_err(|_| Socks4Error::new(Socks4ErrorKind::RuntimeUnavailable))?;

    let address = match target {
        Socks4Target::RemoteDns(endpoint) => encoded_address(endpoint)?,
        Socks4Target::LocalDns(endpoint) => {
            let addresses =
                poll_tokio_io(|| resolve(dialer.resolver, endpoint.host, endpoint.port))
                    .await
                    .map_err(|_| Socks4Error::new(Socks4ErrorKind::RuntimeUnavailable))?
                    .map_err(|source| Socks4Error::io(Socks4ErrorKind::Resolve, source))?;
            if addresses.is_empty() {
                return Err(Socks4Error::new(Socks4ErrorKind::Resolve));
            }
            let address = addresses
                .iter()
                .find_map(|address| match address.ip() {
                    IpAddr::V4(address) => Some(address.octets()),
                    IpAddr::V6(_) => None,
                })
                .ok_or_else(|| Socks4Error::new(Socks4ErrorKind::UnsupportedTarget))?;
            validate_ipv4(address)?;
            (address, None)
        }
    };
    let stream =
        connect_tcp(proxy.host, proxy.port, dialer)
            .await
            .map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => {
                    Socks4Error::new(Socks4ErrorKind::RuntimeUnavailable)
                }
                DirectConnectError::Connect(source) => {
                    Socks4Error::io(Socks4ErrorKind::Connect, source)
                }
            })?;
    establish(stream, endpoint.port, address, user_id).await
}

pub(super) fn validate_target(endpoint: Endpoint<'_>) -> Result<(), Socks4Error> {
    if endpoint.host.is_empty()
        || !endpoint.host.is_ascii()
        || endpoint.host.len() > 253
        || endpoint
            .host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || endpoint.port == 0
    {
        return Err(Socks4Error::new(Socks4ErrorKind::InvalidTarget));
    }
    if endpoint.host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(Socks4Error::new(Socks4ErrorKind::UnsupportedTarget));
    }
    if endpoint.host.contains([':', '[', ']']) {
        return Err(Socks4Error::new(Socks4ErrorKind::InvalidTarget));
    }
    if let Ok(address) = endpoint.host.parse::<std::net::Ipv4Addr>() {
        validate_ipv4(address.octets())?;
    }
    Ok(())
}

pub(super) fn validate_ipv4(address: [u8; 4]) -> Result<(), Socks4Error> {
    // A SOCKS4a proxy interprets this range as a domain extension marker.
    if address[..3] == [0, 0, 0] && address[3] != 0 {
        return Err(Socks4Error::new(Socks4ErrorKind::InvalidTarget));
    }
    Ok(())
}

pub(super) fn encoded_address(
    endpoint: Endpoint<'_>,
) -> Result<([u8; 4], Option<&str>), Socks4Error> {
    validate_target(endpoint)?;
    match endpoint.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Ok((address.octets(), None)),
        Ok(IpAddr::V6(_)) => Err(Socks4Error::new(Socks4ErrorKind::UnsupportedTarget)),
        Err(_) => Ok(([0, 0, 0, 1], Some(endpoint.host))),
    }
}

pub(super) async fn establish<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    port: u16,
    (address, domain): ([u8; 4], Option<&str>),
    user_id: Socks4UserId<'_>,
) -> Result<S, Socks4Error> {
    // SOCKS4 CONNECT and the 4a domain extension are NUL-terminated.
    // https://www.openssh.org/txt/socks4.protocol
    // https://www.openssh.org/txt/socks4a.protocol
    let mut request = Vec::with_capacity(10 + user_id.0.len() + domain.map_or(0, str::len));
    request.extend_from_slice(&[4, 1]);
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(&address);
    request.extend_from_slice(user_id.0.as_bytes());
    request.push(0);
    if let Some(domain) = domain {
        request.extend_from_slice(domain.as_bytes());
        request.push(0);
    }
    stream
        .write_all(&request)
        .await
        .map_err(|source| Socks4Error::io(Socks4ErrorKind::Negotiation, source))?;

    let mut reply = [0; 8];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|source| Socks4Error::io(Socks4ErrorKind::Negotiation, source))?;
    let kind = match (reply[0], reply[1]) {
        (0, 90) => return Ok(stream),
        (0, 91) => Socks4ErrorKind::Rejected,
        (0, 92 | 93) => Socks4ErrorKind::Authentication,
        _ => Socks4ErrorKind::Negotiation,
    };
    Err(Socks4Error {
        kind,
        source: None,
        reply_version: Some(reply[0]),
        reply_status: Some(reply[1]),
    })
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn maximum_user_id_and_domain_preserve_framing_and_tunnel_bytes()
    -> Result<(), Box<dyn Error>> {
        let user = "u".repeat(255);
        let domain = format!(
            "{}.{}.{}.{}",
            "d".repeat(63),
            "d".repeat(63),
            "d".repeat(63),
            "d".repeat(61)
        );
        let (client, mut proxy) = duplex(1024);
        let operation = establish(
            client,
            443,
            ([0, 0, 0, 1], Some(domain.as_str())),
            Socks4UserId::new(&user)?,
        );
        let peer = async {
            let mut request = [0; 518];
            proxy.read_exact(&mut request).await?;
            assert_eq!(&request[..8], &[4, 1, 1, 187, 0, 0, 0, 1]);
            assert_eq!(&request[8..263], vec![b'u'; 255]);
            assert_eq!(request[263], 0);
            assert_eq!(&request[264..517], domain.as_bytes());
            assert_eq!(request[517], 0);
            proxy.write_all(&[0, 90, 0, 0, 0, 0, 0, 0, 42]).await
        };

        let (stream, peer) = tokio::join!(operation, peer);
        peer?;
        let mut stream = stream?;
        assert_eq!(stream.read_u8().await?, 42);
        Ok(())
    }

    #[tokio::test]
    async fn ipv4_connect_sends_no_domain_extension() -> Result<(), Box<dyn Error>> {
        let (client, mut proxy) = duplex(32);
        let operation = establish(client, 80, ([127, 0, 0, 1], None), Socks4UserId::default());
        let peer = async {
            let mut request = [0; 9];
            proxy.read_exact(&mut request).await?;
            assert_eq!(request, [4, 1, 0, 80, 127, 0, 0, 1, 0]);
            proxy.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await
        };

        let (stream, peer) = tokio::join!(operation, peer);
        peer?;
        stream?;
        Ok(())
    }

    #[tokio::test]
    async fn reply_failures_keep_status_and_truncated_reply_keeps_io_source()
    -> Result<(), Box<dyn Error>> {
        for (reply, kind, status) in [
            (
                vec![0, 91, 0, 0, 0, 0, 0, 0],
                Socks4ErrorKind::Rejected,
                Some(91),
            ),
            (
                vec![0, 92, 0, 0, 0, 0, 0, 0],
                Socks4ErrorKind::Authentication,
                Some(92),
            ),
            (
                vec![0, 93, 0, 0, 0, 0, 0, 0],
                Socks4ErrorKind::Authentication,
                Some(93),
            ),
            (
                vec![0, 94, 0, 0, 0, 0, 0, 0],
                Socks4ErrorKind::Negotiation,
                Some(94),
            ),
            (
                vec![4, 90, 0, 0, 0, 0, 0, 0],
                Socks4ErrorKind::Negotiation,
                Some(90),
            ),
            (vec![0, 90, 0], Socks4ErrorKind::Negotiation, None),
        ] {
            let (client, mut proxy) = duplex(32);
            let operation = establish(client, 80, ([127, 0, 0, 1], None), Socks4UserId::default());
            let peer = async {
                let mut request = [0; 9];
                proxy.read_exact(&mut request).await?;
                proxy.write_all(&reply).await?;
                proxy.shutdown().await
            };

            let (result, peer) = tokio::join!(operation, peer);
            peer?;
            let error = result.err().ok_or("invalid reply accepted")?;
            assert_eq!(error.kind(), kind);
            assert_eq!(error.reply_status(), status);
            assert_eq!(error.reply_version(), status.map(|_| reply[0]));
            if status.is_none() {
                assert_eq!(
                    error
                        .source()
                        .and_then(|source| source.downcast_ref::<io::Error>())
                        .map(io::Error::kind),
                    Some(io::ErrorKind::UnexpectedEof)
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn deadline_drops_stalled_negotiation_and_closes_proxy_stream()
    -> Result<(), Box<dyn Error>> {
        let (client, mut proxy) = duplex(32);
        let operation = tokio::time::timeout(
            Duration::from_millis(100),
            establish(client, 80, ([127, 0, 0, 1], None), Socks4UserId::default()),
        );
        let peer = async {
            let mut request = [0; 9];
            proxy.read_exact(&mut request).await?;
            let mut remainder = [0];
            assert_eq!(proxy.read(&mut remainder).await?, 0);
            Ok::<_, io::Error>(())
        };

        let (result, peer) = tokio::join!(operation, peer);
        assert!(result.is_err());
        peer?;
        Ok(())
    }

    #[test]
    fn user_id_limits_and_debug_do_not_leak_identification() -> Result<(), Box<dyn Error>> {
        for value in ["private\0marker".to_owned(), "private-marker".repeat(30)] {
            let error = Socks4UserId::new(&value)
                .err()
                .ok_or("invalid user ID accepted")?;
            assert_eq!(error.kind(), Socks4ErrorKind::InvalidUserId);
            assert!(!format!("{error:?} {error}").contains("private"));
        }
        let user = Socks4UserId::new("private-marker")?;
        assert!(!format!("{user:?}").contains("private-marker"));
        Ok(())
    }

    #[test]
    fn a_missing_runtime_is_a_typed_failure() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };

        let mut operation = std::pin::pin!(socks4_tunnel(
            Dialer::default(),
            Endpoint {
                host: "127.0.0.1",
                port: 1080
            },
            Socks4Target::RemoteDns(Endpoint {
                host: "origin.example",
                port: 80
            }),
            Socks4UserId::default()
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(operation.as_mut().poll(&mut context), Poll::Ready(Err(error))
            if error.kind() == Socks4ErrorKind::RuntimeUnavailable)
        );
    }

    #[tokio::test]
    async fn invalid_remote_targets_fail_without_contacting_proxy() -> Result<(), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        for (host, kind) in [
            ("::1", Socks4ErrorKind::UnsupportedTarget),
            ("bad\0domain", Socks4ErrorKind::InvalidTarget),
            ("bücher.example", Socks4ErrorKind::InvalidTarget),
            ("0.0.0.1", Socks4ErrorKind::InvalidTarget),
        ] {
            let error = socks4_tunnel(
                Dialer::default(),
                Endpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                },
                Socks4Target::RemoteDns(Endpoint { host, port: 80 }),
                Socks4UserId::default(),
            )
            .await
            .err()
            .ok_or("invalid target accepted")?;
            assert_eq!(error.kind(), kind);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    }
}
