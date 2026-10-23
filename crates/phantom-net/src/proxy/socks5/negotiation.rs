use std::{io, net::IpAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_socks::{Error, TargetAddr};
use zeroize::Zeroizing;

use super::{Socks5Auth, Socks5Error, Socks5ErrorKind};

/// Preserve each command's existing write and error-source contract.
#[derive(Clone, Copy)]
pub(in crate::proxy) enum Command {
    Connect,
    Associate,
}

impl Command {
    async fn write(
        self,
        stream: &mut (impl AsyncWrite + Unpin),
        bytes: &[u8],
    ) -> Result<(), Socks5Error> {
        stream
            .write_all(bytes)
            .await
            .map_err(|error| self.io(error))?;
        if matches!(self, Self::Associate) {
            stream.flush().await.map_err(|error| self.io(error))?;
        }
        Ok(())
    }

    async fn read(
        self,
        stream: &mut (impl AsyncRead + Unpin),
        bytes: &mut [u8],
    ) -> Result<(), Socks5Error> {
        stream
            .read_exact(bytes)
            .await
            .map(drop)
            .map_err(|error| self.io(error))
    }

    fn io(self, error: io::Error) -> Socks5Error {
        match self {
            Self::Connect => Socks5Error::negotiation(Error::Io(error)),
            Self::Associate => Socks5Error::io(Socks5ErrorKind::Negotiation, error),
        }
    }

    fn malformed(self, error: Error, message: &'static str) -> Socks5Error {
        match self {
            Self::Connect => Socks5Error::negotiation(error),
            Self::Associate => self.io(io::Error::new(io::ErrorKind::InvalidData, message)),
        }
    }

    fn rejected(self, error: Error) -> Socks5Error {
        match self {
            Self::Connect => Socks5Error::negotiation(error),
            Self::Associate => Socks5Error::without_source(Socks5ErrorKind::Authentication),
        }
    }
}

/// RFC 1928 section 3 and RFC 1929 section 2, shared by both commands.
pub(in crate::proxy) async fn authenticate(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    auth: Socks5Auth<'_>,
    command: Command,
) -> Result<(), Socks5Error> {
    let auth = auth.validate()?;
    let greeting: &[u8] = match auth {
        Socks5Auth::None => &[5, 1, 0],
        Socks5Auth::UsernamePassword { .. } => &[5, 2, 0, 2],
    };
    command.write(stream, greeting).await?;

    let mut selection = [0; 2];
    command.read(stream, &mut selection).await?;
    if selection[0] != 5 {
        return Err(command.malformed(
            Error::InvalidResponseVersion,
            "SOCKS5 method selection used an invalid version",
        ));
    }
    match selection[1] {
        0 => return Ok(()),
        2 => {}
        0xff => return Err(command.rejected(Error::NoAcceptableAuthMethods)),
        _ => {
            return Err(command.malformed(
                Error::UnknownAuthMethod,
                "SOCKS5 proxy selected an unsupported authentication method",
            ));
        }
    }

    let Socks5Auth::UsernamePassword { username, password } = auth else {
        return Err(command.rejected(Error::AuthorizationRequired));
    };
    // RFC 1929 limits both fields to 255 bytes. A fixed buffer avoids adding
    // a credential allocation to CONNECT, and is wiped when setup is dropped.
    let mut request = Zeroizing::new([0; 513]);
    let username_end = 2 + username.len();
    let request_end = username_end + 1 + password.len();
    request[..2].copy_from_slice(&[1, username.len() as u8]);
    request[2..username_end].copy_from_slice(username.as_bytes());
    request[username_end] = password.len() as u8;
    request[username_end + 1..request_end].copy_from_slice(password.as_bytes());
    command.write(stream, &request[..request_end]).await?;
    drop(request);

    let mut response = [0; 2];
    command.read(stream, &mut response).await?;
    if response[0] != 1 {
        return Err(command.malformed(
            Error::InvalidResponseVersion,
            "SOCKS5 authentication response used an invalid version",
        ));
    }
    if response[1] != 0 {
        return Err(command.rejected(Error::PasswordAuthFailure(response[1])));
    }
    Ok(())
}

/// RFC 1928 sections 4 and 6. CONNECT accepts a domain BND.ADDR, unlike
/// UDP ASSOCIATE's relay-address policy. Keep the former error source variants
/// because local target fallback distinguishes individual rejection statuses.
pub(super) async fn connect(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    target: TargetAddr<'_>,
) -> Result<(), Socks5Error> {
    let mut request = [0; 262];
    request[..3].copy_from_slice(&[5, 1, 0]);
    let (address_end, port) = match target {
        TargetAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                request[3] = 1;
                request[4..8].copy_from_slice(&ip.octets());
                (8, address.port())
            }
            IpAddr::V6(ip) => {
                request[3] = 4;
                request[4..20].copy_from_slice(&ip.octets());
                (20, address.port())
            }
        },
        TargetAddr::Domain(domain, port) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                Socks5Error::invalid_target(Error::InvalidTargetAddress("overlong domain"))
            })?;
            request[3] = 3;
            request[4] = length;
            let end = 5 + usize::from(length);
            request[5..end].copy_from_slice(domain.as_bytes());
            (end, port)
        }
    };
    request[address_end..address_end + 2].copy_from_slice(&port.to_be_bytes());
    Command::Connect
        .write(stream, &request[..address_end + 2])
        .await?;

    let mut head = [0; 4];
    Command::Connect.read(stream, &mut head).await?;
    if head[0] != 5 {
        return Err(Socks5Error::negotiation(Error::InvalidResponseVersion));
    }
    if head[2] != 0 {
        return Err(Socks5Error::negotiation(Error::InvalidReservedByte));
    }
    let rejection = match head[1] {
        0 => None,
        1 => Some(Error::GeneralSocksServerFailure),
        2 => Some(Error::ConnectionNotAllowedByRuleset),
        3 => Some(Error::NetworkUnreachable),
        4 => Some(Error::HostUnreachable),
        5 => Some(Error::ConnectionRefused),
        6 => Some(Error::TtlExpired),
        7 => Some(Error::CommandNotSupported),
        8 => Some(Error::AddressTypeNotSupported),
        // tokio-socks 0.5.3 exposed unknown CONNECT status as this source.
        _ => Some(Error::UnknownAuthMethod),
    };
    if let Some(error) = rejection {
        return Err(Socks5Error::negotiation(error));
    }

    let mut address = [0; 257];
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0];
            Command::Connect.read(stream, &mut length).await?;
            usize::from(length[0])
        }
        _ => return Err(Socks5Error::negotiation(Error::UnknownAddressType)),
    };
    Command::Connect
        .read(stream, &mut address[..length + 2])
        .await?;
    if head[3] == 3 && std::str::from_utf8(&address[..length]).is_err() {
        return Err(Socks5Error::negotiation(Error::InvalidTargetAddress(
            "not a valid UTF-8 string",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
