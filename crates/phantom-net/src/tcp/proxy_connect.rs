use std::{io, net::SocketAddr};

use phantom_profile::TcpSettings;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::TcpStream;

use crate::SourceBinding;

/// Keep the initial OS result separate from asynchronous completion.
#[derive(Debug)]
pub(super) enum Failure {
    Initial(io::Error),
    Continuation(io::Error),
    Local(io::Error),
}

pub(super) fn prepare(
    address: SocketAddr,
    settings: Option<TcpSettings>,
    source: Option<&SourceBinding>,
) -> io::Result<Socket> {
    if let Some(settings) = settings {
        super::check_policy_support(&settings)
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    }
    let kind = Type::STREAM;
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "wasi",
    ))]
    let kind = kind.nonblocking();
    let socket = Socket::new(Domain::for_address(address), kind, Some(Protocol::TCP))?;
    if kind == Type::STREAM {
        socket.set_nonblocking(true)?;
    }
    if let Some(settings) = settings {
        super::apply_options(&SockRef::from(&socket), settings)?;
    }
    if let Some(source) = source {
        source.bind_tcp_socket(&SockRef::from(&socket), address)?;
    }
    Ok(socket)
}

pub(super) async fn connect(socket: Socket, address: SocketAddr) -> Result<TcpStream, Failure> {
    if let Err(error) = socket.connect(&address.into())
        && !in_progress(&error)
    {
        return Err(Failure::Initial(error));
    }

    // Match Tokio's connect_mio completion without issuing another connect.
    // Registration/readiness failures are local, not failed DNS candidates.
    let stream = TcpStream::from_std(socket.into()).map_err(Failure::Local)?;
    stream.writable().await.map_err(Failure::Local)?;
    if let Some(error) = stream.take_error().map_err(Failure::Local)? {
        return Err(Failure::Continuation(error));
    }
    Ok(stream)
}

#[cfg(windows)]
fn in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(not(windows))]
fn in_progress(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EINPROGRESS)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn an_initial_socket_error_keeps_its_stage() -> TestResult {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let socket = prepare(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None, None)?;
        let result = connect(socket, listener.local_addr()?).await;

        assert!(matches!(result, Err(Failure::Initial(_))), "{result:?}");
        Ok(())
    }

    #[tokio::test]
    async fn an_asynchronous_refusal_keeps_its_stage() -> TestResult {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        drop(listener);
        let socket = prepare(address, None, None)?;
        let result = timeout(Duration::from_secs(8), connect(socket, address)).await?;

        let Err(Failure::Continuation(error)) = result else {
            return Err(format!("expected an asynchronous refusal, got {result:?}").into());
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        Ok(())
    }

    #[tokio::test]
    async fn completion_preserves_source_options_and_stream_ownership() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let source = SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into());
        let settings = phantom_profile::browser::firefox::v157_tcp();
        let socket = prepare(address, Some(settings), Some(&source))?;
        assert_eq!(
            socket
                .local_addr()?
                .as_socket()
                .ok_or("missing address")?
                .ip(),
            Ipv4Addr::LOCALHOST
        );
        assert!(socket.tcp_nodelay()?);
        let send_buffer = socket.send_buffer_size()?;
        let client = async {
            let mut stream = connect(socket, address)
                .await
                .map_err(|failure| format!("{failure:?}"))?;
            assert_eq!(stream.local_addr()?.ip(), Ipv4Addr::LOCALHOST);
            assert!(stream.nodelay()?);
            assert_eq!(SockRef::from(&stream).send_buffer_size()?, send_buffer);
            stream.write_all(b"proxy").await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(response, b"ready");
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 5];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"proxy");
            stream.write_all(b"ready").await?;
            stream.shutdown().await?;
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await?;
            assert!(rest.is_empty());
            Ok::<_, Box<dyn std::error::Error>>(())
        };

        timeout(Duration::from_secs(8), async {
            tokio::try_join!(client, peer)
        })
        .await??;
        Ok(())
    }
}
