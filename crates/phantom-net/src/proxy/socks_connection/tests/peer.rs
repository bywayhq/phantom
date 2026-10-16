use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(super) const WAIT: Duration = Duration::from_secs(5);
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Host {
    Ip(IpAddr),
    Domain(String),
}
#[derive(Debug, Eq, PartialEq)]
pub(super) struct Request {
    pub(super) host: Host,
    pub(super) port: u16,
}
pub(super) async fn five(
    stream: &mut TcpStream,
    credentials: Option<(&str, &str)>,
) -> TestResult<Request> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, if credentials.is_some() { 2 } else { 1 }]);
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    assert_eq!(
        methods,
        if credentials.is_some() {
            vec![0, 2]
        } else {
            vec![0]
        }
    );
    stream
        .write_all(&[5, if credentials.is_some() { 2 } else { 0 }])
        .await?;
    if let Some((username, password)) = credentials {
        assert_eq!(stream.read_u8().await?, 1);
        let length = stream.read_u8().await?;
        let mut value = vec![0; usize::from(length)];
        stream.read_exact(&mut value).await?;
        assert_eq!(value, username.as_bytes());
        let length = stream.read_u8().await?;
        let mut value = vec![0; usize::from(length)];
        stream.read_exact(&mut value).await?;
        assert_eq!(value, password.as_bytes());
        stream.write_all(&[1, 0]).await?;
    }
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    assert_eq!(head[..3], [5, 1, 0]);
    let host = match head[3] {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            Host::Ip(Ipv4Addr::from(b).into())
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            Host::Ip(Ipv6Addr::from(b).into())
        }
        3 => {
            let n = stream.read_u8().await?;
            let mut b = vec![0; usize::from(n)];
            stream.read_exact(&mut b).await?;
            Host::Domain(String::from_utf8(b)?)
        }
        _ => return Err("unexpected SOCKS address type".into()),
    };
    Ok(Request {
        host,
        port: stream.read_u16().await?,
    })
}
pub(super) async fn reply(stream: &mut TcpStream, status: u8) -> io::Result<()> {
    // An IPv6 BND address must not become the logical target family.
    let mut response = vec![5, status, 0, 4];
    response.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    response.extend_from_slice(&81u16.to_be_bytes());
    stream.write_all(&response).await
}
pub(super) async fn closed(stream: &mut TcpStream) -> io::Result<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::other(
            "unexpected application bytes on an unused tunnel",
        )),
        Err(e) => Err(e),
    }
}

pub(super) fn no_connection(listener: &tokio::net::TcpListener) {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        listener.poll_accept(&mut context).is_pending(),
        "unexpected extra proxy TCP connection"
    );
}
