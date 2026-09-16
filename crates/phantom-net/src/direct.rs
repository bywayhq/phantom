use tokio::net::TcpStream;

pub(crate) enum DirectConnectError {
    RuntimeUnavailable,
    Connect(std::io::Error),
}

pub(crate) async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    TcpStream::connect((host, port))
        .await
        .map_err(DirectConnectError::Connect)
}
