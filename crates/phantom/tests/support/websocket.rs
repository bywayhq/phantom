use std::{future::Future, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::tls::{TestResult, accept_tls, read_head};

pub(crate) const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ClientFrame {
    pub(crate) rsv1: bool,
    pub(crate) opcode: u8,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn read_client_frame(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<ClientFrame> {
    let mut head = [0_u8; 2];
    stream.read_exact(&mut head).await?;
    if head[1] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client frame was not masked",
        ));
    }
    let mut length = u64::from(head[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream.read_exact(&mut extended).await?;
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream.read_exact(&mut extended).await?;
        length = u64::from_be_bytes(extended);
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    let mut mask = [0_u8; 4];
    stream.read_exact(&mut mask).await?;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    Ok(ClientFrame {
        rsv1: head[0] & 0x40 != 0,
        opcode: head[0] & 0x0f,
        payload,
    })
}

pub(crate) fn append_server_frame(
    output: &mut Vec<u8>,
    final_frame: bool,
    opcode: u8,
    payload: &[u8],
) {
    append_server_frame_with_rsv1(output, final_frame, false, opcode, payload);
}

pub(crate) fn append_server_frame_with_rsv1(
    output: &mut Vec<u8>,
    final_frame: bool,
    rsv1: bool,
    opcode: u8,
    payload: &[u8],
) {
    output.push((u8::from(final_frame) << 7) | (u8::from(rsv1) << 6) | opcode);
    if payload.len() < 126 {
        output.push(payload.len() as u8);
    } else if payload.len() <= usize::from(u16::MAX) {
        output.push(126);
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        output.push(127);
        output.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    output.extend_from_slice(payload);
}

pub(crate) async fn append_and_write_server_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    final_frame: bool,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::new();
    append_server_frame(&mut frame, final_frame, opcode, payload);
    stream.write_all(&frame).await?;
    stream.flush().await
}

pub(crate) fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

pub(crate) fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    btls::base64::encode_block(&btls::sha::sha1(&input))
}

pub(crate) async fn forward_one_connect(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<Vec<u8>> {
    let (mut downstream, _) = listener.accept().await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

pub(crate) async fn forward_one_https_connect(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    origin: std::net::SocketAddr,
) -> TestResult<Vec<u8>> {
    let mut downstream = accept_tls(listener, acceptor).await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(request)
}

pub(crate) async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "WebSocket integration test exceeded its deadline")?
}
