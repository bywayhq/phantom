use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) struct Frame {
    pub(crate) kind: u8,
    pub(crate) flags: u8,
    pub(crate) stream_id: u32,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn accept_client_preface<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client omitted the HTTP/2 preface",
        ));
    }

    loop {
        let frame = read_frame(stream).await?;
        if frame.kind == 0x4 && frame.stream_id == 0 && frame.flags & 0x1 == 0 {
            break;
        }
    }
    write_frame(stream, 0x4, 0, 0, &[]).await?;
    write_frame(stream, 0x4, 0x1, 0, &[]).await?;
    stream.flush().await
}

pub(crate) async fn read_frame<T>(stream: &mut T) -> io::Result<Frame>
where
    T: AsyncRead + Unpin,
{
    let mut head = [0; 9];
    stream.read_exact(&mut head).await?;
    let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(Frame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
        payload,
    })
}

pub(crate) async fn read_request_headers<T>(stream: &mut T, stream_id: u32) -> io::Result<()>
where
    T: AsyncRead + Unpin,
{
    loop {
        let frame = read_frame(stream).await?;
        if frame.kind == 0x1 && frame.stream_id == stream_id {
            if frame.flags & 0x4 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test request HEADERS required CONTINUATION",
                ));
            }
            return Ok(());
        }
    }
}

pub(crate) async fn write_frame<T>(
    stream: &mut T,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "HTTP/2 frame is too large"))?;
    let length_bytes = length.to_be_bytes();
    let stream_bytes = stream_id.to_be_bytes();
    let head = [
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
        kind,
        flags,
        stream_bytes[0] & 0x7f,
        stream_bytes[1],
        stream_bytes[2],
        stream_bytes[3],
    ];
    stream.write_all(&head).await?;
    stream.write_all(payload).await
}
