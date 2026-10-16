use super::*;
use std::task::Poll;
use tokio::{io::AsyncRead, net::TcpStream};
pub(super) async fn negotiate(
    listener: &TcpListener,
    socks: Socks,
    port: u16,
    password: &str,
) -> TestResult<TcpStream> {
    let (mut stream, _) = listener.accept().await?;
    match socks {
        Socks::Four => {
            let mut header = [0; 8];
            stream.read_exact(&mut header).await?;
            let [hi, lo] = port.to_be_bytes();
            assert_eq!(header, [4, 1, hi, lo, 0, 0, 0, 1]);
            assert_eq!(nul(&mut stream).await?, b"owner");
            assert_eq!(nul(&mut stream).await?, HOST.as_bytes());
        }
        Socks::FiveRemote | Socks::FiveLocal => {
            let mut greeting = [0; 4];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await?;
            assert_eq!(stream.read_u8().await?, 1);
            assert_eq!(length(&mut stream).await?, b"user");
            assert_eq!(length(&mut stream).await?, password.as_bytes());
            stream.write_all(&[1, 0]).await?;
            let mut header = [0; 4];
            stream.read_exact(&mut header).await?;
            assert_eq!(
                header,
                [
                    5,
                    1,
                    0,
                    if matches!(socks, Socks::FiveRemote) {
                        3
                    } else {
                        1
                    }
                ]
            );
            if matches!(socks, Socks::FiveRemote) {
                assert_eq!(length(&mut stream).await?, HOST.as_bytes());
            } else {
                let mut ip = [0; 4];
                stream.read_exact(&mut ip).await?;
                assert_eq!(ip, Ipv4Addr::LOCALHOST.octets());
            }
            assert_eq!(stream.read_u16().await?, port);
        }
    }
    Ok(stream)
}
pub(super) async fn reply(stream: &mut TcpStream, socks: Socks) -> io::Result<()> {
    stream
        .write_all(if matches!(socks, Socks::Four) {
            &[0, 90, 0, 0, 0, 0, 0, 0]
        } else {
            &[5, 0, 0, 1, 127, 0, 0, 2, 0, 81]
        })
        .await
}
pub(super) async fn quiet(
    stream: &mut (impl AsyncRead + Unpin),
    claimed: oneshot::Receiver<()>,
    ack: oneshot::Sender<()>,
) -> TestResult<()> {
    let mut byte = [0];
    tokio::select! {
        biased;
        read = stream.read(&mut byte) => {
            return Err(format!("unclaimed SOCKS tunnel sent origin bytes or closed: {read:?}").into());
        }
        ready = claimed => ready?,
    }
    ack.send(()).map_err(|_| "claim owner ended")?;
    Ok(())
}
pub(super) async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if crate::support::tls::is_peer_gone(&error) => Ok(()),
        other => Err(format!("quiet tunnel was not retired: {other:?}").into()),
    }
}
pub(super) fn no_redial(listener: &TcpListener) -> TestResult<()> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(listener.poll_accept(&mut context), Poll::Pending),
        "claim redialed the proxy"
    );
    Ok(())
}
async fn length(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u8().await?;
    let mut bytes = vec![0; usize::from(length)];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn nul(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            return Ok(bytes);
        }
        if bytes.len() == 255 {
            return Err(io::Error::other("unbounded SOCKS4 field"));
        }
        bytes.push(byte)
    }
}
