use std::{io, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::super::{MAX_BODY_BYTES, TestResult, bounded, read_frame, read_until_closed};
use super::{finish, join};
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

#[tokio::test]
async fn an_oversized_http2_frame_is_rejected_before_its_payload_arrives() -> TestResult {
    let (mut sender, mut reader) = duplex(32);
    sender.write_all(&[0, 0x40, 1, 0, 0, 0, 0, 0, 1]).await?;

    // Keep the sender open: success must come from the header bound, not EOF.
    let result = timeout(Duration::from_secs(1), read_frame(&mut reader))
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("oversized HTTP/2 frame waited for its payload", elapsed)
        })?;

    match result {
        Err(error)
            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                error.kind() == io::ErrorKind::InvalidData
                    && error.to_string() == "expect-continue HTTP/2 frame exceeded byte bound"
            }) =>
        {
            Ok(())
        }
        Err(error) => finish_with_cleanup(
            Err(error),
            Err("original HTTP/2 frame bound cause missing".into()),
        ),
        Ok(_) => Err("oversized HTTP/2 frame was accepted".into()),
    }
}

#[tokio::test]
async fn an_http1_close_tail_cannot_accumulate_more_than_its_byte_bound() -> TestResult {
    let mut sender = None;
    let result = bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        sender = Some(ConnectionPeer::spawn(async move {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(&vec![b'x'; MAX_BODY_BYTES + 1]).await?;
            stream.shutdown().await?;
            TestResult::Ok(())
        }));

        let (mut stream, _) = listener.accept().await?;
        let result = read_until_closed(&mut stream).await;

        match result {
            Err(error)
                if error.downcast_ref::<io::Error>().is_some_and(|error| {
                    error.kind() == io::ErrorKind::InvalidData
                        && error.to_string() == "expect-continue close tail exceeded byte bound"
                }) => {}
            Err(error) => {
                return finish_with_cleanup(
                    Err(error),
                    Err("original HTTP/1 close-tail bound cause missing".into()),
                );
            }
            Ok(_) => return Err("oversized HTTP/1 close tail was accepted".into()),
        }

        join(&mut sender).await?;
        Ok(())
    })
    .await;

    finish(result, sender).await
}
