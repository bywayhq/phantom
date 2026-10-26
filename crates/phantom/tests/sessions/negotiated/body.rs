use std::{future::poll_fn, io, task::Poll};

use bytes::Bytes;
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::TestResult;

const REQUEST_BODY_BYTES: usize = b"payload".len();
const RESPONSE_BODY_BYTES: usize = b"first".len();
const FRAMED_TRAILER_BYTES: usize =
    b"7\r\npayload\r\n0\r\nx-repeat: alpha\r\nx-middle: between\r\nx-repeat: beta\r\n\r\n".len();

pub(super) async fn collect_response(body: phantom::ResponseBody) -> TestResult<Bytes> {
    Ok(body.collect_with_limit(RESPONSE_BODY_BYTES).await?)
}

pub(super) fn append_request_data(body: &mut Vec<u8>, chunk: &[u8]) -> io::Result<()> {
    if chunk.len() > REQUEST_BODY_BYTES.saturating_sub(body.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negotiated request body exceeded its fixture extent",
        ));
    }

    body.extend_from_slice(chunk);
    Ok(())
}

pub(super) async fn read_framed_trailers(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<Vec<u8>> {
    let mut framed = Vec::new();
    while !framed.ends_with(b"\r\n\r\n") {
        if framed.len() == FRAMED_TRAILER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negotiated chunked request exceeded its fixture extent",
            ));
        }

        framed.push(stream.read_u8().await?);
    }
    Ok(framed)
}

pub(super) async fn next_h2_request_data<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Option<Bytes>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|context| -> Poll<TestResult<Option<Bytes>>> {
        if let Poll::Ready(item) = body.poll_data(context) {
            return Poll::Ready(item.transpose().map_err(Into::into));
        }
        match connection.poll_closed(context) {
            // Driving EOF also updates the stream. Observe that actual outcome.
            Poll::Ready(Ok(())) => match body.poll_data(context) {
                Poll::Ready(item) => Poll::Ready(item.transpose().map_err(Into::into)),
                Poll::Pending => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "negotiated connection closed before request data completed",
                )
                .into())),
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

pub(super) async fn next_h2_request_trailers<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Option<HeaderMap>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|context| -> Poll<TestResult<Option<HeaderMap>>> {
        if let Poll::Ready(item) = body.poll_trailers(context) {
            return Poll::Ready(item.map_err(Into::into));
        }
        match connection.poll_closed(context) {
            Poll::Ready(Ok(())) => match body.poll_trailers(context) {
                Poll::Ready(item) => Poll::Ready(item.map_err(Into::into)),
                Poll::Pending => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "negotiated connection closed before request trailers completed",
                )
                .into())),
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::Ipv4Addr,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncRead, AsyncWriteExt, ReadBuf},
        net::TcpListener,
        sync::oneshot,
    };

    use super::super::{Peer, bounded, finish, join, write_frame};
    use super::{
        TestResult, append_request_data, collect_response, next_h2_request_data,
        next_h2_request_trailers, read_framed_trailers,
    };

    #[tokio::test]
    async fn literal_request_extents_remain_bounded_and_read_errors_keep_their_cause()
    -> TestResult<()> {
        let mut body = Vec::new();
        append_request_data(&mut body, b"pay")?;
        append_request_data(&mut body, b"load")?;
        assert_eq!(body, b"payload");
        assert_eq!(
            append_request_data(&mut body, b"!")
                .err()
                .ok_or("eighth byte must fail")?
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(body, b"payload");

        let literal =
            b"7\r\npayload\r\n0\r\nx-repeat: alpha\r\nx-middle: between\r\nx-repeat: beta\r\n\r\n";
        assert_eq!(
            read_framed_trailers(&mut literal.as_slice()).await?,
            literal
        );
        let oversized = vec![b'x'; literal.len() + 1];
        let mut input = oversized.as_slice();
        assert_eq!(
            read_framed_trailers(&mut input)
                .await
                .err()
                .ok_or("unterminated input must stop at the literal extent")?
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.len(), 1, "guard must run before reading another byte");

        let error = read_framed_trailers(&mut FailedRead)
            .await
            .err()
            .ok_or("local reader fault must propagate")?;
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.get_ref().is_some_and(|cause| cause.is::<ReadFault>()));
        Ok(())
    }

    #[tokio::test]
    async fn clean_h2_transport_eof_keeps_unfinished_stream_data_and_trailer_errors()
    -> TestResult<()> {
        for trailers in [false, true] {
            let mut peer = None;
            let result = bounded(async {
                let (server, mut client) = tokio::io::duplex(4096);
                let (accepted, wait_for_accept) = oneshot::channel();
                peer = Some(Peer::spawn(async move {
                    client
                        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                        .await?;
                    write_frame(&mut client, 0x4, 0, 0, &[]).await?;
                    // POST / over HTTP, with authority localhost and no END_STREAM.
                    write_frame(&mut client, 0x1, 0x4, 1, b"\x83\x86\x84\x41\x09localhost").await?;
                    wait_for_accept.await?;
                    client.shutdown().await?;
                    tokio::io::copy(&mut client, &mut tokio::io::sink()).await?;
                    TestResult::Ok(())
                }));
                let mut connection = ::http2::server::handshake(server).await?;
                let (request, respond) = connection
                    .accept()
                    .await
                    .ok_or("missing unfinished raw request")??;
                assert_eq!(request.method(), http::Method::POST);
                let mut body = request.into_body();
                accepted
                    .send(())
                    .map_err(|_| "raw peer stopped before acceptance")?;

                let error = if trailers {
                    next_h2_request_trailers(&mut connection, &mut body)
                        .await
                        .err()
                        .ok_or("transport EOF must not manufacture absent trailers")?
                } else {
                    next_h2_request_data(&mut connection, &mut body)
                        .await
                        .err()
                        .ok_or("transport EOF must not manufacture completed request data")?
                };
                let stream_error = error
                    .downcast_ref::<::http2::Error>()
                    .ok_or("missing actual HTTP/2 stream error")?;
                assert_eq!(
                    stream_error
                        .get_io()
                        .ok_or("missing original stream I/O classification")?
                        .kind(),
                    io::ErrorKind::BrokenPipe
                );
                drop(body);
                drop(respond);
                std::future::poll_fn(|context| connection.poll_closed(context)).await?;
                join(&mut peer).await?;
                Ok(())
            })
            .await;
            finish(result, &mut peer).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn oversized_actual_response_keeps_the_typed_body_limit_error() -> TestResult<()> {
        let mut peer = None;
        let result = bounded(async {
            let identity = crate::support::tls::TestIdentity::generate()?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            peer = Some(Peer::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let head = crate::support::tls::read_head(&mut stream).await?;
                assert!(head.starts_with(b"GET /extent HTTP/1.1\r\n"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nlonger")
                    .await?;
                TestResult::Ok(())
            }));
            let response = crate::support::tls::test_client(&identity, true)?
                .get(&format!("http://{address}/extent"))?
                .send()
                .await?;
            let error = collect_response(response.into_body())
                .await
                .err()
                .ok_or("six bytes must exceed the five-byte response fixture extent")?;
            assert_eq!(
                error
                    .downcast_ref::<phantom::RequestError>()
                    .ok_or("missing original bounded collector error")?
                    .kind(),
                phantom::RequestErrorKind::ResponseBodyLimit
            );
            join(&mut peer).await?;
            Ok(())
        })
        .await;
        finish(result, &mut peer).await
    }

    struct FailedRead;

    impl AsyncRead for FailedRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ReadFault,
            )))
        }
    }

    #[derive(Debug)]
    struct ReadFault;

    impl std::fmt::Display for ReadFault {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("original negotiated input fault")
        }
    }

    impl std::error::Error for ReadFault {}
}
