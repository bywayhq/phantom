use std::{future::Future, net::SocketAddr, num::NonZeroUsize};

use bytes::Bytes;
use http::{Method, Response};
use http_body_util::Full;
use phantom::{Client, HttpProtocol, RequestError, RequestHeader, ResponseBody, RetryPolicy};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinError,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{
    EXPECTED_CHUNKED_BODY, OutcomeSubscriber, RETRY_DELAY, SECOND_CONNECTION_WINDOW, TEST_TIMEOUT,
    TestResult, read_head,
};

mod ownership;

type RequestResult = Result<Response<ResponseBody>, RequestError>;
type ServerOutput = (Vec<u8>, Vec<u8>, bool);

pub(super) struct Exchange {
    request: Option<ConnectionPeer<RequestResult>>,
    server: Option<ConnectionPeer<TestResult<ServerOutput>>>,
}

pub(super) fn start(
    address: SocketAddr,
    client: &Client,
    subscriber: &OutcomeSubscriber,
    control: Option<ownership::RequestControl>,
) -> TestResult<Exchange> {
    let request = client
        .request_with_protocol(
            HttpProtocol::Http1,
            Method::POST,
            &format!("http://{address}/retried"),
        )?
        .header(RequestHeader::new("X-First", "one"))
        .header(RequestHeader::new("X-Repeat", "alpha"))
        .header(RequestHeader::new("X-Repeat", "beta"))
        .streaming_body(Full::new(Bytes::from_static(b"payload")))
        .trailers(vec![
            RequestHeader::new("X-Trailer", "first"),
            RequestHeader::new("X-Trailer", "second"),
        ])
        .retry_policy(RetryPolicy::connection_failures(
            NonZeroUsize::MIN,
            RETRY_DELAY,
        ));
    Ok(Exchange::spawn(
        request.send().with_subscriber(subscriber.dispatch()),
        control,
    ))
}

impl Exchange {
    fn spawn(
        request: impl Future<Output = RequestResult> + Send + 'static,
        control: Option<ownership::RequestControl>,
    ) -> Self {
        Self {
            request: Some(ConnectionPeer::spawn(ownership::observe_request(
                request, control,
            ))),
            server: None,
        }
    }

    pub(super) fn listen(&mut self, listener: TcpListener, control: Option<ownership::Control>) {
        self.server = Some(ConnectionPeer::spawn(serve_one_chunked_request(
            listener, control,
        )));
    }

    pub(super) async fn response(&mut self) -> TestResult<Response<ResponseBody>> {
        let request = self
            .request
            .as_mut()
            .ok_or("original retry request task missing")?;
        let joined = timeout(TEST_TIMEOUT, request).await?;
        self.request.take();
        Ok(joined??)
    }

    pub(super) async fn finish<T>(
        mut self,
        caller: TestResult<T>,
    ) -> TestResult<(T, ServerOutput)> {
        let mut request_requested = false;
        let mut server_requested = false;
        if caller.is_err() {
            if let Some(request) = &self.request {
                request_requested = !request.is_finished();
                if request_requested {
                    request.abort();
                }
            }
            if let Some(server) = &self.server {
                server_requested = !server.is_finished();
                if server_requested {
                    server.abort();
                }
            }
        }

        let request = if let Some(mut request) = self.request.take() {
            finish_request(&mut request, request_requested).await
        } else {
            Ok(())
        };
        let primary = finish_with_cleanup(caller, request);
        if primary.is_err()
            && let Some(server) = &self.server
            && !server.is_finished()
        {
            server.abort();
            server_requested = true;
        }

        let server = if let Some(mut server) = self.server.take() {
            finish_server(&mut server, server_requested).await
        } else if primary.is_err() {
            Ok(None)
        } else {
            Err("original retry server task missing".into())
        };
        let (output, cleanup) = match server {
            Ok(output) => (output, Ok(())),
            Err(error) => (None, Err(error)),
        };
        let value = finish_with_cleanup(primary, cleanup)?;
        Ok((value, output.ok_or("original retry server output missing")?))
    }
}

async fn finish_request(
    request: &mut ConnectionPeer<RequestResult>,
    mut requested: bool,
) -> TestResult<()> {
    match timeout(TEST_TIMEOUT, &mut *request).await {
        Ok(joined) => request_outcome(joined, requested),
        Err(elapsed) => {
            if !request.is_finished() {
                request.abort();
                requested = true;
            }
            let cleanup = match timeout(TEST_TIMEOUT, request).await {
                Ok(joined) => request_outcome(joined, requested),
                Err(error) => Err(error.into()),
            };
            finish_with_cleanup(Err(elapsed.into()), cleanup)
        }
    }
}

fn request_outcome(joined: Result<RequestResult, JoinError>, requested: bool) -> TestResult<()> {
    match joined {
        Ok(result) => result.map(|_| ()).map_err(Into::into),
        Err(error) if requested && error.is_cancelled() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn finish_server(
    server: &mut ConnectionPeer<TestResult<ServerOutput>>,
    mut requested: bool,
) -> TestResult<Option<ServerOutput>> {
    match timeout(TEST_TIMEOUT, &mut *server).await {
        Ok(joined) => server_outcome(joined, requested),
        Err(elapsed) => {
            if !server.is_finished() {
                server.abort();
                requested = true;
            }
            let cleanup = match timeout(TEST_TIMEOUT, server).await {
                Ok(joined) => server_outcome(joined, requested).map(|_| ()),
                Err(error) => Err(error.into()),
            };
            finish_with_cleanup(Err(elapsed.into()), cleanup)
        }
    }
}

fn server_outcome(
    joined: Result<TestResult<ServerOutput>, JoinError>,
    requested: bool,
) -> TestResult<Option<ServerOutput>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn serve_one_chunked_request(
    listener: TcpListener,
    control: Option<ownership::Control>,
) -> TestResult<ServerOutput> {
    let (stream, _) = listener.accept().await?;
    let mut stream = ownership::ObservedStream::new(stream, control);
    let head = read_head(&mut stream).await?;
    let mut framed = vec![0_u8; EXPECTED_CHUNKED_BODY.len()];
    stream.read_exact(&mut framed).await?;
    stream.body_read(&head, &framed);
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.flush().await?;
    let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
    Ok((head, framed, second.is_err()))
}
