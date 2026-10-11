use std::{future::Future, net::SocketAddr, num::NonZeroUsize};

use bytes::Bytes;
use http::{Method, Response};
use http_body_util::Full;
use phantom::{Client, HttpProtocol, RequestError, RequestHeader, ResponseBody, RetryPolicy};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{
    EXPECTED_CHUNKED_BODY, OutcomeSubscriber, RETRY_DELAY, SECOND_CONNECTION_WINDOW, TestResult,
    read_head,
};

mod ownership;

type RequestResult = Result<Response<ResponseBody>, RequestError>;
type ServerOutput = (Vec<u8>, Vec<u8>, bool);

pub(super) struct Exchange {
    request: Option<JoinHandle<RequestResult>>,
    server: Option<JoinHandle<TestResult<ServerOutput>>>,
}

pub(super) fn start(
    address: SocketAddr,
    client: &Client,
    subscriber: &OutcomeSubscriber,
    control: Option<ownership::RequestControl>,
) -> TestResult<Exchange> {
    let request = client
        .request(
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
            request: Some(tokio::spawn(ownership::observe_request(request, control))),
            server: None,
        }
    }

    pub(super) fn listen(&mut self, listener: TcpListener, control: Option<ownership::Control>) {
        self.server = Some(tokio::spawn(serve_one_chunked_request(listener, control)));
    }

    pub(super) async fn response(&mut self) -> TestResult<Response<ResponseBody>> {
        Ok(self
            .request
            .take()
            .ok_or("original retry request task missing")?
            .await??)
    }

    pub(super) async fn finish<T>(self, caller: TestResult<T>) -> TestResult<(T, ServerOutput)> {
        let value = caller?;
        let output = self
            .server
            .ok_or("original retry server task missing")?
            .await??;
        Ok((value, output))
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
