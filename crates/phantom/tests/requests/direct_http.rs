//! Public direct plaintext HTTP/1.1 integration tests.

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader, RequestTrailerName, ResponseInfo,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    h3 as h3_support, tls as tls_support,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};
use h3_support::client_settings;
use tls_support::{TestResult, read_head, tls_settings};

mod owner_contract;

type Peer<T> = ConnectionPeer<TestResult<T>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const NO_CONNECTION_WINDOW: Duration = Duration::from_millis(100);

#[tokio::test]
async fn direct_http1_preserves_origin_form_order_and_streaming_body() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = streaming_origin(listener, None);

        let caller = async {
            let client = http1_client()?;
            let response = client
                .request(
                    HttpProtocol::Http1,
                    Method::POST,
                    &format!("http://{address}/a/%2e%2e/final?value=%2f"),
                )?
                .headers(vec![
                    RequestHeader::new("X-First", "one"),
                    RequestHeader::new("x-repeat", "alpha"),
                    RequestHeader::new("X-Repeat", "beta"),
                ])
                .streaming_body(UnknownBody::new([
                    b"alpha".as_slice(),
                    b"beta".as_slice(),
                ]))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "direct");
            Ok(Some(client))
        }
        .await;
        let (_client, (head, framed)) = finish_peer(caller, server).await?;
        assert_eq!(
            head,
            format!(
                "POST /a/%2e%2e/final?value=%2f HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(framed, b"5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn bounded_collection_accepts_exact_limit_and_rejects_excess() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = spawn_peer(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                read_head(&mut stream).await?;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
                    )
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let caller = async {
            let client = http1_client()?;
            let exact = client
                .get(HttpProtocol::Http1, &format!("http://{address}/exact"))?
                .send()
                .await?
                .into_body()
                .collect_with_limit(6)
                .await?;
            assert_eq!(exact, "direct");

            let Err(error) = client
                .get(HttpProtocol::Http1, &format!("http://{address}/excess"))?
                .send()
                .await?
                .into_body()
                .collect_with_limit(5)
                .await
            else {
                return Err("body larger than the collection limit was accepted".into());
            };
            assert_eq!(error.kind(), RequestErrorKind::ResponseBodyLimit);
            Ok(Some(client))
        }
        .await;
        let (_client, ()) = finish_peer(caller, server).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_builder_sends_exact_ordered_dynamic_http1_request_trailers() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = spawn_peer(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let mut framed = Vec::new();
            while !framed.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                framed.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, framed))
        });

        let caller = async {
            let client = http1_client()?;
            let Err(conflict) = client
                .request(
                    HttpProtocol::Http1,
                    Method::POST,
                    &format!("http://{address}/conflicting-trailers"),
                )?
                .streaming_body_with_trailers(trailer_body(), trailer_names())
                .trailers(vec![RequestHeader::new("X-Static", "value")])
                .send()
                .await
            else {
                return Err("static and dynamic trailers must conflict".into());
            };
            assert_eq!(conflict.kind(), RequestErrorKind::RequestBody);

            let response = client
                .request(
                    HttpProtocol::Http1,
                    Method::POST,
                    &format!("http://{address}/trailers"),
                )?
                .header(RequestHeader::new("X-Before", "head"))
                .streaming_body_with_trailers(trailer_body(), trailer_names())
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
            Ok(Some(client))
        }
        .await;
        let (_client, (head, framed)) = finish_peer(caller, server).await?;
        assert_eq!(
            head,
            format!(
                "POST /trailers HTTP/1.1\r\nHost: {address}\r\nX-Before: head\r\nTransfer-Encoding: chunked\r\nTrailer: X-Repeat, X-Middle\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            framed,
            b"7\r\npayload\r\n0\r\nX-Repeat: alpha\r\nX-Middle: between\r\nX-Repeat: beta\r\n\r\n"
        );
        Ok(())
    })
    .await
}

fn trailer_names() -> Vec<RequestTrailerName> {
    vec![
        RequestTrailerName::new("X-Repeat"),
        RequestTrailerName::new("X-Middle"),
        RequestTrailerName::new("X-Repeat"),
    ]
}

fn trailer_body() -> TrailerBody {
    let mut trailers = HeaderMap::new();
    trailers.append("x-repeat", HeaderValue::from_static("alpha"));
    trailers.insert("x-middle", HeaderValue::from_static("between"));
    trailers.append("x-repeat", HeaderValue::from_static("beta"));
    TrailerBody {
        frames: [
            Frame::data(Bytes::from_static(b"payload")),
            Frame::trailers(trailers),
        ]
        .into(),
    }
}

struct TrailerBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl Body for TrailerBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front().map(Ok))
    }
}

#[tokio::test]
async fn direct_http1_reuses_same_origin_connection() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = spawn_peer(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
                .await?;
            let opened_another = timeout(NO_CONNECTION_WINDOW, listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second, opened_another))
        });

        let caller = async {
            let client = http1_client()?;
            for (path, expected) in [("first", "first"), ("second", "second")] {
                let response = client
                    .get(HttpProtocol::Http1, &format!("http://{address}/{path}"))?
                    .send()
                    .await?;
                assert_eq!(response_protocol(&response)?, HttpProtocol::Http1);
                assert_eq!(response.into_body().collect().await?.to_bytes(), expected);
            }
            Ok(Some(client))
        }
        .await;
        let (_client, (first, second, opened_another)) = finish_peer(caller, server).await?;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(!opened_another);
        Ok(())
    })
    .await
}

// A loopback `http://` origin is potentially trustworthy, so Chromium sends
// and learns client hints there, as the retained Chrome 154 client-hint
// capture on `http://127.0.0.1` shows. A named plaintext origin gets none;
// `forward_proxy.rs` covers it through a proxy.
#[tokio::test]
async fn direct_plaintext_loopback_sends_and_learns_client_hints() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = spawn_peer(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
        });

        let caller = async {
            let hints = ClientHintSettings::new(vec![
                ClientHint::new("sec-ch-ua", "profile", ClientHintDelivery::Default),
                ClientHint::new(
                    "sec-ch-ua-arch",
                    "\"arm\"",
                    ClientHintDelivery::AcceptCh,
                ),
            ]);
            let profile = ClientProfile::new(tls_settings()).with_client_hints(hints);
            let builder = Client::builder(profile);
            let session = builder.build()?;

            for path in ["first", "second"] {
                session
                    .get(HttpProtocol::Http1, &format!("http://{address}/{path}"))?
                    .send()
                    .await?
                    .into_body()
                    .collect()
                    .await?;
            }
            Ok(Some(session))
        }
        .await;
        let (_client, (first, second)) = finish_peer(caller, server).await?;
        let first = std::str::from_utf8(&first)?.to_ascii_lowercase();
        let second = std::str::from_utf8(&second)?.to_ascii_lowercase();
        assert!(first.contains("\r\nsec-ch-ua: profile\r\n"));
        assert!(!first.contains("sec-ch-ua-arch"));
        assert!(second.contains("\r\nsec-ch-ua: profile\r\n"));
        assert!(second.contains("\r\nsec-ch-ua-arch: \"arm\"\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_http1_plaintext_fails_before_tcp_io() -> TestResult<()> {
    bounded(async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile).build()?;
        let target = format!("http://{origin_address}/unsupported");

        for protocol in [HttpProtocol::Http2, HttpProtocol::Http3] {
            let error = client
                .get(protocol, &target)?
                .send()
                .await
                .err()
                .ok_or("non-HTTP/1 plaintext request unexpectedly succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::UnsupportedScheme);
        }
        assert!(
            timeout(NO_CONNECTION_WINDOW, origin.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await
}

fn http1_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings())).build()?)
}

fn response_protocol(response: &http::Response<phantom::ResponseBody>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted facade metadata".into())
}

struct UnknownBody {
    chunks: VecDeque<Bytes>,
}

impl UnknownBody {
    fn new<const N: usize>(chunks: [&'static [u8]; N]) -> Self {
        Self {
            chunks: chunks.into_iter().map(Bytes::from_static).collect(),
        }
    }
}

impl Body for UnknownBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.chunks.pop_front().map(Frame::data).map(Ok))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn streaming_origin(
    listener: TcpListener,
    mut control: Option<owner_contract::Control>,
) -> Peer<(Vec<u8>, Vec<u8>)> {
    spawn_peer(async move {
        let (mut stream, _) = listener.accept().await?;
        let _life = control.as_ref().map(owner_contract::Control::life);
        let head = owner_contract::observe_head(&mut stream, &mut control).await?;
        let mut framed = Vec::new();
        while !framed.ends_with(b"0\r\n\r\n") {
            let mut byte = [0_u8; 1];
            owner_contract::observe_byte(&mut stream, &mut byte, control.as_ref()).await?;
            framed.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect")
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, framed))
    })
}

fn spawn_peer<T: Send + 'static>(
    future: impl Future<Output = TestResult<T>> + Send + 'static,
) -> Peer<T> {
    ConnectionPeer::spawn(future)
}

async fn finish_peer<T: Send + 'static>(
    caller: TestResult<Option<Client>>,
    mut peer: Peer<T>,
) -> TestResult<(Option<Client>, T)> {
    match caller {
        Ok(client) => {
            let observed = timeout(TEST_TIMEOUT, &mut peer)
                .await
                .map_err(|elapsed| {
                    FixtureDeadline::new("direct HTTP peer cleanup exceeded its deadline", elapsed)
                })???;
            Ok((client, observed))
        }
        Err(primary) => {
            let requested = !peer.is_finished();
            if requested {
                peer.abort();
            }

            let cleanup = match timeout(TEST_TIMEOUT, &mut peer).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "direct HTTP peer cleanup exceeded its deadline",
                    elapsed,
                )
                .into()),
            };
            finish_with_cleanup(Err(primary), cleanup)
        }
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future).await.map_err(|elapsed| {
        FixtureDeadline::new("direct HTTP test exceeded its deadline", elapsed)
    })?
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::poll_fn, io, task::Poll};

    use super::{TestResult, bounded};

    #[tokio::test(start_paused = true)]
    async fn entered_pending_deadline_retains_its_original_elapsed() -> TestResult<()> {
        let entered = Cell::new(false);
        let operation = bounded(poll_fn(|_| {
            entered.set(true);
            Poll::<TestResult<()>>::Pending
        }));
        tokio::pin!(operation);
        assert!(futures_util::poll!(&mut operation).is_pending());
        assert!(entered.get(), "the actual operation was not polled");
        tokio::time::advance(super::TEST_TIMEOUT).await;

        let error = operation.await.err().ok_or("pending operation succeeded")?;
        assert_eq!(error.to_string(), "direct HTTP test exceeded its deadline");
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()),
            "the fixture deadline discarded its original Elapsed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_the_original_operation_error() -> TestResult<()> {
        let failure = io::Error::new(io::ErrorKind::PermissionDenied, "fixture operation failed");
        let error = bounded(async { Err(failure.into()) })
            .await
            .err()
            .ok_or("failed operation succeeded")?;
        let original = error
            .downcast_ref::<io::Error>()
            .ok_or("operation error type changed")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(original.to_string(), "fixture operation failed");
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_success() -> TestResult<()> {
        bounded(async { Ok(()) }).await
    }
}
