//! Owned request inputs and bounded uploads.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use napi::Result;
use phantom::{HttpAttemptBudget, HttpProtocol, Method, RequestBuilder, RequestHeader};
use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    client::ClientState,
    error::{failure, request},
    ffi::{RedirectHistoryInfo, RedirectHopInfo, RequestOptions, positive_count},
    response::{Exchange, Pending},
};

pub(crate) const MAXIMUM_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAXIMUM_HEADER_BYTES: usize = 64 * 1024;

pub(crate) struct ResponseHead {
    pub(crate) status: u32,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) protocol: String,
    pub(crate) url: String,
    pub(crate) redirects: u32,
    pub(crate) connection_retries: u32,
    pub(crate) decoded_content_codings: Vec<String>,
    pub(crate) redirect_history: Option<RedirectHistoryInfo>,
}

pub(crate) struct Prepared {
    builder: RequestBuilder,
    file: Option<(String, u64)>,
    exchange: Arc<Exchange>,
    _pending: Pending,
}

pub(crate) enum BodyInput {
    Bytes(Vec<u8>),
    Stream(Arc<crate::upload::Upload>),
}

impl Prepared {
    pub(crate) fn new(
        client: &Arc<ClientState>,
        options: RequestOptions,
        headers: Vec<RequestHeader>,
        body: Option<BodyInput>,
        started: Instant,
        exchange: Arc<Exchange>,
        budget: Option<HttpAttemptBudget>,
    ) -> Result<Self> {
        if client.is_closed() {
            return Err(failure("ClientClosed", "client is closed"));
        }
        if options.url.len() > 64 * 1024 || options.method.len() > 64 {
            return Err(failure(
                "InputLimit",
                "request target or method exceeds the binding limit",
            ));
        }
        let protocol = match options.protocol.as_str() {
            "http1" => Some(HttpProtocol::Http1),
            "http2" => Some(HttpProtocol::Http2),
            "http3" => Some(HttpProtocol::Http3),
            "negotiated" => None,
            _ => {
                return Err(failure(
                    "InvalidProtocol",
                    "choose http1, http2, http3 or negotiated explicitly",
                ));
            }
        };
        let method = Method::from_bytes(options.method.as_bytes())
            .map_err(|_| failure("InvalidMethod", "invalid HTTP method"))?;
        let mut builder = match protocol {
            Some(protocol) => client.core.request(protocol, method, &options.url),
            None => client.core.request_negotiated(method, &options.url),
        }
        .map_err(request)?
        .headers(headers);
        if let Some(policy) = options.content_decoding {
            builder = builder.content_decoding(policy.policy()?);
        }
        if let Some(policy) = options.redirect_policy {
            builder = builder.redirect_policy(policy.policy()?);
        }
        if let Some(policy) = options.retry_policy {
            builder = builder.retry_policy(crate::retry::policy(policy)?);
        }
        if let Some(maximum) = options.redirect_history_limit {
            builder = builder.redirect_history(positive_count(maximum)?);
        }
        if let Some(prepared) = client.profile.template(&options.context)? {
            builder = builder.template(&prepared);
        }
        if body.is_some() && options.file.is_some() {
            return Err(failure(
                "InvalidBody",
                "choose one byte, file or streaming body",
            ));
        }
        let upload = match body {
            Some(BodyInput::Bytes(body)) => {
                builder = builder.body(body);
                None
            }
            Some(BodyInput::Stream(upload)) => Some(upload),
            None => None,
        };
        let file = options
            .file
            .map(|file| (file.path, u64::from(file.maximum_bytes)));
        if file
            .as_ref()
            .is_some_and(|(path, _)| path.is_empty() || path.len() > 4096)
        {
            return Err(failure(
                "InputLimit",
                "file path must contain 1..4096 UTF-8 bytes",
            ));
        }
        if let Some(budget) = budget {
            builder = builder.attempt_budget(budget);
        }
        let timeouts = options.timeouts.unwrap_or_default();
        if options.timeout_ms.is_some() && timeouts.total.is_some() {
            return Err(failure(
                "InvalidTimeout",
                "choose timeoutMs or timeouts.totalMs, not both",
            ));
        }
        let mut overrides = timeouts.overrides()?;
        if let Some(milliseconds) = options.timeout_ms {
            overrides = overrides.total(phantom::TimeoutOverride::Limit(Duration::from_millis(
                u64::from(milliseconds),
            )));
        }
        let deadline = overrides
            .resolve(client.timeouts)
            .total_duration()
            .map(|duration| {
                started
                    .checked_add(duration)
                    .ok_or_else(|| failure("InvalidTimeout", "deadline cannot be represented"))
            })
            .transpose()?;
        builder = builder.timeouts(overrides);
        let permit = Arc::clone(&client.admission)
            .try_acquire_owned()
            .map_err(|_| failure("Capacity", "client has no free request slots"))?;
        exchange.claim(permit, deadline)?;
        let pending = Pending::new(Arc::clone(&exchange), Arc::clone(client));
        client.register(&exchange)?;
        if let Some(upload) = upload {
            builder = builder.streaming_body(upload.body()?);
            exchange.upload(upload);
        }
        Ok(Self {
            builder,
            file,
            exchange,
            _pending: pending,
        })
    }

    pub(crate) async fn send(self) -> Result<(ResponseHead, Arc<Exchange>)> {
        let Self {
            mut builder,
            file,
            exchange,
            _pending,
        } = self;
        if exchange.upload_state().is_some() {
            let exchange = Arc::clone(&exchange);
            drop(tokio::spawn(async move {
                tokio::select! { biased; () = exchange.finished() => {}, _ = exchange.interrupted() => exchange.fail() }
            }));
        }
        let send = async {
            if let Some((path, maximum)) = file {
                let file = tokio::fs::File::open(path)
                    .await
                    .map_err(|_| failure("FileIo", "could not open upload file"))?;
                let metadata = file
                    .metadata()
                    .await
                    .map_err(|_| failure("FileIo", "could not inspect upload file"))?;
                if !metadata.is_file() || metadata.len() > maximum {
                    return Err(failure(
                        "InputLimit",
                        "upload must be a regular file within maximumBytes",
                    ));
                }
                builder = builder.streaming_body(FileBody {
                    file,
                    remaining: metadata.len(),
                });
            }
            let response = builder.send().await.map_err(request)?;
            let status = u32::from(response.status().as_u16());
            let info = response
                .extensions()
                .get::<phantom::ResponseInfo>()
                .ok_or_else(|| failure("Internal", "response metadata is unavailable"))?;
            let protocol = match info.protocol() {
                HttpProtocol::Http1 => "http1",
                HttpProtocol::Http2 => "http2",
                HttpProtocol::Http3 => "http3",
                _ => return Err(failure("Internal", "response protocol is unsupported")),
            }
            .to_owned();
            let url = info.effective_uri().to_string();
            let count = |value| {
                u32::try_from(value).map_err(|_| {
                    failure("Capacity", "response counter exceeds the supported range")
                })
            };
            let redirects = count(info.redirects_followed())?;
            let connection_retries = count(info.retries_performed())?;
            let redirect_history = response
                .extensions()
                .get::<phantom::RedirectHistory>()
                .map(|history| -> Result<RedirectHistoryInfo> {
                    Ok(RedirectHistoryInfo {
                        entries: history
                            .entries()
                            .iter()
                            .map(|hop| RedirectHopInfo {
                                from_url: hop.from_uri().to_string(),
                                to_url: hop.to_uri().to_string(),
                                method: hop.method().to_string(),
                                next_method: hop.next_method().to_string(),
                                status: u32::from(hop.status().as_u16()),
                            })
                            .collect(),
                        omitted_hops: count(history.omitted_hops())?,
                    })
                })
                .transpose()?;
            let decoded_content_codings = info
                .decoded_content_codings()
                .iter()
                .map(|coding| match coding {
                    phantom::ContentCoding::Gzip => Ok("gzip".to_owned()),
                    phantom::ContentCoding::Deflate => Ok("deflate".to_owned()),
                    phantom::ContentCoding::Brotli => Ok("br".to_owned()),
                    phantom::ContentCoding::Zstd => Ok("zstd".to_owned()),
                    _ => Err(failure(
                        "Internal",
                        "response content coding is unsupported",
                    )),
                })
                .collect::<Result<Vec<_>>>()?;
            let headers = response
                .extensions()
                .get::<phantom::OrderedResponseHeaders>()
                .ok_or_else(|| failure("Internal", "response header order is unavailable"))?
                .iter()
                .map(|header| (header.name().to_owned(), header.value().to_vec()))
                .collect();
            exchange.attach(response.into_body())?;
            Ok((
                ResponseHead {
                    status,
                    headers,
                    protocol,
                    url,
                    redirects,
                    connection_retries,
                    decoded_content_codings,
                    redirect_history,
                },
                Arc::clone(&exchange),
            ))
        };
        tokio::select! {
            biased;
            error = exchange.interrupted() => Err(error),
            result = send => result,
        }
    }
}

struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let maximum = self.remaining.min(64 * 1024) as usize;
        let mut bytes = vec![0; maximum];
        let mut read = ReadBuf::new(&mut bytes);
        match Pin::new(&mut self.file).poll_read(context, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Ok(())) => {
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upload file shrank",
                    ))));
                }
                self.remaining -= count as u64;
                bytes.truncate(count);
                Poll::Ready(Some(Ok(Frame::data(bytes.into()))))
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile(std::path::PathBuf);

    impl TestFile {
        fn create(contents: &[u8]) -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "phantom-node-{}-{}.bin",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn file_growth_does_not_exceed_the_admitted_metadata_length() -> io::Result<()> {
        let path = TestFile::create(b"original")?;
        let file = tokio::fs::File::open(&path.0).await?;
        let remaining = file.metadata().await?.len();
        std::fs::write(&path.0, b"original-more")?;
        let body = FileBody { file, remaining };
        assert_eq!(body.collect().await?.to_bytes(), "original");
        Ok(())
    }

    #[tokio::test]
    async fn file_shrinkage_is_an_explicit_upload_error() -> io::Result<()> {
        let path = TestFile::create(b"original")?;
        let file = tokio::fs::File::open(&path.0).await?;
        let remaining = file.metadata().await?.len();
        std::fs::write(&path.0, b"short")?;
        let result = FileBody { file, remaining }.collect().await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));
        Ok(())
    }
}
