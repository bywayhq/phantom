use std::{
    future::Future,
    io,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use clap::ArgMatches;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use phantom::{
    Bytes, Client, HttpAttemptBudget, HttpProtocol, HttpProxy, Method, RequestBuilder,
    RequestHeader, RequestTimeouts, Route, Socks4Proxy, Socks5Proxy,
};
use phantom_profile::catalog::{self, RequestTemplateKind};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{CliError, Result, diagnostics, profiles};

const SHUTDOWN: Duration = Duration::from_secs(2);

fn route(arguments: &ArgMatches) -> Result<Route> {
    let Some(uri) = arguments.get_one::<String>("proxy") else {
        return Ok(Route::direct());
    };
    let scheme = uri.split_once("://").map(|(scheme, _)| scheme);
    match scheme {
        Some("http" | "https") => HttpProxy::new(uri)
            .map(Route::http_proxy)
            .map_err(CliError::operation),
        Some("socks4" | "socks4a") => Socks4Proxy::new(uri)
            .map(Route::socks4)
            .map_err(CliError::operation),
        Some("socks5" | "socks5h") => Socks5Proxy::new(uri)
            .map(Route::socks5)
            .map_err(CliError::operation),
        _ => Err(CliError::invalid(
            "proxy scheme must be http, https, socks4, socks4a, socks5 or socks5h",
        )),
    }
}

async fn prepare(arguments: &ArgMatches) -> Result<(Client, RequestBuilder)> {
    let mut profile = if let Some(id) = arguments.get_one::<String>("profile") {
        let definition = catalog::profile(id).map_err(CliError::operation)?;
        let mut profile = definition.instantiate(&[]).map_err(CliError::operation)?;
        if let Some(context) = arguments.get_one::<String>("context") {
            let kind = match context.as_str() {
                "navigation" => RequestTemplateKind::Navigation,
                "fetch" => RequestTemplateKind::Fetch,
                "script" => RequestTemplateKind::Script,
                "stylesheet" => RequestTemplateKind::Stylesheet,
                "image" => RequestTemplateKind::Image,
                "font" => RequestTemplateKind::Font,
                _ => return Err(CliError::invalid("unsupported request context")),
            };
            profile = profile.with_request_template(
                definition
                    .request_template(kind)
                    .map_err(CliError::operation)?,
            );
        }
        profile
    } else if arguments.get_one::<String>("bundle").is_some() {
        profiles::bundle::select(arguments).await?
    } else {
        let file = arguments
            .get_one::<PathBuf>("profile-file")
            .ok_or_else(|| CliError::invalid("missing profile"))?;
        profiles::read_profile(file).await?
    };
    // A custom document may already contain its caller-authored template.
    // Catalog profiles above only select a template through --context.
    if arguments.get_one::<String>("profile").is_some()
        && arguments.get_one::<String>("context").is_none()
    {
        profile = profile.without_request_template();
    }
    let mut builder = Client::builder(profile).route(route(arguments)?);
    if let Some(timeout) = arguments.get_one::<NonZeroU64>("timeout-ms") {
        builder = builder
            .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(timeout.get())));
    }
    let client = builder.build().map_err(CliError::operation)?;
    let method = Method::from_bytes(profiles::required(arguments, "method")?.as_bytes())
        .map_err(CliError::operation)?;
    let url = profiles::required(arguments, "url")?;
    let protocol = profiles::required(arguments, "protocol")?;
    let mut request = match protocol {
        "h1" => client.request(HttpProtocol::Http1, method, url),
        "h2" => client.request(HttpProtocol::Http2, method, url),
        "h3" => client.request(HttpProtocol::Http3, method, url),
        "negotiated" => client.request_negotiated(method, url),
        _ => return Err(CliError::invalid("unsupported protocol")),
    }
    .map_err(CliError::operation)?;
    if let Some(headers) = arguments.get_many::<String>("header") {
        for header in headers {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| CliError::invalid("a header must contain Name: value"))?;
            request = request.header(RequestHeader::new(
                name,
                value.trim_start_matches([' ', '\t']).as_bytes(),
            ));
        }
    }
    if let Some(maximum) = arguments.get_one::<usize>("attempts") {
        request = request.attempt_budget(HttpAttemptBudget::new(*maximum));
    }
    if let Some(path) = arguments.get_one::<PathBuf>("upload") {
        let file = tokio::fs::File::open(path).await?;
        let size = file.metadata().await?.len();
        request = request.streaming_body(FileBody {
            file,
            remaining: size,
            buffer: Box::new([0; 8192]),
            done: false,
        });
    }
    Ok((client, request))
}

struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
    buffer: Box<[u8; 8192]>,
    done: bool,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.done || this.remaining == 0 {
            return Poll::Ready(None);
        }
        let maximum = this.remaining.min(this.buffer.len() as u64) as usize;
        let mut buffer = ReadBuf::new(&mut this.buffer[..maximum]);
        match Pin::new(&mut this.file).poll_read(context, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Ok(())) => {
                let bytes = buffer.filled();
                if bytes.is_empty() {
                    this.done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upload file ended before its declared length",
                    ))));
                }
                this.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(bytes)))))
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

async fn transfer(
    request: RequestBuilder,
    mut output: Box<dyn AsyncWrite + Send + Unpin>,
    fail: bool,
) -> Result<()> {
    let response = request.send().await.map_err(CliError::operation)?;
    let status = response.status();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(CliError::operation)?;
        if let Ok(data) = frame.into_data() {
            output.write_all(&data).await?;
        }
    }
    output.flush().await?;
    if fail && (status.is_client_error() || status.is_server_error()) {
        return Err(CliError {
            code: 22,
            message: format!("HTTP status {}", status.as_u16()),
        });
    }
    Ok(())
}

async fn controlled<F: Future<Output = Result<()>>, C: Future<Output = io::Result<()>>>(
    operation: F,
    cancel: C,
) -> Result<()> {
    tokio::select! {
        biased;
        signal = cancel => {
            signal.map_err(CliError::operation)?;
            Err(CliError::interrupted())
        }
        result = operation => result,
    }
}

pub(super) async fn run(arguments: &ArgMatches) -> Result<()> {
    let (client, mut request) = prepare(arguments).await?;
    let diagnostics_path = arguments.get_one::<PathBuf>("diagnostics");
    let diagnostics = diagnostics_path
        .map(|_| request.diagnostics(NonZeroUsize::new(256).unwrap_or(NonZeroUsize::MIN)));
    let output: Box<dyn AsyncWrite + Send + Unpin> =
        if let Some(path) = arguments.get_one::<PathBuf>("output") {
            Box::new(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .await?,
            )
        } else {
            Box::new(tokio::io::stdout())
        };
    let operation = async {
        let transfer = transfer(request, output, arguments.get_flag("fail"));
        if let Some(timeout) = arguments.get_one::<NonZeroU64>("timeout-ms") {
            tokio::time::timeout(Duration::from_millis(timeout.get()), transfer)
                .await
                .map_err(|_| CliError::operation("request deadline exceeded"))?
        } else {
            transfer.await
        }
    };
    let result = controlled(operation, tokio::signal::ctrl_c()).await;
    let shutdown = tokio::time::timeout(SHUTDOWN, client.shutdown()).await;
    if let (Some(path), Some(diagnostics)) = (diagnostics_path, diagnostics) {
        let written = tokio::time::timeout(SHUTDOWN, diagnostics::write(path, &diagnostics))
            .await
            .map_err(|_| CliError::operation("diagnostic output deadline exceeded"))?;
        if let Err(error) = written {
            if let Err(original) = &result {
                eprintln!("phantom: {}", original.message);
            }
            return Err(error);
        }
    }
    result?;
    shutdown.map_err(|_| CliError::operation("client shutdown deadline exceeded"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UploadFile(PathBuf);

    impl Drop for UploadFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    async fn upload_file(bytes: &[u8]) -> io::Result<(UploadFile, FileBody)> {
        use std::{
            io::Write,
            sync::atomic::{AtomicU64, Ordering},
        };
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "phantom-cli-upload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(bytes)?;
        drop(file);
        let guard = UploadFile(path);
        let file = tokio::fs::File::open(&guard.0).await?;
        let body = FileBody {
            file,
            remaining: bytes.len() as u64,
            buffer: Box::new([0; 8192]),
            done: false,
        };
        Ok((guard, body))
    }

    #[tokio::test]
    async fn a_growing_upload_stops_at_its_declared_length() -> io::Result<()> {
        use std::io::Write;
        let (file, body) = upload_file(b"abc").await?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&file.0)?
            .write_all(b"def")?;
        assert_eq!(body.size_hint().exact(), Some(3));
        let bytes = body.collect().await?.to_bytes();
        assert_eq!(&bytes[..], b"abc");
        Ok(())
    }

    #[tokio::test]
    async fn a_shrinking_upload_reports_unexpected_eof() -> io::Result<()> {
        let (file, mut body) = upload_file(b"abcd").await?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file.0)?
            .set_len(2)?;
        let frame = body
            .frame()
            .await
            .transpose()?
            .ok_or_else(|| io::Error::other("expected the retained upload bytes"))?;
        assert_eq!(frame.data_ref().map(Bytes::as_ref), Some(&b"ab"[..]));
        assert_eq!(body.size_hint().exact(), Some(2));
        let error = body
            .frame()
            .await
            .transpose()
            .err()
            .ok_or_else(|| io::Error::other("expected a premature upload EOF"))?;
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(body.frame().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_drops_the_in_flight_operation() {
        struct Dropped(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Dropped(std::sync::Arc::clone(&dropped));
        let operation = async move {
            let _guard = guard;
            std::future::pending::<Result<()>>().await
        };
        let result = controlled(operation, async { Ok(()) }).await;
        assert_eq!(result.err().map(|error| error.code), Some(130));
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
