//! Owned logical callback metadata; the core retains phase and deadline ownership.

use std::{error::Error, fmt, future::Future, io, pin::Pin, sync::Arc};

use phantom::{
    AsyncRequestHooks, RequestError, RequestErrorHookContext, RequestHeader, RequestHookContext,
    RequestHookError, ResponseHookContext,
};

use crate::header_hook::HeaderHooks;

pub(crate) struct Invocation {
    pub(crate) phase: u32,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) status: Option<u32>,
    pub(crate) protocol: Option<String>,
    pub(crate) headers: Vec<RequestHeader>,
    pub(crate) url: Option<String>,
    pub(crate) redirects: Option<u32>,
    pub(crate) retries: Option<u32>,
    pub(crate) codings: Vec<String>,
    pub(crate) error: Option<String>,
    pub(crate) origin: Option<(String, String, u32)>,
}

pub(crate) struct Hooks {
    pub(crate) owner: Arc<HeaderHooks>,
    pub(crate) mask: u32,
}

type Callback<'a> = Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>>;

impl AsyncRequestHooks for Hooks {
    fn on_request<'a>(&'a self, context: &'a RequestHookContext<'_>) -> Callback<'a> {
        Box::pin(async move {
            if self.mask & 1 == 0 {
                return Ok(());
            }
            self.owner.logical(Invocation::request(0, context)).await
        })
    }

    fn on_response<'a>(&'a self, context: &'a ResponseHookContext<'_>) -> Callback<'a> {
        Box::pin(async move {
            if self.mask & 2 == 0 {
                return Ok(());
            }
            // Core receive ceilings are at most 393,216 decoded header bytes.
            // Count before cloning, allowing the request/effective URLs as well.
            let bytes = context
                .headers()
                .iter()
                .fold(0_usize, |total, (name, value)| {
                    total
                        .saturating_add(name.as_str().len())
                        .saturating_add(value.as_bytes().len())
                        .saturating_add(32)
                });
            if bytes > 1024 * 1024 {
                return Err(failure());
            }
            let mut invocation = Invocation::request(1, context.request());
            invocation.status = Some(u32::from(context.status().as_u16()));
            invocation.headers = context
                .headers()
                .iter()
                .map(|(name, value)| {
                    let header = RequestHeader::new(name.as_str(), value.as_bytes());
                    if value.is_sensitive() {
                        header.sensitive()
                    } else {
                        header
                    }
                })
                .collect();
            if let Some(info) = context.info() {
                invocation.protocol = Some(
                    match info.protocol() {
                        phantom::HttpProtocol::Http1 => "http1",
                        phantom::HttpProtocol::Http2 => "http2",
                        phantom::HttpProtocol::Http3 => "http3",
                        _ => return Err(failure()),
                    }
                    .into(),
                );
                invocation.url = Some(info.effective_uri().to_string());
                invocation.redirects =
                    Some(u32::try_from(info.redirects_followed()).map_err(|_| failure())?);
                invocation.retries =
                    Some(u32::try_from(info.retries_performed()).map_err(|_| failure())?);
                invocation.codings = info
                    .decoded_content_codings()
                    .iter()
                    .map(|coding| {
                        Ok(match coding {
                            phantom::ContentCoding::Gzip => "gzip",
                            phantom::ContentCoding::Deflate => "deflate",
                            phantom::ContentCoding::Brotli => "br",
                            phantom::ContentCoding::Zstd => "zstd",
                            _ => return Err(failure()),
                        }
                        .to_owned())
                    })
                    .collect::<Result<_, RequestHookError>>()?;
            }
            self.owner.logical(invocation).await
        })
    }

    fn on_error<'a>(&'a self, context: &'a RequestErrorHookContext<'_>) -> Callback<'a> {
        Box::pin(async move {
            if self.mask & 4 == 0 {
                return Ok(());
            }
            let mut invocation = Invocation::request(2, context.request());
            invocation.error = Some(crate::error::request_ref(context.error()).reason);
            invocation.origin = context.error().origin().map(|origin| {
                (
                    origin.scheme().to_owned(),
                    origin.host().to_owned(),
                    u32::from(origin.port()),
                )
            });
            self.owner.logical(invocation).await
        })
    }
}

impl Invocation {
    fn request(phase: u32, context: &RequestHookContext<'_>) -> Self {
        Self {
            phase,
            method: context.method().to_string(),
            uri: context.uri().to_string(),
            status: None,
            protocol: None,
            headers: Vec::new(),
            url: None,
            redirects: None,
            retries: None,
            codings: Vec::new(),
            error: None,
            origin: None,
        }
    }
}

pub(crate) fn failure() -> RequestHookError {
    RequestHookError::new(io::Error::other("logical request callback unavailable"))
}

pub(crate) struct HostFailure(pub(crate) u64);
impl fmt::Debug for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogicalCallbackFailure { .. }")
    }
}
impl fmt::Display for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("logical request callback failed")
    }
}
impl Error for HostFailure {}

pub(crate) fn failed_serial(error: &RequestError) -> Option<u64> {
    let mut source: Option<&(dyn Error + 'static)> = Some(error);
    for _ in 0..16 {
        let error = source?;
        if let Some(failure) = error.downcast_ref::<HostFailure>() {
            return Some(failure.0);
        }
        source = error.source();
    }
    None
}
