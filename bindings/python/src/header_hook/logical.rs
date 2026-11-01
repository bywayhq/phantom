use std::{future::Future, pin::Pin, sync::Arc};

use phantom::{
    AsyncRequestHooks, RequestErrorHookContext, RequestHookContext, RequestHookError,
    ResponseHookContext,
};
use pyo3::{prelude::*, types::PyBytes};
use tokio::sync::oneshot;

use super::{CallbackReply, Fields, InvocationGuard, Owner};

const MAXIMUM_METADATA_BYTES: usize = 256 * 1024;

pub(super) enum Invocation {
    Request(String, String),
    Response(Response),
    Error(String, String, PyErr),
}

pub(super) struct Response {
    method: String,
    uri: String,
    status: u16,
    protocol: &'static str,
    headers: Fields,
    effective_uri: String,
    redirects: usize,
    retries: usize,
    codings: Vec<&'static str>,
}

impl Invocation {
    pub(super) fn into_python(self, py: Python<'_>, id: u64) -> PyResult<Py<PyAny>> {
        Ok(match self {
            Self::Request(method, uri) => (id, "request", method, uri)
                .into_pyobject(py)?
                .into_any()
                .unbind(),
            Self::Error(method, uri, error) => (id, "error", method, uri, error.value(py))
                .into_pyobject(py)?
                .into_any()
                .unbind(),
            Self::Response(response) => {
                let headers = response
                    .headers
                    .into_iter()
                    .map(|(name, value, sensitive)| {
                        (name, PyBytes::new(py, &value).unbind(), sensitive)
                    })
                    .collect::<Vec<_>>();
                (
                    id,
                    "response",
                    response.method,
                    response.uri,
                    response.status,
                    response.protocol,
                    headers,
                    response.effective_uri,
                    response.redirects,
                    response.retries,
                    response.codings,
                )
                    .into_pyobject(py)?
                    .into_any()
                    .unbind()
            }
        })
    }
}

pub(crate) struct LogicalHooks {
    pub(crate) owner: Arc<Owner>,
    pub(crate) phases: u8,
}

type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>>;

fn metadata_limit() -> RequestHookError {
    RequestHookError::new(std::io::Error::other("request callback metadata limit"))
}

fn closed() -> RequestHookError {
    RequestHookError::new(std::io::Error::other("request callback closed"))
}

fn uri_size(uri: &http::Uri) -> Option<usize> {
    uri.scheme_str()
        .map_or(0, str::len)
        .checked_add(uri.authority().map_or(0, |value| value.as_str().len()))?
        .checked_add(uri.path_and_query().map_or(1, |value| value.as_str().len()))?
        .checked_add(3)
}

fn check_metadata(method: &str, uri: &http::Uri, extra: usize) -> Result<(), RequestHookError> {
    // Uri's structured strings borrow its backing bytes. Check before copying.
    let size = uri_size(uri)
        .and_then(|size| size.checked_add(method.len()))
        .and_then(|size| size.checked_add(extra));
    if size.is_none_or(|size| size > MAXIMUM_METADATA_BYTES) {
        return Err(metadata_limit());
    }
    Ok(())
}

impl Owner {
    async fn observe(self: &Arc<Self>, invocation: Invocation) -> Result<(), RequestHookError> {
        let mut guard = InvocationGuard {
            owner: Arc::clone(self),
            serial: None,
            complete: false,
        };
        let (send, receive) = oneshot::channel();
        {
            let mut state = self.state();
            if state.closed || state.reply.is_some() {
                return Err(closed());
            }
            state.serial = state.serial.checked_add(1).ok_or_else(metadata_limit)?;
            guard.serial = Some(state.serial);
            state.pending = Some(super::Invocation::Logical(state.serial, invocation));
            state.reply = Some((state.serial, send));
        }
        self.changed.notify_waiters();
        let reply = receive.await.map_err(|_| closed())?;
        // A delivered failure selects the core error phase; it is not cancellation.
        guard.complete = true;
        match reply.map_err(RequestHookError::new)? {
            CallbackReply::Logical => Ok(()),
            _ => Err(RequestHookError::new(std::io::Error::other(
                "invalid request callback reply",
            ))),
        }
    }
}

impl AsyncRequestHooks for LogicalHooks {
    fn on_request<'a>(&'a self, context: &'a RequestHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 1 == 0 {
                return Ok(());
            }
            check_metadata(context.method().as_str(), context.uri(), 0)?;
            self.owner
                .observe(Invocation::Request(
                    context.method().to_string(),
                    context.uri().to_string(),
                ))
                .await
        })
    }

    fn on_response<'a>(&'a self, context: &'a ResponseHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 2 == 0 {
                return Ok(());
            }
            let request = context.request();
            let headers_size = context
                .headers()
                .iter()
                .try_fold(0_usize, |size, (name, value)| {
                    size.checked_add(name.as_str().len())?
                        .checked_add(value.as_bytes().len())
                })
                .ok_or_else(metadata_limit)?;
            let info = context.info();
            let effective_uri = info.map_or(request.uri(), phantom::ResponseInfo::effective_uri);
            check_metadata(request.method().as_str(), request.uri(), headers_size)?;
            // Both URL copies count toward the same transfer allowance.
            check_metadata(
                request.method().as_str(),
                effective_uri,
                headers_size.saturating_add(uri_size(request.uri()).ok_or_else(metadata_limit)?),
            )?;
            let protocol = match context.version() {
                http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
                http::Version::HTTP_2 => "h2",
                http::Version::HTTP_3 => "h3",
                _ => "unknown",
            };
            let codings = info
                .into_iter()
                .flat_map(phantom::ResponseInfo::decoded_content_codings)
                .map(|coding| match coding {
                    phantom::ContentCoding::Gzip => "gzip",
                    phantom::ContentCoding::Deflate => "deflate",
                    phantom::ContentCoding::Brotli => "br",
                    phantom::ContentCoding::Zstd => "zstd",
                    _ => "unknown",
                })
                .collect();
            self.owner
                .observe(Invocation::Response(Response {
                    method: request.method().to_string(),
                    uri: request.uri().to_string(),
                    status: context.status().as_u16(),
                    protocol,
                    headers: context
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_owned(),
                                value.as_bytes().to_vec(),
                                value.is_sensitive(),
                            )
                        })
                        .collect(),
                    effective_uri: effective_uri.to_string(),
                    redirects: info.map_or(0, phantom::ResponseInfo::redirects_followed),
                    retries: info.map_or(0, phantom::ResponseInfo::retries_performed),
                    codings,
                }))
                .await
        })
    }

    fn on_error<'a>(&'a self, context: &'a RequestErrorHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 4 == 0 {
                return Ok(());
            }
            let request = context.request();
            check_metadata(request.method().as_str(), request.uri(), 0)?;
            self.owner
                .observe(Invocation::Error(
                    request.method().to_string(),
                    request.uri().to_string(),
                    crate::error::request_ref(context.error()),
                ))
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_hook::NativeHeaderHooks;

    #[test]
    fn delivered_failure_keeps_error_phase_alive_but_drop_cancels_its_generation() -> PyResult<()> {
        Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            let hooks = NativeHeaderHooks::new(0, false, false, 1)?;
            let owner = &hooks.owner;
            let invoke = || owner.observe(Invocation::Request("GET".into(), "http://test/".into()));
            let mut first = Box::pin(invoke());
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(first.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            owner.complete(1, Err(pyo3::exceptions::PyValueError::new_err("callback")))?;
            assert!(first.await.is_err());
            assert!(!owner.state().closed);
            assert_eq!(owner.state().cancelled, 0);

            let mut second = Box::pin(invoke());
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(second.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            drop(second);
            assert!(!owner.state().closed);
            assert_eq!(owner.state().cancelled, 2);

            let mut third = Box::pin(invoke());
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(third.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            owner.cancel(2);
            assert!(owner.active(3));
            owner.complete(3, Ok(CallbackReply::Logical))?;
            assert!(third.await.is_ok());
            Ok(())
        })
    }
}
