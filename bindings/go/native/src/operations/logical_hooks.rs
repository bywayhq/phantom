//! Logical request observations share the existing request callback custody.

use std::{future::Future, pin::Pin, sync::Arc};

use phantom::{
    AsyncRequestHooks, RequestErrorHookContext, RequestHookContext, RequestHookError,
    ResponseHookContext,
};

use super::{
    CallbackCall, CallbackInvocation, CallbackReply, CallbackWait, Completed, Completion, Global,
    MAX_METADATA, Queued, global,
};
use crate::{client::Header, error::Failure};

pub(crate) struct Invocation {
    pub(crate) phase: u64,
    pub(crate) cause_operation: u64,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) response: Option<Response>,
    pub(crate) error: Option<Failure>,
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) protocol: &'static str,
    pub(crate) headers: Vec<Header>,
    pub(crate) effective_uri: String,
    pub(crate) redirects: usize,
    pub(crate) retries: usize,
    pub(crate) codings: Vec<&'static str>,
}

pub(crate) struct Hooks {
    pub(crate) operation: u64,
    pub(crate) phases: u8,
}

pub(super) type HookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>>;

fn failure() -> RequestHookError {
    RequestHookError::new(std::io::Error::other("host request callback failed"))
}

fn uri_size(uri: &http::Uri) -> Option<usize> {
    uri.scheme_str()
        .map_or(0, str::len)
        .checked_add(uri.authority().map_or(0, |part| part.as_str().len()))?
        .checked_add(uri.path_and_query().map_or(1, |part| part.as_str().len()))?
        .checked_add(3)
}

pub(crate) fn request(context: &RequestHookContext<'_>) -> Result<Invocation, RequestHookError> {
    let size =
        uri_size(context.uri()).and_then(|size| size.checked_add(context.method().as_str().len()));
    if size.is_none_or(|size| size > MAX_METADATA) {
        return Err(failure());
    }
    Ok(Invocation {
        phase: 1,
        cause_operation: 0,
        method: context.method().to_string(),
        uri: context.uri().to_string(),
        response: None,
        error: None,
    })
}

pub(crate) fn response(context: &ResponseHookContext<'_>) -> Result<Invocation, RequestHookError> {
    let request = context.request();
    let info = context.info();
    let effective = info.map_or(request.uri(), phantom::ResponseInfo::effective_uri);
    let size = context
        .headers()
        .iter()
        .try_fold(0_usize, |size, (name, value)| {
            size.checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .and_then(|size| size.checked_add(uri_size(effective)?))
        .and_then(|size| size.checked_add(uri_size(request.uri())?))
        .and_then(|size| size.checked_add(request.method().as_str().len()));
    if size.is_none_or(|size| size > MAX_METADATA) || context.headers().len() > MAX_METADATA / 40 {
        return Err(failure());
    }
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
        });
    let coding_size = codings
        .clone()
        .try_fold(size.unwrap_or(MAX_METADATA), |size, value| {
            size.checked_add(value.len())
        });
    if coding_size.is_none_or(|size| size > MAX_METADATA)
        || codings
            .clone()
            .count()
            .saturating_add(context.headers().len())
            > MAX_METADATA / 40
    {
        return Err(failure());
    }
    Ok(Invocation {
        phase: 2,
        cause_operation: 0,
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        error: None,
        response: Some(Response {
            status: context.status().as_u16(),
            protocol,
            headers: context
                .headers()
                .iter()
                .map(|(name, value)| Header {
                    name: name.as_str().to_owned(),
                    value: value.as_bytes().to_vec(),
                    sensitive: value.is_sensitive(),
                })
                .collect(),
            effective_uri: effective.to_string(),
            redirects: info.map_or(0, phantom::ResponseInfo::redirects_followed),
            retries: info.map_or(0, phantom::ResponseInfo::retries_performed),
            codings: codings.collect(),
        }),
    })
}

pub(crate) fn error(context: &RequestErrorHookContext<'_>) -> Result<Invocation, RequestHookError> {
    let mut invocation = request(context.request())?;
    invocation.phase = 4;
    invocation.error = Some(Failure::from(context.error()));
    Ok(invocation)
}

impl AsyncRequestHooks for Hooks {
    fn on_request<'a>(&'a self, context: &'a RequestHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 1 == 0 {
                return Ok(());
            }
            global()
                .map_err(|_| failure())?
                .logical_hook(self.operation, request(context)?)
                .await
        })
    }
    fn on_response<'a>(&'a self, context: &'a ResponseHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 2 == 0 {
                return Ok(());
            }
            global()
                .map_err(|_| failure())?
                .logical_hook(self.operation, response(context)?)
                .await
        })
    }
    fn on_error<'a>(&'a self, context: &'a RequestErrorHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            if self.phases & 4 == 0 {
                return Ok(());
            }
            global()
                .map_err(|_| failure())?
                .logical_hook(self.operation, error(context)?)
                .await
        })
    }
}

impl Global {
    pub(super) async fn logical_hook(
        &'static self,
        operation: u64,
        invocation: Invocation,
    ) -> Result<(), RequestHookError> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let ticket = loop {
            let settled = self.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            {
                let mut state = self.lock();
                let op = state.operations.get(&operation).ok_or_else(failure)?;
                if state.failed || op.abandoned || op.finished {
                    return Err(failure());
                }
                if !op
                    .callback_call
                    .as_ref()
                    .is_some_and(|call| call.host_owned)
                {
                    let ticket = state.id().map_err(|_| failure())?;
                    state
                        .operations
                        .get_mut(&operation)
                        .ok_or_else(failure)?
                        .callback_call = Some(CallbackCall {
                        ticket,
                        invocation: CallbackInvocation::Logical(Arc::new(invocation)),
                        reply: Some(sender),
                        host_owned: false,
                    });
                    state.ready.push_back(Queued {
                        operation,
                        completion: Completion {
                            operation,
                            result: Ok(Completed::LogicalHook(ticket)),
                            data: phantom::Bytes::new(),
                        },
                    });
                    break ticket;
                }
            }
            // A native timeout can start its error phase before host handback.
            // Keep that phase pending within the core's existing deadline.
            settled.await;
        };
        self.ready.notify_one();
        let wait = CallbackWait {
            global: self,
            operation,
            ticket,
        };
        let result = receiver
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        drop(wait);
        match result {
            CallbackReply::Logical => Ok(()),
            _ => Err(failure()),
        }
    }
}

pub(crate) fn invocation(operation: u64, ticket: u64) -> Result<Arc<Invocation>, Failure> {
    global()?
        .lock()
        .operations
        .get(&operation)
        .and_then(|op| op.callback_call.as_ref())
        .filter(|call| call.ticket == ticket)
        .and_then(|call| match &call.invocation {
            CallbackInvocation::Logical(value) => Some(Arc::clone(value)),
            _ => None,
        })
        .ok_or_else(|| Failure::new("header_hook_closed"))
}

pub(crate) fn reply(operation: u64, ticket: u64, outcome: u64) -> Result<(), Failure> {
    global()?.reply_callback(operation, ticket, outcome, CallbackReply::Logical)
}
