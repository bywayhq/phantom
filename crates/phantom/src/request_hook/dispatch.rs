use std::{fmt, sync::Arc};

use http::{Method, Response, Uri};

use super::{
    AsyncRequestHooks, RequestErrorHookContext, RequestHookContext, RequestHooks,
    ResponseHookContext,
};
use crate::{RequestError, ResponseBody, ResponseInfo, TimeoutPhase, timeout::TimeoutBudget};

#[derive(Clone)]
pub(crate) enum SharedRequestHooks {
    Sync(Arc<dyn RequestHooks>),
    Async(Arc<dyn AsyncRequestHooks>),
}

impl SharedRequestHooks {
    pub(crate) fn new(hooks: impl RequestHooks + 'static) -> Self {
        Self::Sync(Arc::new(hooks))
    }

    pub(crate) fn new_async(hooks: impl AsyncRequestHooks + 'static) -> Self {
        Self::Async(Arc::new(hooks))
    }
}

impl fmt::Debug for SharedRequestHooks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestHooks { .. }")
    }
}

pub(crate) struct ActiveRequestHooks {
    method: Method,
    uri: Uri,
    client: Option<SharedRequestHooks>,
    request: Option<SharedRequestHooks>,
}

impl ActiveRequestHooks {
    pub(crate) fn new(
        method: &Method,
        uri: &Uri,
        client: Option<&SharedRequestHooks>,
        request: Option<&SharedRequestHooks>,
    ) -> Option<Box<Self>> {
        if client.is_none() && request.is_none() {
            return None;
        }
        Some(Box::new(Self {
            method: method.clone(),
            uri: uri.clone(),
            client: client.cloned(),
            request: request.cloned(),
        }))
    }

    pub(crate) fn has_async(&self) -> bool {
        self.callbacks()
            .any(|hooks| matches!(hooks, SharedRequestHooks::Async(_)))
    }

    // The caller selects these two methods only when every slot is synchronous.
    // Keep that path free of timed operations and boxed callback futures.
    pub(crate) fn start_sync(&self) {
        let context = self.context();
        for hooks in self.sync_callbacks() {
            hooks.on_request(&context);
        }
    }

    pub(crate) fn finish_sync(&self, result: &Result<Response<ResponseBody>, RequestError>) {
        for hooks in self.sync_callbacks() {
            match result {
                Ok(response) => hooks.on_response(&self.response_context(response)),
                Err(error) => hooks.on_error(&RequestErrorHookContext {
                    request: self.context(),
                    error,
                }),
            }
        }
    }

    pub(crate) async fn start_async(&self, budget: TimeoutBudget) -> Result<(), RequestError> {
        let context = self.context();
        for hooks in self.callbacks() {
            match hooks {
                SharedRequestHooks::Sync(hooks) => hooks.on_request(&context),
                SharedRequestHooks::Async(hooks) => {
                    budget
                        .run(TimeoutPhase::Total, None, async {
                            hooks
                                .on_request(&context)
                                .await
                                .map_err(|error| RequestError::request_hook(None, error))
                        })
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn finish_async(
        &self,
        result: Result<Response<ResponseBody>, RequestError>,
        budget: TimeoutBudget,
    ) -> Result<Response<ResponseBody>, RequestError> {
        match result {
            Ok(response) => {
                let context = self.response_context(&response);
                let protocol = context.info().map(ResponseInfo::protocol);
                for hooks in self.callbacks() {
                    match hooks {
                        SharedRequestHooks::Sync(hooks) => hooks.on_response(&context),
                        SharedRequestHooks::Async(hooks) => {
                            budget
                                .run(TimeoutPhase::Total, protocol, async {
                                    hooks.on_response(&context).await.map_err(|error| {
                                        RequestError::request_hook(protocol, error)
                                    })
                                })
                                .await?;
                        }
                    }
                }
                Ok(response)
            }
            Err(error) => {
                let context = RequestErrorHookContext {
                    request: self.context(),
                    error: &error,
                };
                for hooks in self.callbacks() {
                    let result = match hooks {
                        SharedRequestHooks::Sync(hooks) => {
                            hooks.on_error(&context);
                            Ok(())
                        }
                        SharedRequestHooks::Async(hooks) => {
                            budget
                                .run(TimeoutPhase::Total, error.protocol(), async {
                                    hooks.on_error(&context).await.map_err(|failure| {
                                        RequestError::request_hook(error.protocol(), failure)
                                    })
                                })
                                .await
                        }
                    };
                    if let Err(failure) = result {
                        return Err(error.with_hook_failure(failure));
                    }
                }
                Err(error)
            }
        }
    }

    fn context(&self) -> RequestHookContext<'_> {
        RequestHookContext {
            method: &self.method,
            uri: &self.uri,
        }
    }

    fn response_context<'a>(
        &'a self,
        response: &'a Response<ResponseBody>,
    ) -> ResponseHookContext<'a> {
        ResponseHookContext {
            request: self.context(),
            status: response.status(),
            version: response.version(),
            headers: response.headers(),
            info: response.extensions().get(),
        }
    }

    fn callbacks(&self) -> impl Iterator<Item = &SharedRequestHooks> {
        self.client.iter().chain(self.request.iter())
    }

    fn sync_callbacks(&self) -> impl Iterator<Item = &dyn RequestHooks> {
        self.callbacks().filter_map(|hooks| match hooks {
            SharedRequestHooks::Sync(hooks) => Some(hooks.as_ref()),
            SharedRequestHooks::Async(_) => None,
        })
    }
}
