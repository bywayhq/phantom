//! Response projections and pull-driven access to the existing body owner.

use std::{fmt, sync::Arc};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer},
};
use napi_derive::napi;

use super::options::WireHeader;
use crate::{client::ClientState, error::failure, response::Exchange};

/// One selected redirect, retaining URLs only when explicitly requested.
#[derive(Clone)]
#[napi(object)]
pub struct RedirectHopInfo {
    /// URL that produced the redirect response.
    pub from_url: String,
    /// Resolved destination selected by the core.
    pub to_url: String,
    /// Method used for the redirect response.
    pub method: String,
    /// Method selected for the destination.
    pub next_method: String,
    /// Redirect status received from the peer.
    pub status: u32,
}

/// Opt-in bounded history; missing history is distinct from an empty history.
#[derive(Clone)]
#[napi(object)]
pub struct RedirectHistoryInfo {
    /// First selected hops in order.
    pub entries: Vec<RedirectHopInfo>,
    /// Later selected hops not retained.
    pub omitted_hops: u32,
}

impl fmt::Debug for RedirectHopInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectHopInfo")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RedirectHistoryInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectHistoryInfo")
            .finish_non_exhaustive()
    }
}

/// Non-draining retained response trailers; fields exist only after validated EOF.
#[napi(object)]
#[derive(Debug)]
pub struct ResponseTrailersInfo {
    /// Pending, unavailable, or complete after validated body EOF.
    pub state: String,
    /// Ordered owned fields only for complete, including an empty list.
    pub headers: Option<Vec<WireHeader>>,
}

/// Response head and one pull-driven native body.
#[napi]
pub struct NativeResponse {
    pub(super) status: u32,
    pub(super) headers: Vec<(String, Vec<u8>, bool)>,
    pub(super) protocol: String,
    pub(super) url: String,
    pub(super) redirects: u32,
    pub(super) connection_retries: u32,
    pub(super) decoded_content_codings: Vec<String>,
    pub(super) redirect_history: Option<RedirectHistoryInfo>,
    pub(super) exchange: Arc<Exchange>,
    pub(super) owner: Arc<ClientState>,
}

impl fmt::Debug for NativeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[napi]
impl NativeResponse {
    /// Actual protocol that produced this response.
    #[napi(getter)]
    #[must_use]
    pub fn protocol(&self) -> String {
        self.protocol.clone()
    }
    /// Final URL after following redirects.
    #[napi(getter)]
    #[must_use]
    pub fn url(&self) -> String {
        self.url.clone()
    }
    /// Number of redirects followed for this logical request.
    #[napi(getter)]
    #[must_use]
    pub fn redirects(&self) -> u32 {
        self.redirects
    }
    /// Connection-setup retries, excluding other replay classes.
    #[napi(getter)]
    #[must_use]
    pub fn connection_retries(&self) -> u32 {
        self.connection_retries
    }
    /// Selected coding chain in Content-Encoding order, not completion status.
    #[napi(getter)]
    #[must_use]
    pub fn decoded_content_codings(&self) -> Vec<String> {
        self.decoded_content_codings.clone()
    }
    /// First retained redirects, or no history when not requested.
    #[napi(getter)]
    #[must_use]
    pub fn redirect_history(&self) -> Option<RedirectHistoryInfo> {
        self.redirect_history.clone()
    }
    /// HTTP status received from the peer.
    #[napi(getter)]
    #[must_use]
    pub fn status(&self) -> u32 {
        self.status
    }
    /// Response fields retaining duplicate positions and byte values.
    #[napi(getter)]
    #[must_use]
    pub fn headers(&self) -> Vec<WireHeader> {
        self.headers
            .iter()
            .map(|(name, value, sensitive)| WireHeader {
                name: name.clone(),
                value: value.clone().into(),
                sensitive: Some(*sensitive),
            })
            .collect()
    }
    /// Copies the retained snapshot without reading the response body.
    #[napi(getter)]
    pub fn trailers(&self) -> Result<ResponseTrailersInfo> {
        let (state, headers) = match &*self.exchange.trailers() {
            phantom::ResponseTrailers::Pending => ("pending", None),
            phantom::ResponseTrailers::Unavailable => ("unavailable", None),
            phantom::ResponseTrailers::Complete(fields) => (
                "complete",
                Some(
                    fields
                        .iter()
                        .map(|field| WireHeader {
                            name: field.name().to_owned(),
                            value: field.value().to_vec().into(),
                            sensitive: Some(field.is_sensitive()),
                        })
                        .collect(),
                ),
            ),
            _ => {
                return Err(failure(
                    "UnsupportedResponseTrailers",
                    "unsupported response trailer state",
                ));
            }
        };
        Ok(ResponseTrailersInfo {
            state: state.to_owned(),
            headers,
        })
    }
    /// Reads at most the requested bytes without polling ahead.
    #[napi]
    pub fn read(&self, env: Env, maximum_bytes: u32) -> Result<AsyncBlock<Option<Buffer>>> {
        let exchange = Arc::clone(&self.exchange);
        let owner = Arc::clone(&self.owner);
        AsyncBlockBuilder::new(async move {
            let _owner = owner;
            exchange
                .read(maximum_bytes)
                .await
                .map(|bytes| bytes.map(Buffer::from))
        })
        .build(&env)
    }
    /// Collects the remaining body under one exclusive reader and byte limit.
    #[napi]
    pub fn collect(&self, env: Env, maximum_bytes: u32) -> Result<AsyncBlock<Buffer>> {
        let exchange = Arc::clone(&self.exchange);
        let owner = Arc::clone(&self.owner);
        AsyncBlockBuilder::new(async move {
            let _owner = owner;
            exchange.collect(maximum_bytes).await.map(Buffer::from)
        })
        .build(&env)
    }
    /// Cancels and releases an unfinished body.
    #[napi]
    pub fn close(&self) {
        self.exchange.cancel();
    }
}

impl Drop for NativeResponse {
    fn drop(&mut self) {
        self.exchange.cancel();
    }
}
