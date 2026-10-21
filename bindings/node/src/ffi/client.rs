//! Reusable client operations and submission of native-owned requests.

use std::{
    sync::{Arc, PoisonError},
    time::{Duration, Instant},
};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer},
};
use napi_derive::napi;

use super::{
    buffer::{checkpoint_key, copy_buffer},
    controls::{NativeAttemptBudget, NativeCancellation, NativeTransferControl},
    diagnostics::NativeRequestDiagnostics,
    options::{RequestOptions, WireHeader},
    response::NativeResponse,
    upload::NativeUpload,
};
use crate::{
    client::ClientState,
    error::failure,
    request::{MAXIMUM_HEADER_BYTES, MAXIMUM_INPUT_BYTES, Prepared, RequestControls},
    session,
};

/// Reusable native client.
#[derive(Debug)]
#[napi]
pub struct NativeClient {
    pub(super) state: Arc<ClientState>,
}

#[napi]
impl NativeClient {
    /// Encrypts supported state off the JavaScript and async runtime workers.
    #[napi]
    pub fn export_session(&self, env: Env, secret: Buffer) -> Result<AsyncBlock<Buffer>> {
        let key = checkpoint_key(&env, secret)?;
        let client = self.state.core.clone();
        AsyncBlockBuilder::new(async move { session::export(client, key).await.map(Buffer::from) })
            .build(&env)
    }
    /// Closes idle origin and proxy connections without closing this client.
    #[napi]
    pub fn close_idle_connections(&self, env: Env) -> Result<AsyncBlock<()>> {
        self.state.check_open()?;
        let owner = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            owner.core.close_idle_connections().await;
            Ok(())
        })
        .build(&env)
    }
    /// Retires connections while retaining compatible session state.
    #[napi]
    pub fn refresh_connections(&self, env: Env) -> Result<AsyncBlock<()>> {
        self.state.check_open()?;
        let owner = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            owner.core.refresh_connections().await;
            Ok(())
        })
        .build(&env)
    }
    /// Clears the native DNS cache.
    #[napi]
    pub fn clear_dns_cache(&self) -> Result<()> {
        self.state.check_open()?;
        self.state.core.clear_dns_cache();
        Ok(())
    }
    /// Clears advertised alternatives and their racing history.
    #[napi]
    pub fn clear_alt_svc(&self) -> Result<()> {
        self.state.check_open()?;
        self.state.core.clear_alt_svc();
        Ok(())
    }
    /// Clears racing history while retaining advertised alternatives.
    #[napi]
    pub fn clear_alt_svc_racing_history(&self) -> Result<()> {
        self.state.check_open()?;
        self.state.core.clear_alt_svc_racing_history();
        Ok(())
    }
    /// Clears learned client hints.
    #[napi]
    pub fn clear_client_hints(&self) -> Result<()> {
        self.state.check_open()?;
        self.state.core.clear_client_hints();
        Ok(())
    }
    /// Clears retained TLS tickets and returns the removed count.
    #[napi]
    pub fn clear_session_tickets(&self) -> Result<u32> {
        self.state.check_open()?;
        let count = self
            .state
            .core
            .clear_session_tickets()
            .map_err(|_| failure("SessionTickets", "session tickets could not be cleared"))?;
        u32::try_from(count)
            .map_err(|_| failure("Capacity", "ticket count exceeds the supported range"))
    }
    /// Clears this client's native cookie jar.
    #[napi]
    pub fn clear_cookies(&self) -> Result<()> {
        self.state.check_open()?;
        self.state
            .core
            .cookie_jar()
            .ok_or_else(|| failure("CookiesDisabled", "cookie handling is disabled"))?
            .clear();
        Ok(())
    }
    /// Copies JS-owned input before scheduling a native-owned request future.
    // Keep foreign owners as fixed typed arguments at the Node-API boundary.
    #[allow(clippy::too_many_arguments)]
    #[napi]
    pub fn request(
        &self,
        env: Env,
        mut options: RequestOptions,
        cancellation: &NativeCancellation,
        budget: Option<&NativeAttemptBudget>,
        upload: Option<&NativeUpload>,
        transfer: Option<&NativeTransferControl>,
        diagnostics: Option<&NativeRequestDiagnostics>,
    ) -> Result<AsyncBlock<NativeResponse>> {
        let started = Instant::now();
        let fields = options.headers.take().unwrap_or_default();
        let trailer_fields = options.trailers.take().unwrap_or_default();
        if fields.len().saturating_add(trailer_fields.len()) > 256 {
            return Err(failure(
                "InputLimit",
                "headers and trailers exceed 256 fields",
            ));
        }
        let mut remaining = MAXIMUM_HEADER_BYTES;
        let mut copy_fields = |fields: Vec<WireHeader>| -> Result<Vec<phantom::RequestHeader>> {
            let mut copied = Vec::with_capacity(fields.len());
            for field in fields {
                remaining = remaining.checked_sub(field.name.len()).ok_or_else(|| {
                    failure("InputLimit", "headers and trailers exceed 65536 bytes")
                })?;
                let value = copy_buffer(&env, field.value, remaining)?;
                remaining -= value.len();
                let header = phantom::RequestHeader::new(field.name, value);
                copied.push(if field.sensitive.unwrap_or(false) {
                    header.sensitive()
                } else {
                    header
                });
            }
            Ok(copied)
        };
        let headers = copy_fields(fields)?;
        let trailers = copy_fields(trailer_fields)?;
        let body = options
            .body
            .take()
            .map(|body| copy_buffer(&env, body, MAXIMUM_INPUT_BYTES))
            .transpose()?;
        let body = match (body, upload, options.prepared_body.take()) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                return Err(failure(
                    "InvalidBody",
                    "choose one byte, prepared, file or streaming body",
                ));
            }
            (Some(body), None, None) => Some(crate::request::BodyInput::Bytes(body)),
            (None, Some(upload), None) => {
                Some(crate::request::BodyInput::Stream(Arc::clone(&upload.state)))
            }
            (None, None, Some(body)) => {
                Some(crate::request::BodyInput::Prepared(body.body.clone()))
            }
            (None, None, None) => None,
        };
        let prepared = Prepared::new(
            &self.state,
            options,
            headers,
            body,
            started,
            Arc::clone(&cancellation.exchange),
            RequestControls {
                attempt_budget: budget.map(|budget| budget.budget.clone()),
                transfer_control: transfer.map(|transfer| transfer.control.clone()),
                diagnostics: diagnostics.map(|diagnostics| Arc::clone(&diagnostics.state)),
                trailers,
            },
        )?;
        if let Some(upload) = upload {
            *upload.owner.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Arc::clone(&cancellation.exchange));
        }
        let owner = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            let (head, exchange) = prepared.send().await?;
            Ok(NativeResponse {
                status: head.status,
                headers: head.headers,
                protocol: head.protocol,
                url: head.url,
                redirects: head.redirects,
                connection_retries: head.connection_retries,
                decoded_content_codings: head.decoded_content_codings,
                redirect_history: head.redirect_history,
                exchange,
                owner,
            })
        })
        .build(&env)
    }
    /// Cancels this client's owned work, then waits for public shutdown.
    #[napi]
    pub fn close(&self, env: Env, timeout_ms: u32) -> Result<AsyncBlock<()>> {
        self.state.close();
        let shutdown = self.state.shutdown()?;
        let client = self.state.core.clone();
        AsyncBlockBuilder::new(async move {
            let _shutdown = shutdown;
            tokio::time::timeout(
                Duration::from_millis(u64::from(timeout_ms)),
                client.shutdown(),
            )
            .await
            .map_err(|_| failure("Timeout", "client shutdown deadline expired"))
        })
        .build(&env)
    }
    /// Adds a cookie through the native jar without exposing error inputs.
    #[napi]
    pub fn set_cookie(&self, url: String, cookie: String) -> Result<()> {
        self.state
            .core
            .cookie_jar()
            .ok_or_else(|| failure("CookiesDisabled", "cookie handling is disabled"))?
            .set_cookie(&url, &cookie)
            .map_err(|_| failure("InvalidCookie", "cookie could not be stored"))
    }
    /// Returns the jar's request value for this URL.
    #[napi]
    pub fn cookie_value(&self, url: String) -> Result<Option<String>> {
        self.state
            .core
            .cookie_jar()
            .ok_or_else(|| failure("CookiesDisabled", "cookie handling is disabled"))?
            .request_value(&url)
            .map_err(|_| failure("InvalidCookie", "cookie URL is invalid"))
    }
}
