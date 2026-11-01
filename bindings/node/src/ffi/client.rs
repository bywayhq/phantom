//! Reusable client operations and submission of native-owned requests.

use std::{
    sync::{Arc, PoisonError},
    time::{Duration, Instant},
};

use napi::{
    Env, Result,
    bindgen_prelude::{Array, AsyncBlock, AsyncBlockBuilder, Buffer, Either},
};
use napi_derive::napi;

use super::{
    buffer::{checkpoint_key, copy_buffer},
    controls::{NativeAttemptBudget, NativeCancellation, NativeTransferControl},
    diagnostics::NativeRequestDiagnostics,
    event_source::{EventSourceHead, EventSourceOptions, NativeEventSource},
    header_hook::NativeHeaderHooks,
    options::{RequestOptions, WireHeader},
    response::NativeResponse,
    upload::NativeUpload,
    websocket::{NativeWebSocket, WebSocketHandshake, WebSocketOptions, WebSocketRejection},
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
    /// Exports cookies in creation order; absence means the jar is disabled.
    #[napi]
    pub fn export_cookies(&self) -> Result<Option<Vec<super::state_transfer::CookieEntry>>> {
        self.state.check_open()?;
        self.state
            .core
            .export_cookies()
            .map(super::state_transfer::export_cookies)
            .transpose()
    }

    /// Validates every entry before modifying the receiving jar.
    #[napi]
    pub fn import_cookies(&self, entries: Array<'_>) -> Result<()> {
        self.state.check_open()?;
        let snapshot = super::state_transfer::cookies(entries)?;
        self.state
            .core
            .import_cookies(&snapshot)
            .map_err(crate::state_transfer::cookie_error)
    }

    /// Exports direct-route alternatives in least-recently-used order.
    #[napi]
    pub fn export_alt_svc(&self) -> Result<Option<Vec<super::state_transfer::AltSvcEntry>>> {
        self.state.check_open()?;
        self.state
            .core
            .export_alt_svc()
            .map(super::state_transfer::export_alternatives)
            .transpose()
    }

    /// Imports alternatives without granting validation or certificate trust.
    #[napi]
    pub fn import_alt_svc(&self, entries: Array<'_>) -> Result<()> {
        self.state.check_open()?;
        let snapshot = super::state_transfer::alternatives(entries)?;
        self.state
            .core
            .import_alt_svc(&snapshot)
            .map_err(crate::state_transfer::alt_svc_error)
    }

    /// Encrypts ticket state without consuming it; CPU work is not preemptible.
    #[napi]
    pub fn export_session_tickets(&self, env: Env, secret: Buffer) -> Result<AsyncBlock<Buffer>> {
        self.state.check_open()?;
        let key = super::state_transfer::ticket_key(&env, secret)?;
        let permit = Arc::clone(&self.state.admission)
            .try_acquire_owned()
            .map_err(|_| failure("Capacity", "client has no free request slots"))?;
        let owner = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let snapshot = owner
                    .core
                    .export_session_tickets(&key)
                    .map_err(crate::state_transfer::ticket_error)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(snapshot.as_bytes().len())
                    .map_err(|_| {
                        crate::state_transfer::failure("SessionTickets", "allocation", None)
                    })?;
                bytes.extend_from_slice(snapshot.as_bytes());
                Ok(bytes)
            })
            .await
            .map_err(|_| crate::state_transfer::failure("SessionTickets", "backend", None))?
            .map(Buffer::from)
        })
        .build(&env)
    }

    /// Authenticates all owners before updating compatible ticket caches.
    #[napi]
    pub fn import_session_tickets(
        &self,
        env: Env,
        snapshot: Buffer,
        secret: Buffer,
        routes: Array<'_>,
    ) -> Result<AsyncBlock<()>> {
        self.state.check_open()?;
        let key = super::state_transfer::ticket_key(&env, secret)?;
        let bytes = super::state_transfer::ticket_bytes(&env, snapshot)?;
        let routes = super::state_transfer::receiving_routes(
            routes,
            super::state_transfer::RouteTransfer::Tickets,
        )?;
        let permit = Arc::clone(&self.state.admission)
            .try_acquire_owned()
            .map_err(|_| failure("Capacity", "client has no free request slots"))?;
        let owner = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            tokio::task::spawn_blocking(move || {
                // The blocking worker retains admission even if JS drops its promise.
                let _permit = permit;
                let snapshot = phantom::SessionTicketSnapshot::from_bytes(&bytes)
                    .map_err(crate::state_transfer::ticket_error)?;
                owner
                    .core
                    .import_session_tickets(&snapshot, &key, &routes)
                    .map_err(crate::state_transfer::ticket_error)
            })
            .await
            .map_err(|_| crate::state_transfer::failure("SessionTickets", "backend", None))?
        })
        .build(&env)
    }

    /// Opens an exact-protocol, reconnecting source with native ownership.
    #[napi]
    pub fn event_source(
        &self,
        env: Env,
        options: EventSourceOptions,
        source: &NativeEventSource,
    ) -> Result<AsyncBlock<EventSourceHead>> {
        let builder = super::event_source::prepare(&env, &self.state, options)?;
        let permit = Arc::clone(&self.state.admission)
            .try_acquire_owned()
            .map_err(|_| failure("Capacity", "client has no free request slots"))?;
        let source = Arc::clone(&source.source);
        let permit = source.claim(permit, Arc::clone(&self.state))?;
        if let Err(error) = self.state.register_event_source(&source) {
            source.close();
            return Err(error);
        }
        let owner = Arc::clone(&source);
        let pending = AsyncBlockBuilder::new(async move {
            let _permit = permit;
            let result = async {
                let response = tokio::select! {
                    biased;
                    error = source.interrupted() => return Err(error),
                    response = builder.connect() => response.map_err(crate::event_source::error)?,
                };
                let head = super::event_source::head(&response)?;
                source.attach(response.into_body())?;
                Ok(head)
            }
            .await;
            if result.is_err() {
                source.close();
            }
            result
        })
        .build(&env);
        if pending.is_err() {
            owner.close();
        }
        pending
    }

    /// Opens a WebSocket using this client's native profile, route and trust.
    #[napi]
    pub fn websocket(
        &self,
        env: Env,
        mut options: WebSocketOptions,
        socket: &NativeWebSocket,
    ) -> Result<AsyncBlock<Either<WebSocketHandshake, WebSocketRejection>>> {
        let builder = super::websocket::prepare(&env, &self.state, &mut options)?;
        let url = options.url;
        let permit = Arc::clone(&self.state.admission)
            .try_acquire_owned()
            .map_err(|_| failure("Capacity", "client has no free request slots"))?;
        let socket = Arc::clone(&socket.socket);
        let permit = socket.claim(permit, Arc::clone(&self.state))?;
        if let Err(error) = self.state.register_socket(&socket) {
            socket.abort();
            return Err(error);
        }
        let owner = Arc::clone(&socket);
        let client = Arc::clone(&self.state);
        let pending = AsyncBlockBuilder::new(async move {
            let result = async {
                let connected = tokio::select! {
                    biased;
                    error = socket.interrupted() => return Err(error),
                    result = builder.connect() => match result {
                        Ok(connected) => connected,
                        Err(error) => {
                            let details = crate::websocket::error_details(&error);
                            let Some(response) = error.into_response() else {
                                return Err(details);
                            };
                            let rejection = super::websocket::rejection(
                                response, details.reason, url, client, Arc::clone(&permit),
                            )?;
                            socket.abort();
                            return Ok(Either::B(rejection));
                        }
                    },
                };
                let handshake = super::websocket::handshake(&connected)?;
                socket.attach(connected)?;
                Ok(Either::A(handshake))
            }
            .await;
            if result.is_err() {
                socket.abort();
            }
            result
        })
        .build(&env);
        if pending.is_err() {
            owner.abort();
        }
        pending
    }
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
        header_hooks: Option<&NativeHeaderHooks>,
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
                header_hooks: header_hooks.map(|hooks| Arc::clone(&hooks.state)),
            },
        )?;
        if let Some(upload) = upload {
            *upload.owner.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Arc::clone(&cancellation.exchange));
        }
        if let Some(hooks) = header_hooks {
            cancellation.exchange.header_hooks_started();
            *hooks.owner.lock().unwrap_or_else(PoisonError::into_inner) =
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
                connection_retries: Some(head.connection_retries),
                decoded_content_codings: head.decoded_content_codings,
                redirect_history: head.redirect_history,
                exchange,
                owner,
            })
        })
        .build(&env)
    }
    /// Stops admission and waits for existing responses and sockets to finish.
    #[napi]
    pub fn close(&self, env: Env, timeout_ms: u32) -> Result<AsyncBlock<()>> {
        let shutdown = self.state.shutdown()?;
        self.state.close_admission();
        let owner = Arc::clone(&self.state);
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        AsyncBlockBuilder::new(async move {
            let _shutdown = shutdown;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), owner.drain())
                .await
                .map_err(|_| failure("Timeout", "client shutdown deadline expired"))?
        })
        .build(&env)
    }
    /// Cancels admitted work; close waits for its cleanup.
    #[napi]
    pub fn destroy(&self) {
        self.state.close();
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
