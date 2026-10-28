use crate::{
    client_certificate::{self, NativeClientCertificate},
    configuration,
    diagnostics::NativeRequestDiagnostics,
    error,
    lifecycle::Lifecycle,
    network, pool,
    prepared_body::NativePreparedBody,
    profile, request_fields,
    response::NativeResponse,
    runtime, session,
    streaming_multipart::NativeStreamingMultipart,
    transfer::NativeTransferControl,
    upload::{FileBody, NativeUpload, UploadOwner},
};
use phantom::{Client, HttpAttemptBudget, HttpProtocol, Method, SessionSharing};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyInt, PyList},
};
use std::{num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};

pub(super) fn protocol_name(protocol: HttpProtocol) -> &'static str {
    match protocol {
        HttpProtocol::Http1 => "h1",
        HttpProtocol::Http2 => "h2",
        HttpProtocol::Http3 => "h3",
        _ => "unknown",
    }
}

#[pyclass]
pub(super) struct AttemptBudget {
    inner: HttpAttemptBudget,
}

#[pymethods]
impl AttemptBudget {
    #[new]
    fn new(maximum: usize) -> Self {
        Self {
            inner: HttpAttemptBudget::new(maximum),
        }
    }
    #[getter]
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }
    fn try_admit(&self) -> PyResult<()> {
        self.inner
            .try_admit()
            .map_err(|_| error::input("attempt_budget_exhausted"))
    }
}

#[pyclass]
pub(super) struct NativeCookies {
    client: Client,
}

#[pymethods]
impl NativeCookies {
    fn set(&self, url: &str, set_cookie: &str) -> PyResult<()> {
        self.client
            .cookie_jar()
            .ok_or_else(|| error::input("cookies_disabled"))?
            .set_cookie(url, set_cookie)
            .map_err(|_| error::input("invalid_cookie"))
    }
    fn for_url(&self, url: &str) -> PyResult<Option<String>> {
        self.client
            .cookie_jar()
            .ok_or_else(|| error::input("cookies_disabled"))?
            .request_value(url)
            .map_err(|_| error::input("invalid_cookie_url"))
    }
    fn clear(&self) -> PyResult<()> {
        self.client
            .cookie_jar()
            .ok_or_else(|| error::input("cookies_disabled"))?
            .clear();
        Ok(())
    }
    fn __len__(&self) -> usize {
        self.client.cookie_jar().map_or(0, phantom::CookieJar::len)
    }
}

#[pyclass]
pub(super) struct NativeClient {
    client: Client,
    protocol: String,
    lifecycle: Arc<Lifecycle>,
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (profile, protocol, context=None, proxy=None, cookies=true, timeout_ms=None, base_url=None, roots=Vec::new(), proxy_roots=Vec::new(), proxy_username=None, proxy_password=None, timeouts=None, redirect_maximum_hops=None, retry_policy=None, server_spki_pins=None, proxy_server_spki_pins=None, client_certificate=None, client_certificates_for=None, network=None, pool=None, redirect_credential_headers=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        profile: &Bound<'_, PyAny>,
        protocol: &str,
        context: Option<&str>,
        proxy: Option<&str>,
        cookies: bool,
        timeout_ms: Option<u64>,
        base_url: Option<&str>,
        roots: Vec<Vec<u8>>,
        proxy_roots: Vec<Vec<u8>>,
        proxy_username: Option<&str>,
        proxy_password: Option<&str>,
        timeouts: Option<configuration::TimeoutFields>,
        redirect_maximum_hops: Option<usize>,
        retry_policy: Option<configuration::RetrySettings>,
        server_spki_pins: Option<&Bound<'_, PyAny>>,
        proxy_server_spki_pins: Option<&Bound<'_, PyAny>>,
        client_certificate: Option<PyRef<'_, NativeClientCertificate>>,
        client_certificates_for: Option<&Bound<'_, PyAny>>,
        network: Option<&Bound<'_, PyAny>>,
        pool: Option<&Bound<'_, PyAny>>,
        redirect_credential_headers: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let network = network::parse(network)?;
        let pool = pool::parse(pool)?;
        let client_certificates_for = client_certificate::origins(client_certificates_for)?;
        let server_spki_pins =
            configuration::server_pins(server_spki_pins, "invalid_server_spki_pins")?;
        let proxy_server_spki_pins =
            configuration::server_pins(proxy_server_spki_pins, "invalid_proxy_server_spki_pins")?;
        runtime::initialize()?;
        if !matches!(protocol, "h1" | "h2" | "h3" | "negotiated") {
            return Err(error::input("invalid_protocol"));
        }
        let profile = profile::select(profile, context)?;
        let mut builder = Client::builder(profile)
            .route(configuration::route(proxy, proxy_username, proxy_password)?)
            .request_timeouts(configuration::client_timeouts(timeout_ms, timeouts)?);
        if let Some(policy) =
            configuration::redirect_policy(redirect_maximum_hops, redirect_credential_headers)?
        {
            builder = builder.redirect_policy(policy);
        }
        if let Some(policy) = retry_policy {
            builder = builder.retry_policy(configuration::retry_policy(policy)?);
        }
        if let Some(base_url) = base_url {
            builder = builder
                .base_url(base_url)
                .map_err(|_| error::input("invalid_base_url"))?;
        }
        if let Some(pins) = server_spki_pins {
            builder = builder.server_spki_pins(pins);
        }
        if let Some(pins) = proxy_server_spki_pins {
            builder = builder.proxy_server_spki_pins(pins);
        }
        if let Some(certificate) = client_certificate {
            builder = builder.client_certificate(certificate.inner.clone());
        }
        for (origin, certificate) in client_certificates_for {
            builder = builder.client_certificate_for(&origin, certificate);
        }
        for root in roots {
            builder = builder.add_root_certificate_der(root);
        }
        for root in proxy_roots {
            builder = builder.add_proxy_root_certificate_der(root);
        }
        if cookies {
            builder = builder.cookies();
        }
        let client = pool
            .apply(network.apply(builder)?)
            .build()
            .map_err(client_certificate::build_error)?;
        Ok(Self {
            client,
            protocol: protocol.to_owned(),
            lifecycle: Arc::default(),
        })
    }

    #[getter]
    fn cookies(&self) -> NativeCookies {
        NativeCookies {
            client: self.client.clone(),
        }
    }

    #[getter]
    fn is_closed(&self) -> bool {
        self.lifecycle.is_closed() || self.client.is_closed()
    }

    fn fork(
        &self,
        cookies: bool,
        dns: bool,
        client_hints: bool,
        discovery: bool,
        tickets: bool,
    ) -> Self {
        Self {
            client: self.client.fork(
                SessionSharing::none()
                    .cookies(cookies)
                    .dns(dns)
                    .client_hints(client_hints)
                    .discovery(discovery)
                    .tickets(tickets),
            ),
            protocol: self.protocol.clone(),
            lifecycle: Arc::default(),
        }
    }

    fn export_session(&self, py: Python<'_>, key: &Bound<'_, PyBytes>) -> PyResult<Vec<u8>> {
        session::export(py, &self.client, key)
    }

    fn restore_session(
        &self,
        py: Python<'_>,
        snapshot: &Bound<'_, PyBytes>,
        key: &Bound<'_, PyBytes>,
        receiving_routes: session::Routes,
    ) -> PyResult<Self> {
        Ok(Self {
            client: session::restore(py, &self.client, snapshot, key, receiving_routes)?,
            protocol: self.protocol.clone(),
            lifecycle: Arc::default(),
        })
    }

    #[pyo3(signature = (method, url, headers, body=None, upload=None, budget=None, timeout_ms=None, timeouts=None, maximum_decoded_bytes=None, redirect_maximum_hops=None, redirect_history_limit=None, retry_policy=None, producer=None, transfer_control=None, trailers=None, expect_continue_ms=None, prepared_body=None, body_length=None, diagnostics=None, multipart=None, redirect_credential_headers=None, context=None))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        headers: &Bound<'py, PyList>,
        body: Option<Vec<u8>>,
        upload: Option<PathBuf>,
        budget: Option<PyRef<'_, AttemptBudget>>,
        timeout_ms: Option<u64>,
        timeouts: Option<configuration::TimeoutFields>,
        maximum_decoded_bytes: Option<u64>,
        redirect_maximum_hops: Option<usize>,
        redirect_history_limit: Option<usize>,
        retry_policy: Option<configuration::RetrySettings>,
        producer: Option<PyRef<'_, NativeUpload>>,
        transfer_control: Option<PyRef<'_, NativeTransferControl>>,
        trailers: Option<&Bound<'py, PyList>>,
        expect_continue_ms: Option<Bound<'_, PyAny>>,
        prepared_body: Option<PyRef<'_, NativePreparedBody>>,
        body_length: Option<Bound<'_, PyAny>>,
        diagnostics: Option<PyRef<'_, NativeRequestDiagnostics>>,
        multipart: Option<PyRef<'_, NativeStreamingMultipart>>,
        redirect_credential_headers: Option<&Bound<'_, PyAny>>,
        context: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let admission = self.lifecycle.admit("request")?;
        let started = tokio::time::Instant::now();
        if usize::from(body.is_some())
            + usize::from(upload.is_some())
            + usize::from(producer.is_some())
            + usize::from(prepared_body.is_some())
            + usize::from(multipart.is_some())
            > 1
        {
            return Err(error::input("body_and_upload"));
        }
        let body_length = body_length
            .map(|value| {
                value
                    .cast_exact::<PyInt>()
                    .map_err(|_| error::input("invalid_body_length"))?
                    .extract::<usize>()
                    .map_err(|_| error::input("invalid_body_length"))
            })
            .transpose()?;
        if body_length.is_some_and(|length| {
            prepared_body
                .as_ref()
                .is_none_or(|body| body.inner.bytes().len() != length)
        }) {
            return Err(error::input("invalid_body_length"));
        }
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|_| error::input("invalid_method"))?;
        let mut request = match self.protocol.as_str() {
            "h1" => self
                .client
                .request_with_protocol(HttpProtocol::Http1, method, url),
            "h2" => self
                .client
                .request_with_protocol(HttpProtocol::Http2, method, url),
            "h3" => self
                .client
                .request_with_protocol(HttpProtocol::Http3, method, url),
            "negotiated" => self.client.request(method, url),
            _ => return Err(error::input("invalid_protocol")),
        }
        .map_err(error::request)?;
        request = match context {
            None => request,
            Some("raw") => request.without_template(),
            Some(context) => request
                .context(profile::template_kind(context)?)
                .map_err(error::request)?,
        };
        let (headers, trailers) = request_fields::headers(headers, trailers)?;
        request = request.headers(headers).trailers(trailers);
        if let Some(wait) = request_fields::expect_wait(expect_continue_ms)? {
            request = request.expect_continue(wait);
        }
        if let Some(budget) = budget {
            request = request.attempt_budget(budget.inner.clone());
        }
        if let Some(control) = transfer_control {
            request = request.transfer_control(control.inner.clone());
        }
        let overrides = configuration::request_timeouts(timeout_ms, timeouts)?;
        let total = overrides
            .resolve(self.client.request_timeouts())
            .total_duration();
        // A ready send may beat an asynchronously polled zero timeout.
        if total.is_some_and(|duration| duration.is_zero()) {
            return Err(error::total_timeout(Some(&self.protocol)));
        }
        let bounded_upload = upload.is_some() || producer.is_some() || multipart.is_some();
        let deadline = if bounded_upload {
            total
                .map(|duration| {
                    started
                        .checked_add(duration)
                        .ok_or_else(|| error::input("invalid_timeout"))
                })
                .transpose()?
        } else {
            None
        };
        request = request.timeouts(overrides);
        if let Some(maximum) = maximum_decoded_bytes {
            request = request.content_decoding(phantom::ContentDecoding::advertised(maximum));
        }
        if let Some(policy) =
            configuration::redirect_policy(redirect_maximum_hops, redirect_credential_headers)?
        {
            request = request.redirect_policy(policy);
        }
        if let Some(maximum) = redirect_history_limit {
            request = request.redirect_history(
                NonZeroUsize::new(maximum)
                    .ok_or_else(|| error::input("invalid_redirect_history_limit"))?,
            );
        }
        if let Some(policy) = retry_policy {
            request = request.retry_policy(configuration::retry_policy(policy)?);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        if let Some(body) = prepared_body {
            request = request.prepared_body(body.inner.clone());
        }
        let producer = producer.map(|value| Arc::clone(&value.inner));
        if let Some(owner) = &producer {
            request = request.streaming_body(owner.body()?);
        }
        let is_multipart = multipart.is_some();
        let upload_owner = if let Some(multipart) = multipart {
            request = request.multipart_body(multipart.inner.take_body()?);
            Some(UploadOwner::Multipart(Arc::clone(&multipart.inner)))
        } else {
            producer.map(UploadOwner::Single)
        };
        if let Some(diagnostics) = diagnostics {
            diagnostics.attach(&mut request)?;
        }
        let protocol = self.protocol.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let lifecycle = Arc::clone(admission.lifecycle());
            let send = async move {
                if let Some(path) = upload {
                    request =
                        request.streaming_body(FileBody::open(path).await.map_err(error::io)?);
                }
                if let Some(deadline) = deadline {
                    request = request.timeouts(overrides.total(phantom::TimeoutOverride::Limit(
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )));
                }
                let response = request.send().await.map_err(|error| {
                    if is_multipart {
                        crate::streaming_multipart::request_error(error)
                    } else {
                        error::request(error)
                    }
                })?;
                let response = NativeResponse::new(response)?;
                response.watch_upload(upload_owner, deadline)?;
                response.track(&lifecycle);
                Ok(response)
            };
            let sending = async {
                if let Some(deadline) = deadline {
                    tokio::time::timeout_at(deadline, send)
                        .await
                        .map_err(|_| error::total_timeout(Some(&protocol)))?
                } else {
                    send.await
                }
            };
            tokio::select! {
                biased;
                () = admission.aborted() => Err(error::NativeError::new_err(("request", "client_closed", None::<String>, None::<String>))),
                response = sending => response,
            }
        })
    }

    #[pyo3(signature = (url, protocol, headers, maximum_frame_bytes, maximum_message_bytes, maximum_fragments, inherit_handshake_timeout, handshake_timeout_ms, maximum_connection_failures, retry_delay_ms))]
    #[allow(clippy::too_many_arguments)]
    fn websocket<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        protocol: &str,
        headers: &Bound<'py, PyList>,
        maximum_frame_bytes: &Bound<'py, PyAny>,
        maximum_message_bytes: &Bound<'py, PyAny>,
        maximum_fragments: &Bound<'py, PyAny>,
        inherit_handshake_timeout: bool,
        handshake_timeout_ms: Option<&Bound<'py, PyAny>>,
        maximum_connection_failures: Option<&Bound<'py, PyAny>>,
        retry_delay_ms: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::websocket::connect(
            &self.client,
            self.lifecycle.admit("websocket")?,
            py,
            url,
            protocol,
            headers,
            maximum_frame_bytes,
            maximum_message_bytes,
            maximum_fragments,
            inherit_handshake_timeout,
            handshake_timeout_ms,
            maximum_connection_failures,
            retry_delay_ms,
        )
    }

    #[pyo3(signature = (url, protocol, headers, last_event_id_slot, maximum_line_bytes, maximum_event_bytes, idle_timeout, initial_retry, min_retry, max_reconnects, timeouts, inherit_proxy, proxy, proxy_username, proxy_password))]
    #[allow(clippy::too_many_arguments)]
    fn event_source<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        protocol: &str,
        headers: Option<&Bound<'_, PyList>>,
        last_event_id_slot: Option<usize>,
        maximum_line_bytes: usize,
        maximum_event_bytes: usize,
        idle_timeout: Option<&Bound<'_, PyAny>>,
        initial_retry: &Bound<'_, PyAny>,
        min_retry: Option<&Bound<'_, PyAny>>,
        max_reconnects: &Bound<'_, PyAny>,
        timeouts: Option<configuration::TimeoutFields>,
        inherit_proxy: bool,
        proxy: Option<&str>,
        proxy_username: Option<&str>,
        proxy_password: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::event_source::connect(
            py,
            &self.client,
            &self.lifecycle,
            url,
            protocol,
            headers,
            last_event_id_slot,
            maximum_line_bytes,
            maximum_event_bytes,
            idle_timeout,
            initial_retry,
            min_retry,
            max_reconnects,
            timeouts,
            inherit_proxy,
            proxy,
            proxy_username,
            proxy_password,
        )
    }

    fn close_idle_connections<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.close_idle_connections().await;
            Ok(())
        })
    }

    fn refresh_connections<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.refresh_connections().await;
            Ok(())
        })
    }

    fn clear_session_tickets(&self) -> PyResult<usize> {
        self.client
            .clear_session_tickets()
            .map_err(|_| error::input("session_tickets"))
    }

    fn clear_dns_cache(&self) {
        self.client.clear_dns_cache();
    }

    fn clear_client_hints(&self) {
        self.client.clear_client_hints();
    }

    fn clear_alt_svc(&self) {
        self.client.clear_alt_svc();
    }

    fn clear_alt_svc_racing_history(&self) {
        self.client.clear_alt_svc_racing_history();
    }

    fn shutdown<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Bound<'py, PyAny>> {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or_else(|| error::input("invalid_timeout"))?;
        self.lifecycle.close();
        let client = self.client.clone();
        let lifecycle = Arc::clone(&self.lifecycle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::timeout_at(deadline, async {
                lifecycle.drained().await;
                client.shutdown().await;
            })
            .await
            .map_err(|_| error::input("shutdown_timeout"))
        })
    }

    fn abort(&self) {
        self.lifecycle.abort();
    }
}
