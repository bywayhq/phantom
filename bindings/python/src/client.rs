use crate::{
    configuration, error, profile, request_fields,
    response::NativeResponse,
    runtime, session,
    transfer::NativeTransferControl,
    upload::{FileBody, NativeUpload},
};
use phantom::{Client, HttpAttemptBudget, HttpProtocol, Method, SessionSharing};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyList},
};
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

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

#[derive(Default)]
struct Preparation {
    closed: AtomicBool,
    changed: tokio::sync::Notify,
}
impl Preparation {
    async fn closed(&self) {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if !self.closed.load(Ordering::SeqCst) {
            changed.await;
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

#[pyclass]
pub(super) struct NativeClient {
    client: Client,
    protocol: String,
    preparation: Arc<Preparation>,
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (profile, protocol, context=None, proxy=None, cookies=true, timeout_ms=None, base_url=None, roots=Vec::new(), proxy_roots=Vec::new(), proxy_username=None, proxy_password=None, timeouts=None, redirect_maximum_hops=None, retry_policy=None))]
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
        retry_policy: Option<configuration::RetryFields>,
    ) -> PyResult<Self> {
        runtime::initialize()?;
        if !matches!(protocol, "h1" | "h2" | "h3" | "negotiated") {
            return Err(error::input("invalid_protocol"));
        }
        let profile = profile::select(profile, context)?;
        let mut builder = Client::builder(profile)
            .route(configuration::route(proxy, proxy_username, proxy_password)?)
            .request_timeouts(configuration::client_timeouts(timeout_ms, timeouts)?);
        if let Some(maximum) = redirect_maximum_hops {
            builder = builder.redirect_policy(configuration::redirect_policy(maximum));
        }
        if let Some(policy) = retry_policy {
            builder = builder.retry_policy(configuration::retry_policy(policy)?);
        }
        if let Some(base_url) = base_url {
            builder = builder
                .base_url(base_url)
                .map_err(|_| error::input("invalid_base_url"))?;
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
        let client = builder
            .build()
            .map_err(|_| error::input("invalid_client_configuration"))?;
        Ok(Self {
            client,
            protocol: protocol.to_owned(),
            preparation: Arc::default(),
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
        self.client.is_closed()
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
            preparation: Arc::default(),
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
            preparation: Arc::default(),
        })
    }

    #[pyo3(signature = (method, url, headers, body=None, upload=None, budget=None, timeout_ms=None, timeouts=None, maximum_decoded_bytes=None, redirect_maximum_hops=None, redirect_history_limit=None, retry_policy=None, producer=None, transfer_control=None, trailers=None, expect_continue_ms=None))]
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
        retry_policy: Option<configuration::RetryFields>,
        producer: Option<PyRef<'_, NativeUpload>>,
        transfer_control: Option<PyRef<'_, NativeTransferControl>>,
        trailers: Option<&Bound<'py, PyList>>,
        expect_continue_ms: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let started = tokio::time::Instant::now();
        if usize::from(body.is_some())
            + usize::from(upload.is_some())
            + usize::from(producer.is_some())
            > 1
        {
            return Err(error::input("body_and_upload"));
        }
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|_| error::input("invalid_method"))?;
        let mut request = match self.protocol.as_str() {
            "h1" => self.client.request(HttpProtocol::Http1, method, url),
            "h2" => self.client.request(HttpProtocol::Http2, method, url),
            "h3" => self.client.request(HttpProtocol::Http3, method, url),
            "negotiated" => self.client.request_negotiated(method, url),
            _ => return Err(error::input("invalid_protocol")),
        }
        .map_err(error::request)?;
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
        let bounded_upload = upload.is_some() || producer.is_some();
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
        if let Some(maximum) = redirect_maximum_hops {
            request = request.redirect_policy(configuration::redirect_policy(maximum));
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
        let producer = producer.map(|value| Arc::clone(&value.inner));
        if let Some(owner) = &producer {
            request = request.streaming_body(owner.body()?);
        }
        let protocol = self.protocol.clone();
        let preparation = Arc::clone(&self.preparation);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
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
                let response = request.send().await.map_err(error::request)?;
                let response = NativeResponse::new(response)?;
                response.watch_upload(producer, deadline)?;
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
            if bounded_upload {
                tokio::select! {
                    biased;
                    () = preparation.closed() => Err(error::NativeError::new_err(("request", "client_closed", None::<String>, None::<String>))),
                    response = sending => response,
                }
            } else {
                sending.await
            }
        })
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
        let client = self.client.clone();
        let preparation = Arc::clone(&self.preparation);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            preparation.close();
            tokio::time::timeout(Duration::from_millis(timeout_ms), client.shutdown())
                .await
                .map_err(|_| error::input("shutdown_timeout"))
        })
    }
}
