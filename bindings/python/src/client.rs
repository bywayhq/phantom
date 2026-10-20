use crate::{configuration, error, profile, response::NativeResponse, runtime, upload::FileBody};
use phantom::{Client, HttpAttemptBudget, HttpProtocol, Method, RequestHeader, SessionSharing};
use pyo3::prelude::*;
use std::{path::PathBuf, time::Duration};

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
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (profile, protocol, context=None, proxy=None, cookies=true, timeout_ms=None, base_url=None, roots=Vec::new(), proxy_roots=Vec::new(), proxy_username=None, proxy_password=None, timeouts=None))]
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
    ) -> PyResult<Self> {
        runtime::initialize()?;
        if !matches!(protocol, "h1" | "h2" | "h3" | "negotiated") {
            return Err(error::input("invalid_protocol"));
        }
        let profile = profile::select(profile, context)?;
        let mut builder = Client::builder(profile)
            .route(configuration::route(proxy, proxy_username, proxy_password)?)
            .request_timeouts(configuration::client_timeouts(timeout_ms, timeouts)?);
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
        }
    }

    #[pyo3(signature = (method, url, headers, body=None, upload=None, budget=None, timeout_ms=None, timeouts=None))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        headers: Vec<(String, Vec<u8>, bool)>,
        body: Option<Vec<u8>>,
        upload: Option<PathBuf>,
        budget: Option<PyRef<'_, AttemptBudget>>,
        timeout_ms: Option<u64>,
        timeouts: Option<configuration::TimeoutFields>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if body.is_some() && upload.is_some() {
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
        request = request.headers(
            headers
                .into_iter()
                .map(|(name, value, sensitive)| {
                    let header = RequestHeader::new(name, value);
                    if sensitive {
                        header.sensitive()
                    } else {
                        header
                    }
                })
                .collect(),
        );
        if let Some(budget) = budget {
            request = request.attempt_budget(budget.inner.clone());
        }
        request = request.timeouts(configuration::request_timeouts(timeout_ms, timeouts)?);
        if let Some(body) = body {
            request = request.body(body);
        }
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(path) = upload {
                request = request.streaming_body(FileBody::open(path).await.map_err(error::io)?);
            }
            NativeResponse::new(request.send().await.map_err(error::request)?)
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::timeout(Duration::from_millis(timeout_ms), client.shutdown())
                .await
                .map_err(|_| error::input("shutdown_timeout"))
        })
    }
}
