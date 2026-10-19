use crate::{error, response::NativeResponse, runtime, upload::FileBody};
use phantom::{Client, HttpAttemptBudget, HttpProtocol, Method, RequestHeader, Route};
use phantom_profile::catalog::{self, RequestTemplateKind};
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

fn route(uri: Option<&str>) -> PyResult<Route> {
    let Some(uri) = uri else {
        return Ok(Route::direct());
    };
    match uri.split_once("://").map(|(scheme, _)| scheme) {
        Some("http" | "https") => phantom::HttpProxy::new(uri)
            .map(Route::http_proxy)
            .map_err(|_| error::input("invalid_http_proxy")),
        Some("socks4" | "socks4a") => phantom::Socks4Proxy::new(uri)
            .map(Route::socks4)
            .map_err(|_| error::input("invalid_socks4_proxy")),
        Some("socks5" | "socks5h") => phantom::Socks5Proxy::new(uri)
            .map(Route::socks5)
            .map_err(|_| error::input("invalid_socks5_proxy")),
        _ => Err(error::input("invalid_proxy_scheme")),
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
    #[pyo3(signature = (profile, protocol, context=None, proxy=None, cookies=true, timeout_ms=None))]
    fn new(
        profile: &str,
        protocol: &str,
        context: Option<&str>,
        proxy: Option<&str>,
        cookies: bool,
        timeout_ms: Option<u64>,
    ) -> PyResult<Self> {
        runtime::initialize()?;
        if !matches!(protocol, "h1" | "h2" | "h3" | "negotiated") {
            return Err(error::input("invalid_protocol"));
        }
        let definition = catalog::profile(profile).map_err(|_| error::input("unknown_profile"))?;
        let mut profile = definition
            .instantiate(&[])
            .map_err(|_| error::input("invalid_profile"))?
            .without_request_template();
        if let Some(context) = context {
            let context = match context {
                "navigation" => RequestTemplateKind::Navigation,
                "fetch" => RequestTemplateKind::Fetch,
                _ => return Err(error::input("invalid_context")),
            };
            profile = profile.with_request_template(
                definition
                    .request_template(context)
                    .map_err(|_| error::input("context_unavailable"))?,
            );
        }
        let mut builder = Client::builder(profile).route(route(proxy)?);
        if cookies {
            builder = builder.cookies();
        }
        if let Some(timeout) = timeout_ms {
            builder = builder.request_timeouts(
                phantom::RequestTimeouts::new().total(Duration::from_millis(timeout)),
            );
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

    #[pyo3(signature = (method, url, headers, body=None, upload=None, budget=None, timeout_ms=None))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        headers: Vec<(String, Vec<u8>)>,
        body: Option<Vec<u8>>,
        upload: Option<PathBuf>,
        budget: Option<PyRef<'_, AttemptBudget>>,
        timeout_ms: Option<u64>,
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
                .map(|(name, value)| RequestHeader::new(name, value))
                .collect(),
        );
        if let Some(budget) = budget {
            request = request.attempt_budget(budget.inner.clone());
        }
        if let Some(timeout) = timeout_ms {
            request = request.timeouts(phantom::RequestTimeoutOverrides::new().total(
                phantom::TimeoutOverride::Limit(Duration::from_millis(timeout)),
            ));
        }
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

    fn shutdown<'py>(&self, py: Python<'py>, timeout_ms: u64) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::timeout(Duration::from_millis(timeout_ms), client.shutdown())
                .await
                .map_err(|_| error::input("shutdown_timeout"))
        })
    }
}
