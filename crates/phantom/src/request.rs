use std::{fmt, net::Ipv6Addr};

use http::{Response, Uri, uri::Authority};
use phantom_net::{http1::OriginForm, request::RequestHeader};
use tracing::{Instrument, debug_span, field};

use crate::{Client, HttpProtocol, RequestError, ResponseBody};

/// Builder for one exact-protocol, empty-body GET request.
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder<'a> {
    client: &'a Client,
    request: ResolvedRequest,
    protocol: HttpProtocol,
    headers: Vec<RequestHeader>,
}

impl fmt::Debug for RequestBuilder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol", &self.protocol)
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(
        client: &'a Client,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        match protocol {
            HttpProtocol::Http1 if client.inner.http1.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http1));
            }
            HttpProtocol::Http2 if client.inner.http2.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http2));
            }
            HttpProtocol::Http1 | HttpProtocol::Http2 => {}
        }
        let uri = uri.parse::<Uri>().map_err(RequestError::invalid_uri)?;
        Ok(Self {
            client,
            request: ResolvedRequest::new(&uri)?,
            protocol,
            headers: Vec::new(),
        })
    }

    /// Appends one ordered request field.
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Sends the request over a new direct connection.
    ///
    /// Dropping this future cancels the in-flight operation. After response
    /// headers arrive, the returned body owns protocol cancellation and
    /// connection shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for invalid ordered fields, a missing Tokio
    /// runtime, connection or TLS failure, and protocol failure. Inspect
    /// [`RequestError::kind`](crate::RequestError::kind) for the stable
    /// category.
    ///
    /// # Panics
    ///
    /// Tokio may panic if the current runtime was built without network I/O
    /// enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use phantom::{Client, HttpProtocol, RequestError};
    /// # async fn example(client: &Client) -> Result<(), RequestError> {
    /// let response = client
    ///     .get(HttpProtocol::Http2, "https://example.com/")?
    ///     .send()
    ///     .await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(self) -> Result<Response<ResponseBody>, RequestError> {
        let span = debug_span!(
            "client.request",
            method = "GET",
            protocol = self.protocol.trace_name(),
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        let result = self.send_inner().instrument(span.clone()).await;
        outcome.finish(if result.is_ok() { "ok" } else { "error" });
        result
    }

    async fn send_inner(self) -> Result<Response<ResponseBody>, RequestError> {
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("host"))
        {
            return Err(RequestError::authority_header());
        }

        match self.protocol {
            HttpProtocol::Http1 => {
                let connector = self
                    .client
                    .inner
                    .http1
                    .as_ref()
                    .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http1))?;
                let mut headers = Vec::with_capacity(self.headers.len() + 1);
                headers.push(RequestHeader::new(
                    "Host",
                    self.request.authority.as_str().as_bytes(),
                ));
                headers.extend(self.headers);
                let response = connector
                    .send_get_direct(
                        &self.request.host,
                        self.request.port,
                        &self.request.host,
                        self.request.target,
                        headers,
                    )
                    .await
                    .map_err(RequestError::http1)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http1(body)))
            }
            HttpProtocol::Http2 => {
                let connector = self
                    .client
                    .inner
                    .http2
                    .as_ref()
                    .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http2))?;
                let response = connector
                    .send_get_direct(
                        &self.request.host,
                        self.request.port,
                        &self.request.host,
                        self.request.authority.as_str(),
                        self.request.target,
                        self.headers,
                    )
                    .await
                    .map_err(RequestError::http2)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http2(body)))
            }
        }
    }
}

#[derive(Debug)]
struct ResolvedRequest {
    authority: Authority,
    host: Box<str>,
    port: u16,
    target: OriginForm,
}

impl ResolvedRequest {
    fn new(uri: &Uri) -> Result<Self, RequestError> {
        if uri.scheme_str() != Some("https") {
            return Err(RequestError::unsupported_scheme());
        }
        let authority = uri.authority().cloned().ok_or_else(|| {
            RequestError::invalid_authority("request URI must include an authority")
        })?;
        if authority.as_str().as_bytes().contains(&b'@') {
            return Err(RequestError::invalid_authority(
                "request authority must not contain user information",
            ));
        }
        let (host, port) = resolve_host_and_port(&authority)?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(RequestError::invalid_target)?;

        Ok(Self {
            authority,
            host,
            port,
            target,
        })
    }
}

fn resolve_host_and_port(authority: &Authority) -> Result<(Box<str>, u16), RequestError> {
    let text = authority.as_str();
    if let Some(bracketed) = text.strip_prefix('[') {
        let (literal, suffix) = bracketed.split_once(']').ok_or_else(|| {
            RequestError::invalid_authority("bracketed request host is incomplete")
        })?;
        let address = literal.parse::<Ipv6Addr>().map_err(|_| {
            RequestError::invalid_authority("bracketed request host must be an IPv6 address")
        })?;
        let port = parse_port_suffix(suffix)?;
        return Ok((address.to_string().into(), port));
    }

    let host = authority.host();
    if host.is_empty() {
        return Err(RequestError::invalid_authority(
            "request URI host must not be empty",
        ));
    }
    if host.contains(':') {
        return Err(RequestError::invalid_authority(
            "IPv6 request hosts must use brackets",
        ));
    }
    let port = match text.strip_prefix(host) {
        Some("") => 443,
        Some(suffix) => parse_port_suffix(suffix)?,
        None => {
            return Err(RequestError::invalid_authority(
                "request URI authority does not match its host",
            ));
        }
    };
    Ok((host.into(), port))
}

fn parse_port_suffix(suffix: &str) -> Result<u16, RequestError> {
    if suffix.is_empty() {
        return Ok(443);
    }
    let port = suffix.strip_prefix(':').ok_or_else(|| {
        RequestError::invalid_authority("request URI authority has an invalid suffix")
    })?;
    if port.is_empty() {
        return Err(RequestError::invalid_authority(
            "request URI port must not be empty",
        ));
    }
    port.parse::<u16>()
        .map_err(|_| RequestError::invalid_authority("request URI port is invalid"))
}

struct RequestOutcome {
    span: tracing::Span,
    recorded: bool,
}

impl RequestOutcome {
    fn new(span: &tracing::Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for RequestOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}
