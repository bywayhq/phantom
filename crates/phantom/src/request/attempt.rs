use bytes::Bytes;
use http::{Method, Response};
use phantom_net::request::RequestHeader;

use crate::{HttpProtocol, RequestError, ResponseBody, Route};

use super::{RequestContext, ResolvedRequest};

pub(super) async fn send_once(
    context: &RequestContext,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    method: Method,
    request_headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: &Route,
) -> Result<Response<ResponseBody>, RequestError> {
    let client = context.client();
    let session = context.session();
    let endpoint = &request.endpoint;
    #[cfg(feature = "cookies")]
    let cookie_jar = session.and_then(|session| session.state.cookies.as_deref());
    let mut retried_critical_hints = false;

    loop {
        let mut prepared_headers = request_headers.clone();
        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            let caller_supplied_cookie = prepared_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("cookie"));
            if !caller_supplied_cookie {
                if let Some(value) = jar.request_value_for_url(&request.url) {
                    let name = match protocol {
                        HttpProtocol::Http1 => "Cookie",
                        HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
                    };
                    prepared_headers.push(RequestHeader::new(name, value).sensitive());
                }
            }
        }

        if let Some(settings) = client.inner.client_hints.as_ref() {
            prepared_headers = match session {
                Some(session) => session.prepare_client_hints(endpoint, settings, prepared_headers),
                None => {
                    crate::session::client_hints::prepare_default_fields(settings, prepared_headers)
                }
            };
        }
        let sent_headers = prepared_headers.clone();
        let response = dispatch(
            context,
            request,
            protocol,
            method.clone(),
            prepared_headers,
            body.clone(),
            route,
        )
        .await?;

        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            jar.store_response_headers(&request.url, response.headers());
        }

        let critical_retry_requested = session.is_some_and(|session| {
            client.inner.client_hints.as_ref().is_some_and(|settings| {
                session.learn_client_hints_and_should_retry(
                    endpoint,
                    settings,
                    response.headers(),
                    &sent_headers,
                )
            })
        });
        let should_retry = !retried_critical_hints
            && critical_retry_requested
            && critical_hint_retry_eligible(&method);
        if should_retry {
            retried_critical_hints = true;
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying request with negotiated client hints"
            );
            drop(response);
            continue;
        }
        return Ok(response);
    }
}

fn critical_hint_retry_eligible(method: &Method) -> bool {
    method.is_idempotent()
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    context: &RequestContext,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    method: Method,
    request_headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: &Route,
) -> Result<Response<ResponseBody>, RequestError> {
    let client = context.client();
    let session = context.session();
    let endpoint = &request.endpoint;
    let target = request.target.clone();
    match protocol {
        HttpProtocol::Http1 => {
            let connector = client
                .inner
                .http1
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http1))?;
            let mut headers = Vec::with_capacity(request_headers.len() + 1);
            headers.push(RequestHeader::new(
                "Host",
                endpoint.authority().as_str().as_bytes(),
            ));
            headers.extend(request_headers);
            if let Some(session) = session {
                session
                    .state
                    .http1
                    .send_request(connector, endpoint, route, method, target, headers, body)
                    .await
            } else {
                let response = match route {
                    Route::Direct => {
                        connector
                            .send_request_direct(
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                                method,
                                target,
                                headers,
                                body,
                            )
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        connector
                            .send_request_http_connect(
                                proxy.host(),
                                proxy.port(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                endpoint.host(),
                                method,
                                target,
                                headers,
                                body,
                            )
                            .await
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => {
                            connector
                                .send_request_socks5_local(
                                    proxy.host(),
                                    proxy.port(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                )
                                .await
                        }
                        crate::Socks5DnsMode::Remote => {
                            connector
                                .send_request_socks5_remote(
                                    proxy.host(),
                                    proxy.port(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                )
                                .await
                        }
                    },
                }
                .map_err(RequestError::http1)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http1(body)))
            }
        }
        HttpProtocol::Http2 => {
            let connector = client
                .inner
                .http2
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http2))?;
            if let Some(session) = session {
                session
                    .state
                    .http2
                    .send_request(
                        connector,
                        endpoint,
                        route,
                        method,
                        endpoint.authority().as_str(),
                        target,
                        request_headers,
                        body,
                    )
                    .await
            } else {
                let response = match route {
                    Route::Direct => {
                        connector
                            .send_request_direct(
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                                method,
                                endpoint.authority().as_str(),
                                target,
                                request_headers,
                                body,
                            )
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        connector
                            .send_request_http_connect(
                                proxy.host(),
                                proxy.port(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                endpoint.host(),
                                method,
                                endpoint.authority().as_str(),
                                target,
                                request_headers,
                                body,
                            )
                            .await
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => {
                            connector
                                .send_request_socks5_local(
                                    proxy.host(),
                                    proxy.port(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    endpoint.authority().as_str(),
                                    target,
                                    request_headers,
                                    body,
                                )
                                .await
                        }
                        crate::Socks5DnsMode::Remote => {
                            connector
                                .send_request_socks5_remote(
                                    proxy.host(),
                                    proxy.port(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    endpoint.authority().as_str(),
                                    target,
                                    request_headers,
                                    body,
                                )
                                .await
                        }
                    },
                }
                .map_err(RequestError::http2)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http2(body)))
            }
        }
        HttpProtocol::Http3 => {
            let connector = client
                .inner
                .http3
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
            if let Some(session) = session {
                session
                    .state
                    .http3
                    .send_request(
                        connector,
                        endpoint,
                        route,
                        method,
                        endpoint.authority().as_str(),
                        target,
                        request_headers,
                        body,
                    )
                    .await
            } else {
                let response = connector
                    .send_request_direct(
                        endpoint.host(),
                        endpoint.port(),
                        endpoint.host(),
                        method,
                        endpoint.authority().as_str(),
                        target,
                        request_headers,
                        body,
                    )
                    .await
                    .map_err(RequestError::http3)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http3(body)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::critical_hint_retry_eligible;

    #[test]
    fn critical_hint_replay_uses_http_idempotency() {
        for method in [
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
            Method::TRACE,
        ] {
            assert!(critical_hint_retry_eligible(&method));
        }
        for method in [Method::POST, Method::PATCH] {
            assert!(!critical_hint_retry_eligible(&method));
        }
    }
}
