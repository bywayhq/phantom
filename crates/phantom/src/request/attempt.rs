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
    let target = request.target.clone();
    #[cfg(feature = "cookies")]
    let mut request_headers = request_headers;

    #[cfg(feature = "cookies")]
    let cookie_jar = session.and_then(|session| session.state.cookies.as_deref());
    #[cfg(feature = "cookies")]
    if let Some(jar) = cookie_jar {
        let caller_supplied_cookie = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("cookie"));
        if !caller_supplied_cookie {
            if let Some(value) = jar.request_value_for_url(&request.url) {
                let name = match protocol {
                    HttpProtocol::Http1 => "Cookie",
                    HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
                };
                request_headers.push(RequestHeader::new(name, value).sensitive());
            }
        }
    }

    let response = match protocol {
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
    }?;

    #[cfg(feature = "cookies")]
    if let Some(jar) = cookie_jar {
        jar.store_response_headers(&request.url, response.headers());
    }
    Ok(response)
}
