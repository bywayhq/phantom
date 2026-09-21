//! RFC 9113 section 8.5 CONNECT over an HTTP/2 connection to an HTTPS proxy.

use http::{
    HeaderValue,
    header::{CONNECTION, HeaderName, PROXY_AUTHORIZATION, TE, UPGRADE},
};
use tracing::Span;

use super::{
    HttpBasicCredentials, HttpConnectError, HttpConnectHeader,
    authentication::validate_basic_proxy_challenge,
    http_connect::{Authorization, PreparedBasicConnect, PreparedConnect},
};
use crate::http2::{
    Http2ClassicConnectOutcome, Http2ConnectStream, Http2Connection, Http2TlsError,
    prepare_classic_connect,
};

/// A validated HTTP/2 CONNECT request that can be sent on a fresh connection.
///
/// The ordered field list accepts exactly the input accepted by the HTTP/1.1
/// CONNECT encoder, including its bounds. The authority placeholder becomes
/// the `:authority` pseudo-header, field names use HTTP/2 lowercase form, and
/// connection-specific fields are rejected rather than dropped.
pub(super) struct PreparedHttp2Connect {
    authority: Box<str>,
    fields: Vec<(HeaderName, HeaderValue)>,
}

impl PreparedHttp2Connect {
    pub(super) fn new(
        authority: &str,
        headers: &[HttpConnectHeader],
    ) -> Result<Self, HttpConnectError> {
        PreparedConnect::prepare(authority, headers, Authorization::Forbidden)?;
        Self::convert(authority, headers, Authorization::Forbidden)
    }

    fn convert(
        authority: &str,
        headers: &[HttpConnectHeader],
        authorization: Authorization<'_>,
    ) -> Result<Self, HttpConnectError> {
        let mut fields = Vec::with_capacity(headers.len());
        for (index, header) in headers.iter().enumerate() {
            match header {
                HttpConnectHeader::Authority { .. } => {}
                HttpConnectHeader::Field(header) => {
                    let name = HeaderName::from_bytes(header.name().as_bytes())
                        .map_err(|_| HttpConnectError::InvalidHeaderName { index })?;
                    let mut value = HeaderValue::from_bytes(header.value())
                        .map_err(|_| HttpConnectError::InvalidHeaderValue { index })?;
                    if is_connection_specific(&name, &value) {
                        return Err(HttpConnectError::Http2ConnectionHeader { index });
                    }
                    value.set_sensitive(header.is_sensitive());
                    fields.push((name, value));
                }
                HttpConnectHeader::ProxyAuthorization { .. } => {
                    if let Authorization::Emit(credential) = authorization {
                        let mut value = HeaderValue::from_bytes(credential)
                            .map_err(|_| HttpConnectError::InvalidHeaderValue { index })?;
                        value.set_sensitive(true);
                        fields.push((PROXY_AUTHORIZATION, value));
                    }
                }
            }
        }
        let prepared = Self {
            authority: authority.into(),
            fields,
        };
        prepared.request()?;
        Ok(prepared)
    }

    fn request(&self) -> Result<http::Request<()>, HttpConnectError> {
        prepare_classic_connect(&self.authority, self.fields.clone())
            .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(Http2TlsError::Http2(error))))
    }
}

/// Anonymous and challenge-response forms of one HTTP/2 CONNECT request.
pub(super) struct PreparedBasicHttp2Connect {
    pub(super) anonymous: PreparedHttp2Connect,
    pub(super) authenticated: PreparedHttp2Connect,
}

impl PreparedBasicHttp2Connect {
    pub(super) fn new(
        authority: &str,
        headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
    ) -> Result<Self, HttpConnectError> {
        PreparedBasicConnect::new(authority, headers, credentials)?;
        Ok(Self {
            anonymous: PreparedHttp2Connect::convert(authority, headers, Authorization::Omit)?,
            authenticated: PreparedHttp2Connect::convert(
                authority,
                headers,
                Authorization::Emit(credentials.authorization()),
            )?,
        })
    }
}

pub(super) enum Http2ChallengeOutcome {
    Tunnel(Http2ConnectStream),
    Retry,
}

pub(super) async fn establish(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
) -> Result<Http2ConnectStream, HttpConnectError> {
    match exchange(connection, request, false).await? {
        Http2ChallengeOutcome::Tunnel(stream) => Ok(stream),
        Http2ChallengeOutcome::Retry => Err(HttpConnectError::InvalidResponse),
    }
}

pub(super) async fn establish_challenge(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
) -> Result<Http2ChallengeOutcome, HttpConnectError> {
    exchange(connection, request, true).await
}

pub(super) async fn establish_authenticated(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
) -> Result<Http2ConnectStream, HttpConnectError> {
    match exchange(connection, request, false).await {
        Err(HttpConnectError::Rejected { status: 407 }) => {
            Err(HttpConnectError::AuthenticationRejected)
        }
        Ok(Http2ChallengeOutcome::Tunnel(stream)) => Ok(stream),
        Ok(Http2ChallengeOutcome::Retry) => Err(HttpConnectError::InvalidResponse),
        Err(error) => Err(error),
    }
}

async fn exchange(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
    inspect_challenge: bool,
) -> Result<Http2ChallengeOutcome, HttpConnectError> {
    let outcome = connection
        .send_classic_connect(request.request()?)
        .await
        .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(Http2TlsError::Http2(error))))?;
    match outcome {
        Http2ClassicConnectOutcome::Accepted { status, stream } => {
            Span::current().record("status", status);
            Ok(Http2ChallengeOutcome::Tunnel(stream))
        }
        Http2ClassicConnectOutcome::Rejected { status, headers } => {
            Span::current().record("status", status);
            if inspect_challenge && status == 407 {
                validate_basic_proxy_challenge(&headers)?;
                return Ok(Http2ChallengeOutcome::Retry);
            }
            Err(HttpConnectError::Rejected { status })
        }
    }
}

/// Reports fields that RFC 9113 section 8.2.2 forbids in HTTP/2.
///
/// `Host`, `Transfer-Encoding`, and `Content-Length` are already rejected by
/// the shared CONNECT validation.
fn is_connection_specific(name: &HeaderName, value: &HeaderValue) -> bool {
    name == CONNECTION
        || name == UPGRADE
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
        || (name == TE && value.as_bytes() != b"trailers")
}
