//! RFC 9113 section 8.5 CONNECT over an HTTP/2 connection to an HTTPS proxy.

use ::http2::Reason;
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
    Http2ClassicConnectOutcome, Http2ConnectStream, Http2Connection, Http2Error,
    Http2ProtocolErrorKind, Http2TlsError, prepare_classic_connect,
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

/// Result of the credentialed CONNECT sent on the connection that carried
/// the `407`.
pub(super) enum Http2Replay {
    /// The proxy answered the replay, or failed it after processing it.
    Answered(Result<Http2ConnectStream, HttpConnectError>),
    /// The proxy closed the connection or refused the stream before it
    /// processed the replay, so the replay may go on a new connection.
    Unprocessed,
}

/// Sends the credentialed CONNECT as a new stream on the challenged
/// connection, as Chrome 154, Edge 153, and Firefox 156 do.
///
/// A connection that has stopped or received `GOAWAY` since the `407` is not
/// used.
pub(super) async fn replay_on_challenged(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
) -> Http2Replay {
    // Chrome 154 and Edge 153 end the challenged stream before they open the
    // replay. The vendored encoder writes a new stream's HEADERS ahead of
    // queued DATA, so the connection driver gets a turn to write the queued
    // END_STREAM first. On a current-thread runtime this fixes the order; on
    // a multi-thread runtime the driver may run later.
    tokio::task::yield_now().await;
    if !connection.is_reusable() {
        return Http2Replay::Unprocessed;
    }
    match establish_authenticated(connection, request).await {
        Err(HttpConnectError::ProxyHttp2(error)) if is_unprocessed(&error) => {
            Http2Replay::Unprocessed
        }
        result => Http2Replay::Answered(result),
    }
}

/// Reports a failure that RFC 9113 sections 6.8 and 8.7 describe as a
/// request the peer did not process, or a connection that ended before any
/// response head.
///
/// A received `GOAWAY` fails a stream only when the stream is above its
/// last-stream-id or never opened, so any remote `GOAWAY` qualifies.
fn is_unprocessed(error: &Http2TlsError) -> bool {
    let Http2TlsError::Http2(Http2Error::Protocol(error)) = error else {
        return false;
    };
    match error.kind() {
        Http2ProtocolErrorKind::Transport => true,
        Http2ProtocolErrorKind::ConnectionError => error.is_remote(),
        Http2ProtocolErrorKind::StreamReset => {
            error.is_remote() && error.reason_code() == Some(u32::from(Reason::REFUSED_STREAM))
        }
        Http2ProtocolErrorKind::Protocol | Http2ProtocolErrorKind::Local => false,
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
