//! RFC 9113 section 8.5 CONNECT over an HTTP/2 connection to an HTTPS proxy.

use ::http2::Reason;
use http::{
    HeaderValue,
    header::{CONNECTION, HeaderName, PROXY_AUTHORIZATION, TE, UPGRADE},
};
use phantom_profile::Http2RejectedConnect;
use tracing::Span;

use super::{
    HttpBasicCredentials, HttpConnectError, HttpConnectHeader,
    authentication::validate_basic_proxy_challenge,
    http_connect::{Authorization, PreparedBasicConnect, PreparedConnect},
};
use crate::http2::{
    Http2ClassicConnectOutcome, Http2ConnectStream, Http2Connection, Http2Error,
    Http2ProtocolErrorKind, Http2RejectedStream, Http2TlsError, prepare_classic_connect,
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
    /// A valid Basic `407`, with the challenged stream when the profile
    /// leaves it open.
    Retry(Option<Http2RejectedStream>),
}

pub(super) async fn establish(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
    rejected: Http2RejectedConnect,
) -> Result<Http2ConnectStream, HttpConnectError> {
    match exchange(connection, request, rejected, false).await? {
        Http2ChallengeOutcome::Tunnel(stream) => Ok(stream),
        Http2ChallengeOutcome::Retry(_) => Err(HttpConnectError::InvalidResponse),
    }
}

pub(super) async fn establish_challenge(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
    rejected: Http2RejectedConnect,
) -> Result<Http2ChallengeOutcome, HttpConnectError> {
    exchange(connection, request, rejected, true).await
}

pub(super) async fn establish_authenticated(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
    rejected: Http2RejectedConnect,
) -> Result<Http2ConnectStream, HttpConnectError> {
    match exchange(connection, request, rejected, false).await {
        Err(HttpConnectError::Rejected { status: 407 }) => {
            Err(HttpConnectError::AuthenticationRejected)
        }
        Ok(Http2ChallengeOutcome::Tunnel(stream)) => Ok(stream),
        Ok(Http2ChallengeOutcome::Retry(_)) => Err(HttpConnectError::InvalidResponse),
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
/// connection, as Chrome 154, Edge 154, and Firefox 156 do.
///
/// A connection whose driver has stopped is not used. Opening the stream
/// waits for the proxy's concurrent-stream limit; a `GOAWAY` received since
/// the `407` fails it as unprocessed.
pub(super) async fn replay_on_challenged(
    connection: &Http2Connection,
    request: &PreparedHttp2Connect,
    rejected: Http2RejectedConnect,
) -> Http2Replay {
    if connection.is_closed() {
        return Http2Replay::Unprocessed;
    }
    match establish_authenticated(connection, request, rejected).await {
        Err(HttpConnectError::ProxyHttp2(error)) if is_unprocessed(&error) => {
            Http2Replay::Unprocessed
        }
        result => Http2Replay::Answered(result),
    }
}

/// Reports a replay the proxy did not process.
///
/// That is a connection closed before any response head, a received
/// `GOAWAY`, which fails a stream only when the stream is above its
/// last-stream-id or never opened (RFC 9113 section 6.8), or a
/// `REFUSED_STREAM` reset (RFC 9113 section 8.7).
pub(super) fn is_unprocessed(error: &Http2TlsError) -> bool {
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
    rejected: Http2RejectedConnect,
    inspect_challenge: bool,
) -> Result<Http2ChallengeOutcome, HttpConnectError> {
    let outcome = connection
        .send_classic_connect(request.request()?, rejected)
        .await
        .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(Http2TlsError::Http2(error))))?;
    match outcome {
        Http2ClassicConnectOutcome::Accepted { status, stream } => {
            Span::current().record("status", status);
            Ok(Http2ChallengeOutcome::Tunnel(stream))
        }
        Http2ClassicConnectOutcome::Rejected {
            status,
            headers,
            held,
        } => {
            Span::current().record("status", status);
            if inspect_challenge && status == 407 {
                validate_basic_proxy_challenge(&headers)?;
                return Ok(Http2ChallengeOutcome::Retry(held));
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
