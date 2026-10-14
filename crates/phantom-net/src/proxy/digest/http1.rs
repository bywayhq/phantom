//! Digest CONNECT exchanges over plaintext or independently authenticated TLS.

use std::future::Future;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{DigestChallenge, DigestRequest, HttpDigestCredentials, cache::DigestCacheKey};
use crate::proxy::{
    HttpConnectError, HttpConnectHeader, TunnelStream,
    challenged_connection::{self, ChallengeBody},
    http_connect::{
        Authorization, MAX_CONNECT_HEADERS, MAX_INFORMATIONAL_RESPONSES, PreparedConnect,
        read_response_head,
    },
};

/// Every emission reserves a new nonce count, including a reconnect after the
/// challenged connection closes. The enclosing connection deadline owns time.
pub(in crate::proxy) async fn connect<S, C, F>(
    scope: &DigestCacheKey,
    credentials: &HttpDigestCredentials,
    preemptive: bool,
    authority: &str,
    headers: &[HttpConnectHeader],
    open: C,
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: Fn() -> F,
    F: Future<Output = Result<S, HttpConnectError>>,
{
    validate_slot(headers)?;
    let anonymous = PreparedConnect::prepare(authority, headers, Authorization::Omit)?;
    let mut session = preemptive.then(|| credentials.remembered(scope)).flatten();
    let mut held = None;
    let mut challenged = false;
    let mut stale_retried = false;
    let mut reconnected = false;
    loop {
        let authorization = session
            .as_ref()
            .map(|session| session.request(&http::Method::CONNECT, authority))
            .transpose()
            .map_err(HttpConnectError::Digest)?;
        let authenticated = authorization
            .as_ref()
            .map(|request| {
                PreparedConnect::prepare(
                    authority,
                    headers,
                    Authorization::Emit(request.header.value()),
                )
            })
            .transpose()?;
        let request = authenticated.as_ref().unwrap_or(&anonymous);
        let reused = held.is_some();
        let stream = match held.take() {
            Some(stream) => stream,
            None => open().await?,
        };
        let outcome = exchange(stream, request, credentials, authorization.as_ref(), reused).await;
        match outcome {
            Ok(Reply::Tunnel(stream, nextnonce)) => {
                if let Some(session) = &session {
                    credentials
                        .accept(scope, session, nextnonce)
                        .map_err(HttpConnectError::Digest)?;
                }
                return Ok(stream);
            }
            Ok(Reply::Challenge(challenge, reusable)) => {
                if let Some(previous) = session.take() {
                    credentials.forget(scope, &previous);
                    if !challenge.stale || stale_retried {
                        return Err(HttpConnectError::AuthenticationRejected);
                    }
                    stale_retried = true;
                } else if challenged {
                    return Err(HttpConnectError::AuthenticationRejected);
                }
                challenged = true;
                session = Some(
                    credentials
                        .challenged(scope, challenge)
                        .map_err(HttpConnectError::Digest)?,
                );
                held = reusable;
            }
            Ok(Reply::Closed) if reused && authorization.is_some() && !reconnected => {
                reconnected = true;
            }
            Ok(Reply::Closed) => return Err(HttpConnectError::InvalidResponse),
            Err(error) => {
                if matches!(error, HttpConnectError::Digest(_))
                    && let Some(session) = &session
                {
                    credentials.forget(scope, session);
                }
                return Err(error);
            }
        }
    }
}

pub(in crate::proxy) fn validate_slot(
    headers: &[HttpConnectHeader],
) -> Result<(), HttpConnectError> {
    match headers
        .iter()
        .filter(|header| header.is_proxy_authorization())
        .count()
    {
        0 => Err(HttpConnectError::MissingProxyAuthorizationPlaceholder),
        1 => Ok(()),
        _ => Err(HttpConnectError::MultipleProxyAuthorizationPlaceholders),
    }
}

enum Reply<S> {
    Tunnel(TunnelStream<S>, Option<Box<[u8]>>),
    Challenge(DigestChallenge, Option<S>),
    Closed,
}

async fn exchange<S>(
    mut stream: S,
    request: &PreparedConnect,
    credentials: &HttpDigestCredentials,
    authorization: Option<&DigestRequest>,
    reused: bool,
) -> Result<Reply<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let written = async {
        stream.write_all(request.bytes()).await?;
        stream.flush().await
    }
    .await;
    if let Err(error) = written {
        if reused && challenged_connection::is_connection_close(&error) {
            return Ok(Reply::Closed);
        }
        return Err(HttpConnectError::Write(error));
    }
    let mut response = Vec::with_capacity(1024);
    let mut informational = 0;
    loop {
        let head_end = match read_response_head(&mut stream, &mut response).await {
            Ok(length) => length,
            Err(error) if reused && response.is_empty() && no_response(&error) => {
                return Ok(Reply::Closed);
            }
            Err(error) => return Err(error),
        };
        let mut fields = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
        let mut parsed = httparse::Response::new(&mut fields);
        match parsed.parse(&response[..head_end]) {
            Ok(httparse::Status::Complete(length)) if length == head_end => {}
            _ => return Err(HttpConnectError::InvalidResponse),
        }
        let status = parsed.code.ok_or(HttpConnectError::InvalidResponse)?;
        if status != 101 && (100..200).contains(&status) {
            informational += 1;
            if informational > MAX_INFORMATIONAL_RESPONSES {
                return Err(HttpConnectError::TooManyInformationalResponses {
                    maximum: MAX_INFORMATIONAL_RESPONSES,
                });
            }
            response.drain(..head_end);
            continue;
        }
        if (200..300).contains(&status) {
            let nextnonce = authorization
                .map(|request| {
                    request.verify(field_values(parsed.headers, "Proxy-Authentication-Info"))
                })
                .transpose()
                .map_err(HttpConnectError::Digest)?
                .flatten();
            let prefix = Bytes::from(response).slice(head_end..);
            return Ok(Reply::Tunnel(TunnelStream::new(stream, prefix), nextnonce));
        }
        if status != 407 {
            return Err(HttpConnectError::Rejected { status });
        }
        let challenge = DigestChallenge::select(
            field_values(parsed.headers, "Proxy-Authenticate"),
            credentials,
        )
        .map_err(HttpConnectError::Digest)?;
        let body = ChallengeBody::from_head(
            parsed.version.ok_or(HttpConnectError::InvalidResponse)?,
            parsed.headers,
        );
        let reusable = match body {
            Some(body) => {
                challenged_connection::drain(&mut stream, body, &response[head_end..]).await
            }
            None => false,
        };
        return Ok(Reply::Challenge(challenge, reusable.then_some(stream)));
    }
}

fn field_values<'a>(
    headers: &'a [httparse::Header<'a>],
    name: &'a str,
) -> impl Iterator<Item = &'a [u8]> {
    headers.iter().filter_map(move |header| {
        header
            .name
            .eq_ignore_ascii_case(name)
            .then_some(header.value)
    })
}

fn no_response(error: &HttpConnectError) -> bool {
    match error {
        HttpConnectError::InvalidResponse => true,
        HttpConnectError::Read(error) => challenged_connection::is_connection_close(error),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
