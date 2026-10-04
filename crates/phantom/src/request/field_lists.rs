//! The field lists a negotiated request builds and checks before any I/O.
//!
//! A list is built from the request template, the caller's fields, the
//! cookie jar, the client hints known before a connection is chosen, and, on
//! HTTP/3 to an alternative, `Alt-Used`; it is checked with the request's
//! method, target, trailers, and body. Each list is built and checked once.
//! The attempt that wins a race sends it as built, and so does every attempt
//! that repeats a request the server did not answer: a graceful `GOAWAY`
//! retry, a restart after rejected early data, a reused-connection replay, an
//! unprocessed-request replay, a PING-failure resend, and a race started
//! again after a failed early-data handshake.
//!
//! An attempt that follows a response builds and checks the lists again. The
//! response may have stored cookies or requested client hints, and a
//! `Critical-CH` retry exists to send those hints. So does a request that
//! restarts because its connection's ALPS `ACCEPT_CH` asked for a hint it
//! lacked: nothing of it was sent, and it is built again with that hint. A
//! redirect hop builds the lists again for its own URL, method, body, and
//! fields.

use http::Method;
use phantom_net::request::{RequestBody, RequestHeader};

use super::{
    RequestBodyFraming, ResolvedRequest,
    attempt::{AttemptRequest, attempt_client_hints, attempt_headers, client_hint_origin},
};
use crate::{
    Client, HttpProtocol, RequestError, Route,
    session::{
        alt_svc::AlternativeTarget,
        client_hints::{ClientHintContext, RestartHints},
        http1_or_2_pool::{self, NegotiatedFields},
        http3_pool::{self, Http3Fields, Http3TransportTarget},
    },
};

/// The lists of a request that races an alternative against its origin.
#[derive(Clone)]
pub(super) struct RacedFields {
    pub(super) http3: Http3Fields,
    pub(super) negotiated: NegotiatedFields,
}

/// Builds and checks the HTTP/3 list for the alternative and the HTTP/1.1
/// and HTTP/2 lists for the origin before either candidate performs I/O.
///
/// The body is borrowed, not taken, since only the winner sends it.
pub(super) fn raced(
    client: &Client,
    request: &ResolvedRequest,
    attempt: &AttemptRequest<'_>,
    route: &Route,
    alternative: &AlternativeTarget,
) -> Result<RacedFields, RequestError> {
    // An HTTP/3 connector is required before the body is looked at, as it is
    // for an attempt on the alternative alone.
    if client.inner.http3.is_none() {
        return Err(RequestError::unsupported_protocol(HttpProtocol::Http3));
    }
    let framing = attempt.body.framing()?;
    let body = framing.as_ref().map(RequestBodyFraming::body);
    let hint_origin = client_hint_origin(client, request);
    // A race starts a request, so no connection has restarted it yet.
    let no_restart = RestartHints::default();
    let fields = AttemptFields {
        method: &attempt.method,
        headers: &attempt.headers,
        trailers: &attempt.trailers,
        client_hints: attempt_client_hints(client, request, hint_origin.as_deref(), &no_restart),
        body,
    };
    let http3 = alternative_fields(client, request, route, alternative, &fields)?;
    let negotiated = negotiated(client, request, &fields)?;
    Ok(RacedFields { http3, negotiated })
}

/// What a request's lists are built from and checked against, besides the
/// client and the resolved request.
pub(super) struct AttemptFields<'a> {
    pub(super) method: &'a Method,
    /// The caller's fields.
    pub(super) headers: &'a [RequestHeader],
    pub(super) trailers: &'a [RequestHeader],
    pub(super) client_hints: Option<ClientHintContext<'a>>,
    pub(super) body: Option<&'a RequestBody>,
}

/// Builds and checks the HTTP/1.1 and HTTP/2 lists of a negotiated request.
pub(super) fn negotiated(
    client: &Client,
    request: &ResolvedRequest,
    attempt: &AttemptFields<'_>,
) -> Result<NegotiatedFields, RequestError> {
    let http1 = attempt_headers(client, request, HttpProtocol::Http1, attempt.headers);
    let http2 = attempt_headers(client, request, HttpProtocol::Http2, attempt.headers);
    #[cfg(test)]
    counts::checked(&[HttpProtocol::Http1, HttpProtocol::Http2]);
    http1_or_2_pool::validate_request(
        &request.endpoint,
        attempt.method,
        &request.target,
        http1,
        http2,
        attempt.trailers,
        attempt.client_hints,
        attempt.body,
    )
}

/// Builds and checks the HTTP/3 list of a request to an Alt-Svc alternative,
/// with the alternative's `Alt-Used` field last.
pub(super) fn alternative_fields(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    alternative: &AlternativeTarget,
    attempt: &AttemptFields<'_>,
) -> Result<Http3Fields, RequestError> {
    let connector = client
        .inner
        .http3
        .as_ref()
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    let mut headers = attempt_headers(client, request, HttpProtocol::Http3, attempt.headers);
    if let Some(alt_used) = alternative.alt_used() {
        headers.push(RequestHeader::new("alt-used", alt_used.as_bytes()));
    }
    #[cfg(test)]
    counts::checked(&[HttpProtocol::Http3]);
    http3_pool::validate_request(
        connector,
        client.inner.connect_udp_proxy.as_deref(),
        route,
        Http3TransportTarget::new(alternative.host(), alternative.port()),
        attempt.method,
        request.endpoint.authority().as_str(),
        &request.target,
        headers,
        attempt.trailers,
        attempt.client_hints,
        attempt.body,
    )
}

/// How many lists of each protocol this thread built and checked, for tests
/// that prove a request builds each list once.
#[cfg(test)]
pub(crate) mod counts {
    use std::cell::Cell;

    use crate::HttpProtocol;

    /// Builds and checks per protocol: HTTP/1.1, HTTP/2, then HTTP/3.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counts {
        pub(crate) built: [usize; 3],
        pub(crate) checked: [usize; 3],
    }

    thread_local! {
        static COUNTS: Cell<Counts> = Cell::new(Counts::default());
    }

    const fn index(protocol: HttpProtocol) -> usize {
        match protocol {
            HttpProtocol::Http1 => 0,
            HttpProtocol::Http2 => 1,
            HttpProtocol::Http3 => 2,
        }
    }

    pub(crate) fn built(protocol: HttpProtocol) {
        COUNTS.with(|counts| {
            let mut current = counts.get();
            current.built[index(protocol)] += 1;
            counts.set(current);
        });
    }

    pub(crate) fn checked(protocols: &[HttpProtocol]) {
        COUNTS.with(|counts| {
            let mut current = counts.get();
            for protocol in protocols {
                current.checked[index(*protocol)] += 1;
            }
            counts.set(current);
        });
    }

    /// Returns the counts so far and starts again from zero.
    pub(crate) fn take() -> Counts {
        COUNTS.with(|counts| counts.replace(Counts::default()))
    }
}

#[cfg(test)]
#[path = "field_lists/tests.rs"]
mod tests;
