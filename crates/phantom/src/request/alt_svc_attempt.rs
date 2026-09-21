use super::{
    ResolvedRequest,
    attempt::{
        AttemptLifecycle, AttemptOutcome, AttemptPath, AttemptRequest, attempt_headers,
        client_hint_origin, dispatch, observe_response, prepare_attempt, store_cookies,
    },
    replay::ReplayClass,
};
use crate::{
    Client, HttpProtocol, RequestError, RetryPolicy, Route, retry::ConnectionSetupRetryState,
    session::http3_pool::Http3TransportTarget,
};
use phantom_net::request::RequestHeader;

/// Host, port, `Alt-Used` authority, and store generation of a cached alternative.
type AlternativeTarget = (Box<str>, u16, Box<str>, u64);

pub(super) enum NegotiatedPlan {
    Origin,
    Alternative(AlternativeTarget),
}

pub(super) fn plan(client: &Client, request: &ResolvedRequest) -> NegotiatedPlan {
    match client.alt_svc_location(&request.endpoint) {
        Some(alternative) => NegotiatedPlan::Alternative(alternative),
        None => NegotiatedPlan::Origin,
    }
}

pub(super) async fn send_once_alt_svc(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: AlternativeTarget,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries: _,
        replays,
    } = lifecycle;
    let (alternative_host, alternative_port, alternative_authority, alternative_generation) =
        alternative;
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let endpoint = &request.endpoint;
    let transport = Http3TransportTarget::new(&alternative_host, alternative_port);
    let client_hint_origin = client_hint_origin(client, request);

    loop {
        let mut prepared_headers =
            attempt_headers(client, request, HttpProtocol::Http3, &request_headers);
        prepared_headers.push(RequestHeader::new(
            "alt-used",
            alternative_authority.as_bytes(),
        ));
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), request_span.clone());
        let dispatched = dispatch(
            client,
            request,
            HttpProtocol::Http3,
            method.clone(),
            prepared_headers,
            request_trailers.clone(),
            prepared.client_hints,
            prepared.body,
            route,
            Some(transport),
            false,
            timeout_budget,
            &mut retries,
        )
        .await;
        let dispatched = match dispatched {
            Ok(dispatched) => dispatched,
            Err(error) => {
                if error.invalidates_alt_svc() {
                    client.remove_alt_svc_if_current(endpoint, alternative_generation);
                }
                return Err(error);
            }
        };
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
            store_cookies(client, request, &response);
            client.remove_alt_svc_if_current(endpoint, alternative_generation);
            return Ok(AttemptOutcome {
                response,
                protocol: HttpProtocol::Http3,
            });
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            &response,
            &sent_headers,
            AttemptPath::Alternative,
        );
        if critical_retry_requested && replays.try_begin(ReplayClass::CriticalClientHints, &method)
        {
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying alternative-service request with client hints"
            );
            drop(response);
            continue;
        }
        return Ok(AttemptOutcome {
            response,
            protocol: HttpProtocol::Http3,
        });
    }
}
