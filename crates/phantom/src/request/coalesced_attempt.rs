//! Sends negotiated requests on an authorized connection to another origin.

use super::{
    RequestBodyFraming, ResolvedRequest,
    attempt::{
        AttemptLifecycle, AttemptOutcome, AttemptPath, AttemptRequest, attempt_client_hints,
        begin_accept_ch_restart, begin_status_retry, begin_unprocessed_replay, client_hint_origin,
        may_replay_unanswered, observe_response, prepare_attempt, store_cookies,
    },
    field_lists::{self, AttemptFields},
    replay::ReplayClass,
};
use crate::{
    Client, HttpProtocol, RequestError, Route,
    session::{
        box_send,
        client_hints::{Dispatched, RestartHints},
    },
};

/// A miss leaves the body available for ordinary origin/Alt-Svc planning.
pub(super) async fn send_reused(
    client: &Client,
    request: &ResolvedRequest,
    attempt: &mut AttemptRequest<'_>,
    route: &Route,
    lifecycle: &mut AttemptLifecycle<'_>,
) -> Result<Option<AttemptOutcome>, RequestError> {
    if !matches!(route, Route::Direct)
        || request.alternative.is_some()
        || request.uri.scheme_str() != Some("https")
    {
        return Ok(None);
    }
    let Some(connector) = client.inner.connectors_for(&request.endpoint).http3 else {
        return Ok(None);
    };
    let hint_origin = client_hint_origin(client, request);
    let mut restart_hints = RestartHints::default();
    let keeps_fields = may_replay_unanswered(lifecycle.retries, attempt.body);
    let mut fields = None;

    loop {
        let Some(candidates) = client
            .state
            .http3
            .reuse_candidates(connector, &request.endpoint, route)
            .await
        else {
            return Ok(None);
        };
        lifecycle
            .retries
            .ensure_http_attempt_available(Some(HttpProtocol::Http3))?;
        let attempt_fields = match fields.take() {
            Some(fields) => fields,
            None => {
                let framing = attempt.body.framing(request.expect_continue)?;
                field_lists::reused_fields(
                    client,
                    request,
                    route,
                    &AttemptFields {
                        method: &attempt.method,
                        headers: &attempt.headers,
                        trailers: &attempt.trailers,
                        client_hints: attempt_client_hints(
                            client,
                            request,
                            hint_origin.as_deref(),
                            &restart_hints,
                        ),
                        body: framing.as_ref().map(RequestBodyFraming::body),
                    },
                )?
            }
        };
        let Some(leased) = client
            .state
            .http3
            .acquire_reused(candidates, connector, lifecycle.timeout_budget)
            .await?
        else {
            return Ok(None);
        };
        let kept_fields = keeps_fields.then(|| attempt_fields.clone());
        let prepared = prepare_attempt(
            client,
            request,
            hint_origin.as_deref(),
            &restart_hints,
            attempt.body,
        )?;
        lifecycle
            .request_span
            .record("selected_protocol", HttpProtocol::Http3.trace_name());
        let sent = box_send(client.state.http3.send_request_on_lease(
            leased,
            connector,
            attempt.method.clone(),
            request.endpoint.authority().as_str(),
            request.target.clone(),
            attempt_fields,
            attempt.trailers.clone(),
            prepared.client_hints,
            prepared.body,
            lifecycle.timeout_budget,
            lifecycle.retries,
        ))
        .await;
        let (mut response, sent_headers) = match sent {
            Ok(Dispatched::Sent(sent)) => sent,
            Ok(Dispatched::Restart(restart)) => {
                begin_accept_ch_restart(restart, &mut restart_hints, attempt.body);
                continue;
            }
            Err(error) => {
                if begin_unprocessed_replay(
                    &error,
                    &attempt.method,
                    attempt.body,
                    lifecycle.retries,
                    lifecycle.replays,
                ) {
                    fields = kept_fields;
                    continue;
                }
                return Err(error);
            }
        };
        if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
            // The pool retires this donor for future joins. Return its 421
            // without replaying the request or learning response policies.
            if let Some(control) = &request.transfer {
                response.body_mut().apply_transfer(control.clone());
            }
            store_cookies(client, request, &response);
            return Ok(Some(AttemptOutcome {
                response,
                protocol: HttpProtocol::Http3,
            }));
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            route,
            &mut response,
            &sent_headers,
            AttemptPath::Negotiated,
        );
        if critical_retry_requested
            && lifecycle
                .replays
                .try_begin(ReplayClass::CriticalClientHints, &attempt.method)
        {
            tracing::debug!(
                reason = "critical_client_hints",
                "retrying coalesced request with client hints"
            );
            drop(response);
            continue;
        }
        if let Some(delay) = begin_status_retry(
            &response,
            &attempt.method,
            attempt.body,
            lifecycle.timeout_budget,
            lifecycle.retries,
            lifecycle.replays,
        ) {
            drop(response);
            lifecycle
                .retries
                .ensure_http_attempt_available(Some(HttpProtocol::Http3))?;
            lifecycle
                .timeout_budget
                .delay(delay, Some(HttpProtocol::Http3))
                .await?;
            continue;
        }
        return Ok(Some(AttemptOutcome {
            response,
            protocol: HttpProtocol::Http3,
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::Bytes;
    use http_body_util::BodyExt;
    use phantom_net::request::RequestBody;
    use phantom_profile::browser::firefox;
    use tracing::Span;

    use super::{AttemptLifecycle, AttemptRequest, send_reused};
    use crate::{
        AddressResolver, Client, HttpAttemptBudget, RequestTimeouts, RetryPolicy, Route,
        request::{RequestBodySource, replay::ReplayState},
        retry::ConnectionSetupRetryState,
        timeout::TimeoutBudget,
    };

    #[tokio::test]
    async fn no_donor_leaves_the_body_and_shared_attempt_budget_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let lookups = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&lookups);
        let resolver = AddressResolver::from_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Err(std::io::Error::other("unexpected address lookup")) }
        });
        let client = Client::builder(firefox::v157_windows())
            .dns_resolver(resolver)
            .build()?;
        let request = client
            .get_negotiated("https://other.phantom.test/")?
            .request;
        let mut body = RequestBodySource::Streaming(Some(RequestBody::from_bytes(
            Bytes::from_static(b"one-shot payload"),
        )));
        let mut attempt = AttemptRequest {
            method: http::Method::POST,
            headers: Vec::new(),
            trailers: Vec::new(),
            body: &mut body,
        };
        let span = Span::none();
        let allowance = HttpAttemptBudget::new(1);
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), span.clone());
        retries.set_attempt_budget(Some(allowance.clone()));
        let mut replays = ReplayState::new(0);
        let mut lifecycle = AttemptLifecycle {
            request_span: &span,
            timeout_budget: TimeoutBudget::new(
                RequestTimeouts::new().total(Duration::from_secs(5)),
            )?,
            retries: &mut retries,
            replays: &mut replays,
        };

        let outcome = send_reused(
            &client,
            &request,
            &mut attempt,
            &Route::Direct,
            &mut lifecycle,
        )
        .await?;

        assert!(outcome.is_none());
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
        assert_eq!(allowance.remaining(), 1);
        let payload = body
            .next_attempt()?
            .ok_or("one-shot body was consumed")?
            .collect()
            .await?
            .to_bytes();
        assert_eq!(payload, "one-shot payload");
        Ok(())
    }
}
