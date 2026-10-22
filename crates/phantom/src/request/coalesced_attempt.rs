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
        http1_or_2_pool::NegotiatedFields,
    },
};

pub(super) enum ReusedOutcome {
    Miss,
    Complete(AttemptOutcome),
    /// Continue the same hop on H1/H2 when no authorized H3 donor remains.
    Origin {
        fields: Option<NegotiatedFields>,
        restart_hints: RestartHints,
    },
}

/// An initial miss leaves the body available for ordinary Alt-Svc planning.
pub(super) async fn send_reused(
    client: &Client,
    request: &ResolvedRequest,
    attempt: &mut AttemptRequest<'_>,
    route: &Route,
    lifecycle: &mut AttemptLifecycle<'_>,
) -> Result<ReusedOutcome, RequestError> {
    if !matches!(route, Route::Direct)
        || request.alternative.is_some()
        || request.uri.scheme_str() != Some("https")
    {
        return Ok(ReusedOutcome::Miss);
    }
    let Some(connector) = client.inner.connectors_for(&request.endpoint).http3 else {
        return Ok(ReusedOutcome::Miss);
    };
    let hint_origin = client_hint_origin(client, request);
    let mut restart_hints = RestartHints::default();
    let keeps_fields = may_replay_unanswered(lifecycle.retries, attempt.body);
    let mut fields = None;
    let mut origin_fields = None;
    let mut started = false;

    loop {
        let Some(candidates) = client
            .state
            .http3
            .reuse_candidates(connector, &request.endpoint, route)
            .await
        else {
            return Ok(missing_donor(started, origin_fields, restart_hints));
        };
        lifecycle
            .retries
            .ensure_http_attempt_available(Some(HttpProtocol::Http3))?;
        let attempt_fields = match fields.take() {
            Some(fields) => fields,
            None => {
                let framing = attempt.body.framing(request.expect_continue)?;
                let inputs = AttemptFields {
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
                };
                let fields = field_lists::reused_fields(client, request, route, &inputs)?;
                // If this donor disappears after an unanswered dispatch,
                // origin negotiation must retain this attempt's cookies and hints.
                origin_fields = if keeps_fields {
                    Some(field_lists::negotiated(client, request, &inputs)?)
                } else {
                    None
                };
                fields
            }
        };
        let Some(leased) = client
            .state
            .http3
            .acquire_reused(candidates, connector, lifecycle.timeout_budget)
            .await?
        else {
            return Ok(missing_donor(started, origin_fields, restart_hints));
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
        started = true;
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
                origin_fields = None;
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
            return Ok(ReusedOutcome::Complete(AttemptOutcome {
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
            && attempt.body.can_replay()
            && lifecycle
                .replays
                .try_begin(ReplayClass::CriticalClientHints, &attempt.method)
        {
            tracing::debug!(
                reason = "critical_client_hints",
                "retrying coalesced request with client hints"
            );
            drop(response);
            origin_fields = None;
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
            origin_fields = None;
            lifecycle
                .retries
                .ensure_http_attempt_available(Some(HttpProtocol::Http3))?;
            lifecycle
                .timeout_budget
                .delay(delay, Some(HttpProtocol::Http3))
                .await?;
            continue;
        }
        return Ok(ReusedOutcome::Complete(AttemptOutcome {
            response,
            protocol: HttpProtocol::Http3,
        }));
    }
}

fn missing_donor(
    started: bool,
    fields: Option<NegotiatedFields>,
    restart_hints: RestartHints,
) -> ReusedOutcome {
    if started {
        ReusedOutcome::Origin {
            fields,
            restart_hints,
        }
    } else {
        ReusedOutcome::Miss
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
    use phantom_profile::browser::{chrome, firefox};
    use tracing::Span;

    use super::{
        AttemptLifecycle, AttemptRequest, ReusedOutcome, attempt_client_hints,
        begin_accept_ch_restart, missing_donor, send_reused,
    };
    use crate::{
        AddressResolver, Client, HttpAttemptBudget, RequestTimeouts, RetryPolicy, Route,
        request::{RequestBodySource, replay::ReplayState},
        retry::ConnectionSetupRetryState,
        session::client_hints::{AcceptChRestart, RestartHints},
        timeout::TimeoutBudget,
    };

    #[tokio::test]
    async fn donor_loss_after_accept_ch_preserves_hints_and_the_unpolled_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let hints = chrome::v154_windows_client_hints();
        let arch = hints
            .hints()
            .iter()
            .position(|hint| hint.name() == "sec-ch-ua-arch")
            .ok_or("profile omitted architecture hint")?;
        let client = Client::builder(firefox::v157_windows().with_client_hints(hints)).build()?;
        let request = client
            .get_negotiated("https://other.phantom.test/")?
            .request;
        let origin = super::client_hint_origin(&client, &request);
        let mut body = RequestBodySource::Streaming(None);
        let mut restart_hints = RestartHints::default();
        begin_accept_ch_restart(
            AcceptChRestart {
                hints: vec![arch].into_boxed_slice(),
                body: Some(RequestBody::from_bytes(Bytes::from_static(b"one-shot"))),
            },
            &mut restart_hints,
            &mut body,
        );

        let ReusedOutcome::Origin {
            fields,
            restart_hints,
        } = missing_donor(true, None, restart_hints)
        else {
            return Err("restarted request became an initial donor miss".into());
        };
        assert!(fields.is_none(), "ALPS restart retained an obsolete list");
        let fields = attempt_client_hints(&client, &request, origin.as_deref(), &restart_hints)
            .ok_or("client hints were disabled")?
            .prepare(Vec::new())?;
        assert!(
            fields
                .iter()
                .any(|field| { field.name() == "sec-ch-ua-arch" && field.value() == b"\"x86\"" })
        );
        let payload = body
            .next_attempt()?
            .ok_or("ALPS restart lost its one-shot body")?
            .collect()
            .await?
            .to_bytes();
        assert_eq!(payload, "one-shot");
        Ok(())
    }

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

        assert!(matches!(outcome, ReusedOutcome::Miss));
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
