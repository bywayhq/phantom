use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use http::{Method, StatusCode};
use phantom_net::tcp::AddressFamily;
use phantom_profile::{ClientProfile, browser::firefox};
use tokio::time::timeout;

use super::super::{Checkout, Http1ConnectionMode, Http1Pool, PoolKey};
use crate::{Client, HttpProtocol, Route, authority::Endpoint, session::prune_timer::PruneTimer};
use fixture::{PruneRace, TestResult, WAIT};

mod fixture;

#[derive(Clone, Copy)]
enum OriginState {
    Reconnected,
    Pending,
    Empty,
}

#[tokio::test]
async fn pruning_keeps_the_family_of_a_connection_opened_after_its_empty_snapshot() -> TestResult {
    check_family(OriginState::Reconnected).await
}

#[tokio::test]
async fn pruning_forgets_the_family_when_the_origin_stays_empty() -> TestResult {
    check_family(OriginState::Empty).await
}

#[tokio::test]
async fn pruning_keeps_the_family_of_setup_reserved_after_its_empty_snapshot() -> TestResult {
    check_family(OriginState::Pending).await
}

async fn check_family(state: OriginState) -> TestResult {
    let timer = PruneTimer::unscheduled(Duration::ZERO);
    let profile = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1());
    let mut client = Client::builder(profile).build()?;
    Arc::get_mut(&mut client.state)
        .ok_or("new client state is shared")?
        .http1 =
        Http1Pool::new(bound(4)?, bound(2)?, bound(2)?).with_prune_timer(Some(Arc::clone(&timer)));

    let mut race = PruneRace::new();

    let operation = timeout(WAIT, async {
        let (address, closed) = race.origin(matches!(state, OriginState::Reconnected)).await?;
        let endpoint = Endpoint::new(address.to_string().parse()?, 80)?;
        let origin = client
            .state
            .http1
            .entry(PoolKey::new(&endpoint, &Route::Direct, Http1ConnectionMode::PlaintextOrigin))
            .await;
        let url = format!("http://{address}");
        let priming = client.request(HttpProtocol::Http1, Method::GET, &format!("{url}/prime"))?
            .send().await?;
        if priming.status() != StatusCode::NO_CONTENT {
            return Err("priming response is not literal 204".into());
        }

        drop(priming);
        if origin.connections.lock().idle.len() != 1 {
            return Err("priming connection did not become idle".into());
        }

        if origin.connections.family.family() != Some(AddressFamily::Ipv4) {
            return Err("actual priming TCP connection did not record IPv4".into());
        }

        let second = Endpoint::new("second.test:80".parse()?, 80)?;
        let barrier = client.state.http1.entry(PoolKey::new(
            &second, &Route::Direct, Http1ConnectionMode::PlaintextOrigin,
        )).await;
        let swept = race.sweep(Arc::clone(&timer), Arc::clone(&barrier.connections)).await?;

        closed.await?;
        if !origin.connections.lock().is_empty() {
            return Err("origin was not empty after actual expired-socket closure".into());
        }

        let pending = if matches!(state, OriginState::Pending) {
            let Checkout::Reserved(reservation) = origin.connections.checkout(false) else {
                return Err("empty origin did not reserve new connection setup".into());
            };

            if origin.connections.lock().leased != 1
                || origin.connections.family.family() != Some(AddressFamily::Ipv4)
            {
                return Err("pending setup did not retain the priming family and reservation".into());
            }

            Some(reservation)
        } else {
            None
        };

        let held = match state {
            OriginState::Reconnected => {
                let response = client.request(HttpProtocol::Http1, Method::GET, &format!("{url}/held"))?
                    .send().await?;
                if response.status() != StatusCode::OK
                    || response.headers().get(http::header::CONTENT_LENGTH)
                        != Some(&http::HeaderValue::from_static("1"))
                {
                    return Err("held response did not carry literal 200 and one-byte body length".into());
                }

                if origin.connections.lock().leased != 1 {
                    return Err("actual held response did not retain its pool lease".into());
                }

                if origin.connections.family.family() != Some(AddressFamily::Ipv4) {
                    return Err("actual replacement TCP connection did not record IPv4 before prune resumed".into());
                }

                Some(response)
            }
            OriginState::Pending | OriginState::Empty => None,
        };

        race.resume()?;
        swept.await?;

        let target = match state {
            OriginState::Reconnected => {
                if origin.connections.lock().leased != 1 {
                    Err("held connection ended before the family target".into())
                } else if origin.connections.family.family() != Some(AddressFamily::Ipv4) {
                    Err("prune forgot the family of the actual live replacement connection".into())
                } else {
                    Ok(())
                }
            }
            OriginState::Pending => {
                if origin.connections.lock().leased != 1 {
                    Err("pending setup ended before the family target".into())
                } else if origin.connections.family.family() != Some(AddressFamily::Ipv4) {
                    Err("prune forgot the family of actual pending connection setup".into())
                } else {
                    Ok(())
                }
            }
            OriginState::Empty => {
                if origin.connections.family.family().is_some() {
                    Err("prune retained the family of an origin that stayed empty".into())
                } else {
                    Ok(())
                }
            }
        };

        drop(held);
        drop(pending);
        target
    }).await;
    let outcome = match operation {
        Ok(result) => result,
        Err(elapsed) => Err(elapsed.into()),
    };

    race.finish(outcome).await
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    NonZeroUsize::new(value).ok_or_else(|| "zero pool bound".into())
}
