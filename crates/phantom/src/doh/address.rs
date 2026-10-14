use std::{future::poll_fn, io, net::IpAddr, task::Poll, time::Duration};

use phantom_net::dns::wire::{DnsNegativeKind, DnsWireQuery, DnsWireQueryKind, DnsWireResult};
use tokio::time::Instant;

use super::{DohAddressFamilies, Endpoint, exchange};
use crate::{AddressAnswer, AddressNegativeKind};

#[cfg(test)]
mod tests;

enum Family {
    Positive {
        addresses: Vec<IpAddr>,
        expiry: Instant,
    },
    Negative {
        kind: AddressNegativeKind,
        expiry: Option<Instant>,
    },
}

pub(super) async fn lookup(endpoint: &Endpoint, host: &str) -> io::Result<AddressAnswer> {
    let _permit = endpoint.admission.try_acquire().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "DNS-over-HTTPS lookup admission is full",
        )
    })?;
    let mut ipv6_result = None;
    let mut ipv4_result = None;
    let operation = async {
        let family = match endpoint.configuration.families {
            DohAddressFamilies::Ipv4Only => {
                resolve_family(endpoint, host, DnsWireQueryKind::A).await
            }
            DohAddressFamilies::DualIpv6First => {
                let ipv6 = resolve_family(endpoint, host, DnsWireQueryKind::Aaaa);
                let ipv4 = resolve_family(endpoint, host, DnsWireQueryKind::A);
                let mut ipv6 = std::pin::pin!(ipv6);
                let mut ipv4 = std::pin::pin!(ipv4);
                // Both families belong to this lookup future. An error in
                // one cannot detach the other or publish a cacheable subset.
                let (ipv6, ipv4) = poll_fn(|context| {
                    if ipv6_result.is_none()
                        && let Poll::Ready(result) = ipv6.as_mut().poll(context)
                    {
                        ipv6_result = Some(result);
                    }
                    if ipv4_result.is_none()
                        && let Poll::Ready(result) = ipv4.as_mut().poll(context)
                    {
                        ipv4_result = Some(result);
                    }
                    if ipv6_result.is_some()
                        && ipv4_result.is_some()
                        && let Some(results) = ipv6_result.take().zip(ipv4_result.take())
                    {
                        return Poll::Ready(results);
                    }
                    Poll::Pending
                })
                .await;
                aggregate(ipv6, ipv4)
            }
        }?;
        into_answer(family)
    };
    match crate::timeout::within(endpoint.configuration.lookup_timeout, operation)
        .await
        .map_err(io::Error::other)?
    {
        Some(answer) => answer,
        None => {
            let expired = || {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS-over-HTTPS lookup deadline expired",
                )
            };
            if endpoint.configuration.families == DohAddressFamilies::DualIpv6First {
                // `within` has dropped the join and both pending HTTP futures.
                // A completed positive survives only with zero cache lifetime.
                aggregate(
                    ipv6_result.unwrap_or_else(|| Err(expired())),
                    ipv4_result.unwrap_or_else(|| Err(expired())),
                )
                .and_then(into_answer)
            } else {
                Err(expired())
            }
        }
    }
}

async fn resolve_family(
    endpoint: &Endpoint,
    host: &str,
    kind: DnsWireQueryKind,
) -> io::Result<Family> {
    let mut query = DnsWireQuery::new(
        host,
        kind,
        endpoint.configuration.query_id,
        endpoint.configuration.padding_block,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut earlier_expiry = None;
    loop {
        let response = exchange::send(endpoint, &query).await?;
        match &response.answer {
            DnsWireResult::Addresses(records) => {
                let expiry = limit_expiry(earlier_expiry, response.expiry(records.response_ttl()));
                return Ok(Family::Positive {
                    addresses: records.addresses().to_vec(),
                    expiry,
                });
            }
            DnsWireResult::Negative(negative) => {
                let expiry = negative
                    .response_ttl()
                    .map(|ttl| limit_expiry(earlier_expiry, response.expiry(ttl)));
                let kind = match negative.kind() {
                    DnsNegativeKind::NxDomain => AddressNegativeKind::NxDomain,
                    DnsNegativeKind::NoData => AddressNegativeKind::NoData,
                };
                return Ok(Family::Negative { kind, expiry });
            }
            DnsWireResult::Cname(followup) => {
                // Only this message's TTL sees this message's HTTP Age.
                // Earlier hops retain their independently aged deadline.
                if let Some(ttl) = followup.response_chain_ttl() {
                    earlier_expiry = Some(limit_expiry(earlier_expiry, response.expiry(ttl)));
                }
                query = followup.clone().into_query();
            }
            DnsWireResult::Https(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected HTTPS record answer to address query",
                ));
            }
        }
    }
}

fn limit_expiry(previous: Option<Instant>, current: Instant) -> Instant {
    previous.map_or(current, |previous| previous.min(current))
}

fn remaining(expiry: Instant) -> Duration {
    expiry.saturating_duration_since(Instant::now())
}

fn into_answer(family: Family) -> io::Result<AddressAnswer> {
    match family {
        Family::Positive { addresses, expiry } => {
            AddressAnswer::positive(addresses, remaining(expiry))
        }
        Family::Negative { kind, expiry } => {
            Ok(AddressAnswer::negative(kind, expiry.map(remaining)))
        }
    }
}

fn aggregate(ipv6: io::Result<Family>, ipv4: io::Result<Family>) -> io::Result<Family> {
    match (ipv6, ipv4) {
        (
            Ok(Family::Positive {
                addresses: mut ipv6,
                expiry: ipv6_expiry,
            }),
            Ok(Family::Positive {
                addresses: ipv4,
                expiry: ipv4_expiry,
            }),
        ) => {
            ipv6.extend(ipv4);
            Ok(Family::Positive {
                addresses: ipv6,
                expiry: ipv6_expiry.min(ipv4_expiry),
            })
        }
        (
            Ok(Family::Positive { addresses, expiry }),
            Ok(Family::Negative {
                kind: AddressNegativeKind::NoData,
                expiry: negative,
            }),
        )
        | (
            Ok(Family::Negative {
                kind: AddressNegativeKind::NoData,
                expiry: negative,
            }),
            Ok(Family::Positive { addresses, expiry }),
        ) => Ok(Family::Positive {
            addresses,
            expiry: negative.map_or_else(Instant::now, |negative| negative.min(expiry)),
        }),
        (
            Ok(Family::Negative {
                kind: left,
                expiry: left_expiry,
            }),
            Ok(Family::Negative {
                kind: right,
                expiry: right_expiry,
            }),
        ) if left == right => Ok(Family::Negative {
            kind: left,
            expiry: left_expiry
                .zip(right_expiry)
                .map(|(left, right)| left.min(right)),
        }),
        (Ok(_), Ok(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-HTTPS address families disagree about name existence",
        )),
        (Ok(Family::Positive { addresses, .. }), Err(_))
        | (Err(_), Ok(Family::Positive { addresses, .. })) => Ok(Family::Positive {
            addresses,
            expiry: Instant::now(),
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}
