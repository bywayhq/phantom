use std::io;

use phantom_net::dns::{
    HttpsRecordLookup,
    wire::{DnsWireQuery, DnsWireQueryKind, DnsWireResult},
};
use tokio::time::Instant;

use super::{Endpoint, exchange};

#[cfg(test)]
mod tests;

pub(super) async fn lookup(
    endpoint: &Endpoint,
    host: &str,
    port: u16,
) -> io::Result<HttpsRecordLookup> {
    let query = origin_query(endpoint, host, port)?;
    let _permit = endpoint.admission.try_acquire().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "encrypted DNS lookup admission is full",
        )
    })?;
    crate::timeout::within(endpoint.settings.lookup_timeout, resolve(endpoint, query))
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "encrypted DNS lookup deadline expired",
            )
        })?
}

fn origin_query(endpoint: &Endpoint, host: &str, port: u16) -> io::Result<DnsWireQuery> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if port == 0
        || host.is_empty()
        || !host.is_ascii()
        || !matches!(url::Host::parse(host), Ok(url::Host::Domain(_)))
        || host
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"-_.".contains(&byte))
        || host.split('.').any(str::is_empty)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "origin cannot form an HTTPS DNS query",
        ));
    }
    // RFC 9460 section 9.1: HTTPS service names encode non-default ports.
    let name = if port == 443 {
        format!("{host}.")
    } else {
        format!("_{port}._https.{host}.")
    };
    DnsWireQuery::new(
        &name,
        DnsWireQueryKind::Https,
        endpoint.settings.query_id,
        endpoint.settings.padding_block,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

async fn resolve(endpoint: &Endpoint, mut query: DnsWireQuery) -> io::Result<HttpsRecordLookup> {
    let mut earlier_expiry = None;
    loop {
        let response = exchange::send(endpoint, &query).await?;
        match &response.answer {
            DnsWireResult::Https(records) => {
                let expiry = limit_expiry(earlier_expiry, response.expiry(records.response_ttl()));
                return Ok(apply_deadline(records.clone().into_lookup(), expiry));
            }
            DnsWireResult::Negative(negative) => {
                return Ok(match negative.response_ttl() {
                    Some(ttl) => apply_deadline(
                        HttpsRecordLookup::new(Vec::new(), negative.ttl()),
                        limit_expiry(earlier_expiry, response.expiry(ttl)),
                    ),
                    None => HttpsRecordLookup::new(Vec::new(), None),
                });
            }
            DnsWireResult::Cname(followup) => {
                // A later response's Age never re-ages a previous hop.
                if let Some(ttl) = followup.response_chain_ttl() {
                    earlier_expiry = Some(limit_expiry(earlier_expiry, response.expiry(ttl)));
                }
                query = followup.clone().into_query();
            }
            DnsWireResult::Addresses(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected address answer to HTTPS query",
                ));
            }
        }
    }
}

fn limit_expiry(previous: Option<Instant>, current: Instant) -> Instant {
    previous.map_or(current, |previous| previous.min(current))
}

fn apply_deadline(lookup: HttpsRecordLookup, expiry: Instant) -> HttpsRecordLookup {
    lookup.with_cache_deadline(expiry.into_std())
}
