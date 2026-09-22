//! Happy Eyeballs racing of a host's resolved addresses.

use std::{future::Future, io, net::SocketAddr, pin::Pin};

use super::no_addresses;

/// Connects to one of `addresses` the way Chromium 153's `TcpConnectJob`
/// does with complete DNS results.
///
/// Line numbers are for Chromium tag `153.0.8010.48`, where Happy Eyeballs v2
/// is enabled and v3 disabled by default (`net/base/features.cc:114-124`), so
/// every TCP connection uses a `TcpConnectJob`
/// (`net/socket/transport_connect_job.cc:118-123`):
///
/// - The first attempt prefers IPv6 (`net/socket/tcp_connect_job.h:211`).
///   With one attempt running, a failure makes the next address come from the
///   other family (`net/socket/tcp_connect_job_connector.cc:300-303`).
/// - When `fallback` completes, a second attempt starts. The primary attempt
///   then prefers IPv6 and the second IPv4; a primary attempt already on IPv4
///   becomes the IPv4 one and a new primary attempt starts
///   (`net/socket/tcp_connect_job.cc:450-473`, `:691-694`). Chromium starts
///   that timer when the first attempt begins (`:580-616`).
/// - An attempt takes the first untried address of its preferred family, then
///   of the other; no address is tried twice
///   (`net/socket/tcp_connect_job.cc:703-746`). With two attempts there are
///   never more than two sockets in flight.
/// - The first connection wins and the other attempt is dropped, which closes
///   its socket. When both attempts run out of addresses, the most recent
///   failure is returned (`net/socket/tcp_connect_job.cc:406-431`, `:946-958`).
///
/// `dial` opens one attempt; `fallback` is the delay before the second one.
pub(super) async fn race<Dial, Attempt, Stream, Fallback>(
    addresses: Vec<SocketAddr>,
    fallback: Fallback,
    mut dial: Dial,
) -> io::Result<Stream>
where
    Dial: FnMut(SocketAddr) -> Attempt,
    Attempt: Future<Output = io::Result<Stream>>,
    Fallback: Future<Output = ()>,
{
    let mut addresses = Untried::new(addresses);
    let mut prefer_ipv6 = true;
    let mut primary = addresses
        .take(prefer_ipv6)
        .map(|address| Running::start(address, &mut dial));
    let mut secondary: Option<Running<Attempt>> = None;
    let mut fallback = std::pin::pin!(fallback);
    let mut two_attempts = false;
    let mut last_error = None;

    loop {
        if primary.is_none() && secondary.is_none() {
            return Err(last_error.unwrap_or_else(no_addresses));
        }
        tokio::select! {
            biased;
            (address, result) = Running::finish(&mut primary), if primary.is_some() => {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
                prefer_ipv6 = !address.is_ipv6();
                let preference = if two_attempts { true } else { prefer_ipv6 };
                primary = addresses
                    .take(preference)
                    .map(|address| Running::start(address, &mut dial));
            }
            (_, result) = Running::finish(&mut secondary), if secondary.is_some() => {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
                secondary = addresses
                    .take(false)
                    .map(|address| Running::start(address, &mut dial));
            }
            () = &mut fallback, if !two_attempts => {
                two_attempts = true;
                if primary.as_ref().is_some_and(|attempt| !attempt.address.is_ipv6()) {
                    secondary = primary.take();
                    primary = addresses
                        .take(true)
                        .map(|address| Running::start(address, &mut dial));
                } else {
                    secondary = addresses
                        .take(false)
                        .map(|address| Running::start(address, &mut dial));
                }
            }
        }
    }
}

/// One connection attempt in flight.
struct Running<Attempt> {
    address: SocketAddr,
    attempt: Pin<Box<Attempt>>,
}

impl<Attempt: Future> Running<Attempt> {
    fn start<Dial>(address: SocketAddr, dial: &mut Dial) -> Self
    where
        Dial: FnMut(SocketAddr) -> Attempt,
    {
        Self {
            address,
            attempt: Box::pin(dial(address)),
        }
    }

    /// Waits for the attempt in `slot`; an empty slot never completes.
    async fn finish(slot: &mut Option<Self>) -> (SocketAddr, Attempt::Output) {
        match slot {
            Some(running) => (running.address, running.attempt.as_mut().await),
            None => std::future::pending().await,
        }
    }
}

/// Resolved addresses split by family, keeping resolver order in each.
struct Untried {
    ipv6: Vec<SocketAddr>,
    ipv4: Vec<SocketAddr>,
    tried: Vec<SocketAddr>,
}

impl Untried {
    fn new(addresses: Vec<SocketAddr>) -> Self {
        let (ipv6, ipv4) = addresses.into_iter().partition(SocketAddr::is_ipv6);
        Self {
            ipv6,
            ipv4,
            tried: Vec::new(),
        }
    }

    /// Takes the first untried address of the preferred family, then of the other.
    fn take(&mut self, prefer_ipv6: bool) -> Option<SocketAddr> {
        let (preferred, other) = if prefer_ipv6 {
            (&self.ipv6, &self.ipv4)
        } else {
            (&self.ipv4, &self.ipv6)
        };
        let address = preferred
            .iter()
            .chain(other)
            .copied()
            .find(|address| !self.tried.contains(address))?;
        self.tried.push(address);
        Some(address)
    }
}

#[cfg(test)]
mod tests;
