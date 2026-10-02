//! An IPv4 backup connection for a slow first attempt, as
//! [`TcpBackupConnection`](phantom_profile::TcpBackupConnection) describes.

use std::{collections::VecDeque, future::Future, io, net::SocketAddr, pin::Pin, time::Instant};

use super::{is_refusal_or_timeout, no_addresses};

/// Connects to one of `addresses` the way Firefox 157's `DnsAndConnectSocket`
/// does on release builds.
///
/// Line numbers are for Firefox tag `FIREFOX_157_0_RELEASE`:
///
/// - The primary attempt tries the addresses one at a time in resolver order
///   (`netwerk/dns/nsDNSService2.cpp:163-228`).
/// - When `delay` completes while the primary attempt has not connected, the
///   backup attempt starts with the IPv4 addresses alone
///   (`netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`, `:222-225`,
///   `:242-265`, `:286-290`).
/// - Each attempt moves to its next address only when a connect is refused,
///   finds no route, or times out
///   (`netwerk/base/nsSocketTransport2.cpp:169-200`, `:1747-1755`); any other
///   failure ends that attempt.
/// - The first connection wins and the other attempt is dropped, which
///   closes its socket. A primary attempt that fails before the backup
///   starts ends the connection (`DnsAndConnectSocket.cpp:267-277`). When
///   both attempts fail, the most recent failure is returned.
///
/// `started` is when the host lookup began. The winning stream comes back
/// with the moment its attempt began: `started` for the primary attempt, the
/// end of `delay` for the backup.
pub(super) async fn connect<Dial, Attempt, Stream, Delay>(
    addresses: Vec<SocketAddr>,
    delay: Delay,
    mut dial: Dial,
    started: Instant,
) -> io::Result<(Stream, Instant)>
where
    Dial: FnMut(SocketAddr) -> Attempt,
    Attempt: Future<Output = io::Result<Stream>>,
    Delay: Future<Output = ()>,
{
    let ipv4: VecDeque<SocketAddr> = addresses
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect();
    let mut primary = Walk::start(addresses.into(), &mut dial, started);
    let mut backup: Option<Walk<Attempt>> = None;
    let mut backup_pending = Some(ipv4);
    let mut delay = std::pin::pin!(delay);
    let mut last_error = None;

    loop {
        if primary.is_none() && backup.is_none() {
            return Err(last_error.unwrap_or_else(no_addresses));
        }
        tokio::select! {
            biased;
            result = Walk::finish(&mut primary), if primary.is_some() => {
                match result {
                    Ok(connected) => return Ok(connected),
                    Err(error) => last_error = Some(error),
                }
                let Some(walk) = primary.take() else { continue };
                primary = walk.next(&last_error, &mut dial);
                if primary.is_none() && backup.is_none() {
                    // No backup has started; the timer is cancelled.
                    backup_pending = None;
                }
            }
            result = Walk::finish(&mut backup), if backup.is_some() => {
                match result {
                    Ok(connected) => return Ok(connected),
                    Err(error) => last_error = Some(error),
                }
                let Some(walk) = backup.take() else { continue };
                backup = walk.next(&last_error, &mut dial);
            }
            () = &mut delay, if backup_pending.is_some() && primary.is_some() => {
                if let Some(addresses) = backup_pending.take() {
                    backup = Walk::start(addresses, &mut dial, Instant::now());
                }
            }
        }
    }
}

/// One attempt: the address being connected and the ones it may try next.
struct Walk<Attempt> {
    connecting: Pin<Box<Attempt>>,
    remaining: VecDeque<SocketAddr>,
    started: Instant,
}

impl<Attempt> Walk<Attempt> {
    fn start<Dial>(
        mut addresses: VecDeque<SocketAddr>,
        dial: &mut Dial,
        started: Instant,
    ) -> Option<Self>
    where
        Dial: FnMut(SocketAddr) -> Attempt,
    {
        let address = addresses.pop_front()?;
        Some(Self {
            connecting: Box::pin(dial(address)),
            remaining: addresses,
            started,
        })
    }

    /// The same attempt on its next address, when `error` lets it move on.
    fn next<Dial>(self, error: &Option<io::Error>, dial: &mut Dial) -> Option<Self>
    where
        Dial: FnMut(SocketAddr) -> Attempt,
    {
        if !error.as_ref().is_some_and(is_refusal_or_timeout) {
            return None;
        }
        Self::start(self.remaining, dial, self.started)
    }
}

impl<Attempt, Stream> Walk<Attempt>
where
    Attempt: Future<Output = io::Result<Stream>>,
{
    /// Waits for the attempt in `slot`; an empty slot never completes.
    async fn finish(slot: &mut Option<Self>) -> io::Result<(Stream, Instant)> {
        match slot {
            Some(walk) => {
                let started = walk.started;
                walk.connecting
                    .as_mut()
                    .await
                    .map(|stream| (stream, started))
            }
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests;
