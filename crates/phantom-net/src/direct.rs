use std::{
    any::Any,
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    task::Poll,
};

use phantom_profile::TcpSettings;
use tokio::net::TcpStream;

use crate::host_resolver::{HostResolver, resolve};

const TOKIO_IO_DISABLED_PANIC: &str = "A Tokio 1.x context was found, but IO is disabled. Call `enable_io` on the runtime builder to enable IO.";

#[derive(Debug)]
pub(crate) struct RuntimeUnavailable;

pub(crate) enum DirectConnectError {
    RuntimeUnavailable,
    Connect(std::io::Error),
}

/// How a connector opens its TCP connections: the profile's socket options
/// and the client's host resolver.
#[derive(Clone, Copy, Default)]
pub(crate) struct Dialer<'a> {
    pub(crate) tcp: Option<TcpSettings>,
    pub(crate) resolver: Option<&'a HostResolver>,
}

/// Opens one TCP connection, applying the connector's profile socket options.
///
/// `host` is resolved through the dialer's host resolver when it has one.
/// Without profile options the socket keeps its operating-system defaults and
/// the addresses are tried one at a time in resolver order.
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    dialer: Dialer<'_>,
) -> Result<TcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    let stream = match dialer.tcp {
        Some(settings) => {
            poll_tokio_io(|| crate::tcp::connect(host, port, settings, dialer.resolver)).await
        }
        None => {
            poll_tokio_io(|| async {
                let addresses = resolve(dialer.resolver, host, port).await?;
                TcpStream::connect(&*addresses).await
            })
            .await
        }
    }
    .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
    .map_err(DirectConnectError::Connect)?;
    #[cfg(test)]
    crate::tcp::observed::record(&stream);
    Ok(stream)
}

/// Shortest wait for an HTTPS record after the address answers
/// (`UseDnsHttpsSvcbInsecureExtraTimeMin`, `net/base/features.cc` lines
/// 95-97 at Chromium tag `154.0.8037.58`).
#[cfg(feature = "https-records")]
const HTTPS_RECORD_EXTRA_TIME_MIN: std::time::Duration = std::time::Duration::from_millis(5);
/// Longest such wait (`UseDnsHttpsSvcbInsecureExtraTimeMax`, lines 88-90).
#[cfg(feature = "https-records")]
const HTTPS_RECORD_EXTRA_TIME_MAX: std::time::Duration = std::time::Duration::from_millis(50);

/// Returns how long Chromium keeps waiting for an HTTPS record once the
/// address answers are in: 20% of the time the addresses took, clamped to
/// 5-50 ms (`HostResolverDnsTask::MaybeStartTimeoutTimer`,
/// `net/dns/host_resolver_dns_task.cc` lines 1122-1195 at `154.0.8037.58`).
#[cfg(feature = "https-records")]
pub(crate) fn https_record_extra_time(
    address_resolution: std::time::Duration,
) -> std::time::Duration {
    (address_resolution / 5).clamp(HTTPS_RECORD_EXTRA_TIME_MIN, HTTPS_RECORD_EXTRA_TIME_MAX)
}

/// Opens one TCP connection while `lookup` finishes, as Chromium's
/// `TcpConnectJob` does before its TLS handshake.
///
/// The addresses are resolved first, through the dialer's host resolver
/// when it has one. The TCP connect then starts at once, and `lookup` gets
/// [`https_record_extra_time`] of the address resolution time, counted from
/// the end of that resolution, to finish; a lookup still running then counts
/// as `None` (`net/socket/tcp_connect_job_connector.cc` lines 250-255 at
/// `154.0.8037.58`). A failed TCP connect returns without waiting.
///
/// When a stored answer supplies the addresses, nothing is waited for:
/// `lookup` gets no extra time and counts as `None` unless it is already done.
/// Chromium's cache hit likewise finalizes the request at once, with the
/// HTTPS record state stored beside the addresses, so its handshake does not
/// wait either (`ServiceEndpointRequestImpl::DoResolveLocally` and
/// `EndpointsCryptoReady`,
/// `net/dns/host_resolver_manager_service_endpoint_request_impl.cc` lines
/// 366-369, 433-445, and 161-167).
#[cfg(feature = "https-records")]
pub(crate) async fn connect_tcp_with_lookup<T>(
    host: &str,
    port: u16,
    dialer: Dialer<'_>,
    lookup: impl Future<Output = Option<T>>,
) -> Result<(TcpStream, Option<T>), DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    let started = std::time::Instant::now();
    let (addresses, stored) =
        poll_tokio_io(|| crate::host_resolver::resolve_noting_cache(dialer.resolver, host, port))
            .await
            .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
            .map_err(DirectConnectError::Connect)?;
    let extra_time = if stored {
        std::time::Duration::ZERO
    } else {
        https_record_extra_time(started.elapsed())
    };
    let deadline = crate::shutdown_timer::after(extra_time).map_err(|_| {
        DirectConnectError::Connect(std::io::Error::other(
            "could not schedule the HTTPS record deadline",
        ))
    })?;
    let bounded_lookup = async move {
        tokio::select! {
            biased;
            result = lookup => result,
            _ = deadline => None,
        }
    };
    let connect = connect_addresses(addresses, dialer.tcp);
    let (stream, result) = tokio::try_join!(connect, async {
        Ok::<_, DirectConnectError>(bounded_lookup.await)
    })?;
    Ok((stream, result))
}

/// Opens one TCP connection to `address`, as Chromium's ECH retry connects
/// to the server it reached before (`net/socket/ssl_connect_job.cc` lines
/// 251-285 at `154.0.8037.58`).
#[cfg(feature = "https-records")]
pub(crate) async fn connect_tcp_address(
    address: std::net::SocketAddr,
    tcp: Option<TcpSettings>,
) -> Result<TcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    connect_addresses(vec![address], tcp).await
}

#[cfg(feature = "https-records")]
async fn connect_addresses(
    addresses: Vec<std::net::SocketAddr>,
    tcp: Option<TcpSettings>,
) -> Result<TcpStream, DirectConnectError> {
    let stream = match tcp {
        Some(settings) => poll_tokio_io(|| crate::tcp::connect_resolved(addresses, settings)).await,
        None => poll_tokio_io(|| async move { TcpStream::connect(&addresses[..]).await }).await,
    }
    .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
    .map_err(DirectConnectError::Connect)?;
    #[cfg(test)]
    crate::tcp::observed::record(&stream);
    Ok(stream)
}

pub(crate) async fn poll_tokio_io<Operation, OperationFuture, Output>(
    operation: Operation,
) -> Result<Output, RuntimeUnavailable>
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = Output>,
{
    let future = match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(future) => future,
        Err(payload) if is_io_disabled_panic(payload.as_ref()) => return Err(RuntimeUnavailable),
        Err(payload) => resume_unwind(payload),
    };
    let mut future = std::pin::pin!(future);

    poll_fn(
        |context| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) if is_io_disabled_panic(payload.as_ref()) => {
                Poll::Ready(Err(RuntimeUnavailable))
            }
            Err(payload) => resume_unwind(payload),
        },
    )
    .await
}

fn is_io_disabled_panic(payload: &(dyn Any + Send)) -> bool {
    payload
        .downcast_ref::<&str>()
        .is_some_and(|message| *message == TOKIO_IO_DISABLED_PANIC)
        || payload
            .downcast_ref::<String>()
            .is_some_and(|message| message == TOKIO_IO_DISABLED_PANIC)
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{RuntimeUnavailable, poll_tokio_io};

    #[test]
    fn runtime_without_io_returns_runtime_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = runtime.block_on(poll_tokio_io(|| {
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 9))
        }));

        assert!(matches!(result, Err(RuntimeUnavailable)));
        Ok(())
    }

    #[test]
    fn unrelated_panics_resume_unwinding() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(poll_tokio_io(|| async {
                panic!("unrelated panic");
            }))
        }));

        let payload = match result {
            Ok(_) => return Err("unrelated panic was swallowed".into()),
            Err(payload) => payload,
        };
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"unrelated panic"));
        Ok(())
    }
}
