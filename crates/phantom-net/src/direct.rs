use std::{
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    task::Poll,
};

use phantom_profile::{TcpSettings, UdpSettings};
use tokio::net::TcpStream;

use crate::{
    host_resolver::{HostResolver, resolve},
    source_binding::SourceBinding,
    tcp::ProfileTcpStream,
};

#[derive(Debug)]
pub(crate) struct RuntimeUnavailable;

pub(crate) enum DirectConnectError {
    RuntimeUnavailable,
    Connect(std::io::Error),
}

/// How a connector opens its sockets: the profile's TCP and UDP socket
/// options, the caller's source binding, and the client's host resolver.
///
/// Only a SOCKS5 UDP association opens a UDP socket through a dialer.
#[derive(Clone, Copy, Default)]
pub(crate) struct Dialer<'a> {
    pub(crate) tcp: Option<TcpSettings>,
    pub(crate) udp: Option<UdpSettings>,
    pub(crate) source: Option<&'a SourceBinding>,
    pub(crate) resolver: Option<&'a HostResolver>,
}

/// Opens one TCP connection, applying the connector's profile socket options
/// and source binding.
///
/// `host` is resolved through the dialer's host resolver when it has one.
/// Without profile options the socket keeps its operating-system defaults and
/// the addresses are tried one at a time in resolver order.
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    dialer: Dialer<'_>,
) -> Result<ProfileTcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    let stream = match (dialer.tcp, dialer.source) {
        (None, None) => {
            poll_tokio_io(|| async {
                let addresses = resolve(dialer.resolver, host, port).await?;
                TcpStream::connect(&*addresses)
                    .await
                    .map(ProfileTcpStream::new)
            })
            .await
        }
        (tcp, source) => {
            poll_tokio_io(|| crate::tcp::connect(host, port, tcp, source, dialer.resolver)).await
        }
    }
    .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
    .map_err(DirectConnectError::Connect)?;
    #[cfg(test)]
    crate::tcp::observed::record(stream.tcp_stream());
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
) -> Result<(ProfileTcpStream, Option<T>), DirectConnectError> {
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
    let connect = connect_addresses(addresses, dialer, started);
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
    dialer: Dialer<'_>,
) -> Result<ProfileTcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    connect_addresses(vec![address], dialer, std::time::Instant::now()).await
}

/// Why a direct TLS connection that could offer Encrypted Client Hello failed.
#[cfg(feature = "https-records")]
pub(crate) enum DirectTlsError {
    Direct(DirectConnectError),
    Tls(crate::tls::TlsError),
}

/// Opens one direct TCP connection and TLS handshake that offers Encrypted
/// Client Hello with the `ECHConfigList` that `ech` yields, as Chrome 154's
/// `SSLConnectJob` does for an origin's HTTPS record.
///
/// The TCP connect and the bounded wait for `ech` follow
/// [`connect_tcp_with_lookup`]; `None` gives the handshake
/// [`crate::tls::TlsConnector::connect`] makes. A list the TLS client rejects
/// fails with [`crate::tls::EchFailure::InvalidConfigList`] before any TLS
/// byte is sent. When the server rejects ECH and authenticates as the public
/// name, this connects once more to the same address, offering the server's
/// retry configurations, or ECH GREASE and the true server name when it sent
/// none (`SSLConnectJob::DoSSLConnectComplete`,
/// `net/socket/ssl_connect_job.cc` lines 506-525 at `154.0.8037.58`). A
/// second rejection fails with [`crate::tls::EchFailure::Rejected`].
///
/// With `offer_early_data` set, a connection that offers no ECH configuration
/// is the one [`crate::tls::TlsConnector::connect_offering_early_data`] makes.
#[cfg(feature = "https-records")]
pub(crate) async fn connect_tls_with_ech(
    tls: &crate::tls::TlsConnector,
    dialer: Dialer<'_>,
    host: &str,
    port: u16,
    server_name: &str,
    ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    offer_early_data: bool,
) -> Result<crate::tls::TlsStream<ProfileTcpStream>, DirectTlsError> {
    use crate::{
        dns::EchConfigList,
        tls::{EchFailure, TlsError},
    };

    let (stream, list) = connect_tcp_with_lookup(host, port, dialer, ech)
        .await
        .map_err(DirectTlsError::Direct)?;
    if let Some(Err(error)) = list.as_ref().map(EchConfigList::parse) {
        return Err(DirectTlsError::Tls(TlsError::invalid_ech_config_list(
            error,
        )));
    }
    let address = stream
        .peer_addr()
        .map_err(|error| DirectTlsError::Direct(DirectConnectError::Connect(error)))?;
    let offered = list.as_ref().map(EchConfigList::as_bytes);
    let handshake = match offered {
        None if offer_early_data => tls.connect_offering_early_data(server_name, stream).await,
        offered => tls.connect_with_ech(server_name, stream, offered).await,
    };
    match handshake {
        Ok(stream) => Ok(stream),
        Err(mut error) if error.ech_failure() == Some(EchFailure::Rejected) => {
            let retry_configs = error.take_ech_retry_configs();
            tracing::debug!(
                retry_configs = retry_configs.is_some(),
                "server rejected ECH; connecting once more"
            );
            let stream = connect_tcp_address(address, dialer)
                .await
                .map_err(DirectTlsError::Direct)?;
            tls.connect_with_ech(server_name, stream, retry_configs.as_deref())
                .await
                .map_err(DirectTlsError::Tls)
        }
        Err(error) => Err(DirectTlsError::Tls(error)),
    }
}

#[cfg(feature = "https-records")]
async fn connect_addresses(
    addresses: Vec<std::net::SocketAddr>,
    dialer: Dialer<'_>,
    started: std::time::Instant,
) -> Result<ProfileTcpStream, DirectConnectError> {
    let stream = match (dialer.tcp, dialer.source) {
        (None, None) => {
            poll_tokio_io(|| async move {
                TcpStream::connect(&addresses[..])
                    .await
                    .map(ProfileTcpStream::new)
            })
            .await
        }
        (tcp, source) => {
            poll_tokio_io(|| crate::tcp::connect_resolved(addresses, tcp, source, started)).await
        }
    }
    .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
    .map_err(DirectConnectError::Connect)?;
    #[cfg(test)]
    crate::tcp::observed::record(stream.tcp_stream());
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
        Err(_) if io_driver_missing() => return Err(RuntimeUnavailable),
        Err(payload) => resume_unwind(payload),
    };
    let mut future = std::pin::pin!(future);

    poll_fn(
        |context| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) if io_driver_missing() => Poll::Ready(Err(RuntimeUnavailable)),
            Err(payload) => resume_unwind(payload),
        },
    )
    .await
}

/// Whether the current context has no runtime with an I/O driver.
///
/// Called after an I/O operation panicked. Tokio has no query for its I/O
/// driver, and registering a socket without one panics, so registering an
/// unbound probe socket that panics as well attributes the first panic to the
/// missing driver without relying on the wording of Tokio's panic message. A
/// panic the probe does not repeat, or one the probe cannot check because no
/// socket can be created, keeps unwinding. The probe socket is never bound or
/// connected; an IPv6 one stands in on a host without IPv4.
fn io_driver_missing() -> bool {
    let socket = [socket2::Domain::IPV4, socket2::Domain::IPV6]
        .into_iter()
        .find_map(|domain| socket2::Socket::new(domain, socket2::Type::DGRAM, None).ok());
    let Some(socket) = socket else {
        return false;
    };
    if socket.set_nonblocking(true).is_err() {
        return false;
    }
    let socket = std::net::UdpSocket::from(socket);
    catch_unwind(AssertUnwindSafe(|| tokio::net::UdpSocket::from_std(socket))).is_err()
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
    fn missing_io_driver_is_detected_whatever_the_panic_says()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = runtime.block_on(poll_tokio_io(|| async {
            panic!("the I/O driver is missing, in words a later Tokio might use");
        }));

        assert!(matches!(result, Err(RuntimeUnavailable)));
        Ok(())
    }

    #[test]
    fn unrelated_panics_resume_unwinding() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
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
